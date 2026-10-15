# Security policy

auto_sec is a hardening tool. A flaw in it does not just affect this repository — it
affects every server someone pointed it at. Reports are taken seriously and credited.

## Reporting a vulnerability

**Please do not open a public issue for a vulnerability.**

Use GitHub's private reporting: **Security → Advisories → Report a vulnerability** on
[this repository](https://github.com/pythonistastic/auto_sec/security/advisories/new).
That channel is private until a fix ships.

Useful things to include, in rough order of value:

- The file and line, and the variable or input involved.
- A concrete malicious value and what it achieves (root execution? file write? lockout?).
- Whether it needs operator-supplied input, or input an attacker can influence from a
  managed server.
- The OS and `ansible-core` version you saw it on.

You will get an acknowledgement within a few days. This is a one-maintainer, early-stage
project, so please don't expect enterprise response times — but security reports go to the
front of the queue.

## What counts as a vulnerability here

In scope, roughly in order of severity:

- **Code execution** — any path where a variable's value becomes part of a command. The
  high-risk sinks are Jinja interpolation into `shell:` or into a `.j2` that renders a
  script, and argv splitting in `command:` that injects an extra flag.
- **Privilege escalation** — anything that lets a lower-privileged user on a managed host
  reach root, especially *through* auto_sec's own scheduled jobs.
- **Backup compromise** — anything that changes who can decrypt a backup, lets a managed
  host destroy or hide backup history, or causes a restore to silently produce the wrong
  data.
- **Lockout** — a change that can leave an operator unable to reach their own server, or
  that writes a config whose effect differs from what it reports.
- **Secret disclosure** — tokens or keys reaching logs, `ps`, world-readable files, or a
  client-facing report.
- **False assurance** — the tool, or the generated client report, claiming a control is
  active when it is not. This is treated as a security bug, not a cosmetic one, because
  the report is relied upon.

Out of scope: findings that require the operator to deliberately attack their own
infrastructure with values only they can set, *unless* the same path can be reached by
data read from a managed host. That distinction matters a lot here — see below.

## A note on trust boundaries

Most variables in `host_vars` are typed by the operator, so a malicious value is
self-inflicted and low-risk. That changes the moment a value is **derived from a managed
server** (a hostname read from a config file, a package name, a domain from an nginx
vhost). Then an attacker with limited access to that server can influence a value that
auto_sec later runs as root.

Therefore: **facts collected from a managed host must never be promoted into variables
automatically.** They may be displayed to the operator; a human types the value. Treat any
report that crosses this boundary as high severity.

Likewise, anything auto_sec *reads* from a host — log lines, process names, file names,
CVE descriptions — is untrusted data, never instructions.

### What the SSH role reads from the host (0.4.0)

Role 02 reads a lot from the managed host before it changes SSH: `sshd -T` and `sshd -t`
output, `systemctl` state, `ss`, the journal, file times, `id -un` and `$SSH_CONNECTION`.
All of it is **only compared, displayed, or used to refuse a run**. None of it becomes a
variable value, a file's content, or part of a command, with **one documented exception**:

- **The controller's IP address (`_ssh_controller_ip`).** It is the first field of
  `$SSH_CONNECTION`, as seen on the managed host. It is used in two places:
  - in remote mode, and only when fail2ban's `sshd` jail is active, as one argument to
    `fail2ban-client set sshd addignoreip <ip>`. That stops the run's own login tests from
    getting the operator banned;
  - as the `addr=` field of `sshd -T -C user=...,host=...,addr=<ip>,lport=...`, so that
    `Match Address` blocks are evaluated for the address you really connect from.
    `sshd -T` only prints settings; it changes nothing.
- It must match a strict IPv4/IPv6 pattern first. Anything else, and any loopback
  address, becomes empty: then no ignore is added, and `sshd -T` gets the placeholder
  `192.0.2.1` (TEST-NET-1) instead.
- It is passed as a separate argv item (to `sh -c '...' sh <ip>` as `"$1"`, or directly),
  never pasted into a command line.
- The fail2ban ignore lasts only while the run is going. It is removed again in the
  role's `always:` section, and by the undo guard's revert if the run dies. auto_sec
  writes the address to disk in two places only, both root-only:
  - `/run/auto-sec/f2b-ignore` (tmpfs), while the ignore is in place. If a run is
    interrupted before its `always:` section, the next run reads this file **on the
    host**, checks that it holds a plain address, removes that ignore with
    `fail2ban-client set sshd delignoreip`, and deletes the file. The address never
    goes back into Ansible. An address that also appears in fail2ban's own config
    files is left alone.
  - the guard's pending state (`/var/lib/auto-sec/ssh-guard/`), from the moment the
    undo is armed, so that a revert can remove the ignore. It is deleted when the
    change is kept or undone.
- It is never written to fail2ban's config files, host_vars or the report, and it is
  never used to unban anyone. Like any SSH client address, it does appear in logs on the host:
  sshd's auth log, and the "Invoked with" lines that Ansible modules write to the
  journal (the `fail2ban-client`, guard `arm` and `sshd -T` arguments).
- Worst case: a host that is already compromised can lie in `$SSH_CONNECTION`. Then
  fail2ban on **that same host** ignores some address for a few minutes. That gives an
  attacker nothing they did not already have.

Persistent fail2ban exceptions come only from values the operator types:
`office_static_ip` and `fail2ban_ignore_ips`.

Shell snippets that run **on the host** may use the host's own file names there: the
preflight check "were the SSH files changed after sshd last loaded them?" runs `stat`
on every file that sshd's own trace (`sshd -t -ddd`) says it reads. Those names are
only printed back and compared; they never become an Ansible value, a file's
content, or an argument that Ansible builds.

### What role 01 reads from the host (0.5.0)

Before it changes the update settings, role 01 reads `apt-config dump`, the files in
`/etc/apt/apt.conf.d` (through apt itself, on a copy), `dpkg-query`, dpkg's and ucf's
checksums of `50unattended-upgrades`, `/var/run/reboot-required`, `hostnamectl`,
`timedatectl`, `ss` (ports 25, 465 and 587), the names in `/etc/cron.d`,
`/var/spool/cron/crontabs` and `systemctl list-timers`, `/etc/hosts`, cloud-init's
`preserve_hostname`, and apt's simulation of the package install
(`apt-get -s --no-install-recommends install <missing packages>`). All of it is
**only compared, displayed, or used to refuse a run**, with these documented uses:

- **Whether unattended-upgrades is installed.** With
  `unattended_upgrades_enabled: auto`, a package that was removed on purpose (dpkg
  state `rc`) is not installed again. auto_sec never writes an `APT::Periodic` line in
  this mode: the package's own `20auto-upgrades` holds the switch. Only
  `unattended_upgrades_enabled: true` writes the two lines, as fixed text (`"1"`); no
  value read from the host is written.
- **Which packages to install, and whether to refuse.** The package names are role
  constants. apt's simulation is only parsed for `Inst <package> [<installed version>]`
  (an upgrade) and `Remv` lines; any of them refuses the run unless
  `-e apt_full_upgrade=true` is given. Their names and versions are shown after a
  strict pattern, with braces replaced.
- **The one exception for file content: the 0.1–0.4 restore, only with
  `-e apt_migrate_unattended_upgrades=true`.** When
  `/etc/apt/apt.conf.d/50unattended-upgrades` is byte for byte the file auto_sec
  0.1–0.4 wrote (a SHA-256 fixed in the role), role 01 copies the distro's own
  `/usr/share/unattended-upgrades/50unattended-upgrades` over it, and only after that
  copy's MD5 matched dpkg's record (`/var/lib/dpkg/info/unattended-upgrades.md5sums`).
  Without the switch the run refuses and shows what the restore would change. The
  content is the package's own file, checked against the package's own record;
  role 02's migration back to the stock `sshd_config` is the precedent. The old file
  is kept in `/var/lib/auto-sec/backup/` (directory 0700, file 0600).
- **The current timezone as a command argument.** To show how a timezone change moves
  the clock, the host's current timezone (from `timedatectl`, after it matched a
  strict pattern) is passed as one argv item to `TZ=$1 date +%z` on the host. The
  output is only displayed.
- Names shown in messages (cron files, timers, packages, the hostname, the timezone)
  must match a strict pattern first, or they are not shown. In apt values, `${macro}`
  becomes `<macro>` and any other brace becomes `?` before Ansible uses them, so a
  value can never be read as a Jinja template.
- The trial run copies `/etc/apt/apt.conf.d` to `/run/auto-sec/apt-sim` (tmpfs, root
  only) and removes it again.

### What role 03 reads from fail2ban (0.5.0)

Role 03 runs its helper `auto-sec-f2b-check` (Python standard library) as root with
`python3 -I`, as one argv list without a shell. The helper copies `/etc/fail2ban` to
`/run/auto-sec/f2b-sim` (tmpfs, root only, removed at the end of every trial) and asks
fail2ban's own config reader (`fail2ban-client -d`, `-t`, `-vvv`) and the running
server (`fail2ban-client status` and `get`) what the files and the server mean. On the
host it passes the jail names that the server reports to `fail2ban-client get`; like
the SSH file names above, they never become an argument that Ansible builds. Role 03
also reads `dpkg-query` and `systemctl`.

`00-autosec.conf` is rendered from the operator's variables only: **nothing read from
the host becomes part of it.** The helper's findings are used only:

- to refuse a run (fail2ban's config does not load; auto_sec's values would change a
  jail of the operator's; a file read before auto_sec's sets the same value; the
  running server differs from its files; a file with auto_sec's name that auto_sec
  did not write; a migration would make a jail stop ignoring an address), or to warn
  (for example: the database is off, so restarting the `sshd` jail releases its
  bans);
- to be shown: in the run's output, and as one line of the client report (role 10):
  the `sshd` jail's effective `maxretry`, `findtime` and `bantime` and the names of
  the files they come from;
- to decide whether fail2ban is reloaded (only when its effective config changes) and
  whether its `sshd` jail is restarted with `fail2ban-client reload --restart sshd`
  (only when that jail's port or action changes);
- with `-e fail2ban_migrate_jail_local=true` only: to decide whether `jail.local` is
  exactly the file auto_sec 0.1–0.4 wrote (fixed text; only the port number and the
  ignore list may differ). Only then is it moved to `/var/lib/auto-sec/fail2ban/`
  (directory 0700, file 0600), after the copy's checksum matched. If the change then
  fails, the rollback copies that backup back to `jail.local`: the operator's previous
  file, unchanged.

Every string in the helper's output has `{` and `}` replaced by `?`, so host text can
never be read as a Jinja template. During a run, `/run/auto-sec/f2b-prev` (root only)
keeps the previous `00-autosec.conf` for the rollback, and is removed at the end.

A new use of host data as an argument, a value or file content needs the same kind of
written exception here, and a review. Treat anything else that crosses this line as a
high-severity bug.

## Supported versions

Pre-1.0: only the latest tag receives fixes. Upgrade before reporting if you can.

| Version | Supported |
|---|---|
| latest tag | ✅ |
| anything older | ❌ |

## Disclosure

Fixes ship in a patch release with the advisory published at the same time, and the
CHANGELOG entry links back to it. If you'd like credit, say so in the report and tell me
how you want to be named.

## Honest limitations

auto_sec is early-stage and does not promise complete security. Known gaps — including
parts that are shipped but not yet validated end-to-end — are tracked openly in
[docs/RETROSPECTIVE.md](docs/RETROSPECTIVE.md). Reading that first may save you a report
about something already known.
