```
 █████╗ ██╗   ██╗████████╗ ██████╗         ███████╗███████╗ ██████╗
██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗        ██╔════╝██╔════╝██╔════╝
███████║██║   ██║   ██║   ██║   ██║        ███████╗█████╗  ██║
██╔══██║██║   ██║   ██║   ██║   ██║        ╚════██║██╔══╝  ██║
██║  ██║╚██████╔╝   ██║   ╚██████╔╝███████╗███████║███████╗╚██████╗
╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚══════╝╚══════╝╚══════╝ ╚═════╝
        server hardening - a personal research project
```

# auto_sec

![version](https://img.shields.io/badge/version-0.5.0-blue)
![status](https://img.shields.io/badge/status-personal%20research%20project-orange)
![license](https://img.shields.io/badge/license-MIT-green)

> **A personal research project.** auto_sec is one person's experiment in
> careful, explainable server hardening with Ansible. It is **not** a fully
> working or production service, and nothing here is certified or
> supported. Read what it does, try it on a throwaway server first, and
> see the [Disclaimer](#disclaimer).

**Version 0.5.0** · what's new and what's fixed: [CHANGELOG.md](CHANGELOG.md).

An Ansible playbook for an Ubuntu/Debian VPS. You describe each server in
one file, and every run shows a plan before it changes anything. What it
can do:

- SSH login rules **you choose** per server: keep them as they are, or
  keys only and no root password. Nothing gets stricter until your key
  works on a brand-new login, and an automatic undo timer covers every
  SSH change (see [SSH access](#ssh-access)).
- On a **new** server: turn the firewall (ufw) on with only the ports you
  list, install fail2ban and automatic security updates, and create the
  admin account. On an **existing** server it changes none of these
  unless you ask (see [Existing or new server](#existing-or-new-server)).
- Optional layers for a new server: Node/Docker + nginx + TLS, a local
  database, fwknop, and nightly client-side-encrypted backups (age) to a
  Backblaze B2 bucket whose key cannot delete.
- An opt-in daily **CVE watch** of your app's dependencies.
- A short report, written on your own computer, that states only what the
  run measured.

**Detection is not managed in 0.6.** The detectors of 0.1-0.5 (roles 08
and 09) did not work as documented: the ransomware canary never alerted
and the 5-minute audit scan worked only once
([issue #18](https://github.com/pythonistastic/auto_sec/issues/18)).
0.6 installs and changes nothing there, and warns if old detectors are
still on a server. A rewritten, tested detection suite is planned for 0.7.
See [Detection](#detection-roles-08-and-09).

## Before you start (beginners)

You run this from a **control machine** — that can be your own computer,
or the server itself. Pick whichever is simpler for you:

### Option A — run it *on the server* (easiest, nothing to install locally)

You only need an SSH client to reach the server, which is already built
into Windows 10/11, macOS, and Linux. SSH into your VPS as root (your
provider emails you the IP and root password), then run the
[Quick start](#quick-start) commands right there:

```bash
ssh root@YOUR.SERVER.IP        # enter the root password when asked
```

The wizard runs in "local" mode and prints the one `ssh-keygen` command
to run on your laptop for future logins.

One limit: on the server itself, auto_sec cannot test a new login from
your laptop. So in local mode it never makes SSH logins stricter, and it
cannot turn ufw on (that also needs a fresh login test; the wizard writes
`firewall_state: keep`). To do either later, use Option B (see
[Local mode](#local-mode-running-on-the-server-itself)).

### Option B — run it *from your own computer* (to manage servers remotely)

This needs **git** and **Ansible**, which only run in a Unix-like
environment:

- **Windows:** install WSL (Windows Subsystem for Linux). In an
  Administrator PowerShell run `wsl --install`, reboot, and let it open
  Ubuntu. Do everything below *inside that Ubuntu window*.
- **macOS:** install [Homebrew](https://brew.sh), then `brew install git`.
- **Linux:** git is usually already present.

`./scripts/bootstrap.sh` installs Ansible for you on the first run, so
you don't have to install it by hand.

You do **not** need to prepare an SSH key in advance — the wizard makes
one for you if you don't have it (see "New to SSH keys?" below).

## Quick start

On your workstation (managing a remote server) **or** directly on the
server you want to harden:

```bash
git clone https://github.com/pythonistastic/auto_sec.git
cd auto_sec
./scripts/bootstrap.sh
```

The bootstrap installs Ansible and dependencies, then runs an
interactive wizard that:

1. asks whether the server is **existing** or **new**, then plain-language
   questions (admin account, ports, app, database, alerts, reboots,
   hostname and timezone),
2. generates every secret it can (age backup keypair, fwknop keys,
   database password),
3. writes `host_vars/<server>.yml` + `inventory/<server>.yml`
   (both gitignored), and
4. prints the exact commands: first the plan, then the run.

**Is the server already in use?** Choose `existing`. auto_sec then
changes only what you name, and you can ask for your OK before every run
that would change something. Start with the plan
(`-e autosec_plan_only=true`) and read it. Do not put the playbook in
cron.

**New to SSH keys?** You don't need to prepare anything first. An SSH key
is a pair — a **private** half that stays secret on your computer and a
**public** half that's safe to put on the server. When you run the wizard
from your workstation, it looks for an existing key and, if you don't
have one, offers to create it for you (and explains what it made). If
you're running the wizard *on the server itself*, it prints the exact
`ssh-keygen` command to run on your own laptop and asks you to paste the
public half. Either way it walks you through it — no prior knowledge
assumed.

**Supported targets:** Ubuntu 22.04 and 24.04. Debian 12 and 13 are
tested in CI only (see [Known limitations](#known-limitations)). The SSH
role needs a Debian-family system with OpenSSH 8.2 or newer; anywhere
else, set `ssh_hardening_enabled: false`.

## Existing or new server

Every server needs one line in its `host_vars`. It has no default: the
run stops until you set it.

```yaml
autosec_server: existing   # or: new
```

- **`existing`**: a server that already runs something. auto_sec changes
  **nothing unless you ask for it by name**. It does not turn ufw on,
  install fail2ban or automatic updates, or create an account. It runs no
  ufw command on a ufw that is already on.
- **`new`**: a brand-new server with nothing on it yet. auto_sec turns
  ufw on (SSH plus the ports in `firewall_inbound`), installs fail2ban
  and automatic security updates, and creates the admin account
  `deploy_user` with passwordless sudo (when it is also `ssh_admin_user`).

Each of these has its own setting, and the `existing`/`new` line only
picks its default. You can always write the value yourself:

| Setting | `existing` | `new` | Values |
|---|---|---|---|
| `deploy_user_account` | `keep` | `create` (when `deploy_user` is `ssh_admin_user`) | `keep`, `create` |
| `unattended_upgrades_enabled` | `keep` | `auto` | `auto`, `true`, `keep` |
| `fail2ban_hardening_enabled` | `keep` | `true` | `keep`, `true` |
| `firewall_state` | `keep` | `enabled` | `keep`, `enabled` |
| `cve_watch_enabled` | `false` | `false` | `true`, `false` |

What auto_sec 0.6 never does by itself, on either kind of server:
changing an existing account, writing kernel settings, running a ufw
command on an active ufw, restarting services through needrestart, or
installing a detector.

## The plan, and your OK

Every run starts with checks that only read, and then prints a plan:
one line per role, the totals, and a plan id. Nothing changes before
that point. A run on a server where nothing would change looks like
this:

```
auto_sec 0.6.0 plan for canary (autosec_server: existing)
  01 base:      no change
  02 ssh:       no change
  03 firewall:  ufw active, kept (no ufw command); fail2ban: keep (no install, no file, no reload)
  04-07:        skipped (not configured)
  08 detection: not managed in 0.6 (no change)
  09 watcher:   not managed in 0.6 (no change)
  10 report:    writes reports/security-report-canary.md on this computer; nothing on the server
  11 cve:       skipped (cve_watch_enabled: false)
  packages:     nothing to install
  server: 0 files, 0 packages, 0 services (re)started, 0 firewall rules
  Plan id: 1a2b3c4d5e6f  (no server change: approval not needed)
```

- `-e autosec_plan_only=true` prints the plan and stops. This is the
  safest first command on any server.
- `autosec_require_approval: true` (in `host_vars`) makes a run that
  would change the server stop at the plan. Run it again with
  `-e autosec_approve=<plan id>`. If what the run would change is
  different (another file content, package or rule), the plan id is
  different too, and the run stops again. Notes are not part of the id.
  A run that changes nothing needs no OK, and neither does `--check`.
- A run over several hosts without `-l` stops before it connects
  anywhere (an empty `-l ""` counts as no `-l`), unless you confirm the
  count with `-e autosec_confirm_hosts=<n>`. Hosts run one at a time,
  and the first failure stops the rest.

## Declarative / CI use (without the wizard)

You can skip the wizard and drive auto_sec from committed config — write
`host_vars/<server>.yml` and `inventory/<server>.yml` yourself, then run
`ansible-playbook`. This suits CI, fleets, and GitOps.

The playbook **fails fast**: the `pre_tasks` of [site.yml](site.yml)
check every required variable, and every role's read-only checks run
there too, *before* any change. An incomplete or unsafe config stops the
run instead of leaving a half-done server.

If your checkout is under `/mnt/c` (WSL), Ansible ignores an
`ansible.cfg` there. Set `ANSIBLE_INVENTORY_UNPARSED_FAILED=1` in your
shell, so a broken inventory file stops the run instead of being skipped.

Minimal `host_vars` by scope (only what each needs):

```yaml
# Required on every server:
autosec_server: existing               # or new
# SSH login choices (required, no default). Always quote "no".
ssh_admin_user: "root"                 # set ansible_user to the same name
ssh_admin_public_keys: ["ssh-ed25519 AAAA... you@host"]
ssh_permit_root_login: keep            # keep | prohibit-password | "no"
ssh_password_authentication: keep      # keep | "no"
autosec_require_approval: true         # recommended on a server in use

# A new server with a web app: open 80 and 443 when ufw is turned on.
firewall_inbound:
  - { port: 80 }
  - { port: 443 }

# Add an app + TLS (enables role 05; a new web server only):
app_type: "node"                 # or docker
client_domain: "app.example.com" # required with app_type
letsencrypt_email: "ops@example.com"   # required with app_type (real address)

# Add a database (enables role 06; a new database server only):
db_engine: "postgres"            # or mysql
db_name: "appdb"
db_user: "appuser"
db_password: "..."               # use ansible-vault

# Add backups (enables role 07):
b2_bucket: "my-backups"
b2_key_id: "..."
b2_app_key: "..."                # use ansible-vault
age_public_key: "age1..."

# Alerts (backup status, CVE watch):
telegram_bot_token: "..."
telegram_chat_id: "..."
```

Optional roles (04 fwknop, 05 app, 06 database, 07 backups) are loaded
**only when their trigger var is set** (`paranoia_level: high`,
`app_type`, `db_engine`, `b2_bucket`). They set up something new, so
each stops when the server already has that service or one of its files
and it is not auto_sec's (nginx, an `app` login account or `app_dir`, a
database cluster, root's `rclone.conf`, `/opt/backup` files). Everything
else defaults in [group_vars/all.yml](group_vars/all.yml), and
[host_vars/example-client.yml](host_vars/example-client.yml) shows a new
and an existing server.

## SSH access

This section explains what auto_sec does to SSH, and what you choose.

### What auto_sec changes, and what it leaves alone

- It writes one file: `/etc/ssh/sshd_config.d/00-autosec.conf`. It
  never rewrites the main `/etc/ssh/sshd_config` or other drop-in files,
  so your provider's settings keep working.
- It writes only what you chose. A setting left as `keep` is not
  written at all.
- It only **adds** SSH keys. It never deletes or rewrites a key line.
  You remove old keys yourself.
- It never moves the SSH port, and never touches `ssh.socket`.

### The login model

You choose these per server in `host_vars/<server>.yml`. The wizard
asks.

| Variable | Values | Meaning |
|---|---|---|
| `ssh_admin_user` | an account, default `deploy` | The account you **and** Ansible log in as. Its keys (`ssh_admin_public_keys`) are added and tested. If it is not root, it must exist, or `deploy_user_account: create` must create it. |
| `ssh_permit_root_login` | `keep`, `prohibit-password`, `"no"` | Root login over SSH. `prohibit-password` means keys only. `"no"` needs a non-root admin account. |
| `ssh_password_authentication` | `keep`, `"no"` | Password login, for every account. `"no"` means keys only. |

- The two login choices have **no default**. The run stops until you
  set both.
- auto_sec never writes `yes`.
- Always quote `"no"`. Unquoted, YAML reads it as `false`, and the run
  stops with "quote it".
- Set `ansible_user` in the inventory to the same name as
  `ssh_admin_user`. A stricter rule is applied only on a run where
  Ansible really is logged in as that account. Otherwise it waits, and
  the run tells you why.

Optional extras, all off by default: `ssh_allow_users` (an AllowUsers
list; it must contain the admin account) and `ssh_extra_settings` (a
fixed list of sshd settings, such as `MaxAuthTries`). The old
`ssh_max_auth_tries` is gone: use `ssh_extra_settings.MaxAuthTries`.

### Two stages: keep first, tighten later

**Stage 1** changes nothing about how you log in:

```yaml
ssh_admin_user: root            # or deploy
ssh_admin_public_keys:
  - "ssh-ed25519 AAAA... you@laptop"
ssh_permit_root_login: keep
ssh_password_authentication: keep
```

Run it. Then check, from a **new** terminal, that your key works
(exit code 0 means yes):

```bash
ssh -o BatchMode=yes -o PreferredAuthentications=publickey \
    -i ~/.ssh/your_key root@your.server.ip true
```

**Stage 2**, later, one server at a time. First move every tool that
logs in with a password to a key: VS Code Remote-SSH, scripts,
teammates. Then set:

```yaml
ssh_permit_root_login: prohibit-password
ssh_password_authentication: "no"
```

Look at the plan first (`-e autosec_plan_only=true --tags ssh`), then run
for real. Only these two settings change.

While root login or password login is still on, every run prints a
warning, "SSH login NOT hardened", and the report says so too. In
stage 1 that is expected.

### What a run does to SSH

1. **Checks before anything changes.** They run before role 01, and in
   `--check` too. They only read. The run stops if:
   - `ssh_port` is not the port sshd listens on, or Ansible did not
     arrive on it;
   - a port change is waiting in the files but is not live yet (the
     hidden `ssh.socket` switch);
   - the SSH files changed after sshd last loaded them;
   - an earlier undo is still pending;
   - the run would change sshd, and ufw is active but no rule lets a
     new SSH connection reach `ssh_port` (the login tests would fail);
   - the command line has `-e ansible_ssh_args` or `-e ansible_become`
     (they would replace the login tests' own options).
2. **A trial run on a copy.** The new config is built in
   `/run/auto-sec` and checked with `sshd -t`. The run shows the
   before and after (`sshd -T`). If a login setting you did not choose
   would change, it stops.
3. **Keys are added**, then tested on a **brand-new** connection, the
   way Ansible logs in. If a rule gets stricter and the test fails,
   nothing is written.
4. **An undo timer is armed.** The default is 5 minutes
   (`ssh_revert_seconds`). The run prints the exact server time.
5. The file is written, checked, and **loaded at once** with
   `systemctl try-reload-or-restart ssh.service`. Open sessions
   normally stay connected.
6. **A second fresh login test.** Only when it works is the undo
   cancelled.

If something fails in between, the old files come back and sshd is
reloaded. If the connection drops, the timer does it at the deadline.
If the server reboots inside the window, a boot-time unit puts the old
files back before sshd starts.

While the timer is armed, do not reboot and do not edit `/etc/ssh`.
Check it with `sudo auto-sec-ssh-guard status`.

One more safety rule: for the length of the run, your IP is added to
fail2ban's ignore list (remote mode, when fail2ban's `sshd` jail is
active), so a failed test cannot get you banned. It is removed at the
end. The plan mentions it as a runtime-only note.

### Local mode (running on the server itself)

In local mode, auto_sec cannot test a new login from your laptop. So it
only applies SSH settings that change nothing, and it cannot turn ufw
on. If your choice would change a login rule, or turn ufw on, the run
stops before any change, and tells you to run it from your own computer.
Use `keep` (and `firewall_state: keep`) in local mode. Tighten later,
from your computer.

An SSH login from the server to itself (`ansible_host: 127.0.0.1`)
counts as local mode too: its login tests use a key stored on the
server, so they prove nothing about your own computer.

### The SSH port

`ssh_port` must be the port sshd **already** listens on (default 22).
auto_sec checks it, but never moves sshd. To move the port, follow
[docs/ssh-port.md](docs/ssh-port.md).

### High mode keeps SSH visible

With `paranoia_level: high`, auto_sec installs and starts fwknop (on a
server without fwknop of your own), but the SSH port **stays visible**
and rate-limited, as in standard mode. Hiding SSH behind a knock returns
in a later release. High mode needs `fwknop_pcap_intf`, the network
interface fwknopd listens on (for example `eth0`).

A high-mode server set up by auto_sec 0.1–0.3 has **no** ufw rule for
SSH (0.3's fwknop role deleted it). Before you run auto_sec there, knock,
log in, and add it: `sudo ufw limit <ssh_port>/tcp`. Otherwise the
run refuses, because its login tests need new connections. auto_sec
does not add rules to an active ufw. See CHANGELOG "Upgrading".

### Connecting

```bash
ssh -i /path/to/your_private_key <admin account>@your.server.ip
```

The private key stays on your machine. The server only holds the
public key. If you used the wizard, later runs are just:

```bash
ansible-playbook -i inventory site.yml -l <server>
```

**Don't lock yourself out.** Keep a break-glass path until you have
confirmed access:

- set `office_static_ip` to your office or home static IP (never the
  server's own). auto_sec uses it only where it writes:
  - with `fail2ban_hardening_enabled: true` (the default with `new`) it
    goes into `ignoreip` of auto_sec's fail2ban file, so fail2ban does
    not ban it (`fail2ban_ignore_ips` adds more fixed IPs; if your own
    `jail.local` sets `ignoreip`, that list replaces auto_sec's, and the
    run warns when your IP is then missing);
  - when auto_sec turns ufw on, it adds a rule above the others that lets
    this address reach SSH without the rate limit.
  With `keep` (the default with `existing`) and on a ufw that is already
  on, auto_sec adds it nowhere: put it in your own `jail.local` and ufw
  rules;
- keep your provider's console/VNC (e.g. Contabo) reachable.

### Upgrading a server set up by 0.1–0.3

Old versions replaced the main `sshd_config` with a file that has no
`Include` line. auto_sec refuses that file until you migrate it once. In
short: set the login choices that match what you want (the
[CHANGELOG](CHANGELOG.md) has a block that matches 0.3), then run once:

```bash
ansible-playbook -i inventory site.yml -l <server> --tags ssh \
  -e ssh_migrate_sshd_config=true
```

The stock `sshd_config` comes back, under the same trial run and undo
timer. Keys that 0.1–0.3 deleted cannot be recovered.

## The admin account and sudo

Role 01 creates an account only when you ask for it:
`deploy_user_account: create` (the default with `autosec_server: new`
when `deploy_user` is also `ssh_admin_user`).

- It creates `deploy_user` if it is missing: a home folder, shell
  `/bin/bash`, password locked (key login only), and **no extra groups**.
  (0.1–0.5 also added it to `sudo`.)
- It gives the account passwordless sudo in its own file,
  `/etc/sudoers.d/<deploy_user>`, checked with `visudo` first. Line 1
  says the file is auto_sec's.
- It never changes an account that already exists: not its shell,
  groups, home or password.
- It stops before any change if that sudo file is yours, if your sudo
  rules already name the account or one of its groups (sudo uses the
  last rule that matches, so a new rule could override yours), or if
  `/etc/sudoers` does not read `/etc/sudoers.d`.
- If `ssh_admin_user` does not exist and this run would not create it,
  the run stops before anything changes.

With `keep` (the default with `existing`), auto_sec creates no account
and writes no sudo rule.

## Updates, reboots, hostname and timezone

Role 01 handles automatic security updates (`unattended-upgrades`).

### What auto_sec changes, and what it leaves alone

- It writes at most one apt file,
  `/etc/apt/apt.conf.d/51autosec-unattended-upgrades`, and only for a
  setting you chose (reboots, origins, excluded packages, or
  `unattended_upgrades_enabled: true`). With the defaults it writes no
  apt file at all. It never edits the distro's `20auto-upgrades` or
  `50unattended-upgrades`. One exception, only when you ask for it: on
  a server set up by auto_sec 0.1–0.4, see
  **Upgrading from 0.1–0.4** below.
- Your own settings go in a file that sorts after auto_sec's, for
  example `52unattended-upgrades-local`. Yours win. If yours would
  cancel a choice you made for auto_sec, the run stops and names your
  file and line.
- With `auto` (the default with `new`) it installs `unattended-upgrades`
  if it is missing. The package's own setup turns the updates on (the
  Debian and Ubuntu default). auto_sec writes no update switch of its
  own, so the distro's way to turn them off
  (`dpkg-reconfigure unattended-upgrades`) keeps working, and an interval
  of yours (for example weekly) stays. If the updates are off, or the
  package was removed, they stay off and the run warns. `true` turns them
  on with auto_sec's own file and keeps them on. `keep` (the default with
  `existing`) leaves them as they are and installs nothing; an auto_sec
  file from an earlier `true` run stays too. If another `unattended_*`
  value would rewrite that file without its update switches, the run
  stops (R01-U1) and asks you for `true` or `auto`.
- It never turns on automatic reboots unless you choose them.
- It leaves the hostname and the timezone alone unless you set them.
- It writes no kernel settings. The lines 0.1–0.5 put in
  `/etc/sysctl.conf` stay; they are yours now. On Debian 13, where that
  file is no longer read at boot, the run tells you.
- It no longer upgrades every package on every run. On a brand-new
  server, add `-e apt_full_upgrade=true` to the first run.

Before anything changes, a read-only check (also in `--check`) runs apt
itself on a copy of the configuration with auto_sec's file added, and
shows which update settings would change.

| Variable | Default | Values |
|---|---|---|
| `unattended_upgrades_enabled` | `keep` (`existing`), `auto` (`new`) | `auto`, `true` or `keep`. auto_sec never turns updates off. |
| `unattended_automatic_reboot` | `keep` | `keep`, `true` or `false` |
| `unattended_reboot_time` | none | `"HH:MM"`, quoted. Required with `true`. |
| `unattended_origins` | `keep` | `keep` or `security` |
| `unattended_exclude_docker` | `false` | `true`: Docker is never updated automatically |
| `unattended_upgrade_blacklist` | `[]` | exact package names, never updated automatically |
| `server_hostname` | `keep` | `keep` or a hostname |
| `timezone` | `keep` | `keep` or a name such as `"UTC"` |
| `apt_full_upgrade` | `false` | one run only, with `-e` |
| `apt_migrate_unattended_upgrades` | `false` | one run only, with `-e` (0.1–0.4 servers) |

To allow reboots at a time you choose:

```yaml
unattended_automatic_reboot: true
unattended_reboot_time: "03:30"   # quoted; in the server's own timezone
```

Updates run at about 06:00–07:00 server time. A reboot time that has
already passed that day means the next day.

A Docker update restarts the Docker service and every container. With
`unattended_exclude_docker: true`, Docker is never updated
automatically, and you update it yourself.

A hostname change is refused while a mail server listens on port 25,
465 or 587. A timezone change first lists the cron jobs and timers it
moves.

### Package installs

Every package auto_sec installs goes through one shared check
(`roles/autosec-apt`). It installs only what a feature you chose needs,
without recommended packages:

- apt first does a dry run, and the run stops before any change if the
  install would upgrade or remove a package you have;
- the run stops if systemd has unit edits it has not loaded yet (a
  package's install script would load them);
- needrestart is held back during auto_sec's installs, so it does not
  restart your services. It runs at your next apt run, as before.

With `existing` and nothing else chosen, auto_sec installs nothing.

### Upgrading from 0.1–0.4

auto_sec 0.1–0.4 replaced `50unattended-upgrades` with its own file,
which turns on automatic reboots at 04:00 (and on Debian matched no
archive, so nothing was updated). When that file is still exactly
0.1–0.4's, the run stops and shows what putting the distro's file back
changes. Then run once with:

```bash
ansible-playbook -i inventory site.yml -l <server> --tags base \
  -e apt_migrate_unattended_upgrades=true
```

The old file is kept in `/var/lib/auto-sec/backup/`. On Debian the
next nightly run may then install many waiting updates (point releases
too) and restart services; set `unattended_origins: security` first to
allow security updates only. To keep the old file as your own instead,
add a comment line to it.

## Firewall (ufw)

- **auto_sec runs no ufw command on a ufw that is already on.** It does
  not add, change, reorder or restart anything there. If one of your
  `firewall_inbound` ports is missing, the run prints the `sudo ufw ...`
  line for you to run.
- It turns ufw on only when ufw is off (or not installed) **and**
  `firewall_state: enabled` (the default with `new`). Incoming traffic
  is then denied, except SSH (`firewall_ssh_rule`, rate-limited by
  default), your break-glass address and the ports in `firewall_inbound`.
  80 and 443 are no longer opened by default: list them.
- Before turning ufw on, it checks that:
  - every port that listens now is let in, or listed in
    `firewall_closed_ok`;
  - the server does not forward traffic (VPN, Docker, routing), and no
    other firewall tool is in charge;
  - ufw's own kernel settings would not weaken yours;
  - SSH stays open, and ufw would still be on after a reboot.
- Then it turns ufw on under an automatic undo and tests a brand-new SSH
  login. If that login fails, ufw goes back off and its files are put
  back.
- `egress_lockdown: true` denies outgoing traffic except DNS, NTP, HTTP
  and HTTPS (plus `egress_allow_extra`), only when this run turns ufw on.
  `false` leaves the outgoing policy as it is.

```yaml
firewall_state: enabled          # turn an inactive ufw on
firewall_inbound:
  - { port: 443 }                         # tcp from anywhere
  - { port: 51820, proto: udp }
  - { port: 5432, from: "203.0.113.0/24" } # one address or network
firewall_closed_ok: ["3000/tcp"]          # listens now, may close
```

## fail2ban

- With `fail2ban_hardening_enabled: keep` (the default with `existing`),
  auto_sec leaves fail2ban alone: no install, no file, no reload. If an
  earlier run left its `00-autosec.conf`, the run tells you.
- With `true` (the default with `new`), auto_sec installs fail2ban if it
  is missing (it then starts and bans; the plan says what it bans and who
  is exempt) and writes one file: `/etc/fail2ban/jail.d/00-autosec.conf`.
  It never writes `jail.local`.
- fail2ban reads that file first, right after `jail.conf`. So every
  value that your own files set wins (`jail.local`, other `jail.d`
  files).
- auto_sec's values are fail2ban `[DEFAULT]` values
  (`fail2ban_defaults`), plus `enabled` and `port` for the `sshd` jail.
  `fail2ban_defaults: {}` sets no values at all.
- Before anything changes, fail2ban's own config reader runs on a copy
  of `/etc/fail2ban` (also in `--check`). The run shows what would
  change, and stops if auto_sec's values would change a jail of yours
  (for example a `recidive` jail without its own `maxretry`), or if
  your config does not load.
- fail2ban is reloaded only when its effective config changes. A reload
  keeps the bans. When nothing changes, there is no reload.
- Role 03 adds no nginx jails. Role 05 (only when `app_type` is set)
  adds `nginx-http-auth` and `nginx-botsearch` in
  `/etc/fail2ban/jail.d/00-autosec-nginx.conf` after it has installed
  nginx, with the same checks (`fail2ban_nginx_jails: false` turns them
  off). A server whose nginx is yours gets none.
- A `jail.local` written by auto_sec 0.1–0.4 is refused. The run shows
  what migrating it changes. Then run once with
  `-e fail2ban_migrate_jail_local=true`: the file moves to
  `/var/lib/auto-sec/fail2ban/`. To keep it as your own file instead,
  add a comment line to it. The migration also stops if a jail would
  stop ignoring an address that the old file's `ignoreip` line holds
  (add it to `fail2ban_ignore_ips` first).

## The layers

| # | Role | Purpose |
|---|------|---------|
| 00 | plan | The plan, the plan id and your OK (no server access) |
| 01 | base | Automatic security updates (reboots only if you choose), hostname, timezone, the admin account only with `create` |
| 02 | ssh-hardening | Login rules you choose, key tested first, automatic undo |
| 03 | firewall | ufw turned on only when off and chosen; fail2ban (its own `jail.d` file; your `jail.local` wins) |
| 04 | fwknop | Single Packet Authorization (SSH stays visible) |
| 05 | app-runtime | Node/PM2 or Docker + hardened nginx + TLS (a new web server only) |
| 06 | database | Localhost only, least privilege (a new database server only) |
| 07 | backups | Encrypted nightly backups to a no-delete B2 bucket |
| 08 | detection | **Not managed in 0.6** (#18): warns about 0.1–0.5's audit rules |
| 09 | watcher | **Not managed in 0.6** (#18): warns about 0.1–0.5's detectors |
| 10 | report | A short report on your own computer |
| 11 | cve-watch | Opt-in daily dependency + OS CVE scan against OSV.dev |

`roles/autosec-apt` is the shared package check.

Partial runs with tags:

```bash
ansible-playbook -i inventory site.yml -l myserver --tags ssh
ansible-playbook -i inventory site.yml -l myserver --tags fail2ban
ansible-playbook -i inventory site.yml -l myserver --tags backups
ansible-playbook -i inventory site.yml -l myserver --tags "firewall,report"
```

`fail2ban` is the fail2ban part of role 03 alone, without the ufw part
(`firewall` runs both). Role 05's nginx jails are updated by runs that
include `app`; `--skip-tags fail2ban` leaves them alone too.

The read-only checks run with every tag, and the plan lists only the
roles the tags select. A wrong value in any role's variables stops any
run; a role's checks of the server stop a run only when it includes that
role.

## Detection (roles 08 and 09)

**Not managed in 0.6.** auto_sec 0.1–0.5 installed auditd rules, a
ransomware canary, a 5-minute audit-log scan and three Python detectors
(reverse-shell, recon-burst and an experimental SSH login watcher). Some
of them did not work as documented:

- the ransomware canary never alerted (it stopped after the first file
  event);
- the 5-minute audit scan found events only on its first run;
- the recon detector fires on every auto_sec run.

Details are in [issue #18](https://github.com/pythonistastic/auto_sec/issues/18).
Earlier versions of this README described them as working protection;
that was not accurate.

What 0.6 does instead:

- it installs, writes, starts and deletes nothing in roles 08 and 09;
- it no longer deletes `/etc/audit/rules.d/hardening.rules` (0.3–0.5
  deleted it, even when it was yours);
- it warns when 0.1–0.5's audit rules or detectors are still on a
  server (W08-1, W09-1), and lists detector variables that do nothing;
- it stops before it gathers facts if the old detectors run in `active`
  mode (R00-3), because they would end the run's own SSH session.

A rewritten, tested detection suite is planned for 0.7.

### Removing the 0.1-0.5 detection suite

auto_sec 0.6 does not remove anything for you. On a server where the
warnings appear, as root:

1. Stop and remove the detector services:

   ```bash
   systemctl disable --now login-watcher recon-watch revshell-scan ransomware-canary
   rm -f /etc/systemd/system/login-watcher.service /etc/systemd/system/recon-watch.service \
         /etc/systemd/system/revshell-scan.service /etc/systemd/system/ransomware-canary.service
   systemctl daemon-reload
   ```

2. Remove their folders. `/opt/watcher/watcher.conf` and (in 0.1–0.2)
   files in `/opt/detect` hold your Telegram bot token; consider changing
   the token too.

   ```bash
   rm -r /opt/watcher /opt/detect
   ```

   `/var/log/sentinel` holds the incident files the detectors wrote. Keep
   or delete it as you like.
3. Remove the 5-minute audit scan from root's crontab: `crontab -e`, then
   delete the line `#Ansible: audit alert scan` and the line below it.
4. Remove auto_sec's audit rules. Check what is loaded first
   (`auditctl -l`), then:

   ```bash
   rm /etc/audit/rules.d/90-autosec.rules   # 0.3-0.5
   augenrules --load                        # reloads ALL your audit rules
   ```

   On a server set up by 0.1–0.2, the file is
   `/etc/audit/rules.d/hardening.rules`, but only when the W08-1 warning
   names it: a `hardening.rules` of your own has the same name.
   0.3–0.5 deleted any `hardening.rules`, including yours; it can come
   back only from your backups.
5. The detector variables (`watcher_*`, `revshell_*`, `recon_*`,
   `ssh_pattern_watcher_enabled`) can go from your `host_vars`.

auditd, inotify-tools, audispd-plugins and rsyslog stay installed; remove
them only if nothing else of yours uses them.

## CVE watch — know when your stack becomes vulnerable

**Off by default** (`cve_watch_enabled: false`). When it is on, it adds
a daily timer that runs as root, and once a day it sends the names and
versions of your app's packages to an outside service, `api.osv.dev`.
That is your choice to make, so auto_sec never turns it on by itself,
not even on a new server.

To turn it on, point `app_dir` at your app's folder on the server (it
must exist):

```yaml
cve_watch_enabled: true
app_dir: "/opt/myapp"            # the folder with your lockfiles
cve_watch_min_severity: "high"   # low | moderate | high | critical
cve_watch_hour: 6                # daily, +random <1h
```

Every day, role 11 reads your app's dependency lockfiles, asks
[OSV.dev](https://osv.dev) whether those exact versions have advisories,
and alerts with the **minimal safe upgrade** and a copy-pasteable fix:

```
CVE WATCH [prod-1]
2 new vulnerable dependencies (1 critical, 1 high).
Also 5 pending OS security updates.

[CRITICAL] next 13.4.0 - CVE-2025-29927
  Authorization bypass in Next.js middleware
  fix: npm install next@13.5.9
```

It adds **no third-party binary** to the server — the scanner is stdlib
Python. The only outbound calls are HTTPS to `api.osv.dev` (already
allowed under `egress_lockdown`). auto_sec writes its files only where
they are absent or auto_sec's own, and starts the timer without
`systemctl enable`.

Supported lockfiles: `package-lock.json` (npm), `requirements.txt`
(PyPI), `composer.lock` (Packagist), `go.mod` (Go). Anything present but
unsupported (`yarn.lock`, `poetry.lock`, `Cargo.lock`, …) is **listed in
the report as unscanned**, so coverage is never silently partial.

`min_severity` starts at **high** on purpose: a first scan of a real app
can surface dozens of findings, and an alert channel nobody reads is
worse than no alerts. Lower it once you've triaged the backlog. The full
list — every severity — is always written to
`/var/log/sentinel/cve-report-*.txt`. Findings are alerted once, so a
daily timer doesn't re-nag you about the same CVE.

A cve-watch timer that 0.2–0.5 turned on stays when
`cve_watch_enabled` is false; the run prints the commands to remove it.

### Turning findings into a pull request (Tier 2)

Patching a dependency **on the server is temporary** — your next deploy
overwrites it. The fix belongs in your repo, so `scripts/cve-pr.sh`
scans a checkout, bumps each vulnerable package to the lowest version
that fixes every advisory against it, and opens a PR:

```bash
./scripts/cve-pr.sh --repo ~/code/my-app --min-severity critical --dry-run
```

Run it on your workstation or in CI — **not on the production server**.
Opening a PR needs a token with write access, and a token on an
internet-facing box is exactly what an intruder harvests first. The
on-server scanner stays read-only and credential-free by design. Copy
[examples/cve-pr-workflow.yml](examples/cve-pr-workflow.yml) into your
app repo to run it weekly in GitHub Actions.

**What this does not do.** It won't auto-patch your app. A version bump
can break a build at 3am with nobody watching, and without your tests
there's no way to know it didn't. OS security packages *are* patched
automatically (role 01, via `unattended-upgrades`) precisely because
distros backport fixes without changing APIs — app dependencies don't
get that guarantee. Findings are also matched by **version, not
reachability**: a CVE in a package you never call still gets reported, so
expect some triage.

## The report

Role 10 writes `reports/security-report-<server>.md` on **your own
computer** (0600, in a 0700 folder), never on the server, and not in
`--check`. It states only what the run measured: updates, the effective
SSH settings, fail2ban and the ufw state. Everything else says "not
checked by auto_sec". Lines for `client_name`, `client_domain` and
`report_prepared_by` are left out when they are not set. Old
`/root/security-report-*.md` files from 0.1–0.5 stay on the servers;
remove them yourself.

## Paranoia levels

Set `paranoia_level` in `host_vars/<server>.yml`:

- `standard`: SSH port open and rate-limited (when auto_sec turned ufw
  on), fail2ban when chosen
- `high`: also installs and starts fwknop (Single Packet
  Authorization). **The SSH port stays visible**, exactly as in standard
  mode. Hiding it behind a knock returns in a later release. Needs
  `fwknop_pcap_intf`.

**Before enabling `high`**, confirm you have provider console (VNC)
access as break-glass. You do not need the knock client yet; to get
ready for later, see
[roles/04-fwknop/CLIENT-SIDE.md](roles/04-fwknop/CLIENT-SIDE.md).

## Backups you can trust

- Encrypted **client-side** with [age](https://age-encryption.org)
  before upload — the private key never touches the server. The wizard
  generates the keypair and tells you where to stash the private half.
- The B2 application key has **no delete permission** and the bucket
  keeps versions, so ransomware with root on the box still can't
  destroy backup history. Retention pruning happens via B2 lifecycle
  rules in the account console, never from the server.
- `restore-test/monthly-restore.yml` runs on **your ops machine**:
  pulls the latest backup, decrypts, restores into a scratch Postgres
  container, sanity-checks, reports to Telegram, destroys. Schedule it
  monthly. A backup you have never restored is a hope, not a backup.
- Layer 07 has never run against a real B2 bucket (see the
  [retrospective](docs/RETROSPECTIVE.md)).

## Secrets policy

Never commit: `host_vars/*` (except the example), `inventory/*` (except
the example), `secrets/`, `reports/`, age private keys, B2 keys or
fwknop keys. The `.gitignore` enforces this — don't fight it. For team
setups, use `ansible-vault` for the values in host_vars.

## Repo layout

```
site.yml                 master playbook: checks, plan, then roles 01→11
group_vars/all.yml       global defaults, override per server
host_vars/<server>.yml   per-server config + secrets (gitignored)
inventory/<server>.yml   connection details (gitignored)
scripts/bootstrap.sh     installs deps, runs the wizard
scripts/configure.sh     interactive config generator
restore-test/            monthly backup restore verification
roles/00-plan            the plan, plan id and approval
roles/01..11-*           the layers
roles/autosec-apt        the shared package check
docs/ssh-port.md         how to move the SSH port by hand
tests/                   lab tests (no root) and live tests (CI runners only)
```

## Known limitations

- **auto_sec is a personal research project.** Several parts are tested
  only in a lab (real package code, run without root). 0.4's and 0.5's
  live tests ran on GitHub's VMs; 0.6's, including the full runs
  `full-adopt-live` and `full-new-live`, have not run yet.
- **Detection is not managed in 0.6** ([#18](https://github.com/pythonistastic/auto_sec/issues/18)).
  Old 0.1–0.5 detectors in alert mode keep firing on every run until you
  remove them.
- Turning ufw on (new servers) was checked only in a lab, against the
  ufw code of Ubuntu 22.04 and 24.04 and Debian 12 and 13; never on a
  real server yet. ufw applies its own kernel settings at every start,
  and those stay after an undo until the next reboot (the plan lists
  them).
- needrestart is held back during auto_sec's installs, so services that
  use replaced libraries are restarted at your next apt run (on Ubuntu
  24.04 that is the nightly automatic update), as they would be without
  auto_sec.
- The sudo check does not see rules from LDAP/sssd, Runas aliases or
  `ALL` user lists. A line with a netgroup (`+name`) counts as naming
  the account, so `create` stops there.
- In local mode, SSH login rules cannot be tightened and ufw is not
  turned on (see
  [Local mode](#local-mode-running-on-the-server-itself)).
- High mode keeps the SSH port visible.
- The key test only proves the path Ansible uses: your key, from your
  IP. Other tools, such as VS Code on Windows, can still break in
  stage 2. Test them yourself before you tighten.
- Debian 12 and 13 are tested in CI only: their real OpenSSH, fail2ban
  and unattended-upgrades packages are checked without root. There has
  been no live run on Debian yet.
- The boot-time undo after a reboot was tried once on a real server, for
  an SSH change (0.4.0). Its ufw part is lab-only so far. The
  [CHANGELOG](CHANGELOG.md) lists what is not proven yet.
- A fail2ban jail you add later without its own `maxretry`, `findtime`
  or `bantime` uses auto_sec's `[DEFAULT]` values (`fail2ban_defaults`).
  The run checks your jails only while it runs.
- Keys deleted by versions 0.1–0.3 cannot be recovered.
- The checks read data from the server (`sshd`, `systemctl`, `ss`,
  `/proc`, the journal). They guard against mistakes, not against a
  server that is already compromised.

## Disclaimer

auto_sec is **a personal research project**, provided as-is, with **no
warranty of any kind** (see [LICENSE](LICENSE)). It is **not a fully
working or production service**, it is not certified, and it does not
promise complete security. It cannot make any server "unhackable".

- It automates a set of well-understood hardening steps, carefully and
  with checks. It is a starting point to study and adapt, not a finished
  security product.
- **Do your own research.** Understand your own threat model, read what
  the playbook changes before you run it (the plan helps), and keep your
  OS and application dependencies patched. No tool replaces that.
- **Test first.** Try it on a throwaway server before touching anything
  you care about, and keep break-glass access (provider console, a
  whitelisted IP) until you're confident.
- Earlier versions shipped detectors that did not work as documented
  (#18). Treat any claim here as something to check, not something to
  rely on.
- You are responsible for how you deploy and operate this on your own
  systems.

For an account of what doesn't work, what's unsolved, and what's
shipped-but-unproven, read the
[development retrospective](docs/RETROSPECTIVE.md).

Found a weakness in the playbook itself? Please open a private security
advisory (see [SECURITY.md](SECURITY.md)).

## License

MIT — see [LICENSE](LICENSE).
