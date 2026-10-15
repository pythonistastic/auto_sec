```
 █████╗ ██╗   ██╗████████╗ ██████╗         ███████╗███████╗ ██████╗
██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗        ██╔════╝██╔════╝██╔════╝
███████║██║   ██║   ██║   ██║   ██║        ███████╗█████╗  ██║
██╔══██║██║   ██║   ██║   ██║   ██║        ╚════██║██╔══╝  ██║
██║  ██║╚██████╔╝   ██║   ╚██████╔╝███████╗███████║███████╗╚██████╗
╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚══════╝╚══════╝╚══════╝ ╚═════╝
        one-command server hardening + breach detection
```

# auto_sec

![version](https://img.shields.io/badge/version-0.3.2-blue)
![status](https://img.shields.io/badge/status-early--stage-orange)
![license](https://img.shields.io/badge/license-MIT-green)

One-command hardening for a Linux VPS: preventive lockdown, behavioral
breach detection, and ransomware-proof encrypted backups — as an
Ansible playbook you configure once.

**Version 0.3.2** · what's new and what's fixed: [CHANGELOG.md](CHANGELOG.md).

Takes a fresh Ubuntu/Debian server from zero to:

- SSH login rules **you choose** per server: keep them as they are, or
  keys only and no root password. Nothing gets stricter until your key
  works on a brand-new login, and an automatic undo timer covers every
  SSH change (see [SSH access](#ssh-access))
- Default-deny firewall with fail2ban, and optional **egress lockdown**
  (default-deny outbound) that kills most reverse-shell callbacks.
  High mode adds fwknop (Single Packet Authorization); hiding the SSH
  port behind a knock returns in a later release
- A **breach detection suite** (see below): a reverse-shell scanner and
  a recon-burst detector on by default (plus an experimental SSH login
  tripwire), sharing one alert/response pipeline that captures forensic
  evidence *before* it ever kills anything
- auditd tripwires on identity files, SSH trust, cron and binaries,
  plus a ransomware early-warning canary (mass file-change detection)
- Nightly client-side-encrypted backups (age) to a Backblaze B2 bucket
  whose key **cannot delete** — malware on the box can't destroy history
- A daily **CVE watch** that tells you when your dependencies or OS
  packages pick up a known vulnerability, with the exact upgrade to run
- Telegram alerts for everything, and a generated security report

> ⚠️ **Early-stage project — no guarantees.** auto_sec raises the bar; it
> does **not** make a server unhackable and does not promise "full
> security." Security is a moving target and this project is young. It is
> not a substitute for understanding your own threat model, keeping your
> software patched, and **doing your own research**. Read what the
> playbook does before running it, try it on a throwaway server first,
> and never rely on any single tool. Use at your own risk — see the
> [no-warranty terms](LICENSE) and the [Disclaimer](#disclaimer) below.

## Before you start (beginners)

You run this from a **control machine** — that can be your own computer,
or the server itself. Pick whichever is simpler for you:

### Option A — run it *on the server* (easiest, nothing to install locally)

You only need an SSH client to reach the server, which is already built
into Windows 10/11, macOS, and Linux. SSH into your fresh VPS as root
(your provider emails you the IP and root password), then run the
[Quick start](#quick-start) commands right there:

```bash
ssh root@YOUR.SERVER.IP        # enter the root password when asked
```

The wizard runs in "local" mode and prints the one `ssh-keygen` command
to run on your laptop for future logins. This is the least-friction path
for a first-timer.

One limit: on the server itself, auto_sec cannot test a new login from
your laptop. So in local mode it never makes SSH logins stricter; it
keeps your current login rules. To tighten them later, use Option B
(see [Local mode](#local-mode-running-on-the-server-itself)).

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

1. asks plain-language questions (domain, app type, database, alerts),
2. generates every secret it can (age backup keypair, fwknop keys,
   database password),
3. writes `host_vars/<server>.yml` + `inventory/<server>.yml`
   (both gitignored), and
4. prints — or runs — the exact hardening command.

**Is the server already in production?** Read
[Known limitations](#known-limitations) first. In short: for now, run
only the SSH part there (`--tags ssh`), and do not put the playbook in
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

## Declarative / CI use (without the wizard)

You can skip the wizard and drive auto_sec from committed config — write
`host_vars/<server>.yml` and `inventory/<server>.yml` yourself, then run
`ansible-playbook`. This suits CI, fleets, and GitOps.

The playbook **fails fast**: a `pre_tasks` assert validates every
required variable *before* any change, so an incomplete config aborts the
run instead of leaving a half-hardened box. That assert block (top of
[site.yml](site.yml)) is the **source of truth** for what's required.
The read-only SSH checks run there too, before role 01.

Minimal `host_vars` by scope (only what each needs):

```yaml
# Core hardening + detection only (no app/DB/backups).
# SSH login choices (required, no default). Always quote "no".
ssh_admin_user: "deploy"               # set ansible_user to the same name
ssh_admin_public_keys: ["ssh-ed25519 AAAA... you@host"]
ssh_permit_root_login: keep            # keep | prohibit-password | "no"
ssh_password_authentication: keep      # keep | "no"
# Still supported: also installed (add-only) for the deploy user.
deploy_ssh_public_key: "ssh-ed25519 AAAA... you@host"

# Add an app + TLS (enables role 05):
app_type: "node"                 # or docker
client_domain: "app.example.com" # required with app_type
letsencrypt_email: "ops@example.com"   # required with app_type (real address)

# Add a database (enables role 06):
db_engine: "postgres"            # or mysql
db_name: "appdb"
db_user: "appuser"
db_password: "..."               # use ansible-vault

# Add backups (enables role 07):
b2_bucket: "my-backups"
b2_key_id: "..."
b2_app_key: "..."                # use ansible-vault
age_public_key: "age1..."

# Enable the experimental login watcher:
ssh_pattern_watcher_enabled: true
watcher_pattern: "cd /opt/app"   # required only when the watcher is on

# Alerts (strongly recommended):
telegram_bot_token: "..."
telegram_chat_id: "..."
```

Optional roles (04 fwknop, 05 app, 06 database, 07 backups) are loaded
**only when their trigger var is set** (`paranoia_level: high`,
`app_type`, `db_engine`, `b2_bucket`). Everything else defaults sanely in
[group_vars/all.yml](group_vars/all.yml), so a core run needs just a
key and the two SSH login choices.

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
| `ssh_admin_user` | an account, default `deploy` | The account you **and** Ansible log in as. Its keys (`ssh_admin_public_keys`) are added and tested. |
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

Preview with `--check --diff --tags ssh` first, then run for real. Only these two
settings change.

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

Two more safety rules:

- At most `ssh_max_hosts_per_run` servers (default 5) get an SSH change
  in one run. Use `-l` for the rest.
- For the length of the run, your IP is added to fail2ban's ignore
  list (remote mode, when fail2ban's `sshd` jail is active), so a failed
  test cannot get you banned. It is removed at the end.

### Local mode (running on the server itself)

In local mode, auto_sec cannot test a new login from your laptop. So it
only applies SSH settings that change nothing. If your choice would
change a login rule, the run stops before any change, and tells you to
run it from your own computer. Use `keep` in local mode. Tighten later,
from your computer.

An SSH login from the server to itself (`ansible_host: 127.0.0.1`)
counts as local mode too: its login tests use a key stored on the
server, so they prove nothing about your own computer.

### The SSH port

`ssh_port` must be the port sshd **already** listens on (default 22).
auto_sec checks it and opens it in ufw, but never moves sshd. To move
the port, follow [docs/ssh-port.md](docs/ssh-port.md).

### High mode keeps SSH visible in 0.4.0

With `paranoia_level: high`, auto_sec installs and starts fwknop, but
the SSH port **stays visible** and rate-limited, as in standard mode.
Hiding SSH behind a knock returns in a later release.

A high-mode server set up by auto_sec 0.1–0.3 has **no** ufw rule for
SSH (0.3's fwknop role deleted it). Before you run 0.4.0 there, knock,
log in, and add it: `sudo ufw limit <ssh_port>/tcp`. Otherwise the
run refuses, because its login tests need new connections. See
CHANGELOG "Upgrading".

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
  server's own). It skips the SSH rate limit, and fail2ban never bans
  it. `fail2ban_ignore_ips` adds more fixed IPs;
- keep your provider's console/VNC (e.g. Contabo) reachable.

### Upgrading a server set up by 0.1–0.3

Old versions replaced the main `sshd_config` with a file that has no
`Include` line. auto_sec 0.4.0 refuses that file until you migrate it
once. In short: set the login choices that match what you want (the
[CHANGELOG](CHANGELOG.md) has a block that matches 0.3), then run once:

```bash
ansible-playbook -i inventory site.yml -l <server> --tags ssh \
  -e ssh_migrate_sshd_config=true
```

The stock `sshd_config` comes back, under the same trial run and undo
timer. Keys that 0.1–0.3 deleted cannot be recovered.

## Tested on real hardware

The detection suite isn't just linted — it's been validated end-to-end
on a throwaway **Ubuntu 22.04** VPS. A full hardening run completed with
no lockout, and `tests/redteam.sh` fired every default detector against
real attacks:

| Detector | Attack simulated | Result |
|----------|------------------|--------|
| reverse-shell | `bash -i` wired to a socket (loopback) | ✅ caught, evidence captured |
| service-shell | the `app` user spawning a shell | ✅ caught |
| recon-burst | a burst of enumeration commands | ✅ caught |

That testing also shook out real bugs that no linter would find — an
`ausearch` hang that starved a detector, auditd rules not loading on a
`systemctl restart`, and a reverse-shell false positive on journald's
socket — all fixed. Run `sudo tests/redteam.sh` on your own staging box
to reproduce it. (The SSH login tripwire is off by default because live
testing showed it false-positives on automation; see below.)

That run predates 0.4.0. The new SSH handling in 0.4.0 is covered by CI
and lab tests, but has not yet run on a real VPS.

## The layers

| # | Role | Type | Purpose |
|---|------|------|---------|
| 01 | base | Preventive | Auto security updates, kernel hardening, deploy user |
| 02 | ssh-hardening | Preventive | Login rules you choose, key tested first, automatic undo |
| 03 | firewall | Preventive | UFW default deny + fail2ban |
| 04 | fwknop | Preventive | Single Packet Authorization (SSH stays visible in 0.4.0) |
| 05 | app-runtime | Preventive | Node/PM2 or Docker + hardened Nginx + TLS |
| 06 | database | Protective | Localhost only, least privilege |
| 07 | backups | Recovery | Encrypted nightly backups to no-delete B2 bucket |
| 08 | detection | Detective | auditd tripwires, ransomware canary, Telegram alerts |
| 09 | watcher | Detective/Reactive | Breach detection suite: reverse-shell scanner + recon-burst detector (+ experimental login tripwire) |
| 10 | report | Deliverable | Generated security report |
| 11 | cve-watch | Preventive/Detective | Daily dependency + OS CVE scan against OSV.dev, alerts with the exact fix |

Partial runs with tags:

```bash
ansible-playbook -i inventory site.yml -l myserver --tags ssh
ansible-playbook -i inventory site.yml -l myserver --tags backups
ansible-playbook -i inventory site.yml -l myserver --tags "firewall,detection"
```

The read-only SSH checks run with every tag, because they also protect
the firewall role.

## The detection suite, honestly

Role 09 installs three small detectors that share one alert/response
pipeline (`sentinel_lib.py`). None is machine learning; each is a cheap,
explainable heuristic aimed at a single-purpose server with 1–5 admins.
They are **detection layers, not authentication** — they assume an
attacker may already be inside and try to catch the next move. Run the
whole suite in `alert` mode for at least a week before switching
`watcher_mode` to `active`, and keep a break-glass IP configured.

**1. SSH login pattern watcher** (`watcher.py`) — a tripwire second
factor, **experimental and OFF by default**
(`ssh_pattern_watcher_enabled: false`). The idea: a valid human runs a
command containing a secret pattern within N seconds of an interactive
SSH login; an attacker with a stolen key doesn't know the ritual and
trips the wire. In live testing this proved **racy under concurrent
same-IP logins**: it reacts to an auth-log login and then inspects the
session, and reliably telling an interactive human apart from
`ssh host "sudo …"` automation (Ansible, CI, git) is hard — `sudo`'s
`use_pty` and session-attribution races produce false positives. It's
shipped for people who want to experiment (enable it and whitelist your
automation IPs via `watcher_whitelist_ips`), but the two detectors below
are the ones that carry the load, and detector #3 already delivers the
"catch them looking around" goal more robustly. PRs that make login
attribution reliable are very welcome.

**2. Reverse-shell scanner** (`revshell_scan.py`) — watches the process
table, not the auth log, so it sees intrusions that never log in. It
flags (a) an interactive shell whose stdin/stdout is a network socket —
the classic `bash -i >& /dev/tcp/...` reverse shell, on *any* port
including 443 — and (b) a shell owned by the app/service user or
parented by a service process (node/nginx/php-fpm/...), meaning your app
was made to spawn a shell. *Tuning:* apps that legitimately shell out
(npm scripts, `child_process`) can be exempted via
`revshell_allowed_parent_cmdlines`; signal (a) is safe everywhere.

**3. Recon-burst detector** (`recon_watch.py`) — vector-independent.
It watches auditd's record of what everyone runs and fires when one
session runs a burst of enumeration commands (`whoami`, `id`,
`cat /etc/passwd`, `find … -perm`, `sudo -l`, reading `.ssh`/`.env`/`.aws`
…) within a short window. This is the universal first move after *any*
breach — "looking around for the data" — so it catches stolen-key
sessions, reverse shells, and insiders alike.

**Forensics-first response.** In `active` mode the pipeline snapshots
evidence — full process tree, open sockets, the offending process's
file descriptors, and recent audited commands — into
`/var/log/sentinel/incident-*.txt` **before** it terminates a session or
blocks an IP. Automated response never destroys the only record of the
intrusion, and you get an artifact to investigate rather than just a
dead connection.

**What this is not.** It won't stop a patient attacker who moves slowly,
avoids shells, and tunnels C2 over 443 — no host heuristic will. It is a
layered tripwire that raises the cost and noise of the common cases
(stolen keys, off-the-shelf reverse shells, smash-and-grab recon). PRs
with additional detectors and evasion notes are very welcome.

### Validate the detectors actually fire

Don't take the suite on faith. On a **throwaway/staging** server that has
been hardened by the playbook, run:

```bash
sudo tests/redteam.sh
```

It safely reproduces each attack — a loopback-only reverse shell, the app
user spawning a shell, and a burst of enumeration commands — then checks
that a matching incident file appeared in `/var/log/sentinel` and that
your Telegram lit up. Run it in `alert` mode (it refuses `active` mode
unless you set `REDTEAM_FORCE=1`, since active mode would kill the test
processes). This is also the fastest way to confirm a new detector works
before sending a PR.

## CVE watch — know when your stack becomes vulnerable

The detectors above assume someone got in. This layer works on the other
side: it tells you when the software you're running picks up a **known
vulnerability**, before anyone exploits it.

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
Python, like the detectors, so a machine whose job is to be hard to
compromise doesn't grow new supply-chain surface. The only outbound calls
are HTTPS to `api.osv.dev` (already allowed under `egress_lockdown`).

Supported lockfiles: `package-lock.json` (npm), `requirements.txt`
(PyPI), `composer.lock` (Packagist), `go.mod` (Go). Anything present but
unsupported (`yarn.lock`, `poetry.lock`, `Cargo.lock`, …) is **listed in
the report as unscanned**, so coverage is never silently partial.

```yaml
cve_watch_enabled: true
cve_watch_min_severity: "high"   # low | moderate | high | critical
cve_watch_hour: 6                # daily, +random <1h
```

`min_severity` starts at **high** on purpose: a first scan of a real app
can surface dozens of findings, and an alert channel nobody reads is
worse than no alerts. Lower it once you've triaged the backlog. The full
list — every severity — is always written to
`/var/log/sentinel/cve-report-*.txt`. Findings are alerted once, so a
daily timer doesn't re-nag you about the same CVE.

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
internet-facing box is exactly what an intruder harvests first (see the
July 2026 Hugging Face breach). The on-server scanner stays read-only
and credential-free by design. Copy
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

### Egress lockdown

`egress_lockdown: true` flips the outbound firewall to default-deny,
permitting only DNS, NTP, HTTP and HTTPS (plus `egress_allow_extra`).
That alone refuses the arbitrary-high-port callbacks most reverse shells
use. It is **off by default** because it can break apps that reach
external services on non-standard ports, and because C2 tunnelled over
443 still gets out — that case is what detector #2 is for. Turn it on
once you know your app's outbound needs.

## Paranoia levels

Set `paranoia_level` in `host_vars/<server>.yml`:

- `standard`: SSH port open and rate-limited, fail2ban, watcher alerts
- `high`: also installs and starts fwknop (Single Packet
  Authorization). **In 0.4.0 the SSH port stays visible**, exactly as in
  standard mode. Hiding it behind a knock returns in a later release.
  The watcher may run in `active` mode.

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

## MVP order

Start with roles 01–03 + 07 (hardening + verified backups covers ~80%
of real-world risk). Layer 04, 08 and 09 on top once the basics run
clean.

## Secrets policy

Never commit: `host_vars/*` (except the example), `inventory/*` (except
the example), `secrets/`, age private keys, B2 keys, fwknop keys, or
the watcher pattern. The `.gitignore` enforces this — don't fight it.
For team setups, use `ansible-vault` for the values in host_vars.

## Repo layout

```
site.yml                 master playbook (roles 01→11 in order)
group_vars/all.yml       global defaults, override per server
host_vars/<server>.yml   per-server config + secrets (gitignored)
inventory/<server>.yml   connection details (gitignored)
scripts/bootstrap.sh     installs deps, runs the wizard
scripts/configure.sh     interactive config generator
restore-test/            monthly backup restore verification
roles/01..11-*           the layers
docs/ssh-port.md         how to move the SSH port by hand
tests/                   red-team, guard, sshd and live role tests
```

## Known limitations

- **A full `site.yml` run on a server that is already in production is
  not safe yet.** It rewrites `/etc/fail2ban/jail.local` (#2), turns on
  automatic reboots at 04:00 (#3), and changes the hostname and timezone
  (#7). Until those are fixed, use `--tags ssh` on such servers, and do
  not put the playbook in cron. A fresh server is fine.
- The playbook targets every host in the inventory. Always pass
  `-l <server>`.
- In local mode, SSH login rules cannot be tightened (see
  [Local mode](#local-mode-running-on-the-server-itself)).
- High mode keeps the SSH port visible in 0.4.0.
- The key test only proves the path Ansible uses: your key, from your
  IP. Other tools, such as VS Code on Windows, can still break in
  stage 2. Test them yourself before you tighten.
- Debian 12 and 13 are tested in CI only: their real OpenSSH packages
  are checked for how they read the config. There has been no live run
  on Debian yet.
- Some 0.4.0 safety parts are not yet proven on a real server, such as
  the boot-time undo after a reboot. The [CHANGELOG](CHANGELOG.md) lists
  them.
- Keys deleted by versions 0.1–0.3 cannot be recovered.
- The checks read data from the server (`sshd`, `systemctl`, `ss`, the
  journal). They guard against mistakes, not against a server that is
  already compromised.

## Disclaimer

auto_sec is **early-stage software provided as-is, with no warranty of
any kind** (see [LICENSE](LICENSE)). It does **not** promise complete
security and cannot make any server "unhackable."

- Security is layered and always evolving. This project automates a set
  of sensible, well-understood hardening and detection measures — it is a
  strong starting point, **not** a finished or certified security
  solution.
- **Do your own research.** Understand your own threat model, read what
  the playbook changes before you run it, and keep your OS and
  application dependencies patched. No tool replaces that.
- **Test first.** Always trial it on a throwaway/staging server before
  touching anything you care about, and keep break-glass access
  (provider console, a whitelisted IP) until you're confident.
- The detection layers are tripwires that raise the cost of common
  attacks; a patient, skilled attacker can still evade them. Treat alerts
  as signals to investigate, not proof of total safety.
- You are responsible for how you deploy and operate this on your own
  systems.

For a candid account of what doesn't work, what's unsolved, and what's
shipped-but-unproven, read the
[development retrospective](docs/RETROSPECTIVE.md).

Found a weakness in the playbook itself? Please open a private security
advisory (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## License

MIT — see [LICENSE](LICENSE).
