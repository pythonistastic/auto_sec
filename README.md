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

One-command hardening for a Linux VPS: preventive lockdown, behavioral
breach detection, and ransomware-proof encrypted backups — as an
idempotent Ansible playbook you configure once and re-run forever.

Takes a fresh Ubuntu/Debian server from zero to:

- SSH locked to keys-only for a single deploy user, root login disabled
- Default-deny firewall with fail2ban, optional *invisible* SSH port
  (Single Packet Authorization via fwknop — the port doesn't exist
  until you knock), and optional **egress lockdown** (default-deny
  outbound) that kills most reverse-shell callbacks
- A **breach detection suite** (see below): a reverse-shell scanner and
  a recon-burst detector on by default (plus an experimental SSH login
  tripwire), sharing one alert/response pipeline that captures forensic
  evidence *before* it ever kills anything
- auditd tripwires on identity files, SSH trust, cron and binaries,
  plus a ransomware early-warning canary (mass file-change detection)
- Nightly client-side-encrypted backups (age) to a Backblaze B2 bucket
  whose key **cannot delete** — malware on the box can't destroy history
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

Re-running the playbook is always safe. It's idempotent and
self-corrects drift; add it to cron for continuous enforcement.

**New to SSH keys?** You don't need to prepare anything first. An SSH key
is a pair — a **private** half that stays secret on your computer and a
**public** half that's safe to put on the server. When you run the wizard
from your workstation, it looks for an existing key and, if you don't
have one, offers to create it for you (and explains what it made). If
you're running the wizard *on the server itself*, it prints the exact
`ssh-keygen` command to run on your own laptop and asks you to paste the
public half. Either way it walks you through it — no prior knowledge
assumed.

**Supported targets:** Ubuntu 22.04/24.04, Debian 12.

## Connecting to the server after hardening

Role 02 disables password authentication **and** root login, and
restricts SSH to the single `deploy` user. After the first run you can
no longer `ssh root@host` with a password — connect as `deploy` with the
private key whose public half you installed:

```bash
ssh -i /path/to/your_private_key deploy@your.server.ip
# deploy has passwordless sudo:
sudo whoami   # -> root
```

The private key stays on your machine; the server only ever holds the
**public** key in `/home/deploy/.ssh/authorized_keys`. If you used the
wizard, the connection details are written to `inventory/<server>.yml`,
so later playbook runs are just:

```bash
ansible-playbook -i inventory site.yml -l <server>
```

**Don't lock yourself out.** Before the first run, make sure the public
key you install matches a private key you actually hold. Keep a
break-glass path until you've confirmed access:

- set `office_static_ip` so your IP keeps direct SSH access, and/or
- keep your provider's console/VNC (e.g. Contabo) reachable.

With `paranoia_level: high`, the SSH port is also invisible until you
send a valid fwknop knock — see
[roles/04-fwknop/CLIENT-SIDE.md](roles/04-fwknop/CLIENT-SIDE.md):

```bash
fwknop -n <server> && ssh -i /path/to/key deploy@your.server.ip
```

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

## The layers

| # | Role | Type | Purpose |
|---|------|------|---------|
| 01 | base | Preventive | Auto security updates, kernel hardening, deploy user |
| 02 | ssh-hardening | Preventive | Keys only, no root, no passwords |
| 03 | firewall | Preventive | UFW default deny + fail2ban |
| 04 | fwknop | Preventive | Single Packet Authorization, invisible SSH |
| 05 | app-runtime | Preventive | Node/PM2 or Docker + hardened Nginx + TLS |
| 06 | database | Protective | Localhost only, least privilege |
| 07 | backups | Recovery | Encrypted nightly backups to no-delete B2 bucket |
| 08 | detection | Detective | auditd tripwires, ransomware canary, Telegram alerts |
| 09 | watcher | Detective/Reactive | Breach detection suite: reverse-shell scanner + recon-burst detector (+ experimental login tripwire) |
| 10 | report | Deliverable | Generated security report |

Partial runs with tags:

```bash
ansible-playbook -i inventory site.yml -l myserver --tags backups
ansible-playbook -i inventory site.yml -l myserver --tags "firewall,detection"
```

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

- `standard`: SSH port open (rate-limited, keys only), watcher alerts
- `high`: fwknop gates SSH (port invisible until a valid knock),
  watcher may run in `active` mode

**Before enabling `high`**, confirm you have provider console (VNC)
access as break-glass, and keep `office_static_ip` allowed directly on
the SSH port until you're comfortable. Client-side knock setup:
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
site.yml                 master playbook (roles 01→10 in order)
group_vars/all.yml       global defaults, override per server
host_vars/<server>.yml   per-server config + secrets (gitignored)
inventory/<server>.yml   connection details (gitignored)
scripts/bootstrap.sh     installs deps, runs the wizard
scripts/configure.sh     interactive config generator
restore-test/            monthly backup restore verification
roles/01..10-*           the layers
```

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
