# secure-deploy

One-command hardening for a Linux VPS: preventive lockdown, behavioral
breach detection, and ransomware-proof encrypted backups — as an
idempotent Ansible playbook you configure once and re-run forever.

Takes a fresh Ubuntu/Debian server from zero to:

- SSH locked to keys-only for a single deploy user, root login disabled
- Default-deny firewall with fail2ban, optional *invisible* SSH port
  (Single Packet Authorization via fwknop — the port doesn't exist
  until you knock)
- A behavioral **login watcher**: every interactive SSH session must run
  a secret command within a time window, or it's treated as a breach —
  alert, or kill the session and block the IP
- auditd tripwires on identity files, SSH trust, cron and binaries,
  plus a ransomware early-warning canary (mass file-change detection)
- Nightly client-side-encrypted backups (age) to a Backblaze B2 bucket
  whose key **cannot delete** — malware on the box can't destroy history
- Telegram alerts for everything, and a generated security report

## Quick start

On your workstation (managing a remote server) **or** directly on the
server you want to harden:

```bash
git clone https://github.com/YOURUSER/secure-deploy.git
cd secure-deploy
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

**Supported targets:** Ubuntu 22.04/24.04, Debian 12.

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
| 09 | watcher | Detective/Reactive | Behavioral login pattern watcher |
| 10 | report | Deliverable | Generated security report |

Partial runs with tags:

```bash
ansible-playbook -i inventory site.yml -l myserver --tags backups
ansible-playbook -i inventory site.yml -l myserver --tags "firewall,detection"
```

## The watcher, honestly

The watcher is a **tripwire second factor**, not machine-learning
anomaly detection. Legitimate humans know the secret: type a command
containing the pattern within N seconds of logging in. An attacker with
a stolen SSH key doesn't know the ritual, goes straight for the data,
and trips the wire.

Design notes:

- Sessions are tracked individually (systemd-logind / audit session
  IDs), so a valid user logged in at the same time cannot vouch for an
  intruder on the same account — and enforcement kills only the
  offending session.
- Non-interactive sessions (`scp`, `rsync`, Ansible itself, git) are
  skipped automatically; trusted IPs/CIDRs can be whitelisted
  (`watcher_whitelist_ips`).
- **Run in `alert` mode for at least a week** before switching to
  `active`, and keep your break-glass IP configured. Rotate the
  pattern quarterly. Treat it as one detection layer among several,
  not a guarantee.

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

## License

MIT — see [LICENSE](LICENSE).
