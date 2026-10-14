# Changelog

All notable changes to auto_sec are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
[SemVer](https://semver.org/).

While auto_sec is **pre-1.0**, minor versions (0.x) may include breaking
changes. Treat it as early-stage — see the
[Disclaimer](README.md#disclaimer) and [RETROSPECTIVE](docs/RETROSPECTIVE.md).

## [Unreleased]

**Security release — upgrade promptly.** A codebase-wide audit found a class of injection bugs
where a variable's *value* could stop being data and become part of a command,
a file path, or a config directive. 59 issues were found and fixed.

**Realistic impact today:** most of these variables are typed by the operator,
so exploiting them meant attacking your own infrastructure. The reason they are
being treated as security bugs is the boundary: the moment any value is derived
from a managed host — a hostname read from a vhost, a package name, a domain —
an attacker with limited access to that host could reach a root command. One
issue (the detector one, below) was reachable **without any operator mistake**.

### Fixed — code execution

- `node_version` was interpolated into `curl … | bash` as root. Replaced with a
  fetch-then-run via `get_url` + `command`, so no shell is involved.
- `db_name`, `app_dir`, `b2_bucket` and `age_public_key` were interpolated into
  `backup.sh`, which runs **as root from cron every night**. All values now go
  through `| quote` (a single-quoted shell literal). Double quotes are *not*
  sufficient — bash expands `$(…)` and backticks inside them.
- `telegram_bot_token` / `telegram_chat_id` were rendered into two root-run
  shell scripts (the 5-minute audit cron and the `Restart=always` canary unit).
  Credentials are now written to root-only files and read at runtime, so they
  never appear in shell source, in `ps`, or in a `--diff`.
- `restore-test/monthly-restore.yml` had unquoted values in shell tasks and runs
  on the **ops machine that holds every client's age private key**. Rewritten to
  use `command: argv:` throughout, with `| quote` where a shell is genuinely
  required.

### Fixed — backup integrity

- **`age -r "{{ age_public_key }}"` could be given a second recipient.** A
  crafted value rendered as two `-r` flags, so every backup would also be
  readable by an attacker — and a restore test would still pass, because the
  legitimate recipient was still present. The recipient is now written to a
  root-only file and consumed with `age -R`, which cannot be extended through a
  command line.
- The monthly restore test now **counts the recipient stanzas in the age header
  and fails if there is more than one**, which detects exactly the attack a
  successful decrypt cannot see.

### Fixed — privilege escalation and file writes

- `client_domain` reached `certbot` through `command:`, where argv splitting let
  a value inject `--deploy-hook` — persisted by certbot into the renewal config
  as root execution on every future renewal. Now passed via `argv:`.
- `client_domain` was used as a path component under `/etc/nginx/sites-*`,
  allowing traversal to arbitrary root-owned files. Now validated as a hostname.
- `app_dir` reached `pm2 startup --hp` through argv splitting, which could append
  a second `--user` and make the application's process manager run **as root**.
  Now passed via `argv:`.
- `db_name` was interpolated into MySQL's `priv` string DSL, where `/` and `:`
  could append grants (e.g. `*.*:ALL`). Now passed as a dict key.

### Fixed — config injection

A newline in a value could append directives to files that are newline-
delimited. Affected `sshd_config` (`ssh_port`, `ssh_max_auth_tries`,
`deploy_user` — where an injected `Match` block overrides hardening regardless
of order, and `sshd -t` still passes because the result is valid syntax), the
fail2ban jail, fwknop `access.conf`, the audit rules, and `watcher.conf`.
Numerics are now coerced with `| int` in the templates themselves, so a
tag-scoped run that skips the preflight is still safe.

### Fixed — detector hardening

- **`block_ip()` accepted an unvalidated address parsed from `auth.log`.** Log
  lines contain attacker-influencable text, so a crafted entry could make the
  detector ban an arbitrary address — including the operator's. The value must
  now parse as a routable IP; loopback, private, link-local and reserved
  addresses are refused.
- The ransomware canary had **no `sleep`** in its loop. With a missing or wrong
  `app_dir`, `inotifywait` exits instantly and the unit spins a full CPU core
  forever. It now backs off, excludes `node_modules`/`.next`, and tolerates a
  missing directory.

### Added

- **Preflight value validation** in `site.yml` — charset, range and CR/LF checks
  for every operator-supplied variable, enforced before any change. This is the
  single enforcement point; roles may assume a validated value and must still
  quote it.
- `no_log: true` on every task that handles a token, key or password. Previously
  **no task in the repo had it**, so `-vvv` or `--diff` printed secrets.
- `SECURITY.md` — disclosure process, and the trust boundary written down:
  *facts collected from a managed host must never be promoted into variables
  automatically.*
- CI now lints the **rendered** `.sh.j2` templates and fails the build if any
  interpolation in a shell template skips `| quote` or `| int`.
- Role 08 refuses to run if auditd is in immutable mode, and only watches the
  deploy user's `authorized_keys` if the path exists (previously a tag-scoped
  run could fail the whole ruleset load).

### Changed

- The audit rules file is now `90-autosec.rules` (was `hardening.rules`) so a
  site-local `99-*.rules` can still apply `-e 2` last. The old file is removed
  on upgrade to avoid a duplicate ruleset.
- Preflight validation **may reject configurations that previously ran** — this
  is why the minor version is bumped. If a run now fails preflight, the value it
  names was reaching a shell or a config file unescaped.

## [0.2.1] - 2026-08-15

### Fixed

- CI: the CVE scanner smoke test asserted the wrong package count. Its
  fixture contained one runtime dependency plus a dev-only one — which the
  scanner correctly excludes — so it reported 1 where the test demanded 2,
  turning the v0.2.0 build red. The scanner itself was never affected. The
  fixture now holds two runtime dependencies (one scoped, exercising
  `@scope/name` parsing) plus a dev-only one, so the assertion proves both
  inclusion and dev-exclusion.

## [0.2.0] - 2026-08-15

### Added

- **CVE watch (role 11)** — a daily scan that answers "is anything I run
  now known-vulnerable?". Reads the app's dependency lockfiles, queries
  [OSV.dev](https://osv.dev), and alerts with the **minimal safe upgrade**
  and a copy-pasteable fix command; also counts unapplied OS security
  updates. Supports npm, PyPI, Packagist and Go lockfiles, and *reports*
  unsupported lockfiles rather than silently skipping them. Findings are
  alerted once (state-deduplicated) and the full list is always written to
  `/var/log/sentinel/cve-report-*.txt`.
  - Adds **no third-party binary** to the server: the scanner is stdlib
    Python, so hardened hosts gain no new supply-chain surface. Outbound
    calls are HTTPS to `api.osv.dev` only, already allowed by
    `egress_lockdown`.
  - Runs under a hardened systemd timer (`ProtectSystem=strict`,
    `NoNewPrivileges`), daily with a randomized delay.
  - Defaults to `min_severity: high` to avoid first-run alert fatigue.
- **`scripts/cve-pr.sh` (Tier 2)** — turns findings into a pull request
  against your repository, which is where a dependency fix actually
  persists (patching the server is undone by the next deploy). Collapses
  multiple advisories per package into one upgrade, supports `--dry-run`,
  `--package`, and `--min-severity`, and opens the PR via `gh` or the
  GitHub API. Deliberately intended for a workstation or CI, **not** the
  production server, so no write-scoped token has to live on an
  internet-facing box.
- **`examples/cve-pr-workflow.yml`** — drop-in GitHub Actions workflow to
  run Tier 2 weekly in CI.
- CI now compile-checks the CVE scanner and smoke-tests its lockfile
  parsing (including dev-dependency exclusion).

## [0.1.0] - 2026-07-26

First tagged release. A one-command Ubuntu/Debian hardening playbook with
a breach-detection suite, ransomware-resistant backups, and a beginner
wizard. Hardened before release across **two real-hardware test runs**
(Ubuntu 22.04 and 24.04); see [docs/RETROSPECTIVE.md](docs/RETROSPECTIVE.md)
for the honest limits.

### Added

- **10-layer playbook:** base hardening, SSH lockdown (keys-only, no
  root/passwords), UFW + fail2ban, optional fwknop Single Packet
  Authorization, Node/Docker app runtime + hardened Nginx + TLS,
  localhost-only least-privilege database, encrypted off-site backups,
  auditd detection, the detector suite, and a client security report.
- **Breach-detection suite** with a forensics-first response pipeline
  (captures evidence to `/var/log/sentinel` *before* any kill/block):
  - reverse-shell scanner (socket-stdio shells + service/app users
    spawning shells) — validated on real hardware;
  - recon-burst detector (a session enumerating the system) — validated;
  - experimental SSH login-pattern watcher, **off by default**.
- **Ransomware-resistant backups:** client-side `age` encryption to a
  Backblaze B2 bucket with a **no-delete** key, plus a monthly
  restore-test playbook.
- **Optional egress lockdown** (default-deny outbound).
- **Onboarding:** `bootstrap.sh` installer and an interactive wizard that
  generates keys, auto-detects the Telegram chat id, and guides
  non-technical users; beginner-friendly README.
- **`tests/redteam.sh`** — validates each detector against real attacks on
  a throwaway box.
- **CI** (syntax check, ansible-lint, shellcheck, detector py_compile) incl.
  a distro-representative ansible-core 2.16 job; MIT license; ASCII banner.

### Fixed

Issues caught and fixed before release during the real-hardware runs:

- MySQL tasks referenced a non-existent `ansible.mysql` collection, which
  broke **every** playbook invocation (even `--syntax-check`) on the
  ansible-core versions distros ship. Now `community.mysql`.
- `ansible-galaxy` pulled collections newer than the distro ansible-core
  supported. `requirements.yml` now pins compatible ranges.
- A missing `watcher_pattern` could fail **after** SSH was already locked
  down. Added defaults and a fail-fast `pre_tasks` preflight assert that
  validates every required variable **before** any change.
- One broken optional role broke unrelated runs (static import). Optional
  roles now load dynamically only when their feature is configured.
- `auditd` rules not loading on `systemctl restart`; `ausearch` hanging and
  starving detectors; a reverse-shell false positive on journald sockets.

### Known limitations

Backups/restore, fwknop, app/DB/TLS roles, Telegram delivery, `active`
mode, and non-Ubuntu-22.04 targets are shipped but **not yet validated
end-to-end**. See [docs/RETROSPECTIVE.md](docs/RETROSPECTIVE.md).

[Unreleased]: https://github.com/pythonistastic/auto_sec/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/pythonistastic/auto_sec/releases/tag/v0.2.1
[0.2.0]: https://github.com/pythonistastic/auto_sec/releases/tag/v0.2.0
[0.1.0]: https://github.com/pythonistastic/auto_sec/releases/tag/v0.1.0
