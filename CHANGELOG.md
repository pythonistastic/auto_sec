# Changelog

All notable changes to auto_sec are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
[SemVer](https://semver.org/).

While auto_sec is **pre-1.0**, minor versions (0.x) may include breaking
changes. Treat it as early-stage — see the
[Disclaimer](README.md#disclaimer) and [RETROSPECTIVE](docs/RETROSPECTIVE.md).

## [Unreleased]

_Nothing yet._

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

[Unreleased]: https://github.com/pythonistastic/auto_sec/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/pythonistastic/auto_sec/releases/tag/v0.1.0
