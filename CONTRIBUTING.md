# Contributing

auto_sec is a personal research project: deliberately small, readable,
and honest about its limits. Contributions that close gaps, add tests,
or broaden OS support are welcome.

## Good first contributions

- **Detection ideas for 0.7.** The 0.1–0.5 detectors did not work as
  documented ([#18](https://github.com/pythonistastic/auto_sec/issues/18)),
  so 0.6 ships none. Ideas, test cases and evasion notes for the rewrite
  are welcome as issues: eBPF-based syscall monitoring, outbound-connection
  anomalies, `/etc/ld.so.preload` tampering, SUID-binary changes,
  cron/systemd-timer persistence.
- **Run a live job.** 0.6's live test jobs in CI are written but have not
  run yet. A run on a fork, with its logs, helps a lot.
- **Distro support.** Currently targets Ubuntu 22.04/24.04. Debian 12
  and 13 are tested in CI only. RHEL/Alma/Rocky ports (dnf, firewalld
  instead of ufw, SELinux) are welcome as parallel task files.

## Ground rules

- **Every role states its plan.** Each role's preflight or `plan.yml`
  sets `_plan_NN`, a list of `{role, part, do, what, note}` (see
  `roles/00-plan/tasks/summary.yml`). "what" is built from the
  operator's values and constant names only; host details go in "note".
  A change the plan does not list is a bug. CI checks that every role
  sets its `_plan_NN`.
- **Refusal IDs are namespaced.** `R<role>-...` (refuse before any
  change), `M<role>-...` (the host changed during the run), `N<role>-...`
  and `W<role>-...` (notes and warnings) live only in that role's
  directory; `P1`–`P5`, `M-P*` and `N-P*` only in `roles/autosec-apt`.
  Every preflight refusal ends with "Nothing has been changed." CI checks
  the namespaces.
- **`existing` means change nothing unless named.** A new feature that
  installs, writes or starts something needs its own setting, with
  `keep` (or off) as the default for `autosec_server: existing`.
- **Never replace a file auto_sec cannot prove is its own** (a header
  line, or the exact bytes of an older release). Otherwise refuse, and
  say how to proceed.
- **Packages only through `roles/autosec-apt`.** No `apt` module: the
  guard simulates first, refuses upgrades and removals, and holds
  needrestart back. CI greps for the apt module.
- **No ufw command on an active ufw**, no `ufw default` on its own, no
  `systemctl enable` (it reloads systemd). CI checks the `ufw`, `sysctl`
  and `apt` modules, `augenrules`, and `enabled: true` outside roles
  04-07.
- **No secrets in git.** `host_vars/*`, `inventory/*`, `secrets/`,
  `reports/` and all keys are gitignored. Keep it that way.
- **Keep it idempotent.** Re-running the playbook must converge, not
  duplicate. Test with `--check` where practical.
- **SSH changes go through the guard.** Role 02 writes only
  `/etc/ssh/sshd_config.d/00-autosec.conf`. It loads it at once with
  `systemctl try-reload-or-restart ssh.service`, under the undo timer,
  and then tests a fresh login. Never add a `restart sshd` handler, never
  write `Port` or `ListenAddress`, never touch `ssh.socket`. CI checks
  the first rule.
- **fail2ban changes go to auto_sec's own file.** Role 03 writes only
  `/etc/fail2ban/jail.d/00-autosec.conf` (and role 05 only
  `00-autosec-nginx.conf`). Never write `jail.local`, never add a
  `restart fail2ban` handler: fail2ban is reloaded only when the trial
  run shows an effective change. CI checks both.
- **Update settings go to auto_sec's own file.** Role 01 writes only
  `/etc/apt/apt.conf.d/51autosec-unattended-upgrades`, and only when an
  operator setting asks for something (with the defaults it writes
  none). Never write `20auto-upgrades` or `50unattended-upgrades` (the
  one-time 0.1–0.4 restore, behind `-e apt_migrate_unattended_upgrades=true`,
  is the only exception). The hostname and timezone change only when
  the operator set `server_hostname` or `timezone`. Role 01 installs
  missing packages only, without recommendations, and never one whose
  install upgrades or removes another. The base-semantics tests check
  all of this.
- **Public variables live in `group_vars/all.yml`.** Roles 00-plan, 01,
  03 and 11 keep the same values in their `defaults/main.yml`, so their
  tests run without group_vars. CI fails when the two differ.
- **Host data is not input.** Values read from a managed host may be
  compared, shown, or used to refuse a run. They never become variables,
  file content or command arguments without a written exception in
  [SECURITY.md](SECURITY.md).

## Before you open a PR

```bash
ansible-galaxy collection install -r requirements.yml
ansible-playbook site.yml -i inventory/hosts.yml --syntax-check
ansible-lint
# default severity, same files as CI (bash, for **):
shopt -s globstar
shellcheck -x scripts/*.sh tests/**/*.sh tests/guard/stubs/* tests/legacy/stubs/* \
  roles/02-ssh-hardening/files/auto-sec-ssh-guard \
  roles/01-base/files/autosec-apt-sim roles/01-base/files/autosec-sudo-scan
# the run-wide checks and the plan, without root (current ansible-core):
bash tests/site/semantics/run.sh
```

CI runs all of these on every push and pull request, and the lab suites
of each role (`tests/*/semantics`, `tests/legacy`) on the current
ansible-core and on 2.16.

If you touch SSH (role 02, the guard script, roles 03 or 04, or the
preflight in `site.yml`), also run the two SSH test suites below. If you
touch fail2ban (role 03) or the update, hostname and timezone settings
(role 01), run their lab tests (see
[The fail2ban and update tests](#the-fail2ban-and-update-tests)).

### The SSH tests in CI

- **Static checks.** No task notifies `restart sshd`, and the old
  `sshd_config.j2` template is gone. The syntax check also runs on the
  ansible-core 2.16 that Ubuntu 24.04 ships.
- **sshd semantics** (`tests/sshd-semantics/`). Real OpenSSH builds
  from Ubuntu 22.04, 24.04 and 26.04 and Debian 12 and 13 read the
  config auto_sec would write. Golden checks: a keep-everything file
  changes nothing; stage 2 changes exactly the two login values;
  `Subsystem` is never written; for layouts that role 02's trial run
  (P8) must refuse (a stray `AllowUsers` drop-in, an earlier drop-in
  that wins, an `Include` that wakes `50-cloud-init`), sshd's effective
  values really are the unwanted ones. This suite runs sshd only, not
  the role: the refusals themselves are tested by the live role tests.
- **Guard unit tests** (`tests/guard/`). The undo script
  `auto-sec-ssh-guard`: the deadline, the lock, `arm`, `check`,
  `disarm`, `revert`, and boot mode.
- **Live role tests** (`tests/role02-live/`). The real role, run against
  the runner's own sshd on GitHub's Ubuntu 22.04 and 24.04 VMs,
  including the trial run's refusals (case p).

### Running the SSH tests on your machine

Both local suites run **without root**, and never touch your real
`/etc/ssh`. WSL (Ubuntu) works.

**Guard unit tests:**

```bash
bash tests/guard/run.sh
```

They need a running user systemd (`systemctl --user` must work; in WSL,
enable systemd in `/etc/wsl.conf`). `sshd`, `fail2ban-client` and
`logger` are stubs, and the sshd reload is only logged. The guard's
undo timers are real: they run under your `systemd --user`.

**sshd semantics:**

```bash
bash tests/sshd-semantics/run.sh
```

It downloads pinned `openssh-server` packages from the Ubuntu and Debian
archives, checks each one's SHA256, unpacks it with `dpkg-deb -x`, and
runs that build's `sshd -t` and `sshd -T` on test configs. Nothing is
installed. It needs `dpkg-deb`, `curl`, `ssh-keygen`, `ansible-playbook`
(it renders the role's template) and network access to the archives.
`--cache DIR` reuses packages you already downloaded.

**Live role tests:** GitHub runners only. They use `sudo` and change
the runner's sshd, ufw and fail2ban. Do not run them on your own
machine or on a server you care about.

### The fail2ban and update tests

- **fail2ban semantics** (`tests/fail2ban/semantics/`). Real fail2ban
  builds from Ubuntu 22.04, 24.04 and 26.04 and Debian 12 and 13 read
  `/etc/fail2ban` layouts next to role 03's file: the read order, the
  canary-like layout that must not change at all, migration of an
  auto_sec 0.1–0.4 `jail.local`, the refusals and warnings. With a
  Python that can import `asyncore` (`pip install pyasyncore` on Python
  3.12+), a real fail2ban 1.0.2 server also runs as your user: reload
  and restart semantics, and role 03's own task files against it.
- **Update semantics** (`tests/base/semantics/`). Real
  unattended-upgrades builds from the same five releases: role 01's own
  task files run against lab apt configurations, and each release's
  unattended-upgrades code reports what it would install from and
  whether it would reboot, before and after. Role 01's package step
  runs against real `apt-get -s` output (fake `dpkg-query` and `apt-get`
  in `PATH`).
- **Live tests** (`tests/fail2ban/live/`, `tests/base/live/`). The real
  roles against GitHub's Ubuntu 22.04 and 24.04 VMs. GitHub runners
  only: they reconfigure fail2ban, apt, the hostname and the timezone of
  the machine they run on.

Both lab suites run **without root**, download pinned packages
(SHA256-checked) and unpack them with `dpkg-deb -x`. WSL (Ubuntu) works:

```bash
bash tests/fail2ban/semantics/run.sh --ansible "$(command -v ansible-playbook)"
bash tests/base/semantics/run.sh
```

The update suite also needs `python3-apt`, `python3-distro-info` and
`lsb_release` for the system's `/usr/bin/python3`; without them its
unattended-upgrades checks print SKIP. `--cache DIR` reuses downloaded
packages.

`tests/redteam.sh` belongs to the 0.1–0.5 detectors, which 0.6 no
longer installs. It stays as a starting point for the 0.7 rewrite.

### The full-run tests

- **`full-adopt-live`** (`tests/full-adopt-live/`): a runner set up like
  a server already in use (active ufw, fail2ban with its own
  `jail.local`, auditd rules, an app port, root as the admin). Plan-only,
  `--check` and two real runs with `autosec_server: existing` must leave
  every file under `/etc` and `/opt`, every service and the firewall
  counters as they were. Only the report on the controller is new.
- **`full-new-live`** (`tests/full-new-live/`): a runner without ufw,
  `autosec_server: new`. ufw is turned on under the undo, `deploy` and
  its sudo file are created, fail2ban is installed; the second run
  changes nothing; an injected login failure turns ufw back off.
- **`legacy-live`** (`tests/full-legacy-live/`): 0.5's detectors in active
  mode stop the run before fact gathering (R00-3); in alert mode the run
  warns and changes nothing.

GitHub runners only: they change the machine they run on.

## Cutting a release

Add your user-facing changes under `## [Unreleased]` in
[CHANGELOG.md](CHANGELOG.md) as you go (Breaking / Added / Changed /
Fixed / Upgrading / Known limitations, as needed). When
it's time to release, run one command from a clean tree:

```bash
./scripts/release.sh patch     # 0.1.0 -> 0.1.1 (or: minor | major | X.Y.Z)
```

It bumps `VERSION`, rolls `[Unreleased]` into a new dated version section,
updates the README badge and changelog links, commits, and creates an
annotated `vX.Y.Z` tag. It does **not** push — review, then:

```bash
git push origin main --tags
```

Finally, draft a GitHub Release from the new tag and paste that version's
changelog section. Versioning is SemVer; while pre-1.0, minor versions
may include breaking changes.

## Security disclosure

Found a vulnerability in the playbook itself (something that would
weaken a server it hardens)? Please open a private security advisory
rather than a public issue, so operators can patch before it's public.
