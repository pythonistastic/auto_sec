# Contributing

This project is deliberately small, readable, and honest about its
limits. Contributions that add detection techniques, close evasion
gaps, or broaden OS support are very welcome.

## Good first contributions

- **New detectors** for role 09. Each is a standalone script under
  `roles/09-watcher/templates/` that imports `sentinel_lib` and calls
  `S.respond(...)`. Ideas the community has raised: eBPF-based syscall
  monitoring, outbound-connection anomaly detection, LD_PRELOAD /
  `/etc/ld.so.preload` tampering watches, SUID-binary change detection,
  cron/systemd-timer persistence diffing.
- **Evasion notes.** If you can slip past a detector, document how in an
  issue (or add a failing case). Knowing the gaps is more valuable than
  pretending they don't exist.
- **Distro support.** Currently targets Ubuntu 22.04/24.04. Debian 12
  and 13 are tested in CI only. RHEL/Alma/Rocky ports (dnf, firewalld
  instead of ufw, SELinux) are welcome as parallel task files.

## Ground rules

- **Detectors default to `alert` mode.** Automated killing is opt-in
  (`watcher_mode: active`) and must always capture evidence *before*
  acting — use `S.respond()`, never call `kill`/`ufw` directly from a
  detector.
- **Never crash the loop.** Detectors wrap their work so a bad scan
  logs nothing and continues. Alerting failures must be swallowed.
- **No secrets in git.** `host_vars/*`, `inventory/*`, `secrets/`,
  and all keys are gitignored. Keep it that way.
- **Keep it idempotent.** Re-running the playbook must converge, not
  duplicate. Test with `--check` where practical.
- **SSH changes go through the guard.** Role 02 writes only
  `/etc/ssh/sshd_config.d/00-autosec.conf`. It loads it at once with
  `systemctl try-reload-or-restart ssh.service`, under the undo timer,
  and then tests a fresh login. Never add a `restart sshd` handler, never
  write `Port` or `ListenAddress`, never touch `ssh.socket`. CI checks
  the first rule.
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
shellcheck scripts/*.sh tests/**/*.sh tests/guard/stubs/* \
  roles/02-ssh-hardening/files/auto-sec-ssh-guard
python3 -m py_compile roles/09-watcher/templates/*.py.j2   # after stripping {{ }}
```

CI runs all of these on every push and pull request.

If you touch SSH (role 02, the guard script, roles 03 or 04, or the
preflight in `site.yml`), also run the two SSH test suites below.

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

To validate a detector end-to-end on real hardware, run
`sudo tests/redteam.sh` on a throwaway server the playbook has hardened.
If you add a detector, add a matching trigger + assertion there.

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
