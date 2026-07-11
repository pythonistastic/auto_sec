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
- **Distro support.** Currently targets Ubuntu 22.04/24.04 and Debian
  12. RHEL/Alma/Rocky ports (dnf, firewalld instead of ufw, SELinux)
  are welcome as parallel task files.

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

## Before you open a PR

```bash
ansible-galaxy collection install -r requirements.yml
ansible-playbook site.yml -i inventory/hosts.yml --syntax-check
ansible-lint
shellcheck scripts/*.sh
python3 -m py_compile roles/09-watcher/templates/*.py.j2   # after stripping {{ }}
```

CI runs the first four automatically on every push and pull request.

## Security disclosure

Found a vulnerability in the playbook itself (something that would
weaken a server it hardens)? Please open a private security advisory
rather than a public issue, so operators can patch before it's public.
