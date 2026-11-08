#!/usr/bin/env bash
# full-adopt-live: the goal test of auto_sec 0.6 (plan 6.2). The GitHub
# runner is set up like a server that already runs something (the canary):
#   ufw active (deny in, allow out, logging low; limit 22/tcp, allow 80 and
#   443/tcp), fail2ban with the operator's jail.local, auditd with the
#   operator's own rules (also a hardening.rules), /etc/sysctl.d/
#   60-hardening.conf, needrestart and unattended-upgrades as installed, an
#   app listening on :3000, a cron.d file, root as the admin and no deploy
#   account, and auto_sec 0.4's SSH stage 1 (keep/keep) already applied.
# Then, over SSH to root@127.0.0.1 with the canary's host_vars
# (autosec_server: existing, autosec_require_approval: true, every choice
# keep): the plan only, --check, and the real run twice.
#   a  plan only: every line says "no change"; packages: nothing to
#      install; server: 0 files, 0 packages, 0 services, 0 firewall rules;
#      no approval needed
#   b  --check: rc 0
#   c  real run, twice: rc 0 without -e autosec_approve, the same plan id as
#      a, only the report's tasks change anything, no daemon-reload
#   d  the server is exactly as before: every file under /etc and /opt (and
#      /usr/local/{s,}bin, /var/lib/auto-sec, /root/.ssh), symlinks,
#      packages, accounts, the PID and start time of every running service
#      (ssh, fail2ban, auditd, cron, journald, the app, ufw's start), the
#      firewall rules (counters only grew), audit rules, kernel values,
#      root's crontab and apt's history; the only new file is the report on
#      this computer
#
# GITHUB-HOSTED RUNNERS ONLY (tests/full-live/lib.sh refuses elsewhere).
# UNVERIFIED: written and linted, never run on a runner yet.
# Usage: bash tests/full-adopt-live/run.sh
# Logs: $RUNNER_TEMP/full-adopt-live/logs. Exit 0 = every check passed.
set -u -o pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
NAME=full-adopt-live
WORK=${RUNNER_TEMP:-/tmp}/full-adopt-live
# shellcheck source-path=SCRIPTDIR/..
# shellcheck source=full-live/lib.sh
. "$ROOT/tests/full-live/lib.sh"
HOST=adopt
REPORT=$ROOT/reports/security-report-$HOST.md

setup() {
  echo "== setup (like the canary)"
  apt_update || die "apt-get update"
  apt_install ufw fail2ban python3-systemd auditd needrestart unattended-upgrades cron || die "setup packages"
  ssh_setup
  if id deploy >/dev/null 2>&1; then sudo -n userdel -r deploy >/dev/null 2>&1 || die "userdel deploy"; fi
  sudo -n rm -f /etc/sudoers.d/deploy

  # Kernel settings of the operator's own (60-hardening.conf), nothing in
  # /etc/sysctl.conf from auto_sec.
  printf '%s\n' '# operator (full-adopt-live)' 'net.ipv4.tcp_syncookies=1' 'net.ipv4.conf.all.rp_filter=1' \
    'kernel.dmesg_restrict=1' | sudo -n tee /etc/sysctl.d/60-hardening.conf >/dev/null
  sudo -n sysctl --system >/dev/null 2>&1 || true

  # auditd with the operator's rules.
  sudo -n install -m 0640 "$ROOT/tests/legacy/fixtures/operator-hardening.rules" /etc/audit/rules.d/hardening.rules
  sudo -n systemctl enable --now auditd >/dev/null 2>&1 || true
  sudo -n augenrules --load >/dev/null 2>&1 || info setup "augenrules --load failed on this runner"

  # fail2ban with the canary's jail.local (systemd backend for sshd).
  sudo -n install -d -m 0755 /var/log/nginx
  sudo -n touch /var/log/nginx/error.log /var/log/nginx/access.log
  cp "$ROOT/tests/fail2ban/semantics/fixtures/canary.jail.local" "$WORK/jail.local"
  if [ ! -e /etc/fail2ban/filter.d/nginx-bad-request.conf ]; then
    awk '/^\[/ { skip = ($0 == "[nginx-bad-request]") } !skip' "$ROOT/tests/fail2ban/semantics/fixtures/canary.jail.local" >"$WORK/jail.local"
  fi
  sudo -n install -m 0644 "$WORK/jail.local" /etc/fail2ban/jail.local
  sudo -n rm -f /etc/fail2ban/jail.d/00-autosec.conf
  sudo -n systemctl enable fail2ban >/dev/null 2>&1
  sudo -n systemctl restart fail2ban || die "fail2ban does not start with the canary's jail.local"

  # ufw active, the canary's rules.
  sudo -n ufw --force reset >/dev/null
  sudo -n ufw default deny incoming >/dev/null
  sudo -n ufw default allow outgoing >/dev/null
  sudo -n ufw logging low >/dev/null
  sudo -n ufw limit 22/tcp >/dev/null
  sudo -n ufw allow 80/tcp >/dev/null
  sudo -n ufw allow 443/tcp >/dev/null
  sudo -n ufw --force enable >/dev/null || die "ufw enable"

  # An app on :3000 (ufw blocks it from outside, like an app behind nginx),
  # and a cron.d file of the operator's.
  sudo -n systemd-run --unit=ci-app -p Restart=always /usr/bin/python3 -m http.server 3000 >/dev/null 2>&1 \
    || die "cannot start the :3000 app"
  printf '%s\n' '# operator (full-adopt-live)' '15 2 * * * root /bin/true' | sudo -n tee /etc/cron.d/ci-backup >/dev/null

  # The canary's host_vars (plan section 2).
  cat >"$WORK/vars.yml" <<EOF
      autosec_server: existing
      autosec_require_approval: true
      deploy_user_account: keep
      unattended_upgrades_enabled: keep
      fail2ban_hardening_enabled: keep
      firewall_state: keep
      cve_watch_enabled: false
      ssh_admin_user: root
      ssh_admin_public_keys:
        - "$ADMIN_PUB"
      ssh_permit_root_login: keep
      ssh_password_authentication: keep
      office_static_ip: ""
      paranoia_level: standard
EOF
  write_inv "$HOST" "$WORK/vars.yml"

  # auto_sec 0.4's SSH stage 1, as on the canary: 00-autosec.conf (comments
  # only) and the undo guard. This run is setup, not a test case.
  play setup-stage1 -l "$HOST" --tags ssh -e autosec_require_approval=false || die "SSH stage 1 (setup) failed"
  sudo -n test -f /etc/ssh/sshd_config.d/00-autosec.conf || die "setup: no 00-autosec.conf after stage 1"
  rm -f "$REPORT"
  ssh_load_info setup
}

case_a() {
  local rc=0
  play a-plan -l "$HOST" -e autosec_plan_only=true || rc=$?
  expect a "plan only: rc" "$rc" 0
  log_has a a-plan "01 base:      no change" "01 base: no change"
  log_has a a-plan "02 ssh:       no change" "02 ssh: no change"
  log_has a a-plan "03 firewall:  ufw active, kept (no ufw command); fail2ban: keep" "03: ufw kept, fail2ban keep"
  log_has a a-plan "04-07:        skipped (not configured)" "04-07 skipped"
  log_has a a-plan "08 detection: not managed in 0.6 (no change)" "08 not managed"
  log_has a a-plan "09 watcher:   not managed in 0.6 (no change)" "09 not managed"
  log_has a a-plan "11 cve:       skipped (cve_watch_enabled: false)" "11 skipped"
  log_has a a-plan "packages:     nothing to install" "nothing to install"
  log_has a a-plan "server: 0 files, 0 packages, 0 services (re)started, 0 firewall rules" "totals all zero"
  log_has a a-plan "(no server change: approval not needed)" "no approval needed"
  PLAN_ID=$(plan_id a-plan)
  if [ -n "$PLAN_ID" ]; then pass a "plan id $PLAN_ID"; else fail a "no plan id printed"; fi
  if [ -e "$REPORT" ]; then fail a "plan only wrote the report"; else pass a "plan only wrote nothing"; fi
}

case_b() {
  local rc=0
  play b-check -l "$HOST" --check || rc=$?
  expect b "--check: rc" "$rc" 0
  if [ -e "$REPORT" ]; then fail b "--check wrote the report"; else pass b "--check wrote no report"; fi
}

case_c() {
  local rc n t0 run
  t0=$(date +%s)
  sleep 1
  for run in c-run1 c-run2; do
    rc=0
    play "$run" -l "$HOST" || rc=$?
    expect c "$run: rc without autosec_approve" "$rc" 0
    expect c "$run: plan id" "$(plan_id "$run")" "$PLAN_ID"
    n=$(changed_tasks "$run" | grep -v '^10-report : Report: ' | paste -sd'|' -)
    expect c "$run: tasks that changed something, apart from the report" "${n:-none}" none
  done
  expect c "systemd daemon-reloads during the runs" "$(reloads_since "$t0")" 0
  if [ -f "$REPORT" ] && [ "$(stat -c %a "$REPORT")" = 600 ]; then
    pass c "report written on this computer (0600)"
  else
    fail c "no 0600 report at $REPORT"
  fi
  if sudo -n sh -c 'ls /root/security-report-* >/dev/null 2>&1'; then
    fail c "a report was written on the server"
  else
    pass c "no report on the server"
  fi
  log_lacks c c-run1 "needrestart" "needrestart not mentioned (no apt run)"
}

setup
snapshot before
ssh_load_info a
echo "== case a"; case_a
echo "== case b"; case_b
echo "== case c"; case_c
snapshot after
echo "== case d"; same d before after
finish
