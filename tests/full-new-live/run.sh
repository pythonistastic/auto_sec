#!/usr/bin/env bash
# full-new-live: a full run of auto_sec 0.6 with autosec_server: new (plan
# 6.2) on a GitHub runner made to look new: ufw and fail2ban purged, no
# deploy account, Docker stopped and forwarding off (the turn-on refuses a
# forwarding host, R03-W7a). Over SSH to root@127.0.0.1 with autosec_ci:
# true (the CI-only exception that lets role 02 and role 03 prove a login
# over a loopback connection).
#   u1-u3 (plan 6.2's ufw-live cases, folded in here; ufw is not installed)
#   u1 --check: rc 0, and nothing changes on the server (snapshot)
#   u2 local mode (-c local): the turn-on is refused (R03-W10), nothing
#      installed
#   u3 an unconnected UDP socket on 51820: the turn-on is refused (R03-W5),
#      nothing installed
#   a  plan only: the plan lists the account, its sudo file, the ufw rules,
#      ufw on, and fail2ban install and start
#   b  the real run: ufw active with exactly limit 22/tcp, allow 80/tcp and
#      allow 443/tcp (each with comment 'auto_sec'); deploy exists with no
#      extra groups and its sudo file (0440 root:root, auto_sec's header);
#      sudo -n works for deploy; fail2ban active; the undo guard idle
#   c  the second run: nothing changes on the server (only the report)
#   d  CI-only injected failure of the login test after ufw comes on
#      (autosec_ci_inject_ufw_fail, AUTOSEC_CI_INJECT_FAILURE=ufw): the run
#      fails, ufw is off again, and its four files are byte-identical to
#      before the run
# Ports that listen on this runner when the test starts (other than SSH and
# loopback) go into firewall_closed_ok: the test accepts that they close.
#
# GITHUB-HOSTED RUNNERS ONLY (tests/full-live/lib.sh refuses elsewhere).
# UNVERIFIED: written and linted, never run on a runner yet. It uses role
# 02's undo guard in its --ufw mode (plan 4.5).
# Usage: bash tests/full-new-live/run.sh
# Logs: $RUNNER_TEMP/full-new-live/logs. Exit 0 = every check passed.
set -u -o pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
NAME=full-new-live
WORK=${RUNNER_TEMP:-/tmp}/full-new-live
# shellcheck source-path=SCRIPTDIR/..
# shellcheck source=full-live/lib.sh
. "$ROOT/tests/full-live/lib.sh"
HOST=fresh
UFW_FILES="/etc/ufw/ufw.conf /etc/default/ufw /etc/ufw/user.rules /etc/ufw/user6.rules"
PENDING=/var/lib/auto-sec/ssh-guard/pending

ufw_sums() { local f; for f in $UFW_FILES; do sudo -n sha256sum "$f" 2>/dev/null || echo "absent $f"; done; }

setup() {
  echo "== setup (a new server)"
  apt_update || die "apt-get update"
  ssh_setup
  apt_purge ufw fail2ban
  sudo -n rm -rf /etc/ufw /etc/fail2ban
  if id deploy >/dev/null 2>&1; then sudo -n userdel -r deploy >/dev/null 2>&1 || die "userdel deploy"; fi
  sudo -n rm -f /etc/sudoers.d/deploy
  # A new server forwards nothing: stop Docker and turn forwarding off.
  sudo -n systemctl stop docker.socket docker.service containerd.service >/dev/null 2>&1 || true
  sudo -n sysctl -w net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0 >/dev/null
  # Ports that listen now, apart from SSH and loopback (firewall_closed_ok).
  CLOSED=$( { ss -Hltn; ss -Hlun; } 2>/dev/null | awk '{ print $4 }' \
    | grep -Ev '^(127\.|\[::1\]|::1|\[::ffff:127\.)' | sed -E 's/.*:([0-9]+)$/\1/' | sort -un | grep -vx 22 || true)
  info setup "ports listening now that may close: ${CLOSED:-none}"
  {
    echo "      autosec_server: new"
    echo "      autosec_ci: true"
    echo "      ssh_admin_user: deploy"
    echo "      ssh_admin_public_keys:"
    echo "        - \"$ADMIN_PUB\""
    echo "      ssh_permit_root_login: keep"
    echo "      ssh_password_authentication: keep"
    echo "      office_static_ip: \"\""
    echo "      paranoia_level: standard"
    echo "      firewall_revert_seconds: 120"
    echo "      firewall_inbound:"
    echo "        - { port: 80 }"
    echo "        - { port: 443 }"
    echo "      firewall_closed_ok: [$(for p in $CLOSED; do printf '"%s/tcp", "%s/udp", ' "$p" "$p"; done | sed 's/, $//')]"
    # No /var/log/auth.log on the runner images: the sshd jail reads the journal.
    echo "      fail2ban_defaults: {bantime: \"1h\", findtime: \"10m\", maxretry: 4, backend: systemd}"
  } >"$WORK/vars.yml"
  write_inv "$HOST" "$WORK/vars.yml"
}

no_ufw() { # case: ufw is still not installed
  if command -v ufw >/dev/null 2>&1 || [ -e /usr/sbin/ufw ]; then fail "$1" "ufw was installed"; else pass "$1" "ufw is still not installed"; fi
}

case_u1() {
  local rc=0
  snapshot u1-before
  play u1-check -l "$HOST" --check || rc=$?
  expect u1 "--check on a host without ufw: rc" "$rc" 0
  snapshot u1-after
  same u1 u1-before u1-after
  no_ufw u1
}

case_u2() {
  local rc=0
  play u2-local -l "$HOST" -c local || rc=$?
  if [ "$rc" -ne 0 ]; then pass u2 "local mode: the run stops (rc $rc)"; else fail u2 "local mode: the run succeeded"; fi
  log_has u2 u2-local "in local mode: auto_sec proves the" "local mode: R03-W10"
  no_ufw u2
}

case_u3() {
  local rc=0 pid
  python3 -c 'import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 51820))
time.sleep(900)' &
  pid=$!
  sleep 1
  play u3-udp -l "$HOST" || rc=$?
  kill "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  if [ "$rc" -ne 0 ]; then pass u3 "a listening 51820/udp: the run stops (rc $rc)"; else fail u3 "the run succeeded"; fi
  log_has u3 u3-udp "51820/udp" "R03-W5 names 51820/udp"
  no_ufw u3
}

case_a() {
  local rc=0
  play a-plan -l "$HOST" -e autosec_plan_only=true || rc=$?
  expect a "plan only: rc" "$rc" 0
  log_has a a-plan "user: create deploy" "plan: create deploy"
  log_has a a-plan "sudoers: write /etc/sudoers.d/deploy" "plan: the sudo file"
  log_has a a-plan "add-rule: ufw limit 22/tcp comment auto_sec" "plan: SSH rule"
  log_has a a-plan "add-rule: ufw allow 80/tcp comment auto_sec" "plan: 80/tcp"
  log_has a a-plan "add-rule: ufw allow 443/tcp comment auto_sec" "plan: 443/tcp"
  log_has a a-plan "firewall-on: ufw --force enable" "plan: ufw on"
  log_has a a-plan "start: fail2ban (sshd jail: bans after 4 failures in 10m; exempt: nobody)" "plan: fail2ban start, nobody exempt"
  if command -v ufw >/dev/null 2>&1; then fail a "plan only installed ufw"; else pass a "plan only installed nothing"; fi
}

case_b() {
  local rc=0 added
  play b-run -l "$HOST" || rc=$?
  expect b "run: rc" "$rc" 0
  expect b "ufw status" "$(sudo -n ufw status 2>/dev/null | head -n 1)" "Status: active"
  added=$(sudo -n ufw show added 2>/dev/null | grep '^ufw ' | paste -sd'|' -)
  expect b "ufw show added" "$added" \
    "ufw limit 22/tcp comment 'auto_sec'|ufw allow 80/tcp comment 'auto_sec'|ufw allow 443/tcp comment 'auto_sec'"
  expect b "deploy exists" "$(getent passwd deploy | cut -d: -f1,7)" "deploy:/bin/bash"
  expect b "deploy has no extra groups" "$(id -nG deploy 2>/dev/null)" deploy
  expect b "sudo file mode and owner" "$(sudo -n stat -c '%a %U:%G' /etc/sudoers.d/deploy 2>/dev/null)" "440 root:root"
  expect b "sudo file line 1" "$(sudo -n head -n 1 /etc/sudoers.d/deploy 2>/dev/null | cut -c1-30)" "# Written by auto_sec (role 01"
  if sudo -n runuser -u deploy -- sudo -n true 2>/dev/null; then pass b "sudo -n works for deploy"; else fail b "sudo -n fails for deploy"; fi
  expect b "fail2ban" "$(systemctl is-active fail2ban 2>/dev/null)" active
  if sudo -n test -e "$PENDING"; then fail b "an undo is still pending"; else pass b "undo guard idle"; fi
  if ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -i "$KEYS/admin" deploy@127.0.0.1 true </dev/null; then
    pass b "key login as deploy works"
  else
    fail b "key login as deploy fails"
  fi
}

case_c() {
  local rc=0 n
  snapshot c-before
  play c-run2 -l "$HOST" || rc=$?
  expect c "second run: rc" "$rc" 0
  log_has c c-run2 "03 firewall:  ufw active, kept (no ufw command)" "second run: ufw kept"
  n=$(changed_tasks c-run2 | grep -v '^10-report : Report: ' | paste -sd'|' -)
  expect c "second run: tasks that changed something, apart from the report" "${n:-none}" none
  snapshot c-after
  same c c-before c-after
}

case_d() {
  local rc=0
  sudo -n ufw --force disable >/dev/null
  sudo -n ufw --force reset >/dev/null
  ufw_sums >"$WORK/ufw-before"
  AUTOSEC_CI_INJECT_FAILURE=ufw play d-inject -l "$HOST" -e autosec_ci_inject_ufw_fail=true || rc=$?
  if [ "$rc" -ne 0 ]; then pass d "the injected login failure fails the run (rc $rc)"; else fail d "the run succeeded"; fi
  expect d "ufw status after the undo" "$(sudo -n ufw status 2>/dev/null | head -n 1)" "Status: inactive"
  ufw_sums >"$WORK/ufw-after"
  if cmp -s "$WORK/ufw-before" "$WORK/ufw-after"; then
    pass d "ufw's four files byte-identical to before the run"
  else
    fail d "ufw's files differ: $(diff "$WORK/ufw-before" "$WORK/ufw-after" | grep '^[<>]' | tr '\n' ' ')"
  fi
  if sudo -n test -e "$PENDING"; then fail d "an undo is still pending"; else pass d "undo guard idle"; fi
}

setup
echo "== case u1"; case_u1
echo "== case u2"; case_u2
echo "== case u3"; case_u3
echo "== case a"; case_a
echo "== case b"; case_b
echo "== case c"; case_c
echo "== case d"; case_d
finish
