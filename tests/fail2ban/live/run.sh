#!/usr/bin/env bash
# fail2ban live tests (role 03, issue #2) against the GitHub runner itself:
# ansible-playbook site.yml --tags fail2ban in local mode (become: sudo),
# then checks of fail2ban's files, its running jails and bans, its main
# process and its firewall set.
#
# GITHUB-HOSTED RUNNERS ONLY. It installs, purges and reconfigures fail2ban
# and writes /etc/fail2ban. It refuses to start anywhere else.
# Needs site.yml to import role 03's preflight in pre_tasks (import_role
# name=03-firewall tasks_from=preflight, tags always).
#
# Usage: bash tests/fail2ban/live/run.sh [--cases "LIST"]
#   --cases  a subset of: c7 c1 c2 c6 c3 c5 c9 c4 c8 (always run in this
#            order; c2 and c6 need c1). Default: all.
# Cases:
#   c7  --check with fail2ban purged: rc 0, "not installed yet", nothing new in /etc
#   c1  the canary's layout (fixtures/canary.jail.local) with live bans: rc 0,
#       jail.local byte-identical, 00-autosec.conf written, `fail2ban-client -d`
#       identical, same main PID, same bans and firewall set, no reload
#   c2  second run: nothing changed, no reload
#   c6  office_static_ip next to the canary's own ignoreip: WARNING, rc 0
#   c3  no jail.local: sshd maxretry becomes 4 by a reload, the ban stays, same PID
#   c5  a recidive jail without own values: refused (R3), nothing changed
#   c9  a config that no longer loads: refused (R1) with fail2ban's error
#   c4  auto_sec 0.3's jail.local: refused (R4) without the switch; with
#       -e fail2ban_migrate_jail_local=true moved to a 0600 backup, nginx jails
#       gone, sshd values as in 0.3, the ban stays
#   c8  fail2ban installed but disabled and stopped: file written, NOTE, not started
# Logs: $RUNNER_TEMP/fail2ban-live/logs. Exit 0 = every check passed.
set -u -o pipefail
export LC_ALL=C.UTF-8   # ansible needs a UTF-8 locale

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
FIX=$ROOT/tests/fail2ban/semantics/fixtures
ALL_CASES="c7 c1 c2 c6 c3 c5 c9 c4 c8"
CASES=$ALL_CASES

die() { echo "ERROR: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case $1 in
    --cases) [ $# -ge 2 ] || die "--cases needs a list"; CASES=$2; shift 2 ;;
    -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
if [ "${GITHUB_ACTIONS:-}" != true ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ]; then
  die "GitHub-hosted runners only: this installs and reconfigures fail2ban on the machine it runs on"
fi
for c in $CASES; do
  case " $ALL_CASES " in *" $c "*) ;; *) die "unknown case: $c" ;; esac
done
for t in ansible-playbook sudo sha256sum; do
  command -v "$t" >/dev/null 2>&1 || die "missing tool: $t"
done
if ! awk '/name: 03-firewall/ { f = 1; next } f && /tasks_from: preflight/ { ok = 1 } { f = 0 } END { exit !ok }' \
     "$ROOT/site.yml"; then
  die "site.yml does not import role 03's preflight (import_role name=03-firewall tasks_from=preflight)"
fi

WORK=${RUNNER_TEMP:-/tmp}/fail2ban-live
LOGS=$WORK/logs
INV=$WORK/inventory.yml
F2B=/etc/fail2ban
OWN=$F2B/jail.d/00-autosec.conf
MARKER='# Written by auto_sec (role 03). Do not edit: the next run replaces this file.'
rm -rf "$WORK"
mkdir -p "$LOGS" || die "cannot create $WORK"

PASSES=0
FAILS=0
pass() { PASSES=$((PASSES + 1)); printf 'PASS  [%s] %s\n' "$1" "$2"; }
fail() { FAILS=$((FAILS + 1)); printf 'FAIL  [%s] %s\n' "$1" "$2"; }
expect() { # case what got want
  if [ "$3" = "$4" ]; then pass "$1" "$2: $3"; else fail "$1" "$2: got '$3', want '$4'"; fi
}
expect_refused() { # case rc what
  if [ "$2" -ne 0 ]; then pass "$1" "$3"; else fail "$1" "run succeeded, want a refusal"; fi
}
log_has() { # case log-name fixed-string what
  if grep -Fq -- "$3" "$LOGS/$2.log"; then pass "$1" "$4"; else fail "$1" "$4 (no '$3' in $2.log)"; fi
}
log_lacks() { # case log-name fixed-string what
  if grep -Fq -- "$3" "$LOGS/$2.log"; then fail "$1" "$4 ('$3' in $2.log)"; else pass "$1" "$4"; fi
}
play() { # log-name ansible-playbook-args...: site.yml --tags fail2ban; returns its rc
  local name=$1 rc=0
  shift
  (cd "$ROOT" && ANSIBLE_NOCOLOR=1 ansible-playbook -i "$INV" site.yml -l live --tags fail2ban "$@") \
    >"$LOGS/$name.log" 2>&1 || rc=$?
  echo "      ansible-playbook rc=$rc, log $LOGS/$name.log"
  if [ "$rc" != 0 ]; then
    grep -E 'fatal:|FAILED!|ERROR|msg|\[WARNING\]' "$LOGS/$name.log" | tail -n 12 | cut -c1-400 | sed 's/^/      | /'
  fi
  return "$rc"
}

# --- host probes ----------------------------------------------------------------
f2b() { sudo -n fail2ban-client "$@"; }
sum_of() { local s; s=$(sudo -n sha256sum "$1" 2>/dev/null) || { echo absent; return; }; echo "${s%% *}"; }
mainpid() { systemctl show -p MainPID --value fail2ban.service; }
banned() { f2b status "$1" 2>/dev/null | sed -n 's/.*Banned IP list:[[:space:]]*//p' | tr ' ' '\n' | sort | paste -sd' ' -; }
jails() { f2b status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr -d ' ' | tr ',' '\n' | sort | paste -sd' ' -; }
dump_sum() { sudo -n fail2ban-client -d 2>/dev/null | sha256sum | cut -d' ' -f1; }
fw_sum() { # the firewall sets fail2ban fills (nftables on 24.04, iptables on 22.04)
  { sudo -n nft list table inet f2b-table 2>/dev/null; sudo -n iptables-save 2>/dev/null | grep -i f2b; } \
    | grep -v '^#' | sha256sum | cut -d' ' -f1
}
logpos() { sudo -n stat -c %s /var/log/fail2ban.log 2>/dev/null || echo 0; }
new_log() { sudo -n tail -c "+$(($1 + 1))" /var/log/fail2ban.log 2>/dev/null; }
wait_f2b() {
  for _ in $(seq 60); do f2b ping >/dev/null 2>&1 && return 0; sleep 1; done
  die "fail2ban did not answer ping"
}
restart_f2b() { sudo -n systemctl restart fail2ban.service && wait_f2b && sleep 2; }
layout() { # jail.local-file|none: a clean /etc/fail2ban with that jail.local, fail2ban restarted
  sudo -n rm -f "$OWN" "$F2B/jail.d/00-autosec-nginx.conf" "$F2B/jail.d/zz-"*.local "$F2B/jail.local"
  [ "$1" = none ] || sudo -n install -m 0644 "$1" "$F2B/jail.local"
  restart_f2b
}
ban() { f2b set sshd banip 203.0.113.5 >/dev/null; f2b set recidive banip 198.51.100.7 >/dev/null 2>&1; sleep 1; }

snapshot() { # name: jail.local, own file, dump, PID, bans, firewall, log position
  printf '%s\n' "$(sum_of "$F2B/jail.local")" "$(sum_of "$OWN")" "$(dump_sum)" "$(mainpid)" \
    "$(jails)" "$(banned sshd)" "$(banned recidive)" "$(fw_sum)" >"$WORK/$1.snap"
}
LOGPOS=0
mark() { LOGPOS=$(logpos); }  # fail2ban.log size before a run
snap_line() { sed -n "${2}p" "$WORK/$1.snap"; }

# --- setup ------------------------------------------------------------------------
setup() {
  echo "== setup"
  for _ in 1 2 3; do sudo -n apt-get update -qq && break; sleep 10; done
  # Role 02's preflight (always) checks that sshd listens on ssh_port when
  # sshd is installed; make sure it does.
  if [ -x /usr/sbin/sshd ]; then
    sudo -n systemctl start ssh.service >/dev/null 2>&1 || sudo -n systemctl start ssh.socket >/dev/null 2>&1
  fi
  sudo -n install -d -m 0755 /var/log/nginx
  sudo -n touch /var/log/nginx/error.log /var/log/nginx/access.log
  id deploy >/dev/null 2>&1 || sudo -n useradd -m -s /bin/bash deploy || die "useradd deploy"
  cat >"$INV" <<EOF
all:
  hosts:
    live:
      ansible_connection: local
      ansible_python_interpreter: /usr/bin/python3
      deploy_user: deploy
      ssh_hardening_enabled: false
      ssh_port: 22
      paranoia_level: standard
      office_static_ip: ""
EOF
  # The canary's jail.local with the runner's log paths (they are the same).
  cp "$FIX/canary.jail.local" "$WORK/canary.jail.local"
  # fail2ban 0.11 (Ubuntu 22.04) has no nginx-bad-request filter (it came
  # with 1.0), so there the canary's file is broken and auto_sec rightly
  # refuses. Drop that one jail on such runners; the canary runs 1.0.2.
  if [ ! -e "$F2B/filter.d/nginx-bad-request.conf" ]; then
    echo "      note: no filter.d/nginx-bad-request.conf on this fail2ban; testing the canary layout without that jail"
    awk '/^\[/ { skip = ($0 == "[nginx-bad-request]") } !skip' "$FIX/canary.jail.local" >"$WORK/canary.jail.local"
  fi
  printf '[recidive]\nenabled = true\nlogpath = /var/log/fail2ban.log\n' >"$WORK/leak.jail.local"
}

install_f2b() {
  sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban >/dev/null || die "apt-get install fail2ban"
  sudo -n systemctl enable --now fail2ban.service >/dev/null 2>&1
  wait_f2b
}

# --- cases --------------------------------------------------------------------------
case_c7() {
  local rc=0 found
  sudo -n env DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq fail2ban >/dev/null 2>&1
  sudo -n rm -rf "$F2B"
  touch "$WORK/stamp"
  sleep 1.2
  play c7 --check || rc=$?
  expect c7 "--check without fail2ban: rc" "$rc" 0
  log_has c7 c7 "fail2ban is not installed on live yet" "says fail2ban is not installed yet"
  found=$(sudo -n find /etc /var/lib/auto-sec -xdev -newer "$WORK/stamp" 2>/dev/null | paste -sd' ' -)
  expect c7 "paths changed under /etc and /var/lib/auto-sec" "${found:-none}" none
  install_f2b
}

case_c1() {
  local rc=0
  layout "$WORK/canary.jail.local"
  ban
  snapshot c1-before
  mark
  play c1 || rc=$?
  snapshot c1-after
  expect c1 "run rc" "$rc" 0
  expect c1 "jail.local byte-identical" "$(snap_line c1-after 1)" "$(snap_line c1-before 1)"
  expect c1 "00-autosec.conf line 1" "$(sudo -n head -n 1 "$OWN" 2>/dev/null)" "$MARKER"
  expect c1 "fail2ban-client -d identical" "$(snap_line c1-after 3)" "$(snap_line c1-before 3)"
  expect c1 "main PID" "$(snap_line c1-after 4)" "$(snap_line c1-before 4)"
  expect c1 "jails" "$(snap_line c1-after 5)" "$(snap_line c1-before 5)"
  expect c1 "sshd bans" "$(snap_line c1-after 6)" "203.0.113.5"
  expect c1 "recidive bans" "$(snap_line c1-after 7)" "198.51.100.7"
  expect c1 "firewall set" "$(snap_line c1-after 8)" "$(snap_line c1-before 8)"
  log_has c1 c1 "no effective change, no reload" "plan: no effective change"
  if new_log "$LOGPOS" | grep -q 'Reload'; then fail c1 "fail2ban was reloaded"; else pass c1 "no reload in fail2ban.log"; fi
}

case_c2() {
  local rc=0
  mark
  play c2 || rc=$?
  expect c2 "run rc" "$rc" 0
  log_has c2 c2 "changed=0" "nothing changed"
  if new_log "$LOGPOS" | grep -q 'Reload'; then fail c2 "fail2ban was reloaded"; else pass c2 "no reload"; fi
}

case_c6() {
  local rc=0
  play c6 -e office_static_ip=203.0.113.7 || rc=$?
  expect c6 "run rc" "$rc" 0
  log_has c6 c6 "WARNING: 203.0.113.7" "W1: your ignoreip hides office_static_ip"
}

case_c3() {
  local rc=0
  layout none
  ban
  snapshot c3-before
  mark
  play c3 || rc=$?
  expect c3 "run rc" "$rc" 0
  expect c3 "sshd maxretry" "$(f2b get sshd maxretry)" 4
  expect c3 "sshd ban kept" "$(banned sshd)" "203.0.113.5"
  expect c3 "main PID" "$(mainpid)" "$(snap_line c3-before 4)"
  if new_log "$LOGPOS" | grep -q 'Reload finished'; then pass c3 "reloaded"; else fail c3 "no reload"; fi
}

case_c5() {
  local rc=0
  layout "$WORK/leak.jail.local"
  snapshot c5-before
  play c5 || rc=$?
  expect_refused c5 "$rc" "refused (rc $rc)"
  log_has c5 c5 "would change jails of yours" "R3 message"
  expect c5 "00-autosec.conf" "$(sum_of "$OWN")" absent
  log_lacks c5 c5 "TASK [03-firewall : fail2ban F1" "stopped in the preflight"
}

case_c9() {
  local rc=0
  layout "$WORK/canary.jail.local"
  # (%(known/ignoreip)s would load here: the canary's [DEFAULT] sets ignoreip.)
  printf '[sshd]\nfindtime = %%(autosec_no_such_option)s\n' >"$WORK/broken.local"
  sudo -n install -m 0644 "$WORK/broken.local" "$F2B/jail.d/zz-broken.local"
  play c9 || rc=$?
  expect_refused c9 "$rc" "refused (rc $rc)"
  log_has c9 c9 "does not load" "R1 message"
  log_has c9 c9 "autosec_no_such_option" "fail2ban's own error is shown"
  expect c9 "00-autosec.conf" "$(sum_of "$OWN")" absent
  sudo -n rm -f "$F2B/jail.d/zz-broken.local"
}

case_c4() {
  local rc=0 bk mode
  layout "$FIX/legacy-0.3.jail.local"
  ban
  snapshot c4-before
  play c4-refused || rc=$?
  expect_refused c4 "$rc" "refused without the switch (rc $rc)"
  log_has c4 c4-refused "fail2ban_migrate_jail_local=true" "R4 says how to migrate"
  expect c4 "jail.local unchanged" "$(sum_of "$F2B/jail.local")" "$(snap_line c4-before 1)"
  rc=0
  # The 0.3 fixture was rendered for ssh_port 2222; the runner's sshd is on 22,
  # so the jail's port changes and the sshd jail is restarted.
  play c4-migrate -e fail2ban_migrate_jail_local=true || rc=$?
  expect c4 "migrate rc" "$rc" 0
  expect c4 "jail.local" "$(sum_of "$F2B/jail.local")" absent
  bk=$(sudo -n sh -c 'ls /var/lib/auto-sec/fail2ban/jail.local.auto_sec-0.x.* 2>/dev/null' | tail -n 1)
  mode=$(sudo -n stat -c %a "$bk" 2>/dev/null)
  expect c4 "backup mode" "$mode" 600
  expect c4 "backup identical" "$(sum_of "$bk")" "$(snap_line c4-before 1)"
  expect c4 "jails after" "$(jails)" sshd
  expect c4 "sshd maxretry/findtime/bantime" "$(f2b get sshd maxretry)/$(f2b get sshd findtime)/$(f2b get sshd bantime)" "4/600/3600"
  expect c4 "sshd ban kept" "$(banned sshd)" "203.0.113.5"
}

case_c8() {
  local rc=0
  layout none
  sudo -n systemctl disable --now fail2ban.service >/dev/null 2>&1
  sudo -n rm -f "$OWN"
  play c8 || rc=$?
  expect c8 "run rc" "$rc" 0
  expect c8 "00-autosec.conf line 1" "$(sudo -n head -n 1 "$OWN" 2>/dev/null)" "$MARKER"
  log_has c8 c8 "never starts, stops or enables a fail2ban that was already" "NOTE (W4)"
  expect c8 "fail2ban.service active" "$(systemctl is-active fail2ban.service)" inactive
  expect c8 "fail2ban.service enabled" "$(systemctl is-enabled fail2ban.service 2>/dev/null)" disabled
  sudo -n systemctl enable --now fail2ban.service >/dev/null 2>&1
}

setup
command -v fail2ban-client >/dev/null 2>&1 || install_f2b
for c in $ALL_CASES; do
  case " $CASES " in *" $c "*) ;; *) continue ;; esac
  echo "== case $c"
  "case_$c"
done
echo
echo "$PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
