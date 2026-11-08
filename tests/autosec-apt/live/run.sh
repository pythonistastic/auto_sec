#!/usr/bin/env bash
# apt-guard-live: live tests of the shared package guard (roles/autosec-apt)
# against the GitHub runner itself, with play.yml (the guard's preflight,
# then an install, the way the roles use it) over a local connection with
# sudo.
#
# GITHUB-HOSTED RUNNERS ONLY. It installs needrestart and hello, and purges
# hello, python3-apt and unattended-upgrades. It refuses to start anywhere
# else.
#
# UNVERIFIED: this script has not run on a runner yet.
#
# Cases:
#   1  hello installed through the guard: apt's output says "needrestart is
#      suspended", the MainPID of ssh, cron and systemd-journald (those that
#      run) is unchanged, /run/needrestart/unpacked is left for the next apt
#      run, and a second run installs nothing (no apt run at all)
#   2  without python3-apt and unattended-upgrades (the apt module would
#      install python3-apt by itself): --check works and installs nothing,
#      a real run installs hello, and python3-apt stays absent
# Usage: bash tests/autosec-apt/live/run.sh
# Logs: $RUNNER_TEMP/apt-guard-live/logs. Exit 0 = every check passed.

# shellcheck disable=SC2024 # apt output goes to logs owned by this user
set -u -o pipefail
export LC_ALL=C.UTF-8   # ansible needs a UTF-8 locale

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
die() { echo "ERROR: $*" >&2; exit 2; }
if [ "${GITHUB_ACTIONS:-}" != true ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ]; then
  die "GitHub-hosted runners only: this installs and purges packages on the machine it runs on"
fi
for t in ansible-playbook sudo dpkg-query systemctl; do command -v "$t" >/dev/null 2>&1 || die "missing tool: $t"; done

WORK=${RUNNER_TEMP:-/tmp}/apt-guard-live
LOGS=$WORK/logs
INV=$WORK/inventory.yml
rm -rf "$WORK"
mkdir -p "$LOGS" || die "cannot create $WORK"

PASSES=0
FAILS=0
pass() { PASSES=$((PASSES + 1)); printf 'PASS  [%s] %s\n' "$1" "$2"; }
fail() { FAILS=$((FAILS + 1)); printf 'FAIL  [%s] %s\n' "$1" "$2"; }
expect() { # case what got want
  if [ "$3" = "$4" ]; then pass "$1" "$2: $3"; else fail "$1" "$2: got '$3', want '$4'"; fi
}
log_has() { # case log-name fixed-string what
  if grep -Fq -- "$3" "$LOGS/$2.log"; then pass "$1" "$4"; else fail "$1" "$4 (no '$3' in $2.log)"; fi
}
installed() { if dpkg-query -W -f='${db:Status-Abbrev}' "$1" 2>/dev/null | grep -q '^.i'; then echo yes; else echo no; fi; }
pids() { # MainPID of the services that run here
  local u
  for u in ssh.service cron.service systemd-journald.service; do
    if systemctl is-active --quiet "$u"; then printf '%s=%s\n' "$u" "$(systemctl show -p MainPID --value "$u")"; fi
  done
}
play() { # log-name ansible-playbook-args...: returns its rc
  local name=$1 rc=0
  shift
  (cd "$HERE" && ANSIBLE_ROLES_PATH="$ROOT/roles" ANSIBLE_NOCOLOR=1 ANSIBLE_LOCALHOST_WARNING=False \
    ansible-playbook -i "$INV" play.yml -e '{"_base_pkg_want": ["hello"]}' "$@") >"$LOGS/$name.log" 2>&1 || rc=$?
  echo "      ansible-playbook rc=$rc, log $LOGS/$name.log"
  if [ "$rc" != 0 ]; then
    grep -E 'fatal:|FAILED!|ERROR|msg|\[WARNING\]' "$LOGS/$name.log" | tail -n 12 | cut -c1-400 | sed 's/^/      | /'
  fi
  return "$rc"
}

echo "== setup"
for _ in 1 2 3; do sudo -n apt-get update -qq && break; sleep 10; done
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq needrestart >"$LOGS/setup.log" 2>&1 || die "cannot install needrestart"
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq hello >>"$LOGS/setup.log" 2>&1
cat >"$INV" <<EOF
all:
  hosts:
    live:
      ansible_connection: local
      ansible_python_interpreter: /usr/bin/python3
EOF

echo "== case 1: install hello with needrestart held back"
before=$(pids)
rc=0
play c1 -v || rc=$?
expect 1 "run rc" "$rc" 0
expect 1 "hello installed" "$(installed hello)" yes
log_has 1 c1 '[N-P1] INFO: packages this run installs on live' "N-P1 in the preflight"
log_has 1 c1 'needrestart is suspended' "apt's needrestart hook was held back"
log_has 1 c1 '[N-P2] NOTE: installed on live for apt-guard-live: hello' "N-P2"
expect 1 "MainPID of the running services unchanged" "$(pids)" "$before"
expect 1 "/run/needrestart/unpacked is left for the next apt run" "$(test -e /run/needrestart/unpacked && echo yes || echo no)" yes
rc=0
play c1-again || rc=$?
expect 1 "second run: rc" "$rc" 0
log_has 1 c1-again 'packages: nothing to install' "second run: nothing to install"
if grep -q 'Packages: refresh the package lists' "$LOGS/c1-again.log" && ! grep -A1 'Packages: refresh the package lists' "$LOGS/c1-again.log" | grep -q skipping; then
  fail 1 "second run: apt-get update ran although nothing was missing"
else
  pass 1 "second run: no apt run at all"
fi

echo "== case 2: no python3-apt, no unattended-upgrades"
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq hello python3-apt unattended-upgrades >"$LOGS/c2-purge.log" 2>&1 \
  || fail 2 "cannot purge (log $LOGS/c2-purge.log)"
expect 2 "python3-apt absent" "$(installed python3-apt)" no
rc=0
play c2-check --check || rc=$?
expect 2 "--check: rc" "$rc" 0
expect 2 "--check: hello not installed" "$(installed hello)" no
rc=0
play c2 || rc=$?
expect 2 "real run: rc" "$rc" 0
expect 2 "real run: hello installed" "$(installed hello)" yes
expect 2 "python3-apt still absent" "$(installed python3-apt)" no

echo "== cleanup"
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq hello >/dev/null 2>&1
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-apt unattended-upgrades >/dev/null 2>&1
echo
echo "$PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
