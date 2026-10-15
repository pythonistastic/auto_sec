#!/usr/bin/env bash
# base-live: live tests of role 01 (apt updates, reboot, hostname, timezone)
# against the GitHub runner itself, with play.yml (preflight + role, the way
# site.yml runs them) over a local connection with sudo.
#
# GITHUB-HOSTED RUNNERS ONLY. It installs unattended-upgrades, rewrites files
# in /etc/apt/apt.conf.d, changes the hostname and the timezone, opens a
# listener on port 25, runs unattended-upgrade for real and schedules (then
# cancels) a reboot. It refuses to start anywhere else.
#
# UNVERIFIED: this script has not run on a runner yet.
#
# Usage: bash tests/base/live/run.sh [--cases "LIST"]
#   --cases  a subset of: i a r d l e o s f u h t p k (default: all, in this
#            order; every case starts from the canary-like baseline)
# Cases:
#   i  --check changes nothing (find -newer)
#   a  defaults: no file in apt.conf.d is added or changed, the effective
#      update settings, hostname and timezone stay; a second run changes nothing
#   r  reboot true at now+3h: a real unattended-upgrade run (that installs
#      nothing) schedules exactly that reboot; with keep, nothing is scheduled
#   d  Docker excluded: unattended-upgrade --dry-run -d shows the blacklist
#   l  a 0.1-0.4 host: refused without -e apt_migrate_unattended_upgrades=true
#      (nothing changed); with it: backup (0600, same sha), distro file back,
#      ucf's md5
#   e  an edited 0.1-0.4 file is kept, with the reboot WARNING
#   o  your later file cancels a choice: refused, nothing changed
#   s  a broken apt file: refused, nothing changed
#   f  a foreign 51autosec-unattended-upgrades: refused, nothing changed
#   u  auto writes no switch, so the distro's off switch (20auto-upgrades "0",
#      as dpkg-reconfigure writes it) works after a run; auto then keeps them
#      off (WARNING), true turns them on, back to auto removes auto_sec's file
#   h  hostname: refused while port 25 listens; otherwise changed, /etc/hosts
#      untouched
#   t  timezone: offsets and pg-backup shown, changed; an unknown zone refused
#   p  apt_full_upgrade in --check changes no package
#   k  curl removed: the run installs it again or refuses because that would
#      upgrade an installed package; either way no installed package changes
# Logs: $RUNNER_TEMP/base-live/logs. Exit 0 = every check passed.

# shellcheck disable=SC2024 # unattended-upgrade output goes to logs owned by this user
set -u -o pipefail
export LC_ALL=C.UTF-8   # ansible needs a UTF-8 locale

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
SEM=$ROOT/tests/base/semantics
ALL_CASES="i a r d l e o s f u h t p k"
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
  die "GitHub-hosted runners only: this changes the apt configuration, hostname and timezone of the machine it runs on"
fi
for c in $CASES; do
  case " $ALL_CASES " in *" $c "*) ;; *) die "unknown case: $c" ;; esac
done
for t in ansible-playbook sudo timedatectl hostnamectl busctl apt-config python3 sha256sum md5sum; do
  command -v "$t" >/dev/null 2>&1 || die "missing tool: $t"
done

WORK=${RUNNER_TEMP:-/tmp}/base-live
LOGS=$WORK/logs
INV=$WORK/inventory.yml
PARTS=/etc/apt/apt.conf.d
OWN=$PARTS/51autosec-unattended-upgrades
DIST=$PARTS/50unattended-upgrades
PRISTINE=/usr/share/unattended-upgrades/50unattended-upgrades
BACKUP=/var/lib/auto-sec/backup/50unattended-upgrades.auto_sec-0.4
TEST_HOST=vmi-canary-test
TEST_TZ=Europe/Berlin
rm -rf "$WORK"
mkdir -p "$LOGS" || die "cannot create $WORK"

PASSES=0
FAILS=0
pass() { PASSES=$((PASSES + 1)); printf 'PASS  [%s] %s\n' "$1" "$2"; }
fail() { FAILS=$((FAILS + 1)); printf 'FAIL  [%s] %s\n' "$1" "$2"; }
expect() { # case what got want
  if [ "$3" = "$4" ]; then pass "$1" "$2: $3"; else fail "$1" "$2: got '$3', want '$4'"; fi
}
expect_refused() { # case rc
  if [ "$2" -ne 0 ]; then pass "$1" "run refused (rc $2)"; else fail "$1" "run succeeded, want a refusal"; fi
}
log_has() { # case log-name fixed-string what
  if grep -Fq -- "$3" "$LOGS/$2.log"; then pass "$1" "$4"; else fail "$1" "$4 (no '$3' in $2.log)"; fi
}

# --- host probes ----------------------------------------------------------------
managed() { # the effective update keys, as role 01 compares them
  apt-config dump | grep -E '^(APT::Periodic::(Enable|Unattended-Upgrade|Update-Package-Lists)|Unattended-Upgrade::[^ ]+) ' | sort
}
uu_now() { apt-config dump | sed -n 's/^APT::Periodic::Unattended-Upgrade "\(.*\)";$/\1/p' | tail -n 1; }
own_file() { if [ -e "$OWN" ]; then echo present; else echo absent; fi; }
pkg_versions() { dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version}\n' | awk '$1 ~ /^.i/ { print $2, $3 }' | sort; }
parts_state() { sudo -n sh -c 'cd /etc/apt/apt.conf.d && sha256sum -- * 2>/dev/null' | sort; }
host_state() { printf '%s %s\n' "$(hostnamectl --static status)" "$(timedatectl show -p Timezone --value)"; }
scheduled() { # "reboot <usec>" or "none"
  local s
  s=$(busctl get-property org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager ScheduledShutdown 2>/dev/null)
  # Nothing scheduled: an empty type. systemd 249 reports ("", 0),
  # systemd 255 ("", 18446744073709551615).
  case $s in '(st) ""'*|'') echo none ;; *) echo "$s" | awk '{ gsub(/"/, "", $2); print $2, $3 }' ;; esac
}
play() { # log-name ansible-playbook-args...: returns its rc
  local name=$1 rc=0
  shift
  (cd "$HERE" && ANSIBLE_ROLES_PATH="$ROOT/roles" ANSIBLE_NOCOLOR=1 ANSIBLE_LOCALHOST_WARNING=False \
    ansible-playbook -i "$INV" play.yml "$@") >"$LOGS/$name.log" 2>&1 || rc=$?
  echo "      ansible-playbook rc=$rc, log $LOGS/$name.log"
  if [ "$rc" != 0 ]; then
    grep -E 'fatal:|FAILED!|ERROR|msg|\[WARNING\]' "$LOGS/$name.log" | tail -n 12 | cut -c1-400 | sed 's/^/      | /'
  fi
  return "$rc"
}

# --- setup and baseline -----------------------------------------------------------
setup() {
  echo "== setup"
  for _ in 1 2 3; do sudo -n apt-get update -qq && break; sleep 10; done
  sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unattended-upgrades \
    || die "cannot install unattended-upgrades"
  ORIG_HOST=$(hostnamectl --static status)
  ORIG_TZ=$(timedatectl show -p Timezone --value)
  cat >"$INV" <<EOF
all:
  hosts:
    live:
      ansible_connection: local
      ansible_python_interpreter: /usr/bin/python3
      deploy_user: deploy
EOF
}
baseline() { # the canary's state: stock files, 10periodic, a pending reboot, local time
  sudo -n rm -f "$OWN" "$PARTS/52unattended-upgrades-local" "$PARTS/60broken" "$PARTS/99autosec-test"
  sudo -n install -m 0644 "$PRISTINE" "$DIST"
  sudo -n install -m 0644 /usr/share/unattended-upgrades/20auto-upgrades "$PARTS/20auto-upgrades"
  sudo -n install -m 0644 "$SEM/fixtures/canary-10periodic" "$PARTS/10periodic"
  sudo -n rm -rf /var/lib/auto-sec/backup
  printf 'linux-image-autosec-test\n' | sudo -n tee /var/run/reboot-required.pkgs >/dev/null
  sudo -n touch /var/run/reboot-required
  printf '17 3 * * * root /bin/true # pg-backup test job\n' | sudo -n tee /etc/cron.d/pg-backup >/dev/null
  sudo -n hostnamectl set-hostname "$TEST_HOST"
  sudo -n timedatectl set-timezone "$TEST_TZ"
  sudo -n shutdown -c >/dev/null 2>&1
  BASE_MANAGED=$(managed)
  BASE_PARTS=$(parts_state)
  BASE_HOST=$(host_state)
}
case_vars() { # name yaml-lines: write an -e file
  local name=$1
  shift
  printf '%s\n' '---' "$@" >"$WORK/$name.yml"
}
unchanged() { # case
  expect "$1" "apt.conf.d unchanged" "$(parts_state | sha256sum | cut -c1-16)" "$(printf '%s\n' "$BASE_PARTS" | sha256sum | cut -c1-16)"
  expect "$1" "hostname and timezone unchanged" "$(host_state)" "$BASE_HOST"
}

# --- cases ---------------------------------------------------------------------------
case_i() {
  local rc=0 found
  touch "$WORK/stamp"; sleep 1.2
  play i-check --check || rc=$?
  expect i "--check: run rc" "$rc" 0
  found=$(sudo -n find /etc /var/lib/auto-sec -xdev -newer "$WORK/stamp" 2>/dev/null | paste -sd' ' -)
  expect i "--check: paths changed under /etc and /var/lib/auto-sec" "${found:-none}" none
}
case_a() {
  local rc=0 new
  play a-first || rc=$?
  expect a "defaults: run rc" "$rc" 0
  new=$(comm -13 <(printf '%s\n' "$BASE_PARTS" | sort) <(parts_state | sort) | awk '{print $2}' | paste -sd' ' -)
  expect a "files added or changed in apt.conf.d" "${new:-none}" none
  expect a "effective update settings unchanged" "$(managed | sha256sum | cut -c1-16)" "$(printf '%s\n' "$BASE_MANAGED" | sha256sum | cut -c1-16)"
  expect a "hostname and timezone unchanged" "$(host_state)" "$BASE_HOST"
  log_has a a-first '"keys_that_change": "no change"' "summary: no change"
  log_has a a-first 'a reboot is pending' "pending reboot noted"
  rc=0
  play a-second || rc=$?
  expect a "second run: rc" "$rc" 0
  log_has a a-second 'changed=0' "second run changes nothing"
  expect a "no reboot scheduled" "$(scheduled)" none
}
case_r() {
  local rc=0 t want got
  t=$(TZ=$TEST_TZ date -d '+3 hours' +%H:%M)
  case_vars r "unattended_automatic_reboot: true" "unattended_reboot_time: \"$t\""
  play r-on -e "@$WORK/r.yml" || rc=$?
  expect r "reboot at $t: run rc" "$rc" 0
  # A real unattended-upgrade run that may install nothing at all.
  printf '%s\n' 'Unattended-Upgrade::Package-Whitelist-Strict "true";' \
    'Unattended-Upgrade::Package-Whitelist { "autosec-no-such-package"; };' \
    | sudo -n tee "$PARTS/99autosec-test" >/dev/null
  sudo -n unattended-upgrade -v >"$LOGS/r-uu.log" 2>&1
  got=$(scheduled)
  want=$(TZ=$TEST_TZ date -d "$t" +%s 2>/dev/null)
  [ "$want" -le "$(date +%s)" ] && want=$((want + 86400))
  [ "$got" != none ] && got="${got%% *} $(( ${got##* } / 1000000 ))"
  expect r "reboot scheduled by unattended-upgrade" "$got" "reboot $want"
  sudo -n shutdown -c >/dev/null 2>&1
  expect r "reboot cancelled again" "$(scheduled)" none
  # keep: the stock setting (off) stays, nothing is scheduled.
  baseline
  printf '%s\n' 'Unattended-Upgrade::Package-Whitelist-Strict "true";' \
    'Unattended-Upgrade::Package-Whitelist { "autosec-no-such-package"; };' \
    | sudo -n tee "$PARTS/99autosec-test" >/dev/null
  rc=0
  play r-keep || rc=$?
  expect r "keep: run rc" "$rc" 0
  sudo -n unattended-upgrade -v >"$LOGS/r-uu-keep.log" 2>&1
  expect r "keep: no reboot scheduled" "$(scheduled)" none
}
case_d() {
  local rc=0
  case_vars d "unattended_exclude_docker: true"
  play d -e "@$WORK/d.yml" || rc=$?
  expect d "Docker excluded: run rc" "$rc" 0
  sudo -n unattended-upgrade --dry-run -d >"$LOGS/d-uu.log" 2>&1
  log_has d d-uu 'containerd\.io$' "unattended-upgrade reads the Docker blacklist"
}
case_l() {
  local rc=0
  sudo -n install -m 0644 "$SEM/fixtures/legacy-50unattended-upgrades" "$DIST"
  BASE_PARTS=$(parts_state)
  play l-noswitch || rc=$?
  expect_refused l "$rc"
  log_has l l-noswitch 'apt_migrate_unattended_upgrades=true' "the refusal names the switch"
  log_has l l-noswitch 'Unattended-Upgrade::Automatic-Reboot: true -> (unset)' "the refusal lists the reboot change"
  unchanged l
  rc=0
  play l -e apt_migrate_unattended_upgrades=true || rc=$?
  expect l "0.1-0.4 host, with the switch: run rc" "$rc" 0
  expect l "backup sha256" "$(sudo -n sha256sum "$BACKUP" | cut -d' ' -f1)" "$(sha256sum "$SEM/fixtures/legacy-50unattended-upgrades" | cut -d' ' -f1)"
  expect l "backup mode" "$(sudo -n stat -c %a "$BACKUP")" 600
  expect l "50unattended-upgrades is the distro file" "$(md5sum <"$DIST" | cut -d' ' -f1)" "$(md5sum <"$PRISTINE" | cut -d' ' -f1)"
  expect l "ucf records that md5" "$(awk -v p="$DIST" '$2 == p { print $1 }' /var/lib/ucf/hashfile)" "$(md5sum <"$DIST" | cut -d' ' -f1)"
  expect l "automatic reboot after the run" "$(apt-config dump | grep -c '^Unattended-Upgrade::Automatic-Reboot "true"')" 0
}
case_e() {
  local rc=0
  { cat "$SEM/fixtures/legacy-50unattended-upgrades"; echo '// edited by hand'; } | sudo -n tee "$DIST" >/dev/null
  local before
  before=$(sha256sum <"$DIST")
  play e || rc=$?
  expect e "edited 0.1-0.4 file: run rc" "$rc" 0
  expect e "the edited file is kept" "$(sha256sum <"$DIST")" "$before"
  log_has e e 'WARNING: automatic reboots are ON' "reboot WARNING"
}
case_o() {
  local rc=0
  printf 'Unattended-Upgrade::Automatic-Reboot "true";\n' | sudo -n tee "$PARTS/52unattended-upgrades-local" >/dev/null
  BASE_PARTS=$(parts_state)
  case_vars o "unattended_automatic_reboot: false"
  play o -e "@$WORK/o.yml" || rc=$?
  expect_refused o "$rc"
  log_has o o '52unattended-upgrades-local 1:Unattended-Upgrade::Automatic-Reboot' "the message names your line"
  unchanged o
}
case_s() {
  local rc=0
  printf 'Foo::Bar "x" junk;\n' | sudo -n tee "$PARTS/60broken" >/dev/null
  BASE_PARTS=$(parts_state)
  play s || rc=$?
  expect_refused s "$rc"
  log_has s s 'apt cannot read its configuration' "the message"
  unchanged s
  sudo -n rm -f "$PARTS/60broken"
}
case_f() {
  local rc=0
  printf 'APT::Periodic::Unattended-Upgrade "1";\n' | sudo -n tee "$OWN" >/dev/null
  BASE_PARTS=$(parts_state)
  play f || rc=$?
  expect_refused f "$rc"
  log_has f f 'auto_sec never replaces a file it did not write' "the message"
  unchanged f
}
case_u() {
  local rc=0
  # auto on a host whose updates are on: auto_sec writes no switch ...
  play u-on || rc=$?
  expect u "auto, updates on: run rc" "$rc" 0
  expect u "auto, updates on: auto_sec's apt file" "$(own_file)" absent
  # ... so the distro's off switch works afterwards (dpkg-reconfigure's
  # postinst puts this file in place when you answer No).
  sudo -n install -m 0644 /usr/share/unattended-upgrades/20auto-upgrades-disabled "$PARTS/20auto-upgrades"
  expect u "the distro's off switch after a run" "$(uu_now)" 0
  rc=0
  play u-auto || rc=$?
  expect u "off on purpose, auto: run rc" "$rc" 0
  log_has u u-auto 'WARNING: automatic updates are OFF' "WARNING"
  expect u "auto: Unattended-Upgrade stays" "$(uu_now)" 0
  case_vars u "unattended_upgrades_enabled: true"
  rc=0
  play u-true -e "@$WORK/u.yml" || rc=$?
  expect u "true: run rc" "$rc" 0
  expect u "true: Unattended-Upgrade" "$(uu_now)" 1
  # Back to auto: auto_sec's file goes, the distro's "0" counts again.
  rc=0
  play u-back || rc=$?
  expect u "back to auto: run rc" "$rc" 0
  expect u "back to auto: auto_sec's apt file" "$(own_file)" absent
  expect u "back to auto: Unattended-Upgrade" "$(uu_now)" 0
  log_has u u-back 'WARNING: automatic updates are OFF' "WARNING again"
}
case_h() {
  local rc=0 pid hosts_before
  hosts_before=$(sha256sum </etc/hosts)
  sudo -n python3 -m http.server 25 --bind 127.0.0.1 >/dev/null 2>&1 &
  pid=$!
  sleep 2
  case_vars h "server_hostname: autosec-renamed"
  play h-mta -e "@$WORK/h.yml" || rc=$?
  expect_refused h "$rc"
  log_has h h-mta 'something listens on' "mail server refusal"
  expect h "hostname unchanged while port 25 listens" "$(hostnamectl --static status)" "$TEST_HOST"
  sudo -n pkill -f 'http.server 25' ; wait "$pid" 2>/dev/null
  rc=0
  play h -e "@$WORK/h.yml" || rc=$?
  expect h "rename: run rc" "$rc" 0
  expect h "hostname" "$(hostnamectl --static status)" autosec-renamed
  expect h "/etc/hosts untouched" "$(sha256sum </etc/hosts)" "$hosts_before"
}
case_t() {
  local rc=0
  case_vars t "timezone: UTC"
  play t -e "@$WORK/t.yml" || rc=$?
  expect t "UTC: run rc" "$rc" 0
  log_has t t "changes from $TEST_TZ" "offset note"
  log_has t t "pg-backup" "cron job listed"
  expect t "timezone" "$(timedatectl show -p Timezone --value)" UTC
  case_vars t2 "timezone: Mars/Olympus_Mons"
  rc=0
  play t-bad -e "@$WORK/t2.yml" || rc=$?
  expect_refused t "$rc"
  log_has t t-bad 'does not know that' "unknown zone refused"
}
case_p() {
  local rc=0 before
  before=$(dpkg -l | sha256sum)
  play p --check -e apt_full_upgrade=true || rc=$?
  expect p "full upgrade in --check: run rc" "$rc" 0
  log_has p p 'apt_full_upgrade is on' "INFO line"
  expect p "no package changed" "$(dpkg -l | sha256sum)" "$before"
}
case_k() {
  local rc=0 before changed
  sudo -n env DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq curl >"$LOGS/k-remove.log" 2>&1 \
    || { fail k "cannot remove curl (log $LOGS/k-remove.log)"; return; }
  before=$(pkg_versions)
  play k || rc=$?
  changed=$(comm -23 <(printf '%s\n' "$before") <(pkg_versions) | paste -sd' ' -)
  expect k "installed packages whose version changed or that went away" "${changed:-none}" none
  if [ "$rc" -eq 0 ]; then
    expect k "curl installed again" "$(dpkg-query -W -f='${db:Status-Abbrev}' curl 2>/dev/null | cut -c1-2)" ii
  else
    log_has k k 'would also change packages you have' "refused: installing curl would upgrade an installed package"
  fi
  sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl >/dev/null 2>&1
}

setup
for c in $CASES; do
  echo "== case $c"
  baseline
  "case_$c"
done
echo "== restore the runner's hostname and timezone"
sudo -n rm -f "$PARTS/99autosec-test" "$PARTS/52unattended-upgrades-local" /etc/cron.d/pg-backup
sudo -n hostnamectl set-hostname "$ORIG_HOST"
sudo -n timedatectl set-timezone "$ORIG_TZ"
sudo -n shutdown -c >/dev/null 2>&1
echo
echo "$PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
