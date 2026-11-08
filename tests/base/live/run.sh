#!/usr/bin/env bash
# base-live: live tests of role 01 (apt updates, reboot, hostname, timezone,
# the admin account and its sudo rule) against the GitHub runner itself, with
# play.yml (preflight, package-guard preflight and role, the way site.yml
# runs them) over a local connection with sudo.
#
# GITHUB-HOSTED RUNNERS ONLY. It installs and purges unattended-upgrades,
# rewrites files in /etc/apt/apt.conf.d, changes the hostname and the
# timezone, opens a listener on port 25, runs unattended-upgrade for real,
# schedules (then cancels) a reboot, creates and deletes the accounts deploy
# and alice and writes files in /etc/sudoers.d. It refuses to start anywhere
# else.
#
# Ran green on GitHub's runners (0.5 and 0.6).
#
# Usage: bash tests/base/live/run.sh [--cases "LIST"]
#   --cases  a subset of: i a r d l e o s f u h t p k n (default: all, in
#            this order; every case starts from the canary-like baseline)
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
#   k  unattended-upgrades purged (auto): the run installs it again through
#      the package guard, with needrestart held back, or refuses because that
#      would upgrade an installed package; either way no installed package
#      changes or goes away. Removed with its configuration kept (dpkg rc)
#      and unattended_upgrades_enabled: true: refused (P1)
#   n  the account and its sudo rule (deploy_user_account): keep creates
#      nothing; create makes deploy (bash, no extra groups, password locked)
#      and /etc/sudoers.d/deploy (0440 root:root, header), sudo works for it,
#      a second run changes nothing; an existing account is never changed;
#      0.1-0.5's file stays; a file of yours, a rule of yours that names the
#      account, a sudoers without @includedir (a copy: the runner's own is not
#      touched) and UsePAM no (role 02's facts, given with -e) are refused
#      with nothing changed; --check writes nothing
# The inventory sets autosec_server: existing and, for the 0.5 cases,
# unattended_upgrades_enabled: auto.
# Logs: $RUNNER_TEMP/base-live/logs. Exit 0 = every check passed.

# shellcheck disable=SC2024 # unattended-upgrade output goes to logs owned by this user
set -u -o pipefail
export LC_ALL=C.UTF-8   # ansible needs a UTF-8 locale

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
SEM=$ROOT/tests/base/semantics
ALL_CASES="i a r d l e o s f u h t p k n"
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
for t in ansible-playbook sudo timedatectl hostnamectl busctl apt-config python3 sha256sum md5sum getent useradd userdel; do
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
# The runner image's own sudo files (as in tests/full-live/lib.sh): role
# 01 refuses (R01-A5) while `visudo -c` fails; a wrong mode or owner left
# by the image is fixed the way an operator would.
sudo_ready() {
  local out f
  out=$(sudo -n visudo -c 2>&1) && return 0
  echo "INFO  visudo -c on this runner: $(printf '%s\n' "$out" | grep -v 'parsed OK$' | head -n 5 | paste -sd' ' -)"
  printf '%s\n' "$out" | sed -n 's/^\(\/etc\/sudoers[^:]*\): bad permissions.*$/\1/p' | while IFS= read -r f; do
    sudo -n chmod 0440 -- "$f" && echo "INFO  chmod 0440 $f (runner image)"
  done
  printf '%s\n' "$out" | sed -n 's/^\(\/etc\/sudoers[^:]*\): wrong owner.*$/\1/p' | while IFS= read -r f; do
    sudo -n chown root:root -- "$f" && echo "INFO  chown root:root $f (runner image)"
  done
  out=$(sudo -n visudo -c 2>&1) \
    || die "visudo -c still fails on this runner: $(printf '%s\n' "$out" | grep -v 'parsed OK$' | head -n 5 | paste -sd' ' -)"
}
setup() {
  echo "== setup"
  for _ in 1 2 3; do sudo -n apt-get update -qq && break; sleep 10; done
  sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unattended-upgrades \
    || die "cannot install unattended-upgrades"
  sudo_ready
  ORIG_HOST=$(hostnamectl --static status)
  ORIG_TZ=$(timedatectl show -p Timezone --value)
  cat >"$INV" <<EOF
all:
  hosts:
    live:
      ansible_connection: local
      ansible_python_interpreter: /usr/bin/python3
      deploy_user: deploy
      autosec_server: existing
      unattended_upgrades_enabled: auto
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
  sudo -n env DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq unattended-upgrades >"$LOGS/k-purge.log" 2>&1 \
    || { fail k "cannot purge unattended-upgrades (log $LOGS/k-purge.log)"; return; }
  before=$(pkg_versions)
  play k -v || rc=$?
  changed=$(comm -23 <(printf '%s\n' "$before") <(pkg_versions) | paste -sd' ' -)
  expect k "installed packages whose version changed or that went away" "${changed:-none}" none
  if [ "$rc" -eq 0 ]; then
    expect k "unattended-upgrades installed again" "$(dpkg-query -W -f='${db:Status-Abbrev}' unattended-upgrades 2>/dev/null | cut -c1-2)" ii
    log_has k k '[N-P2] NOTE: installed on live for role 01 (base): unattended-upgrades' "N-P2"
    if [ -e /etc/apt/apt.conf.d/99needrestart ]; then
      log_has k k 'needrestart is suspended' "needrestart's apt hook was held back"
    else
      echo "      (needrestart is not installed on this runner)"
    fi
  else
    log_has k k 'would also change packages you have' "refused: installing it would upgrade an installed package"
  fi
  # Removed with its configuration kept (dpkg "rc"): auto_sec does not bring it back.
  sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unattended-upgrades >/dev/null 2>&1
  sudo -n env DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq unattended-upgrades >"$LOGS/k-remove.log" 2>&1 \
    || { fail k "cannot remove unattended-upgrades (log $LOGS/k-remove.log)"; return; }
  case_vars k "unattended_upgrades_enabled: true"
  rc=0
  play k-rc -e "@$WORK/k.yml" || rc=$?
  expect_refused k "$rc"
  log_has k k-rc '[P1] unattended-upgrades was removed on purpose' "P1"
  expect k "still removed" "$(dpkg-query -W -f='${db:Status-Abbrev}' unattended-upgrades 2>/dev/null | cut -c1-2)" rc
  sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unattended-upgrades >/dev/null 2>&1
}
case_n() {
  local rc=0 found before sha grp
  n_clean() {
    sudo -n userdel -r deploy >/dev/null 2>&1
    sudo -n userdel -r alice >/dev/null 2>&1
    sudo -n groupdel alice >/dev/null 2>&1
    sudo -n groupdel deploy >/dev/null 2>&1
    sudo -n rm -f /etc/sudoers.d/deploy /etc/sudoers.d/alice /etc/sudoers.d/50-autosec-test
  }
  n_clean
  # keep (the inventory's autosec_server: existing): nothing at all.
  play n-keep || rc=$?
  expect n "keep: run rc" "$rc" 0
  expect n "keep: no account deploy" "$(getent passwd deploy >/dev/null && echo yes || echo no)" no
  expect n "keep: no sudo file" "$(sudo -n test -e /etc/sudoers.d/deploy && echo yes || echo no)" no
  # --check with create: nothing is written.
  touch "$WORK/stamp-n"; sleep 1.2
  rc=0
  play n-check --check -e deploy_user_account=create || rc=$?
  expect n "--check: run rc" "$rc" 0
  found=$(sudo -n find /etc/passwd /etc/shadow /etc/group /etc/sudoers.d /home -maxdepth 1 -newer "$WORK/stamp-n" 2>/dev/null | paste -sd' ' -)
  expect n "--check: account files, sudoers.d and /home unchanged" "${found:-none}" none
  # create
  rc=0
  play n-create -e deploy_user_account=create || rc=$?
  expect n "create: run rc" "$rc" 0
  expect n "create: shell" "$(getent passwd deploy | cut -d: -f7)" /bin/bash
  expect n "create: no extra groups" "$(id -nG deploy 2>/dev/null)" deploy
  expect n "create: password locked (key login only)" "$(sudo -n getent shadow deploy | cut -d: -f2 | cut -c1)" '!'
  expect n "create: home" "$(sudo -n test -d /home/deploy && echo yes || echo no)" yes
  expect n "create: sudo file mode and owner" "$(sudo -n stat -c '%a %U:%G' /etc/sudoers.d/deploy 2>/dev/null)" "440 root:root"
  expect n "create: sudo file header" "$(sudo -n head -n 1 /etc/sudoers.d/deploy | cut -c1-31)" "# Written by auto_sec (role 01)"
  expect n "create: passwordless sudo for deploy" "$(sudo -n -u deploy sudo -n true >/dev/null 2>&1 && echo yes || echo no)" yes
  rc=0
  play n-create2 -e deploy_user_account=create || rc=$?
  expect n "create, second run: rc" "$rc" 0
  log_has n n-create2 'changed=0' "create, second run changes nothing"
  n_clean
  # An existing account is never changed (shell, groups, home).
  grp=adm
  if sudo -n grep -rqsE '%:?adm([[:space:],=]|$)' /etc/sudoers /etc/sudoers.d; then grp=users; fi
  sudo -n useradd -m -s /bin/sh -G "$grp" alice
  before=$(getent passwd alice; id alice)
  rc=0
  play n-alice -e deploy_user_account=create -e deploy_user=alice || rc=$?
  expect n "existing alice (/bin/sh, group $grp): run rc" "$rc" 0
  expect n "existing alice: getent and id unchanged" "$(getent passwd alice; id alice)" "$before"
  expect n "existing alice: gets the sudo file" "$(sudo -n test -f /etc/sudoers.d/alice && echo yes || echo no)" yes
  log_has n n-alice '[N01-A1] INFO: alice exists' "N01-A1"
  n_clean
  # 0.1-0.5's exact file stays.
  printf 'deploy ALL=(ALL) NOPASSWD:ALL\n' | sudo -n tee /etc/sudoers.d/deploy >/dev/null
  sudo -n chmod 0440 /etc/sudoers.d/deploy
  sha=$(sudo -n sha256sum /etc/sudoers.d/deploy)
  rc=0
  play n-legacy -e deploy_user_account=create || rc=$?
  expect n "0.1-0.5's file: run rc" "$rc" 0
  expect n "0.1-0.5's file: unchanged" "$(sudo -n sha256sum /etc/sudoers.d/deploy)" "$sha"
  log_has n n-legacy '[N01-A2]' "N01-A2"
  n_clean
  # A file of yours: refused, unchanged, no account.
  printf 'deploy ALL=(ALL) ALL\n' | sudo -n tee /etc/sudoers.d/deploy >/dev/null
  sudo -n chmod 0440 /etc/sudoers.d/deploy
  sha=$(sudo -n sha256sum /etc/sudoers.d/deploy)
  rc=0
  play n-foreign -e deploy_user_account=create || rc=$?
  expect_refused n "$rc"
  log_has n n-foreign '[R01-A2]' "R01-A2"
  expect n "your file: unchanged" "$(sudo -n sha256sum /etc/sudoers.d/deploy)" "$sha"
  expect n "your file: no account created" "$(getent passwd deploy >/dev/null && echo yes || echo no)" no
  n_clean
  # A rule of yours that names the account: refused.
  printf 'Defaults:deploy !lecture\n' | sudo -n tee /etc/sudoers.d/50-autosec-test >/dev/null
  sudo -n chmod 0440 /etc/sudoers.d/50-autosec-test
  rc=0
  play n-rule -e deploy_user_account=create || rc=$?
  expect_refused n "$rc"
  log_has n n-rule '[R01-A3]' "R01-A3"
  log_has n n-rule '/etc/sudoers.d/50-autosec-test:1' "the message names your file and line"
  expect n "a rule of yours: no account, no sudo file" \
    "$(getent passwd deploy >/dev/null && echo yes || echo no) $(sudo -n test -e /etc/sudoers.d/deploy && echo yes || echo no)" "no no"
  n_clean
  # A sudoers without @includedir (a copy; the runner's own is not touched).
  sudo -n sh -c "grep -v 'includedir' /etc/sudoers > '$WORK/sudoers-noinc'"
  rc=0
  play n-noinc -e deploy_user_account=create -e "_base_sudoers=$WORK/sudoers-noinc" || rc=$?
  expect_refused n "$rc"
  log_has n n-noinc '[R01-A4]' "R01-A4"
  n_clean
  # UsePAM no: a locked account could not log in with a key (role 02's facts).
  rc=0
  play n-pam -e deploy_user_account=create \
    -e '{"_ssh_role_runs": true, "_ssh_enabled": true, "_ssh_admin": "deploy", "_ssh_before": {"admin": {"usepam": "no"}}}' || rc=$?
  expect_refused n "$rc"
  log_has n n-pam '[R01-A7]' "R01-A7"
  expect n "UsePAM no: no account" "$(getent passwd deploy >/dev/null && echo yes || echo no)" no
  n_clean
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
