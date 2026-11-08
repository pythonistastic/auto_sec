#!/usr/bin/env bash
# autosec-apt-semantics: unprivileged tests of the shared package guard
# (roles/autosec-apt, auto_sec 0.6). No root and nothing installed: fake
# dpkg-query, apt-get and systemctl come first in PATH. apt-get prints real
# `apt-get -s` output (fixtures/pkg-*.txt, apt 2.7, Ubuntu 24.04) and, for a
# real install, applies its Inst/Remv lines to a fake dpkg database; every
# call is logged with the needrestart variables it saw. guard.yml runs the
# guard's own task files:
#   plan.yml       which packages are missing; P1 removed on purpose (rc),
#                  P2 upgrades or removals, P3 bad names, P4 unit edits not
#                  loaded yet, P5 apt errors (a missing package list is only
#                  a note before `apt-get update`)
#   preflight.yml  the union of every selected role's wants, and the
#                  selection under --tags and --skip-tags
#   install.yml    update, check again, install, prove (M-P1, M-P2), the
#                  environment that holds needrestart back
#   upgrade.yml    role 01's apt_full_upgrade
#   keepall        role 01 with every choice keep wants nothing: apt is not
#                  asked at all
# Static: no apt module anywhere in roles/; shellcheck.
#
# Usage: tests/autosec-apt/semantics/run.sh [--keep]
# Needs: ansible-playbook python3. ShellCheck is optional.
# Exit 0 = every check passed, 1 = a check failed, 2 = setup problem.
set -u -o pipefail
export LC_ALL=C

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
KEEP=0
die() { echo "ERROR: $*" >&2; exit 2; }
while [ $# -gt 0 ]; do
  case $1 in
    --keep) KEEP=1; shift ;;
    -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
for t in ansible-playbook python3; do command -v "$t" >/dev/null 2>&1 || die "missing tool: $t"; done
PY=$(command -v python3)

W=$(mktemp -d "${TMPDIR:-/tmp}/autosec-apt-semantics.XXXXXX") || die "mktemp failed"
cleanup() { if [ "$KEEP" = 1 ]; then echo "work dir kept: $W"; else rm -rf "$W"; fi; }
trap cleanup EXIT
mkdir -p "$W/fakebin" "$W/out" "$W/lab" || die "cannot create directories"

PASSES=0
FAILS=0
pass() { PASSES=$((PASSES + 1)); printf 'PASS  %-10s %s\n' "$1" "$2"; }
fail() { FAILS=$((FAILS + 1)); printf 'FAIL  %-10s %s\n' "$1" "$2"; }
skip() { printf 'SKIP  %-10s %s\n' "$1" "$2"; }
expect() { # test what got want
  if [ "$3" = "$4" ]; then pass "$1" "$2: $3"; else fail "$1" "$2: got '$3', want '$4'"; fi
}

# --- fakes -------------------------------------------------------------------
cat >"$W/fakebin/dpkg-query" <<'FAKE'
#!/bin/sh
# Fake dpkg-query. $LAB_STATE: one "name state arch version" line per package
# (the last line for a name wins).
#   -W -f=<format with ${Version}>  every package: "<state>  name arch version"
#   -W -f=<format> pkg...           each asked package: "<state>  name"
printf 'dpkg-query %s\n' "$*" >>"$LAB_CALLS"
[ "$1" = -W ] || exit 2
fmt=$2
shift 2
case $fmt in
  *Version*) awk '{ printf "%s  %s %s %s\n", $2, $1, $3, $4 }' "$LAB_STATE"; exit 0 ;;
esac
rc=0
for p in "$@"; do
  s=$(awk -v p="$p" '$1 == p { s = $2 } END { print s }' "$LAB_STATE")
  if [ -n "$s" ]; then printf '%s  %s\n' "$s" "$p"; else echo "dpkg-query: no packages found matching $p" >&2; rc=1; fi
done
exit $rc
FAKE
cat >"$W/fakebin/apt-get" <<'FAKE'
#!/bin/sh
# Fake apt-get. Logs every call and the environment that matters.
#   -s ... install pkg...  prints $LAB_APT_OUT ("E:" lines on stderr), exits $LAB_APT_RC
#   update                 exits 0
#   dist-upgrade           prints the "nothing to do" line
#   install -y ...         applies $LAB_APT_OUT's Inst and Remv lines to $LAB_STATE,
#                          then $LAB_EXTRA ("bump:<pkg>:<version>", "add:<pkg>"),
#                          exits $LAB_INSTALL_RC
printf 'apt-get %s\n' "$*" >>"$LAB_CALLS"
printf 'env NEEDRESTART_SUSPEND=%s NEEDRESTART_MODE=%s DEBIAN_FRONTEND=%s APT_LISTCHANGES_FRONTEND=%s LC_ALL=%s\n' \
  "${NEEDRESTART_SUSPEND:-}" "${NEEDRESTART_MODE:-}" "${DEBIAN_FRONTEND:-}" "${APT_LISTCHANGES_FRONTEND:-}" "${LC_ALL:-}" >>"$LAB_CALLS"
case $1 in
  -s) printf '%s\n' "$*" >"$LAB_APT_ARGS"
      grep -v '^E:' "$LAB_APT_OUT"
      grep '^E:' "$LAB_APT_OUT" >&2
      exit "${LAB_APT_RC:-0}" ;;
  update) exit 0 ;;
esac
case " $* " in
  *" dist-upgrade "*) echo "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."; exit 0 ;;
  *" install "*)
    awk 'FNR == NR {
           if ($1 == "Inst") { n = $2; sub(/:.*/, "", n); v = ($3 ~ /^\[/) ? $4 : $3; gsub(/[()]/, "", v); inst[n] = v }
           else if ($1 == "Remv") { rm[$2] = 1 }
           next }
         { if ($1 in rm) next
           if ($1 in inst) { print $1, "ii", $3, inst[$1]; seen[$1] = 1; next }
           print }
         END { for (n in inst) if (!(n in seen)) print n, "ii", "amd64", inst[n] }' "$LAB_APT_OUT" "$LAB_STATE" >"$LAB_STATE.new"
    for e in ${LAB_EXTRA:-}; do
      case $e in
        bump:*) p=${e#bump:}; v=${p#*:}; p=${p%%:*}
                awk -v p="$p" -v v="$v" '$1 == p { $4 = v } { print }' "$LAB_STATE.new" >"$LAB_STATE.x" && mv "$LAB_STATE.x" "$LAB_STATE.new" ;;
        add:*) printf '%s ii amd64 1.0\n' "${e#add:}" >>"$LAB_STATE.new" ;;
      esac
    done
    mv "$LAB_STATE.new" "$LAB_STATE"
    exit "${LAB_INSTALL_RC:-0}" ;;
esac
exit 0
FAKE
cat >"$W/fakebin/systemctl" <<'FAKE'
#!/bin/sh
# Fake systemctl: list-units prints $LAB_UNITS; show -p Id,NeedDaemonReload --
# <units> says "yes" for the units listed in $LAB_ND.
printf 'systemctl %s\n' "$*" >>"$LAB_CALLS"
case $1 in
  list-units) cat "$LAB_UNITS" ;;
  show)
    while [ $# -gt 0 ] && [ "$1" != -- ]; do shift; done
    [ $# -gt 0 ] && shift
    first=1
    for u in "$@"; do
      [ "$first" = 1 ] || echo
      first=0
      echo "Id=$u"
      if grep -qxF -- "$u" "$LAB_ND"; then echo NeedDaemonReload=yes; else echo NeedDaemonReload=no; fi
    done ;;
esac
exit 0
FAKE
cat >"$W/fakebin/getent" <<'FAKE'
#!/bin/sh
# Fake getent: no account exists.
exit 2
FAKE
chmod +x "$W/fakebin/"*

# Loaded units (systemctl list-units --all --no-legend --plain --full).
cat >"$W/lab/units" <<'UNITS'
ssh.service loaded active running OpenBSD Secure Shell server
nginx.service loaded inactive dead A high performance web server
auto-sec-ssh-guard-boot.service loaded inactive dead auto_sec SSH guard
dev-disk-by\x2duuid-1.device loaded active plugged /dev/disk/by-uuid/1
gone.service not-found inactive dead gone.service
UNITS
: >"$W/lab/nd-none"
printf '%s\n' nginx.service auto-sec-ssh-guard-boot.service 'dev-disk-by\x2duuid-1.device' gone.service >"$W/lab/nd-some"

STATE_BASE='curl ii amd64 8.5.0
unattended-upgrades ii all 2.9.1
libc6 ii amd64 2.39-0ubuntu8.6
libapparmor1 ii amd64 4.0.1really4.0.1-0ubuntu0.24.04.3
apparmor ii amd64 4.0.1really4.0.1-0ubuntu0.24.04.3
systemd-timesyncd ii amd64 255.4-1ubuntu8.16'

# guard name state-extra apt-out apt-rc [ansible args...]: returns ansible's rc.
# state-extra: more "name state arch version" lines ("-" none). apt-out: a
# file in fixtures/, or an absolute path.
guard() {
  local n=$1 extra=$2 out=$3 arc=$4 rc=0
  shift 4
  case $out in /*) ;; *) out=$HERE/fixtures/$out ;; esac
  rm -f "$W/out/$n".*
  printf '%s\n' "$STATE_BASE" >"$W/out/$n.state"
  if [ "$extra" != - ]; then printf '%s\n' "$extra" >>"$W/out/$n.state"; fi
  : >"$W/out/$n.calls"
  (cd "$HERE" && PATH="$W/fakebin:$PATH" LAB_STATE="$W/out/$n.state" LAB_CALLS="$W/out/$n.calls" \
    LAB_APT_OUT="$out" LAB_APT_RC="$arc" LAB_APT_ARGS="$W/out/$n.args" \
    LAB_UNITS="${LAB_UNITS:-$W/lab/units}" LAB_ND="${LAB_ND:-$W/lab/nd-none}" \
    LAB_EXTRA="${LAB_EXTRA:-}" LAB_INSTALL_RC="${LAB_INSTALL_RC:-0}" \
    LC_ALL=C.UTF-8 ANSIBLE_ROLES_PATH="$ROOT/roles" ANSIBLE_LOCALHOST_WARNING=False \
    ANSIBLE_INVENTORY_UNPARSED_WARNING=False ANSIBLE_NOCOLOR=1 ANSIBLE_RETRY_FILES_ENABLED=False \
    ansible-playbook guard.yml -e "lab_out=$W/out/$n.json" "$@") >"$W/out/$n.log" 2>&1 || rc=$?
  return "$rc"
}
ok() { # test name ...
  local t=$1
  shift
  if guard "$@"; then pass "$t" "$1: passes"; return 0; fi
  fail "$t" "$1: refused (log $W/out/$1.log)"; grep -E '"msg"|ERROR' "$W/out/$1.log" | head -n 3 | cut -c1-400; return 1
}
refused() { # test name fixed-string ...
  local t=$1 n=$2 s=$3 rc=0
  shift 3
  guard "$n" "$@" || rc=$?
  if [ "$rc" -eq 0 ]; then fail "$t" "$n: run succeeded, want a refusal"; return; fi
  if grep -Fq -- "$s" "$W/out/$n.log"; then pass "$t" "$n: refused with \"$s\""
  else fail "$t" "$n: refused (rc $rc) but without \"$s\" (log $W/out/$n.log)"; grep -E '"msg"|ERROR' "$W/out/$n.log" | head -n 3 | cut -c1-400; fi
}
j() { # name python-expression over d (the facts)
  "$PY" -I -c 'import json, sys
d = json.load(open(sys.argv[1]))
v = eval(sys.argv[2], {"d": d})
print(v if isinstance(v, str) else json.dumps(v, sort_keys=True))' "$W/out/$1.json" "$2"
}
asked() { # name what: did the fake see that command?
  if grep -q "^$2" "$W/out/$1.calls"; then echo asked; else echo not-asked; fi
}
REQ() { printf '{"lab_mode": "plan", "lab_req": [{"who": "%s", "pkgs": %s}]}' "$1" "$2"; }

# --- 0. static checks ------------------------------------------------------------
bad=$(grep -rnE --include='*.yml' '^[[:space:]]*-?[[:space:]]*(ansible\.builtin\.)?apt:[[:space:]]*$' "$ROOT/roles" | sed "s|$ROOT/||" | paste -sd' ' -)
expect static "no apt module in roles/ (every install goes through autosec-apt)" "${bad:-none}" none
n=$(grep -c 'NEEDRESTART_SUSPEND: "1"' "$ROOT/roles/autosec-apt/vars/main.yml")
expect static "the guard's environment suspends needrestart" "$n" 1
bad=$(grep -rnE 'needrestart +-' "$ROOT/roles" --include='*.yml' | grep -vE ':[[:space:]]*#' | grep -v '"needrestart -r l" lists them' | sed "s|$ROOT/||" | paste -sd' ' -)
expect static "auto_sec never runs needrestart itself" "${bad:-none}" none
if command -v shellcheck >/dev/null 2>&1; then
  if shellcheck "$0"; then pass static "shellcheck run.sh"; else fail static "shellcheck run.sh"; fi
  if shellcheck -s sh "$W/fakebin/dpkg-query" "$W/fakebin/apt-get" "$W/fakebin/systemctl"; then pass static "shellcheck the fakes"; else fail static "shellcheck the fakes"; fi
else
  skip static "shellcheck not installed"
fi

# --- 1. plan.yml: missing packages, apt's simulation, P1-P5 ------------------------
if ok plan k-all - pkg-clean.txt 0 -e "$(REQ 'role 01 (base)' '["curl", "unattended-upgrades"]')"; then
  expect plan "everything installed: nothing missing, apt not asked" "$(j k-all 'd["missing"]')/$(asked k-all 'apt-get')/$(asked k-all 'systemctl')" "[]/not-asked/not-asked"
fi
if ok plan k-held "jq hi amd64 1.7.1" pkg-clean.txt 0 -e "$(REQ 'role 01 (base)' '["jq"]')"; then
  expect plan "a held package counts as installed" "$(j k-held 'd["missing"]')" "[]"
fi
if ok plan k-clean - pkg-clean.txt 0 -e "$(REQ 'role 01 (base)' '["curl", "jq"]')"; then
  expect plan "jq missing: a clean install" "$(j k-clean '[d["missing"], d["side"]]')" '[["jq"], []]'
  expect plan "apt is asked without recommendations, without locking" "$(cat "$W/out/k-clean.args")" "-s -o Debug::NoLocking=true --no-install-recommends install jq"
  expect plan "new packages, and the new dependencies" "$(j k-clean '[d["new"], d["deps"]]')" '[["libonig5", "libjq1", "jq"], ["libonig5", "libjq1"]]'
  expect plan "by role" "$(j k-clean 'd["by_who"]')" '[["role 01 (base)", ["jq"]]]'
  expect plan "something missing: unit edits are checked" "$(asked k-clean 'systemctl list-units')" asked
fi
refused plan k-upgrade "[P2] Installing libapparmor-dev on localhost would also change packages you have: libapparmor1 4.0.1really4.0.1-0ubuntu0.24.04.3 -> 4.0.1really4.0.1-0ubuntu0.24.04.7" \
  - pkg-upgrade.txt 0 -e "$(REQ 'role 03 (fail2ban)' '["libapparmor-dev"]')"
if grep -Fq 'or run once with' "$W/out/k-upgrade.log"; then fail plan "k-upgrade: apt_full_upgrade is offered to a role other than 01"
else pass plan "k-upgrade: apt_full_upgrade is offered only to role 01"; fi
refused plan k-upgrade-01 "-e apt_full_upgrade=true" - pkg-upgrade.txt 0 -e "$(REQ 'role 01 (base)' '["libapparmor-dev"]')"
refused plan k-upgrade-main "only the package lists were refreshed" - pkg-upgrade.txt 0 -e "$(REQ 'role 01 (base)' '["libapparmor-dev"]')" -e lab_ctx=main
if ok plan k-upgrade-full - pkg-upgrade.txt 0 -e "$(REQ 'role 01 (base)' '["libapparmor-dev"]')" -e lab_allow=true; then
  expect plan "apt_full_upgrade allows the upgrades" "$(j k-upgrade-full 'len(d["side"])')" 2
fi
refused plan k-remove "remove systemd-timesyncd 255.4-1ubuntu8.16" - pkg-remove.txt 0 -e "$(REQ 'role 01 (base)' '["ntpsec"]')"
if ok plan k-nolists - pkg-nolists.txt 100 -e "$(REQ 'role 01 (base)' '["jq"]')"; then
  expect plan "no package lists yet (preflight): a note, checked again after apt-get update" \
    "$(grep -c "NOTE: apt cannot plan the install of jq" "$W/out/k-nolists.log")" 1
fi
refused plan k-nolists-main "[P5] apt cannot install jq on localhost: E: Unable to locate package autosec-no-such-package" \
  - pkg-nolists.txt 100 -e "$(REQ 'role 01 (base)' '["jq"]')" -e lab_ctx=main
printf '%s\n' 'Reading package lists...' "E: dpkg was interrupted, you must manually run 'dpkg --configure -a' to correct the problem." >"$W/lab/pkg-broken.txt"
refused plan k-broken "[P5] apt cannot install jq on localhost: E: dpkg was interrupted" - "$W/lab/pkg-broken.txt" 100 -e "$(REQ 'role 01 (base)' '["jq"]')"
refused plan k-rc "[P1] unattended-upgrades was removed on purpose on localhost (dpkg state rc)" \
  "unattended-upgrades rc all 2.9.1" pkg-clean.txt 0 -e "$(REQ 'role 01 (base)' '["unattended-upgrades", "jq"]')"
refused plan k-rc-off "to turn that off, remove b2_bucket" "jq rc amd64 1.7.1" pkg-clean.txt 0 \
  -e '{"lab_mode": "plan", "lab_req": [{"who": "role 07 (backups)", "pkgs": ["jq"], "off": "remove b2_bucket"}]}'
if grep -Fq 'jq is wanted by role 07 (backups)' "$W/out/k-rc-off.log"; then pass plan "k-rc-off: P1 names the role"; else fail plan "k-rc-off: P1 does not name the role"; fi
expect plan "P1 refuses before apt is asked" "$(asked k-rc-off 'apt-get')" not-asked
refused plan k-badname "[P3] auto_sec bug" - pkg-clean.txt 0 -e "$(REQ 'role 01 (base)' '["-oDebug=1"]')"
LAB_ND=$W/lab/nd-some refused plan k-units "[P4] localhost has unit edits systemd has not loaded yet: nginx.service, dev-disk-by" \
  - pkg-clean.txt 0 -e "$(REQ 'role 01 (base)' '["jq"]')"
if grep -Fq 'auto-sec-ssh-guard-boot' "$W/out/k-units.log" || grep -Fq 'gone.service' "$W/out/k-units.log"; then
  fail plan "k-units: auto_sec's own unit or a unit that is not loaded is listed"
else pass plan "k-units: auto_sec's own units and units that are not loaded are left out"; fi
expect plan "k-units: every loaded unit is asked" \
  "$(grep -cxF 'systemctl show -p Id,NeedDaemonReload -- ssh.service nginx.service auto-sec-ssh-guard-boot.service dev-disk-by\x2duuid-1.device' "$W/out/k-units.calls")" 1
LAB_ND=$W/lab/nd-some ok plan k-units-none - pkg-clean.txt 0 -e "$(REQ 'role 01 (base)' '["curl"]')"
expect plan "nothing missing: unit edits are not checked" "$(asked k-units-none 'systemctl')" not-asked

# --- 2. preflight.yml: the union of the selected roles' wants --------------------------
WANTS='{"lab_mode": "preflight", "_base_pkg_want": ["unattended-upgrades", "jq"], "_f2b_pkg_want": ["jq", "libonig5"], "_l07_pkg_want": []}'
if ok union u-all - pkg-clean.txt 0 -e "$WANTS" -e '{"_base_pkg_want": ["jq"]}'; then
  expect union "one simulation for all of them" "$(cat "$W/out/u-all.args")" "-s -o Debug::NoLocking=true --no-install-recommends install jq libonig5"
  expect union "by role" "$(j u-all 'd["pf_by_who"]')" '[["role 01 (base)", ["jq"]], ["role 03 (fail2ban)", ["jq", "libonig5"]]]'
  expect union "the plan line" "$(j u-all 'd["plan_line"]')" "role 01 (base): jq; role 03 (fail2ban): jq libonig5 (+ new dependencies libjq1)"
  expect union "N-P1 is shown" "$(grep -c '\[N-P1\] INFO: packages' "$W/out/u-all.log")" 1
fi
for v in "u-tag-base|--tags base|role 01 (base)" "u-tag-f2b|--tags fail2ban|role 03 (fail2ban)" \
         "u-tag-fw|--tags firewall|role 03 (fail2ban)" "u-skip-f2b|--skip-tags fail2ban|role 01 (base)" \
         "u-skip-fw|--skip-tags firewall|role 01 (base)" "u-skip-base|--skip-tags base|role 03 (fail2ban)"; do
  IFS='|' read -r n tags who <<<"$v"
  # shellcheck disable=SC2086 # two words on purpose
  if ok union "$n" - pkg-clean.txt 0 -e "$WANTS" $tags; then
    expect union "$tags: only $who" "$(j "$n" '" + ".join(r["who"] for r in d["pf_req"])')" "$who"
  fi
done
if ok union u-tag-ssh - pkg-clean.txt 0 -e "$WANTS" --tags ssh; then
  expect union "--tags ssh: nothing to install, apt not asked" "$(j u-tag-ssh 'd["plan_line"]')/$(asked u-tag-ssh 'apt-get')" "nothing to install/not-asked"
fi
if ok union u-none - pkg-clean.txt 0 -e lab_mode=preflight; then
  expect union "no role wants anything: nothing asked at all" \
    "$(j u-none 'd["plan_line"]')/$(asked u-none 'apt-get')/$(asked u-none 'dpkg-query')" "nothing to install/not-asked/not-asked"
  expect union "the summary line" "$(grep -c 'packages: nothing to install' "$W/out/u-none.log")" 1
fi
refused union u-upgrade "[P2]" - pkg-upgrade.txt 0 -e '{"lab_mode": "preflight", "_base_pkg_want": ["libapparmor-dev"]}'
ok union u-upgrade-full - pkg-upgrade.txt 0 -e '{"lab_mode": "preflight", "_base_pkg_want": ["libapparmor-dev"], "_base_full_upgrade": true}'
# apt_full_upgrade: role 01 upgrades every package first (main step 5), so
# the other roles' installs may count on it; without role 01 in the run they
# may not.
ok union u-upgrade-f2b-full - pkg-upgrade.txt 0 -e '{"lab_mode": "preflight", "_f2b_pkg_want": ["libapparmor-dev"], "_base_full_upgrade": true}'
refused union u-upgrade-f2b-nobase "[P2]" - pkg-upgrade.txt 0 \
  -e '{"lab_mode": "preflight", "_f2b_pkg_want": ["libapparmor-dev"], "_base_full_upgrade": true}' --skip-tags base
LAB_ND=$W/lab/nd-some refused union u-full-units "[P4]" - pkg-clean.txt 0 -e '{"lab_mode": "preflight", "_base_full_upgrade": true}'
if grep -Fq 'The full upgrade (apt_full_upgrade) reloads' "$W/out/u-full-units.log"; then pass union "P4 names the full upgrade"; else fail union "P4 does not name the full upgrade"; fi

# --- 3. install.yml ------------------------------------------------------------------
if ok install i-jq - pkg-clean.txt 0 -e '{"lab_mode": "install", "lab_want": ["curl", "jq"]}'; then
  expect install "calls" "$(grep '^apt-get' "$W/out/i-jq.calls" | paste -sd'|' -)" \
    "apt-get update|apt-get -s -o Debug::NoLocking=true --no-install-recommends install jq|apt-get install -y --no-install-recommends -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold jq"
  expect install "the install runs with needrestart held back" "$(grep -A1 '^apt-get install' "$W/out/i-jq.calls" | tail -n 1)" \
    "env NEEDRESTART_SUSPEND=1 NEEDRESTART_MODE=l DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none LC_ALL=C"
  expect install "the list refresh too" "$(grep -A1 '^apt-get update' "$W/out/i-jq.calls" | tail -n 1)" \
    "env NEEDRESTART_SUSPEND=1 NEEDRESTART_MODE=l DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none LC_ALL=C"
  expect install "installed: jq and its dependencies" "$(awk '$1 ~ /^(jq|libjq1|libonig5)$/ { print $1, $2 }' "$W/out/i-jq.state" | sort | paste -sd' ' -)" "jq ii libjq1 ii libonig5 ii"
  expect install "N-P2 is shown" "$(grep -c '\[N-P2\] NOTE: installed on localhost for role 01 (base): jq (+ libonig5 libjq1)' "$W/out/i-jq.log")" 1
fi
if ok install i-none - pkg-clean.txt 0 -e '{"lab_mode": "install", "lab_want": ["curl"]}'; then
  expect install "nothing missing: no apt run at all" "$(asked i-none 'apt-get')" not-asked
fi
if ok install i-check - pkg-clean.txt 0 -e '{"lab_mode": "install", "lab_want": ["jq"]}' --check; then
  expect install "--check: no apt run at all" "$(asked i-check 'apt-get')/$(asked i-check 'dpkg-query')" "not-asked/not-asked"
fi
LAB_EXTRA="bump:libc6:2.39-9" refused install i-bump "[M-P1] this should not happen; another apt run (unattended-upgrades?) changed packages at the same time on localhost: version changed: libc6:amd64 was 2.39-0ubuntu8.6" \
  - pkg-clean.txt 0 -e '{"lab_mode": "install", "lab_want": ["jq"]}'
LAB_EXTRA="add:evil" refused install i-add "added without notice: evil" - pkg-clean.txt 0 -e '{"lab_mode": "install", "lab_want": ["jq"]}'
LAB_INSTALL_RC=100 refused install i-fail "[M-P2] apt-get install jq failed on localhost (exit 100)" \
  - pkg-clean.txt 0 -e '{"lab_mode": "install", "lab_want": ["jq"]}'
refused install i-upgrade "only the package lists were refreshed" - pkg-upgrade.txt 0 -e '{"lab_mode": "install", "lab_want": ["libapparmor-dev"]}'
expect install "a refusal after the refresh installs nothing" "$(asked i-upgrade 'apt-get install')" not-asked
if ok install i-upgrade-full - pkg-upgrade.txt 0 -e '{"lab_mode": "install", "lab_want": ["libapparmor-dev"], "lab_allow": true}'; then
  expect install "apt_full_upgrade: upgrades allowed and proven" "$(awk '$1 == "libapparmor1" { print $4 }' "$W/out/i-upgrade-full.state")" "4.0.1really4.0.1-0ubuntu0.24.04.7"
fi

# --- 4. upgrade.yml (role 01's apt_full_upgrade) -----------------------------------------
if ok upgrade g-full - pkg-clean.txt 0 -e lab_mode=upgrade; then
  expect upgrade "calls" "$(grep '^apt-get' "$W/out/g-full.calls" | paste -sd'|' -)" \
    "apt-get update|apt-get -y -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold dist-upgrade"
  expect upgrade "with needrestart held back" "$(grep -A1 'dist-upgrade' "$W/out/g-full.calls" | tail -n 1)" \
    "env NEEDRESTART_SUSPEND=1 NEEDRESTART_MODE=l DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none LC_ALL=C"
  expect upgrade "nothing to upgrade: not changed" "$(grep -A1 'Packages: full upgrade (apt_full_upgrade)\]' "$W/out/g-full.log" | tail -n 1 | cut -d: -f1)" ok
fi
if ok upgrade g-check - pkg-clean.txt 0 -e lab_mode=upgrade --check; then
  expect upgrade "--check: no apt run" "$(asked g-check 'apt-get')" not-asked
fi

# --- 5. every choice keep: role 01 wants nothing, apt is not asked --------------------
mkdir -p "$W/lab/sudoers.d"
for srv in existing ""; do
  n=keep-${srv:-unset}
  # shellcheck disable=SC2086 # no argument at all when srv is empty
  if ok keepall "$n" - pkg-clean.txt 0 -e lab_mode=keepall -e deploy_user=deploy -e "_base_sudo_dir=$W/lab/sudoers.d" \
       ${srv:+-e autosec_server=$srv}; then
    expect keepall "$n: role 01 wants no package; nothing to install; apt and dpkg-query not asked" \
      "$(j "$n" '[d["base_want"], d["plan_line"]]')/$(asked "$n" 'apt-get')/$(asked "$n" 'dpkg-query')" '[[], "nothing to install"]/not-asked/not-asked'
  fi
done
if ok keepall keep-new - pkg-clean.txt 0 -e lab_mode=keepall -e deploy_user=deploy -e "_base_sudo_dir=$W/lab/sudoers.d" \
     -e autosec_server=new -e "_base_run_dir=$W/out/keep-new.run" -e "_base_sudo_candidate=$W/out/keep-new.run/cand" \
     -e "_base_sudoers=$W/lab/sudoers"; then
  expect keepall "new: role 01 wants unattended-upgrades and sudo (installed here)" "$(j keep-new '[d["base_want"], d["plan_line"]]')" \
    '[["unattended-upgrades", "sudo"], "role 01 (base): sudo (+ new dependencies libonig5 libjq1 jq)"]'
fi

echo
echo "$PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
