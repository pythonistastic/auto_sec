#!/usr/bin/env bash
# base-semantics: unprivileged tests of role 01: its apt handling (#3, auto_sec
# 0.5) and the account, sudo and kernel-settings parts of 0.6. No root and
# nothing installed: the pinned unattended-upgrades .debs
# in debs.txt (SHA256-checked) are unpacked with dpkg-deb -x. Each test builds
# a lab apt configuration (its own apt.conf.d) that apt reads through
# APT_CONFIG. Then
#   - role 01's own task files run against it through lab.yml: plan.yml
#     (variable checks), decide.yml and trial.yml (the trial run with
#     files/autosec-apt-sim and the checks of verify.yml);
#   - each release's own unattended-upgrade code (uu_eval.py) reports what it
#     would use before and after the run: the archives it accepts (matched
#     against real Release headers in fixtures/release), automatic reboot,
#     the blacklist.
# The labs: the canary's files (Ubuntu 24.04), Debian 12 stock and fresh (no
# unattended-upgrades yet), hosts set up by auto_sec 0.1-0.4 (Ubuntu and
# Debian), updates switched off on purpose (also after an earlier run, the
# way dpkg-reconfigure does it), an update interval of yours, a removed
# package, a file of yours that sorts after auto_sec's, broken apt files,
# and the stock files of 22.04, 13 and 26.04.
# Then account.yml runs role 01's account.yml, sudo_check.yml, admin.yml,
# kernel.yml and plan_items.yml against lab trees (their own sudoers,
# sudoers.d and sysctl files), with fake getent, id and dpkg-query and the
# real visudo (-f): deploy_user_account and its defaults for existing and
# new servers, whose sudo file it is (absent, 0.1-0.5's, auto_sec's, yours,
# not a file), the scan for your rules that name the account or its groups,
# @includedir, a broken configuration, the account role 02 logs in as
# (R01-A6, R01-A7), the notes about /etc/sysctl.conf (N01-K1, N01-K2), main
# step 6b's check before the write (M01-A1) and the plan items. The package
# guard has its own tests (tests/autosec-apt/semantics).
#
# Usage: tests/base/semantics/run.sh [--cache DIR]... [--keep] [--verbose]
#   --cache DIR  where the .debs are kept. Searched 3 levels deep by package
#                and version (an apt download dir works too). Repeatable: all
#                are searched, a missing file is downloaded into the FIRST.
#                Default: ~/.cache/auto-sec-base-semantics
#   --keep       keep the work directory and print its path
#   --verbose    print what unattended-upgrades uses in every lab
# Needs: curl dpkg-deb sha256sum apt-config ansible-playbook python3 visudo. The
# unattended-upgrades checks also need python3-apt, python3-distro-info and
# lsb_release for /usr/bin/python3 (SKIP lines without them). ShellCheck is
# optional.
# Exit 0 = every check passed, 1 = a check failed, 2 = setup problem.
set -u -o pipefail
export LC_ALL=C

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
SIM=$ROOT/roles/01-base/files/autosec-apt-sim
UUFILE=51autosec-unattended-upgrades
HEADER='// Written by auto_sec (role 01)'
CACHES=()
KEEP=0
VERBOSE=0

die() { echo "ERROR: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case $1 in
    --cache) [ $# -ge 2 ] || die "--cache needs a directory"; CACHES+=("$2"); shift 2 ;;
    --keep) KEEP=1; shift ;;
    --verbose) VERBOSE=1; shift ;;
    -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[ ${#CACHES[@]} -gt 0 ] || CACHES=("${XDG_CACHE_HOME:-$HOME/.cache}/auto-sec-base-semantics")
CACHE=${CACHES[0]}
for t in curl dpkg-deb sha256sum apt-config ansible-playbook python3 visudo; do
  command -v "$t" >/dev/null 2>&1 || die "missing tool: $t"
done
# The distro's python3: python3-apt is not on PyPI.
PY=/usr/bin/python3
[ -x "$PY" ] || PY=$(command -v python3)

W=$(mktemp -d "${TMPDIR:-/tmp}/base-semantics.XXXXXX") || die "mktemp failed"
cleanup() { if [ "$KEEP" = 1 ]; then echo "work dir kept: $W"; else rm -rf "$W"; fi; }
trap cleanup EXIT
mkdir -p "$CACHE" "$W/x" "$W/ctl" "$W/lab" "$W/out" "$W/scratch" || die "cannot create directories"

PASSES=0
FAILS=0
pass() { PASSES=$((PASSES + 1)); printf 'PASS  %-12s %s\n' "$1" "$2"; }
fail() { FAILS=$((FAILS + 1)); printf 'FAIL  %-12s %s\n' "$1" "$2"; }
skip() { printf 'SKIP  %-12s %s\n' "$1" "$2"; }
info() { printf 'INFO  %-12s %s\n' "$1" "$2"; }
expect() { # test what got want
  if [ "$3" = "$4" ]; then pass "$1" "$2: $3"; else fail "$1" "$2: got '$3', want '$4'"; fi
}

# --- fetch and unpack the pinned packages ----------------------------------
sha_of() { sha256sum "$1" | cut -d' ' -f1; }

fetch() { # file sha url... -> prints the path of a verified copy
  local fn=$1 sha=$2 f u
  shift 2
  while IFS= read -r f; do
    if [ "$(sha_of "$f")" = "$sha" ]; then printf '%s\n' "$f"; return 0; fi
  done < <(find "${CACHES[@]}" -maxdepth 3 -type f -name "$fn" 2>/dev/null)
  for u in "$@"; do
    echo "download $u" >&2
    if curl -fsSL --retry 3 --retry-all-errors --retry-delay 3 --max-time 300 \
         -o "$CACHE/$fn.part" "$u" && [ "$(sha_of "$CACHE/$fn.part")" = "$sha" ]; then
      mv -f "$CACHE/$fn.part" "$CACHE/$fn" && printf '%s\n' "$CACHE/$fn" && return 0
    fi
    echo "  download failed or SHA256 mismatch: $u" >&2
  done
  rm -f "$CACHE/$fn.part"
  return 1
}

SETS=""
while read -r set fn sha rest; do
  case $set in ''|'#'*) continue ;; esac
  read -ra urls <<<"$rest"
  deb=$(fetch "$fn" "$sha" "${urls[@]}") || die "no verified copy of $fn (see debs.txt)"
  mkdir -p "$W/x/$set" "$W/ctl/$set" || die "mkdir $set"
  dpkg-deb -x "$deb" "$W/x/$set" || die "dpkg-deb -x $deb failed"
  dpkg-deb -e "$deb" "$W/ctl/$set" || die "dpkg-deb -e $deb failed"
  [ -f "$W/x/$set/usr/share/unattended-upgrades/50unattended-upgrades" ] || die "$set: no 50unattended-upgrades"
  SETS="$SETS $set"
done <"$HERE/debs.txt"

ud() { printf '%s\n' "$W/x/$1/usr/share/unattended-upgrades"; }
dpkg_md5() { awk '$2 == "usr/share/unattended-upgrades/50unattended-upgrades" { print $1 }' "$W/ctl/$1/md5sums"; }

UU_OK=1
if ! command -v lsb_release >/dev/null 2>&1 || ! "$PY" -I -c 'import apt_pkg, distro_info' 2>/dev/null; then
  UU_OK=0
  echo "NOTE: $PY lacks python3-apt or python3-distro-info, or lsb_release is missing:"
  echo "      the unattended-upgrades checks are skipped."
fi

# --- labs ---------------------------------------------------------------------
mklab() { # name: an empty apt.conf.d of its own; apt reads nothing else
  local d=$W/lab/$1
  rm -rf "$d"
  mkdir -p "$d/parts" || die "mkdir $d"
  printf 'Dir::Etc::Parts "%s/parts";\nDir::Etc::Main "/dev/null";\n' "$d" >"$d/apt.conf"
}
put() { cp "$2" "$W/lab/$1/parts/$3" || die "copy $2 into lab $1"; }   # lab src name
stock() { # lab set: the two files the package installs
  put "$1" "$(ud "$2")/20auto-upgrades" 20auto-upgrades
  put "$1" "$(ud "$2")/50unattended-upgrades" 50unattended-upgrades
}
clone() { # from to
  rm -rf "$W/lab/$2"
  cp -a "$W/lab/$1" "$W/lab/$2" || die "clone $1"
  printf 'Dir::Etc::Parts "%s/parts";\nDir::Etc::Main "/dev/null";\n' "$W/lab/$2" >"$W/lab/$2/apt.conf"
}
after() { # lab run-name new-lab [pristine]: the lab as the run leaves it
  clone "$1" "$3"
  if [ -n "${4:-}" ]; then put "$3" "$4" 50unattended-upgrades; fi
  if [ -f "$W/out/$2.render" ]; then put "$3" "$W/out/$2.render" "$UUFILE"; fi
}

lab() { # lab case run-name [ansible args...]: role 01 B1-B6; returns ansible's rc
  local l=$1 c=$2 n=$3 rc=0
  shift 3
  rm -f "$W/out/$n".*
  (cd "$HERE" && APT_CONFIG="$W/lab/$l/apt.conf" LC_ALL=C.UTF-8 ANSIBLE_ROLES_PATH="$ROOT/roles" \
    ANSIBLE_LOCALHOST_WARNING=False ANSIBLE_INVENTORY_UNPARSED_WARNING=False ANSIBLE_NOCOLOR=1 \
    ANSIBLE_RETRY_FILES_ENABLED=False \
    ansible-playbook lab.yml -e "@cases/$c.yml" -e "lab_dir=$W/lab/$l" -e "lab_out=$W/out/$n.json" \
      -e "lab_render=$W/out/$n.render" -e "lab_scratch=$W/scratch/$n" "$@") >"$W/out/$n.log" 2>&1 || rc=$?
  return "$rc"
}
lab_ok() { # test lab case run-name [args...]: the run must succeed
  local t=$1
  shift
  if lab "$@"; then pass "$t" "$2: role 01 preflight B1-B6 passes"; return 0; fi
  fail "$t" "$2: role 01 preflight refused (log $W/out/$3.log):"
  grep -E '"msg"' "$W/out/$3.log" | head -n 3 | cut -c1-400
  return 1
}
lab_refused() { # test lab case run-name fixed-string [args...]: must refuse with that message
  local t=$1 l=$2 c=$3 n=$4 s=$5 rc=0
  shift 5
  lab "$l" "$c" "$n" "$@" || rc=$?
  if [ "$rc" -eq 0 ]; then fail "$t" "$c: run succeeded, want a refusal"; return; fi
  if grep -Fq -- "$s" "$W/out/$n.log"; then pass "$t" "$c: refused with \"$s\""
  else fail "$t" "$c: refused (rc $rc) but without \"$s\" (log $W/out/$n.log)"; fi
  if [ -e "$W/scratch/$n/apt-sim" ] || [ -e "$W/scratch/$n/apt-candidate" ]; then
    fail "$t" "$c: the trial run left its copy behind"
  fi
}
j() { # run-name python-expression over d (the facts)
  "$PY" -I -c 'import json, sys
d = json.load(open(sys.argv[1]))
v = eval(sys.argv[2], {"d": d})
print(v if isinstance(v, str) else json.dumps(v, sort_keys=True))' "$W/out/$1.json" "$2"
}
uu() { # lab set distro_id codename prefix [package...] -> $W/out/uu-<lab>
  local l=$1 s=$2
  APT_CONFIG="$W/lab/$l/apt.conf" "$PY" -I "$HERE/uu_eval.py" "$W/x/$s/usr/bin/unattended-upgrade" \
    "$3" "$4" "$HERE/fixtures/release" "$5" "${@:6}" >"$W/out/uu-$l" 2>"$W/out/uu-$l.err" \
    || { cat "$W/out/uu-$l.err" >&2; die "uu_eval.py failed on lab $l"; }
  if [ "$VERBOSE" = 1 ]; then sed "s/^/      [$l] /" "$W/out/uu-$l"; fi
}
uu_line() { # test lab exact-line what
  if grep -Fxq -- "$3" "$W/out/uu-$2"; then pass "$1" "$4: $3"
  else fail "$1" "$4: no line '$3' in [$(grep -E "^${3%% *} " "$W/out/uu-$2" | paste -sd'|' -)]"; fi
}
uu_show() { # test lab: print what unattended-upgrades uses (the lab's evidence)
  info "$1" "unattended-upgrades in lab $2 uses:"
  sed 's/^/        /' "$W/out/uu-$2"
}
validates() { # test lab render-file: apt-config -c <file> dump accepts it (role 01's validate:)
  if APT_CONFIG="$W/lab/$2/apt.conf" apt-config -c "$3" dump >/dev/null 2>&1; then
    pass "$1" "$(basename "$3"): passes apt-config -c (validate)"
  else fail "$1" "$(basename "$3"): apt-config -c rejects it"; fi
  if head -n 1 "$3" | grep -Fq -- "$HEADER"; then pass "$1" "$(basename "$3"): first line is auto_sec's header"
  else fail "$1" "$(basename "$3"): first line is not the header"; fi
}

# --- 0. static checks -----------------------------------------------------------
if command -v shellcheck >/dev/null 2>&1; then
  if shellcheck -s sh "$SIM"; then pass static "shellcheck -s sh autosec-apt-sim"; else fail static "shellcheck autosec-apt-sim"; fi
else
  skip static "shellcheck not installed"
fi
bad=$(grep -rnE 'dest:.*(20auto-upgrades|50unattended-upgrades)' "$ROOT/roles" | grep -v '_base_uu_dist_file' | paste -sd' ' -)
expect static "no role writes 20auto-upgrades or 50unattended-upgrades by name" "${bad:-none}" none
n=$(grep -cE '^ *dest: "\{\{ _base_uu_dist_file \}\}"' "$ROOT/roles/01-base/tasks/main.yml")
expect static "role 01 writes 50unattended-upgrades in one task (the 0.1-0.4 restore)" "$n" 1
SCAN=$ROOT/roles/01-base/files/autosec-sudo-scan
if command -v shellcheck >/dev/null 2>&1; then
  if shellcheck -s sh "$SCAN"; then pass static "shellcheck -s sh autosec-sudo-scan"; else fail static "shellcheck autosec-sudo-scan"; fi
fi
bad=$(grep -rnE --include='*.yml' 'ansible\.posix\.sysctl|(dest|path): *"?/etc/sysctl\.(conf|d)' "$ROOT/roles" | grep -vE ':[[:space:]]*#' | sed "s|$ROOT/||" | paste -sd' ' -)
expect static "no role writes kernel settings (no ansible.posix.sysctl, no sysctl file as a destination)" "${bad:-none}" none
bad=$(grep -rnE --include='*.yml' 'dest: .*sudoers' "$ROOT/roles" | sed "s|$ROOT/||" | grep -v '^roles/01-base/tasks/main.yml:.*dest: "{{ _base_sudo_file }}"' | paste -sd' ' -)
expect static "only role 01 writes into sudoers.d (its own file, from its template)" "${bad:-none}" none
n=$(awk '/ansible\.builtin\.user:/ { u = 1; next } u && /^ *[a-z_]+:/ { if ($1 ~ /^(groups|append|password|update_password):/) print; } /^ *- name:/ { u = 0 }' "$ROOT/roles/01-base/tasks/main.yml" | wc -l)
expect static "role 01 creates the account with no groups, append or password" "$n" 0
n=$(grep -cE '^ *(ansible\.builtin\.hostname|community\.general\.timezone):' "$ROOT/roles/01-base/tasks/main.yml")
g=$(grep -B2 -E '^ *(ansible\.builtin\.hostname|community\.general\.timezone):' "$ROOT/roles/01-base/tasks/main.yml" \
  | grep -cE 'when: _base_(hostname|tz)_change')
expect static "hostname and timezone modules run only behind _base_*_change" "$g/$n" "2/2"

# --- 1. which file names apt reads (and the trial run's S lines) ------------------
mklab names
i=0
for f in 52noext 52x.conf 52b.c.conf 52a:b 52y.cfg 52z.ucf-dist 52w~ .52hidden 52d.dpkg-old 52e.disabled; do
  i=$((i + 1))
  printf 'Unattended-Upgrade::Lab%s "%s";\n' "$i" "$f" >"$W/lab/names/parts/$f"
done
out=$(APT_CONFIG="$W/lab/names/apt.conf" sh -c "$(cat "$SIM")" sh "$W/lab/names/parts" "$W/scratch/names" - "$UUFILE" - 2>&1)
rc=$?
expect names "autosec-apt-sim exit" "$rc" 0
read_by_apt=$(printf '%s\n' "$out" | sed -n 's/^A Unattended-Upgrade::Lab[0-9]* "\(.*\)";$/\1/p' | sort | paste -sd' ' -)
shown=$(printf '%s\n' "$out" | sed -n 's/^S \([^ ]*\) .*/\1/p' | sort -u | paste -sd' ' -)
expect names "files apt reads" "$read_by_apt" "52a:b 52b.c.conf 52noext 52x.conf"
expect names "files the trial run shows lines of (same rule as apt)" "$shown" "$read_by_apt"
rm -rf "$W/scratch/names"

# --- 2. the canary: Ubuntu 24.04 stock files plus 10periodic ---------------------
mklab canary
put canary "$HERE/fixtures/canary-10periodic" 10periodic
stock canary noble
DOCKER_PKGS=(docker-ce docker-ce-cli docker-ce-rootless-extras docker-buildx-plugin docker-compose-plugin containerd.io docker.io containerd nginx libstdc++6 runc containerd-shim nginx-common dockerXio)
[ "$UU_OK" = 1 ] && uu canary noble Ubuntu noble u2404 "${DOCKER_PKGS[@]}"

for c in default reboot rebootfalse docker security keepall enabled; do
  lab_ok canary canary "$c" "canary-$c" || continue
done
expect canary "default: keys that change" "$(j canary-default 'd["diff"]')" "[]"
expect canary "default: legacy file / restore" "$(j canary-default '[d["legacy"], d["restore"]]')" "[false, false]"
expect canary "default: no update switch of its own, nothing to write" "$(j canary-default '[d["write_periodic"], d["plan_empty"], d["off_on_purpose"]]')" "[false, true, false]"
expect canary "default: no apt file at all on the canary" "$(test -e "$W/out/canary-default.render" && echo yes || echo no)" no
expect canary "reboot: keys that change" "$(j canary-reboot 'd["diff"]')" '["Unattended-Upgrade::Automatic-Reboot", "Unattended-Upgrade::Automatic-Reboot-Time"]'
expect canary "rebootfalse: keys that change" "$(j canary-rebootfalse 'd["diff"]')" '["Unattended-Upgrade::Automatic-Reboot"]'
expect canary "docker: blacklist entries" "$(j canary-docker '" ".join(d["blacklist_re"])')" 'docker-ce$ docker-ce-cli$ docker-ce-rootless-extras$ docker-buildx-plugin$ docker-compose-plugin$ containerd\.io$ docker\.io$ containerd$ nginx$ libstdc\+\+6$'
expect canary "security: Allowed-Origins after #clear" "$(j canary-security 'd["after"].get("Unattended-Upgrade::Allowed-Origins::", [])')" "[]"
expect canary "keepall: nothing to write" "$(j canary-keepall '[d["plan_empty"], d["diff"]]')" "[true, []]"
expect canary "keepall: no candidate rendered" "$(test -e "$W/out/canary-keepall.render" && echo yes || echo no)" no
expect canary "enabled: keys that change" "$(j canary-enabled 'd["diff"]')" "[]"
for c in reboot rebootfalse docker security enabled; do validates canary canary "$W/out/canary-$c.render"; done

if [ "$UU_OK" = 1 ]; then
  uu_show canary canary
  for c in default reboot rebootfalse docker security; do
    after canary "canary-$c" "canary-$c-after"
    uu "canary-$c-after" noble Ubuntu noble u2404 "${DOCKER_PKGS[@]}"
  done
  uu_show canary canary-default-after
  if cmp -s "$W/out/uu-canary" "$W/out/uu-canary-default-after"; then
    pass canary "default: unattended-upgrades uses exactly the same settings after the run"
  else
    fail canary "default: unattended-upgrades settings differ: $(diff "$W/out/uu-canary" "$W/out/uu-canary-default-after" | paste -sd' ' -)"
  fi
  uu_line canary canary "reboot False now True" "today: automatic reboot"
  uu_line canary canary-reboot-after "reboot True 03:30 True" "reboot: automatic reboot"
  uu_line canary canary-rebootfalse-after "reboot False now True" "rebootfalse: automatic reboot"
  for p in docker-ce docker-ce-cli docker-ce-rootless-extras docker-buildx-plugin docker-compose-plugin containerd.io docker.io containerd nginx libstdc++6; do
    uu_line canary canary-docker-after "excluded $p True" "docker: excluded"
  done
  for p in runc containerd-shim nginx-common dockerXio docker-ce; do
    [ "$p" = docker-ce ] && continue
    uu_line canary canary-docker-after "excluded $p False" "docker: not excluded"
  done
  uu_line canary canary-default-after "excluded docker-ce False" "default: docker-ce not excluded"
  for a in "u2404-release YES" "u2404-security YES" "u2404-esm-apps YES" "u2404-updates no"; do
    uu_line canary canary-default-after "archive $a" "default: archive"
    uu_line canary canary-security-after "archive $a" "security: archive"
  done
  expect canary "security: origins unattended-upgrades uses" "$(grep -c '^origin ' "$W/out/uu-canary-security-after")" 6
else
  skip canary "unattended-upgrades checks"
fi

# --- 3. a file of yours read after auto_sec's, and broken apt files ----------------
clone canary over-reboot
printf 'Unattended-Upgrade::Automatic-Reboot "true";\n' >"$W/lab/over-reboot/parts/52unattended-upgrades-local"
lab_refused refuse over-reboot rebootfalse over-reboot-false "would NOT use what you chose"
if grep -Fq '52unattended-upgrades-local 1:Unattended-Upgrade::Automatic-Reboot' "$W/out/over-reboot-false.log"; then
  pass refuse "rebootfalse: the message names your line (52unattended-upgrades-local 1:...)"
else fail refuse "rebootfalse: the message does not name the line"; fi
lab_ok refuse over-reboot default over-reboot-default

clone canary over-origins
# shellcheck disable=SC2016 # apt macros, not shell variables
printf 'Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-updates";\n' \
  >"$W/lab/over-origins/parts/52unattended-upgrades-local"
lab_refused refuse over-origins security over-origins-security "origins are not security only"
# A later file that re-adds only ESM security origins (what Ubuntu Pro's
# 51ubuntu-advantage-esm does) keeps "security only": no refusal.
clone canary over-esm
# shellcheck disable=SC2016 # apt macros, not shell variables
printf 'Unattended-Upgrade::Allowed-Origins:: "${distro_id}ESMApps:${distro_codename}-apps-security";\n' \
  >"$W/lab/over-esm/parts/51ubuntu-advantage-esm"
lab_ok refuse over-esm security over-esm-security

clone canary over-blacklist
printf '#clear Unattended-Upgrade::Package-Blacklist;\n' >"$W/lab/over-blacklist/parts/99local"
lab_refused refuse over-blacklist docker over-blacklist-docker "Package-Blacklist lacks"

clone canary over-off
printf 'APT::Periodic::Unattended-Upgrade "0";\n' >"$W/lab/over-off/parts/99local"
lab_refused refuse over-off enabled over-off-enabled "automatic updates would be off"
if lab_ok refuse over-off default over-off-default; then
  expect refuse "auto with updates off in your file: left off" "$(j over-off-default '[d["off_on_purpose"], d["write_periodic"], d["diff"]]')" "[true, false, []]"
fi

clone canary broken-now
printf 'Foo::Bar "x" junk;\n' >"$W/lab/broken-now/parts/60broken"
APT_CONFIG="$W/lab/broken-now/apt.conf" sh -c "$(cat "$SIM")" sh "$W/lab/broken-now/parts" "$W/scratch/bn" - "$UUFILE" - >"$W/out/broken-now.out" 2>&1
expect refuse "an apt file broken now: autosec-apt-sim exit" "$?" 91
expect refuse "an apt file broken now: apt's error is shown" "$(grep -q '^E E: Syntax error' "$W/out/broken-now.out" && echo yes)" yes
printf 'Foo::Bar "x" junk;\n' >"$W/out/broken-candidate"
APT_CONFIG="$W/lab/canary/apt.conf" sh -c "$(cat "$SIM")" sh "$W/lab/canary/parts" "$W/scratch/bc" "$W/out/broken-candidate" "$UUFILE" - >"$W/out/broken-cand.out" 2>&1
expect refuse "a broken candidate: autosec-apt-sim exit" "$?" 92
rm -rf "$W/scratch/bn" "$W/scratch/bc"

# --- 4. Debian 12: stock, and fresh (unattended-upgrades not installed yet) ---------
mklab deb12
stock deb12 bookworm
for c in default security; do lab_ok deb12 deb12 "$c" "deb12-$c"; done
expect deb12 "stock + default: keys that change" "$(j deb12-default 'd["diff"]')" "[]"
mklab deb12fresh
lab_ok deb12 deb12fresh default deb12fresh-default -e lab_installed=false
expect deb12 "fresh: installs the package, writes no switch of its own" \
  "$(j deb12fresh-default '[d["install"], d["write_periodic"], d["plan_empty"], d["off_on_purpose"]]')" "[true, false, true, false]"
# The package's postinst installs its 20auto-upgrades ("1", "1") when debconf
# unattended-upgrades/enable_auto_updates is true, the default of every
# release here: that turns the updates on, not auto_sec.
for s in $SETS; do
  expect deb12 "$s: debconf default of enable_auto_updates" \
    "$(awk '/^Template: unattended-upgrades\/enable_auto_updates$/ { t = 1; next } t && /^Default:/ { print $2; exit }' "$W/ctl/$s/templates")" true
done
expect deb12 "postinst writes 20auto-upgrades from the package copy when debconf says true" \
  "$(grep -c 'NEWFILE="/usr/share/unattended-upgrades/20auto-upgrades"$' "$W/ctl/bookworm/postinst")" 1
if [ "$UU_OK" = 1 ]; then
  uu deb12 bookworm Debian bookworm deb12
  after deb12 deb12-default deb12-default-after
  after deb12 deb12-security deb12-security-after
  # Fresh host after the run: only the package's files (role 01 step 1).
  after deb12 deb12fresh-default deb12fresh-after
  uu deb12-default-after bookworm Debian bookworm deb12
  uu deb12-security-after bookworm Debian bookworm deb12
  uu deb12fresh-after bookworm Debian bookworm deb12
  uu_show deb12 deb12fresh-after
  if cmp -s "$W/out/uu-deb12" "$W/out/uu-deb12-default-after"; then
    pass deb12 "stock + default: unattended-upgrades uses exactly the same settings after the run"
  else fail deb12 "stock + default: settings differ"; fi
  for a in "deb12-main YES" "deb12-security YES" "deb12-updates no"; do
    uu_line deb12 deb12fresh-after "archive $a" "fresh, after the run: archive"
  done
  uu_line deb12 deb12fresh-after "periodic 1 1 -" "fresh, after the run: periodic switches"
  uu_line deb12 deb12fresh-after "reboot False now True" "fresh, after the run: automatic reboot"
  for a in "deb12-main no" "deb12-security YES" "deb12-updates no"; do
    uu_line deb12 deb12-security-after "archive $a" "security: archive"
  done
else
  skip deb12 "unattended-upgrades checks"
fi

# --- 5. hosts set up by auto_sec 0.1-0.4 -------------------------------------------
# The migration needs -e apt_migrate_unattended_upgrades=true, once (like
# role 03's jail.local and role 02's sshd_config): without it the run stops
# and lists what putting the distro file back changes.
MIG=(-e apt_migrate_unattended_upgrades=true)
for v in "legacy noble Ubuntu noble u2404" "legacydeb bookworm Debian bookworm deb12"; do
  read -r l s did code pfx <<<"$v"
  mklab "$l"
  put "$l" "$(ud "$s")/20auto-upgrades" 20auto-upgrades
  put "$l" "$HERE/fixtures/legacy-50unattended-upgrades" 50unattended-upgrades
  pristine=$(ud "$s")/50unattended-upgrades
  lab_refused legacy "$l" default "$l-noswitch" "is the file auto_sec 0.1-0.4 wrote" -e "lab_pristine=$pristine" -e "lab_dpkg_md5=$(dpkg_md5 "$s")"
  if grep -Fq 'Unattended-Upgrade::Automatic-Reboot: true -> (unset)' "$W/out/$l-noswitch.log"; then
    pass legacy "$l: the refusal lists what the migration changes (reboot true -> unset)"
  else fail legacy "$l: the refusal does not list the reboot change"; fi
  lab_ok legacy "$l" default "$l-default" -e "lab_pristine=$pristine" -e "lab_dpkg_md5=$(dpkg_md5 "$s")" "${MIG[@]}"
  expect legacy "$l: with the switch: legacy file found, distro copy verified, restore" "$(j "$l-default" '[d["legacy"], d["restore"]]')" "[true, true]"
  lab_refused legacy "$l" default "$l-badmd5" "reinstall unattended-upgrades first" -e "lab_pristine=$pristine" \
    -e "lab_dpkg_md5=00000000000000000000000000000000"
  lab_refused legacy "$l" default "$l-badmd5-switch" "cannot put it back" -e "lab_pristine=$pristine" \
    -e "lab_dpkg_md5=00000000000000000000000000000000" "${MIG[@]}"
  if [ "$UU_OK" = 1 ]; then
    uu "$l" "$s" "$did" "$code" "$pfx"
    after "$l" "$l-default" "$l-after" "$pristine"
    uu "$l-after" "$s" "$did" "$code" "$pfx"
    uu_show legacy "$l"
    uu_show legacy "$l-after"
  fi
done
expect legacy "legacy: keys that change" "$(j legacy-default '[k for k in d["diff"] if k in ("Unattended-Upgrade::Automatic-Reboot", "Unattended-Upgrade::Automatic-Reboot-Time", "Unattended-Upgrade::Remove-Unused-Dependencies", "Unattended-Upgrade::Allowed-Origins::")]')" \
  '["Unattended-Upgrade::Allowed-Origins::", "Unattended-Upgrade::Automatic-Reboot", "Unattended-Upgrade::Automatic-Reboot-Time", "Unattended-Upgrade::Remove-Unused-Dependencies"]'
lab_refused legacy canary default canary-switch "there is nothing to migrate" "${MIG[@]}"
if [ "$UU_OK" = 1 ]; then
  uu_line legacy legacy "reboot True 04:00 True" "Ubuntu 0.4 host today: automatic reboot"
  uu_line legacy legacy "archive u2404-release no" "Ubuntu 0.4 host today: release pocket"
  uu_line legacy legacy-after "reboot False now True" "Ubuntu 0.4 host after the run: automatic reboot"
  uu_line legacy legacy-after "remove_unused False" "Ubuntu 0.4 host after the run: Remove-Unused-Dependencies"
  for a in "u2404-release YES" "u2404-security YES" "u2404-esm-apps YES" "u2404-updates no"; do
    uu_line legacy legacy-after "archive $a" "Ubuntu 0.4 host after the run: archive"
  done
  for a in "deb12-main no" "deb12-security no" "deb12-updates no"; do
    uu_line legacy legacydeb "archive $a" "Debian 0.4 host today (false assurance): archive"
  done
  for a in "deb12-main YES" "deb12-security YES"; do
    uu_line legacy legacydeb-after "archive $a" "Debian 0.4 host after the run: archive"
  done
  # After the restore the Ubuntu host reads exactly like a stock one (with
  # the defaults auto_sec writes no file of its own).
  expect legacy "0.4 host, defaults: no apt file of auto_sec's" "$(test -e "$W/out/legacy-default.render" && echo yes || echo no)" no
  mklab stock-noble
  stock stock-noble noble
  uu stock-noble noble Ubuntu noble u2404
  if cmp -s "$W/out/uu-stock-noble" "$W/out/uu-legacy-after"; then
    pass legacy "Ubuntu 0.4 host after the run = a stock 24.04 host"
  else fail legacy "Ubuntu 0.4 host after the run differs from stock"; fi
fi

# --- 6. updates switched off on purpose --------------------------------------------
clone canary off
put off "$(ud noble)/20auto-upgrades-disabled" 20auto-upgrades
lab_ok off off default off-default
expect off "auto: left off" "$(j off-default '[d["off_on_purpose"], d["write_periodic"], d["diff"]]')" "[true, false, []]"
lab_ok off off enabled off-enabled
expect off "true: turned on" "$(j off-enabled 'd["diff"]')" '["APT::Periodic::Unattended-Upgrade", "APT::Periodic::Update-Package-Lists"]'
if [ "$UU_OK" = 1 ]; then
  after off off-enabled off-enabled-after
  uu off-enabled-after noble Ubuntu noble u2404
  uu_line off off-enabled-after "periodic 1 1 -" "true: periodic switches after the run"
fi
# The distro's off switch keeps working after a run (auto): the operator
# answers No in `dpkg-reconfigure unattended-upgrades`, whose postinst puts
# 20auto-upgrades-disabled in place; the next run leaves the updates off.
clone canary dr
lab_ok off dr default dr-first
after dr dr-first dr-after
put dr-after "$(ud noble)/20auto-upgrades-disabled" 20auto-upgrades
expect off "dpkg-reconfigure off after a run: apt reads" \
  "$(APT_CONFIG="$W/lab/dr-after/apt.conf" apt-config dump | sed -n 's/^APT::Periodic::Unattended-Upgrade "\(.*\)";$/\1/p')" 0
lab_ok off dr-after default dr-second
expect off "dpkg-reconfigure off after a run: the next run leaves them off and warns" \
  "$(j dr-second '[d["off_on_purpose"], d["plan_empty"], d["diff"], d["after"]["APT::Periodic::Unattended-Upgrade"]]')" '[true, true, [], ["0"]]'
# A host where an earlier run (unattended_upgrades_enabled: true, or the
# first 0.5 draft) left auto_sec's "1" switches, and 20auto-upgrades now says
# "0": in auto mode auto_sec's file goes, and the distro's "0" counts.
clone canary old51
put old51 "$(ud noble)/20auto-upgrades-disabled" 20auto-upgrades
printf '%s\n' "$HEADER from an earlier run" 'APT::Periodic::Update-Package-Lists "1";' 'APT::Periodic::Unattended-Upgrade "1";' \
  >"$W/lab/old51/parts/$UUFILE"
lab_ok off old51 default old51-default
expect off "earlier auto_sec switches, distro says 0: file removed, off on purpose" \
  "$(j old51-default '[d["plan_empty"], d["off_on_purpose"], d["diff"], d["after"]["APT::Periodic::Unattended-Upgrade"]]')" \
  '[true, true, ["APT::Periodic::Unattended-Upgrade", "APT::Periodic::Update-Package-Lists"], ["0"]]'
# The same host with keep (the default with autosec_server: existing):
# auto_sec's file stays, so its "1" switches still count.
lab_ok off old51 keepall old51-keepall
expect off "earlier auto_sec switches, keep: the file stays, nothing changes" \
  "$(j old51-keepall '[d["plan_empty"], d["file_change"], d["diff"], d["off_on_purpose"], d["after"]["APT::Periodic::Unattended-Upgrade"]]')" \
  '[true, "none", [], false, ["1"]]'
clone old51 p-old51-keepall
if lab_ok off p-old51-keepall keepall p-old51-keepall -e lab_prove=true; then
  expect off "earlier auto_sec switches, keep: after main step 3 the file is there and apt reads the same" \
    "$(j p-old51-keepall '[d["real_after"] == d["before"], d["real_after"]["APT::Periodic::Unattended-Upgrade"]]') $(test -f "$W/lab/p-old51-keepall/parts/$UUFILE" && echo file)" \
    '[true, ["1"]] file'
fi
# keep with another unattended_* value would rewrite that file without the
# switches: refused.
lab_refused off old51 rebootfalse old51-rebootfalse "[R01-U1] unattended_upgrades_enabled is keep"
# An interval of yours ("7": weekly; "always") is left alone in auto mode.
for iv in 7 always; do
  clone canary "iv-$iv"
  printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "%s";\n' "$iv" >"$W/lab/iv-$iv/parts/20auto-upgrades"
  lab_ok off "iv-$iv" default "iv-$iv-default"
  expect off "your interval \"$iv\": left alone, not off" "$(j "iv-$iv-default" '[d["plan_empty"], d["off_on_purpose"], d["diff"]]')" '[true, false, []]'
done
# unattended-upgrades removed on purpose (dpkg "rc"): auto does not reinstall it.
lab_ok off canary default rc-default -e lab_installed=false -e lab_removed=true
expect off "removed (rc): not installed again, off on purpose" "$(j rc-default '[d["install"], d["off_on_purpose"], d["plan_empty"]]')" '[false, true, true]'
lab_ok off canary enabled rc-enabled -e lab_installed=false -e lab_removed=true
expect off "removed (rc), true: installed again" "$(j rc-enabled 'd["install"]')" true

# --- 7. the other releases: stock files, default and security -----------------------
for v in "jammy Ubuntu jammy" "trixie Debian trixie" "resolute Ubuntu resolute"; do
  read -r s did code <<<"$v"
  mklab "stock-$s"
  stock "stock-$s" "$s"
  for c in default security reboot docker; do lab_ok "$s" "stock-$s" "$c" "$s-$c"; done
  expect "$s" "stock + default: keys that change" "$(j "$s-default" 'd["diff"]')" "[]"
  validates "$s" "stock-$s" "$W/out/$s-security.render"
done
if [ "$UU_OK" = 1 ]; then
  uu stock-trixie trixie Debian trixie deb13
  after stock-trixie trixie-security trixie-security-after
  uu trixie-security-after trixie Debian trixie deb13
  for a in "deb13-main YES" "deb13-security YES"; do uu_line trixie stock-trixie "archive $a" "stock: archive"; done
  for a in "deb13-main no" "deb13-security YES"; do uu_line trixie trixie-security-after "archive $a" "security: archive"; done
fi

# --- 8. variables the preflight refuses (plan.yml) ------------------------------------
lab_refused vars canary bad-time-unquoted bad1 "YAML read an unquoted time as 210"
lab_refused vars canary bad-time-24 bad2 "Use a 24-hour time HH:MM"
lab_refused vars canary bad-time-missing bad3 "unattended_reboot_time is required"
lab_refused vars canary bad-hostname bad4 'server_hostname is \"Canary_1\"'
lab_refused vars canary bad-tz bad5 'timezone is \"../x\"'
lab_refused vars canary bad-blacklist bad6 "exact Debian package names"
lab_refused vars canary bad-enabled-false bad7 "never turns automatic updates off"

# --- 9. main step 4: the proof after the write (prove.yml) ---------------------------
for c in default reboot docker security keepall; do
  clone canary "p-canary-$c"
  if lab_ok prove "p-canary-$c" "$c" "p-canary-$c" -e lab_prove=true; then
    expect prove "canary $c: after the write, apt reads what the trial run said" "$(j "p-canary-$c" 'd["real_after"] == d["after"]')" true
  fi
done
clone legacy p-legacy
if lab_ok prove p-legacy default p-legacy -e lab_prove=true -e "lab_pristine=$(ud noble)/50unattended-upgrades" \
  -e "lab_dpkg_md5=$(dpkg_md5 noble)" "${MIG[@]}"; then
  expect prove "0.4 host: restored and proved" "$(j p-legacy '[d["restore"], d["real_after"] == d["after"]]')" "[true, true]"
  expect prove "0.4 host: 50unattended-upgrades is the distro file again" \
    "$(cmp -s "$W/lab/p-legacy/parts/50unattended-upgrades" "$(ud noble)/50unattended-upgrades" && echo yes)" yes
fi
mklab p-fresh
if lab_ok prove p-fresh default p-fresh -e lab_installed=false -e lab_prove=true -e "lab_install_from=$(ud bookworm)"; then
  expect prove "fresh Debian 12: updates on after the package is installed" \
    "$(j p-fresh '[d["real_after"]["APT::Periodic::Unattended-Upgrade"], d["real_after"]["APT::Periodic::Update-Package-Lists"]]')" '[["1"], ["1"]]'
fi
clone canary p-inject1
lab_refused prove p-inject1 rebootfalse p-inject1 "but apt now uses" -e lab_prove=true \
  -e '{"lab_inject": "Unattended-Upgrade::Automatic-Reboot \"true\";"}'
clone canary p-inject2
lab_refused prove p-inject2 default p-inject2 "different configuration than the trial run predicted" -e lab_prove=true \
  -e '{"lab_inject": "Unattended-Upgrade::Mail \"root\";"}'

# --- 10. the account and its sudo rule (account.yml, sudo_check.yml) ------------
# account.yml runs against lab trees: their own sudoers, sudoers.d, sysctl
# files. Fake getent, id and dpkg-query come first in PATH; visudo is the
# real one, run on the lab with -f.
mkdir -p "$W/fakebin2" "$W/acct"
cat >"$W/fakebin2/getent" <<'FAKE'
#!/bin/sh
# Fake getent passwd <name>: the line from $LAB_PASSWD, else exit 2.
[ "$1" = passwd ] || exit 1
grep -m1 "^$2:" "$LAB_PASSWD" 2>/dev/null || exit 2
FAKE
cat >"$W/fakebin2/id" <<'FAKE'
#!/bin/sh
# Fake id -nG|-u|-G [--] <name>: for an account in $LAB_PASSWD, its groups
# from $LAB_GROUPS ("name group..."), its uid from $LAB_PASSWD, its gids
# from $LAB_GIDS ("name gid..."); else exit 1, as id does.
o=$1; shift
[ "${1:-}" = -- ] && shift
grep -q "^$1:" "$LAB_PASSWD" 2>/dev/null || { echo "id: '$1': no such user" >&2; exit 1; }
case $o in
  -nG) l=$(grep -m1 "^$1 " "$LAB_GROUPS" 2>/dev/null) || { echo "id: '$1': no such user" >&2; exit 1; }
       printf '%s\n' "${l#* }" ;;
  -u) grep -m1 "^$1:" "$LAB_PASSWD" | cut -d: -f3 ;;
  -G) l=$(grep -m1 "^$1 " "$LAB_GIDS" 2>/dev/null) || { echo "id: '$1': no such user" >&2; exit 1; }
      printf '%s\n' "${l#* }" ;;
  *) exit 1 ;;
esac
FAKE
cat >"$W/fakebin2/dpkg-query" <<'FAKE'
#!/bin/sh
# Fake: LAB_DPKG="name:ii name2:rc ..." are the known packages.
shift 2
rc=0
for p in "$@"; do
  s=$(printf '%s\n' $LAB_DPKG | sed -n "s/^$p:\(..\)$/\1/p")
  if [ -n "$s" ]; then printf '%s  %s\n' "$s" "$p"; else echo "dpkg-query: no packages found matching $p" >&2; rc=1; fi
done
exit $rc
FAKE
chmod +x "$W/fakebin2/"*
printf '%s\n' 'alice:x:1001:1001::/home/alice:/bin/sh' 'deploy:x:1002:1002::/home/deploy:/bin/bash' \
  'odd:x:1003:1003::/home/odd:/bin/sh;rm' >"$W/acct/passwd"
printf '%s\n' 'alice alice adm' 'deploy deploy sudo' 'odd odd Domain.Users' >"$W/acct/groups"
printf '%s\n' 'alice 1001 4' 'deploy 1002 27' 'odd 1003 5000' >"$W/acct/gids"
: >"$W/acct/nobody"

# A lab's directory name must not contain an account name: the scan would
# find it in the @includedir line (grep -w).
L() { printf '%s/acct/c%s' "$W" "$(printf '%s' "$1" | cksum | cut -d' ' -f1)"; }
mksudo() { # name: a lab tree like Ubuntu's: sudoers reads sudoers.d; sysctl.conf is read
  local d
  d=$(L "$1")
  rm -rf "$d"
  mkdir -p "$d/sudoers.d" "$d/sysctl.d" || die "mkdir $d"
  printf 'Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n%%admin ALL=(ALL) ALL\n%%sudo ALL=(ALL:ALL) ALL\n@includedir %s/sudoers.d\n' "$d" >"$d/sudoers"
  printf '%s\n' '#' '# Files in this directory are read by sudo. deploy is named only in this comment.' '#' >"$d/sudoers.d/README"
  : >"$d/sysctl.conf"
  ln -s ../sysctl.conf "$d/sysctl.d/99-sysctl.conf"
}
acct() { # name [ansible args...]: role 01's pieces on lab tree $W/acct/<name>; returns ansible's rc
  local n=$1 rc=0
  shift
  rm -f "$W/out/$n".*
  (cd "$HERE" && PATH="$W/fakebin2:$PATH" LAB_PASSWD="${LAB_PASSWD:-$W/acct/nobody}" LAB_GROUPS="$W/acct/groups" \
    LAB_GIDS="$W/acct/gids" \
    LAB_DPKG="${LAB_DPKG:-sudo:ii unattended-upgrades:ii}" LC_ALL=C.UTF-8 ANSIBLE_ROLES_PATH="$ROOT/roles" \
    ANSIBLE_LOCALHOST_WARNING=False ANSIBLE_INVENTORY_UNPARSED_WARNING=False ANSIBLE_NOCOLOR=1 \
    ANSIBLE_RETRY_FILES_ENABLED=False \
    ansible-playbook account.yml -e "lab_dir=$(L "$n")" -e "lab_out=$W/out/$n.json" -e deploy_user=deploy "$@") \
    >"$W/out/$n.log" 2>&1 || rc=$?
  return "$rc"
}
acct_ok() { # test name [args...]
  local t=$1
  shift
  if acct "$@"; then pass "$t" "$1: passes"; return 0; fi
  fail "$t" "$1: refused (log $W/out/$1.log):"
  grep -E '"msg"|ERROR' "$W/out/$1.log" | head -n 3 | cut -c1-400
  return 1
}
acct_refused() { # test name fixed-string [args...]: must refuse with that message
  local t=$1 n=$2 s=$3 rc=0
  shift 3
  acct "$n" "$@" || rc=$?
  if [ "$rc" -eq 0 ]; then fail "$t" "$n: run succeeded, want a refusal"; return; fi
  if grep -Fq -- "$s" "$W/out/$n.log"; then pass "$t" "$n: refused with \"$s\""
  else fail "$t" "$n: refused (rc $rc) but without \"$s\" (log $W/out/$n.log)"; grep -E '"msg"|ERROR' "$W/out/$n.log" | head -n 3 | cut -c1-400; fi
  if [ -e "$(L "$n")/run/sudoers-candidate" ]; then fail "$t" "$n: the rendered sudo file was left behind"; fi
}
NEW=(-e autosec_server=new)
CREATE=(-e deploy_user_account=create)

# Defaults: with autosec_server unset or existing, every choice is keep.
for c in unset existing; do
  mksudo "def-$c"
  # shellcheck disable=SC2046 # no argument at all for unset
  if acct_ok acct "def-$c" $( [ "$c" = existing ] && echo "-e autosec_server=existing" ); then
    expect acct "$c: account keep, updates keep, nothing planned, no package" \
      "$(j "def-$c" '[d["account_mode"], d["uu_enabled"], d["user_plan"], d["sudo_write"], d["pkg_want"], d["plan"]]')" \
      '["keep", "keep", "keep", false, [], []]'
    expect acct "$c: the sudo configuration is not even read" "$(j "def-$c" 'd["sudo"]["checked"]')" false
  fi
done
mksudo new
if acct_ok acct new "${NEW[@]}" -e "lab_render=$W/out/new.render"; then
  expect acct "new: create deploy and its sudo file; updates auto" \
    "$(j new '[d["account_mode"], d["uu_enabled"], d["user_plan"], d["sudo_write"], d["sudo"]["state"], d["sudo"]["checked"]]')" \
    '["create", "auto", "create", true, "absent", true]'
  expect acct "new: sudo wanted (installed here), nothing missing" "$(j new '[d["pkg_want"], d["pkgs_missing"]]')" '[["sudo"], []]'
  expect acct "new: the sudo scan finds nothing (README names deploy only in a comment)" \
    "$(j new '[d["sudo"]["includedir"], d["sudo"]["user_lines"], d["sudo"]["group_lines"], int(d["sudo"]["visudo_rc"])]')" '[true, [], [], 0]'
  expect acct "new: plan items" "$(j new '[[i["part"], i["do"], i["what"]] for i in d["plan"]]' | sed "s|$(L new)|LAB|g")" \
    '[["account", "user", "create deploy"], ["sudo", "sudoers", "write LAB/sudoers.d/deploy"]]'
  expect acct "new: the rendered sudo file is removed again" "$(j new 'd["candidate_left"]')" false
fi
mksudo new-uu
if acct_ok acct new-uu "${NEW[@]}" -e lab_uu_install=true; then
  expect acct "new, updates to install: both packages wanted" "$(j new-uu 'd["pkg_want"]')" '["unattended-upgrades", "sudo"]'
fi
mksudo new-rootadmin
if acct_ok acct new-rootadmin "${NEW[@]}" -e ssh_admin_user=root; then
  expect acct "new, ssh_admin_user root: no account" "$(j new-rootadmin '[d["account_mode"], d["uu_enabled"]]')" '["keep", "auto"]'
fi
mksudo new-deployroot
if acct_ok acct new-deployroot "${NEW[@]}" -e deploy_user=root; then
  expect acct "new, deploy_user root: no account (and no R01-A1)" "$(j new-deployroot 'd["account_mode"]')" keep
fi
mksudo create-root
acct_refused acct create-root "[R01-A1] deploy_user is root" "${CREATE[@]}" -e deploy_user=root
mksudo bad-value
acct_refused acct bad-value '[R01-A0] deploy_user_account is \"True\"' -e '{"deploy_user_account": true}'

# The file /etc/sudoers.d/<user>: whose is it?
for v in "deploy" "a_b-c" "abcdefghijklmnopqrstuvwxyz012345"; do
  mksudo "name-$v"
  if acct_ok names "name-$v" "${CREATE[@]}" -e "deploy_user=$v" -e "lab_render=$W/out/name-$v.render"; then
    if visudo -c -q -f "$W/out/name-$v.render"; then pass names "$v: visudo -cf accepts auto_sec's sudo file"
    else fail names "$v: visudo -cf rejects auto_sec's sudo file"; fi
    expect names "$v: first line is the header" "$(head -n 1 "$W/out/name-$v.render" | cut -c1-31)" "# Written by auto_sec (role 01)"
    expect names "$v: the rule line" "$(tail -n 1 "$W/out/name-$v.render")" "$v ALL=(ALL) NOPASSWD:ALL"
    expect names "$v: 0.1-0.5's exact bytes" "$(j "name-$v" 'd["legacy_sha256"]')" "$(printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$v" | sha256sum | cut -d' ' -f1)"
  fi
done
expect names "deploy: 0.1-0.5's sha256 (30 bytes, main.yml:206 in 0.5)" "$(j name-deploy 'd["legacy_sha256"]')" 62c2729541ccc891a071a3e96739f155ef56275cc8af2d373e2f1d539442dc11

mksudo legacy
printf 'deploy ALL=(ALL) NOPASSWD:ALL\n' >"$(L legacy)/sudoers.d/deploy"
if acct_ok sudofile legacy "${CREATE[@]}"; then
  expect sudofile "0.1-0.5's exact file: kept, nothing written" "$(j legacy '[d["sudo"]["state"], d["sudo_write"], d["pkg_want"]]')" '["legacy", false, []]'
fi
mksudo ours-same
cp "$W/out/new.render" "$(L ours-same)/sudoers.d/deploy"
if acct_ok sudofile ours-same "${CREATE[@]}"; then
  expect sudofile "auto_sec's file, same content: nothing written" "$(j ours-same '[d["sudo"]["state"], d["sudo_write"], d["plan"]]')" \
    '["ours", false, [{"do": "user", "note": "home, shell /bin/bash, password locked (key login only), no extra groups", "part": "account", "role": "01", "what": "create deploy"}]]'
fi
mksudo ours-diff
printf '%s\n' '# Written by auto_sec (role 01). An older text.' 'deploy ALL=(ALL) NOPASSWD:ALL' >"$(L ours-diff)/sudoers.d/deploy"
if acct_ok sudofile ours-diff "${CREATE[@]}"; then
  expect sudofile "auto_sec's file, other content: written again" "$(j ours-diff '[d["sudo"]["state"], d["sudo_write"]]')" '["ours", true]'
fi
mksudo foreign
printf 'deploy ALL=(ALL) ALL\n' >"$(L foreign)/sudoers.d/deploy"
acct_refused sudofile foreign "[R01-A2] $(L foreign)/sudoers.d/deploy on localhost was not written by auto_sec" "${CREATE[@]}"
mksudo foreign-keep
printf 'deploy ALL=(ALL) ALL\n' >"$(L foreign-keep)/sudoers.d/deploy"
if acct_ok sudofile foreign-keep; then
  expect sudofile "a file of yours with keep: no refusal, nothing planned" "$(j foreign-keep '[d["sudo"]["state"], d["sudo_write"]]')" '["foreign", false]'
fi
mksudo other-dir
mkdir "$(L other-dir)/sudoers.d/deploy"
acct_refused sudofile other-dir "is not a regular file" "${CREATE[@]}"
mksudo other-link
ln -s ../sudoers "$(L other-link)/sudoers.d/deploy"
acct_refused sudofile other-link "is not a regular file" "${CREATE[@]}"

# The scan: your rules that name the account or its groups. Groups are
# known only for an account that exists.
mksudo pct-sudo-missing
acct_ok scan pct-sudo-missing "${CREATE[@]}"
mksudo pct-sudo
LAB_PASSWD=$W/acct/passwd acct_refused scan pct-sudo \
  "[R01-A3] Your sudo configuration already names deploy or a group of deploy: $(L pct-sudo)/sudoers:4 (%sudo)" "${CREATE[@]}"
scan_case() { # name refused|ok line...: a 50ops file with these lines (deploy exists, in group sudo; no %sudo line)
  local n=$1 want=$2
  shift 2
  mksudo "$n"
  sed -i '/^%sudo/d' "$(L "$n")/sudoers"
  printf '%s\n' "$@" | sed "s|LAB|$(L "$n")|g" >"$(L "$n")/sudoers.d/50ops"
  : >"$(L "$n")/extra.deploy"
  if [ "$want" = refused ]; then
    LAB_PASSWD=$W/acct/passwd acct_refused scan "$n" "[R01-A3] Your sudo configuration already names deploy" "${CREATE[@]}"
  else
    LAB_PASSWD=$W/acct/passwd acct_ok scan "$n" "${CREATE[@]}"
  fi
}
scan_case pct-colon refused '%:sudo ALL=(ALL) NOPASSWD: ALL'
expect scan "%:sudo is named with its file and line" "$(grep -qF "$(L pct-colon)/sudoers.d/50ops:1 (%sudo)" "$W/out/pct-colon.log" && echo yes)" yes
scan_case defaults-line refused 'Defaults:deploy !requiretty'
scan_case user-alias refused 'User_Alias ADMINS = bob, deploy'
scan_case comment ok '# deploy ALL=(ALL) NOPASSWD: ALL' '   ## deploy is not here'
scan_case include-line refused '#include LAB/extra.deploy'
scan_case deployer ok 'deployer ALL=(ALL) ALL' 'Cmnd_Alias DEPLOYX = /bin/true'
scan_case deploy-ci refused 'deploy-ci ALL=(ALL) ALL'
scan_case admin-group ok '%adm ALL=(ALL) ALL'
# By number (sudoers(5): "#" and digits in a user position is a uid, not a
# comment), and netgroups, which the scan cannot resolve. deploy is uid
# 1002, gids 1002 and 27 in the lab.
scan_case by-uid refused '#1002 ALL=(ALL) ALL'
expect scan "#1002 is named with its file and line" "$(grep -qF "$(L by-uid)/sudoers.d/50ops:1" "$W/out/by-uid.log" && echo yes)" yes
scan_case by-gid refused '%#27 ALL=(ALL) ALL'
scan_case by-gid-colon refused '%:#27 ALL=(ALL) NOPASSWD: ALL'
scan_case netgroup refused '+admins ALL=(ALL) ALL'
scan_case netgroup-defaults refused 'Defaults:+admins !authenticate'
scan_case other-uid ok '#1003 ALL=(ALL) ALL' '%#4 ALL=(ALL) ALL'
scan_case number-comment ok '# 1002 is deploy' '#  1002 too'
scan_case plus-in-command ok 'bob ALL=(ALL) /usr/bin/chmod +x /srv/x'
for f in 50.ops 50ops~; do
  mksudo "skip-$f"
  printf 'deploy ALL=(ALL) ALL\n' >"$(L "skip-$f")/sudoers.d/$f"
  acct_ok scan "skip-$f" "${CREATE[@]}"
done
mksudo no-includedir
sed -i '/includedir/d' "$(L no-includedir)/sudoers"
acct_refused scan no-includedir "[R01-A4] $(L no-includedir)/sudoers on localhost does not read $(L no-includedir)/sudoers.d" "${CREATE[@]}"
mksudo hash-includedir
sed -i 's/^@includedir/#includedir/' "$(L hash-includedir)/sudoers"
if acct_ok scan hash-includedir "${CREATE[@]}"; then
  expect scan "#includedir counts as reading sudoers.d" "$(j hash-includedir 'd["sudo"]["includedir"]')" true
fi
mksudo broken
printf 'oops(\n' >"$(L broken)/sudoers.d/60bad"
acct_refused scan broken "[R01-A5] sudo cannot read its configuration on localhost now (visudo -c: $(L broken)/sudoers.d/60bad:1:5: syntax error)" \
  "${CREATE[@]}"
mksudo odd-group
sed -i '/^%sudo/d' "$(L odd-group)/sudoers"
LAB_PASSWD=$W/acct/passwd acct_refused scan odd-group "groups of odd with unusual names: Domain.Users" "${CREATE[@]}" -e deploy_user=odd
mksudo alice
if LAB_PASSWD=$W/acct/passwd acct_ok scan alice "${CREATE[@]}" -e deploy_user=alice; then
  expect scan "an existing account (shell /bin/sh, group adm): never changed, gets the sudo file" \
    "$(j alice '[d["user_plan"], d["user_shell"], d["sudo_write"], [i["do"] for i in d["plan"]]]')" '["exists", "/bin/sh", true, ["sudoers"]]'
fi
mksudo odd
if LAB_PASSWD=$W/acct/passwd acct_ok scan odd -e deploy_user=odd -e deploy_user_account=keep; then
  expect scan "keep: an existing account is only looked at; a shell of an odd shape is not shown" \
    "$(j odd '[d["user_plan"], d["user_exists"], d["user_shell"]]')" '["keep", true, ""]'
fi
mksudo nosudo
if LAB_DPKG="unattended-upgrades:ii" acct_ok scan nosudo "${CREATE[@]}"; then
  expect scan "sudo missing: it is installed first, the scan waits for main step 1" \
    "$(j nosudo '[d["pkg_want"], d["pkgs_missing"], d["sudo_installed"], d["sudo"]["checked"], [i["what"] for i in d["plan"]][:1]]')" \
    '[["sudo"], ["sudo"], false, false, ["sudo"]]'
fi

# Main step 6b: the reads right before the write must equal the preflight's.
mksudo m-file
acct_refused main m-file "[M01-A1] $(L m-file)/sudoers.d/deploy on localhost changed during this run" "${CREATE[@]}" \
  -e 'lab_mutate=deploy ALL=(ALL) NOPASSWD:ALL'
mksudo m-other
sed -i '/^%sudo/d' "$(L m-other)/sudoers"
LAB_PASSWD=$W/acct/passwd acct_refused main m-rule "[M01-A1]" "${CREATE[@]}" -e "lab_dir=$(L m-other)" \
  -e '{"lab_mutate": "deploy ALL=(ALL) ALL", "lab_mutate_file": "99late"}'
mksudo m-same
acct_ok main m-same "${CREATE[@]}" -e '{"lab_mutate": "Defaults env_reset", "lab_mutate_file": "99other"}'

# --- 11. the account role 02 logs in as (admin.yml) -----------------------------
SSH='"_ssh_role_runs": true, "_ssh_enabled": true'
mksudo b12
acct_refused admin b12-other "[R01-A6] ssh_admin_user is carol, but carol does not exist on localhost, and this run does not create it (it is not deploy_user)" \
  -e "{$SSH, \"_ssh_admin\": \"carol\"}" -e "lab_dir=$(L b12)"
acct_refused admin b12-keep "(deploy_user_account is keep)" -e "{$SSH, \"_ssh_admin\": \"deploy\"}" -e "lab_dir=$(L b12)"
acct_refused admin b12-tags "(role 01 is not in this run's tags)" -e "{$SSH, \"_ssh_admin\": \"deploy\"}" "${CREATE[@]}" \
  -e lab_role_runs=false -e "lab_dir=$(L b12)"
acct_ok admin b12-create -e "{$SSH, \"_ssh_admin\": \"deploy\"}" "${CREATE[@]}" -e "lab_dir=$(L b12)"
acct_refused admin b12-pam "[R01-A7] deploy would be created password-locked (key login only), but sshd on localhost has UsePAM no" \
  -e "{$SSH, \"_ssh_admin\": \"deploy\", \"_ssh_before\": {\"admin\": {\"usepam\": \"no\"}, \"root\": {\"usepam\": \"no\"}}}" "${CREATE[@]}" \
  -e "lab_dir=$(L b12)"
acct_ok admin b12-pam-yes -e "{$SSH, \"_ssh_admin\": \"deploy\", \"_ssh_before\": {\"admin\": {\"usepam\": \"yes\"}}}" "${CREATE[@]}" \
  -e "lab_dir=$(L b12)"
LAB_PASSWD=$W/acct/passwd acct_ok admin b12-exists -e "{$SSH, \"_ssh_admin\": \"alice\"}" -e "lab_dir=$(L b12)"
if acct_ok admin b12-root -e "{$SSH, \"_ssh_admin\": \"root\"}" -e "lab_dir=$(L b12)"; then
  expect admin "ssh_admin_user root: not checked" "$(j b12-root 'd["b12"]')" false
fi
if acct_ok admin b12-nossh -e '{"_ssh_role_runs": false, "_ssh_enabled": true, "_ssh_admin": "carol"}' -e "lab_dir=$(L b12)"; then
  expect admin "role 02 not in the run: not checked" "$(j b12-nossh 'd["b12"]')" false
fi

# --- 12. kernel settings, read only (kernel.yml) -----------------------------------
LEGACY7='net.ipv4.tcp_syncookies=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
kernel.dmesg_restrict=1'
mksudo k-legacy
printf '# /etc/sysctl.conf\n;comment\n\n%s\n' "$LEGACY7" >"$(L k-legacy)/sysctl.conf"
if acct_ok kernel k-legacy; then
  expect kernel "0.1-0.5's 7 lines, read at boot: N01-K2 only" "$(j k-legacy '[int(d["sysctl_lines"]), d["sysctl_legacy"], d["sysctl_unread"]]')" '[7, true, false]'
fi
mksudo k-deb13
printf 'vm.swappiness=10\nnet.ipv4.ip_forward = 0\n' >"$(L k-deb13)/sysctl.conf"
rm "$(L k-deb13)/sysctl.d/99-sysctl.conf"
if acct_ok kernel k-deb13; then
  expect kernel "settings, but 99-sysctl.conf does not lead to the file (Debian 13): N01-K1" "$(j k-deb13 '[int(d["sysctl_lines"]), d["sysctl_legacy"], d["sysctl_unread"]]')" '[2, false, true]'
fi
mksudo k-comments
printf '# only comments\n;and this\n   \n' >"$(L k-comments)/sysctl.conf"
rm "$(L k-comments)/sysctl.d/99-sysctl.conf"
if acct_ok kernel k-comments; then
  expect kernel "only comments: nothing to say" "$(j k-comments '[int(d["sysctl_lines"]), d["sysctl_unread"]]')" '[0, false]'
fi
mksudo k-six
printf '%s\n' "$LEGACY7" | head -n 6 >"$(L k-six)/sysctl.conf"
if acct_ok kernel k-six; then
  expect kernel "6 of the 7 lines: not 0.1-0.5's set" "$(j k-six 'd["sysctl_legacy"]')" false
fi

# --- 13. plan items (plan_items.yml) ------------------------------------------------
mksudo plan
MORE=(-e lab_uu_change=write -e server_hostname=mail.example.com -e timezone=Europe/Berlin -e apt_full_upgrade=true -e lab_pending=3)
if acct_ok plan plan-a "${NEW[@]}" "${MORE[@]}" -e "lab_dir=$(L plan)"; then
  expect plan "items" "$(j plan-a '[[i["role"], i["part"], i["do"]] for i in d["plan"]]')" \
    '[["01", "updates", "write"], ["01", "updates", "install"], ["01", "account", "user"], ["01", "sudo", "sudoers"], ["01", "hostname", "write"], ["01", "timezone", "write"]]'
  expect plan "the dos are in the plan contract" "$(j plan-a 'sorted(set(i["do"] for i in d["plan"]) - set("write replace install start restart reload daemon-reload enable add-rule policy firewall-on user sudoers cron timer network-call local-file".split()))')" "[]"
  expect plan "what: only your values and constant names" "$(j plan-a '[i["what"] for i in d["plan"] if i["part"] in ("hostname", "timezone", "updates")]')" \
    '["write /etc/apt/apt.conf.d/51autosec-unattended-upgrades: comments only", "apt-get dist-upgrade (apt_full_upgrade)", "hostname mail.example.com", "timezone Europe/Berlin"]'
fi
# What auto_sec's apt file says is part of the item, so another value gives
# another plan id.
if acct_ok plan plan-d "${NEW[@]}" "${MORE[@]}" -e lab_uu_periodic=true -e unattended_automatic_reboot=true \
     -e unattended_reboot_time=03:30 -e unattended_exclude_docker=true -e unattended_origins=security -e "lab_dir=$(L plan)"; then
  expect plan "the apt file's values are in its item" "$(j plan-d '[i["what"] for i in d["plan"] if i["part"] == "updates"][0]')" \
    "write /etc/apt/apt.conf.d/51autosec-unattended-upgrades: updates on (Update-Package-Lists 1, Unattended-Upgrade 1); Automatic-Reboot true at 03:30; blacklist docker-ce docker-ce-cli docker-ce-rootless-extras docker-buildx-plugin docker-compose-plugin containerd.io docker.io containerd; origins security"
fi
if acct_ok plan plan-b "${NEW[@]}" "${MORE[@]}" -e lab_tz_now=Asia/Tokyo -e lab_pending=7 -e "lab_dir=$(L plan)"; then
  expect plan "host values change only the notes" "$(j plan-a '[{k: v for k, v in i.items() if k != "note"} for i in d["plan"]]')" \
    "$(j plan-b '[{k: v for k, v in i.items() if k != "note"} for i in d["plan"]]')"
  if [ "$(j plan-a '[i["note"] for i in d["plan"]]')" != "$(j plan-b '[i["note"] for i in d["plan"]]')" ]; then
    pass plan "and the notes do change"
  else fail plan "the notes do not change with the host values"; fi
fi
if acct_ok plan plan-c "${NEW[@]}" "${MORE[@]}" -e timezone=UTC -e "lab_dir=$(L plan)"; then
  if [ "$(j plan-a '[i["what"] for i in d["plan"]]')" != "$(j plan-c '[i["what"] for i in d["plan"]]')" ]; then
    pass plan "a changed value changes an item"
  else fail plan "a changed value does not change any item"; fi
fi

echo
echo "$PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
