#!/usr/bin/env bash
# base-semantics: unprivileged tests of role 01's apt handling (#3, auto_sec
# 0.5). No root and nothing installed: the pinned unattended-upgrades .debs
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
# and the stock files of 22.04, 13 and 26.04. Last, role 01's packages.yml
# (install only, upgrade nothing) runs against canned apt output (pkg.yml).
#
# Usage: tests/base/semantics/run.sh [--cache DIR]... [--keep] [--verbose]
#   --cache DIR  where the .debs are kept. Searched 3 levels deep by package
#                and version (an apt download dir works too). Repeatable: all
#                are searched, a missing file is downloaded into the FIRST.
#                Default: ~/.cache/auto-sec-base-semantics
#   --keep       keep the work directory and print its path
#   --verbose    print what unattended-upgrades uses in every lab
# Needs: curl dpkg-deb sha256sum apt-config ansible-playbook python3. The
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
for t in curl dpkg-deb sha256sum apt-config ansible-playbook python3; do
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

# --- 10. packages: install only, upgrade or remove nothing (packages.yml) --------------
# Fake dpkg-query and apt-get first in PATH print canned output. The apt-get
# outputs in fixtures/pkg-*.txt are real `apt-get -s --no-install-recommends
# install` output of apt 2.7 (Ubuntu 24.04), with the package names kept.
mkdir -p "$W/fakebin"
cat >"$W/fakebin/dpkg-query" <<'FAKE'
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
cat >"$W/fakebin/apt-get" <<'FAKE'
#!/bin/sh
# Fake: prints $LAB_APT_OUT (its "E:" lines on stderr, as apt does) and
# exits $LAB_APT_RC; records its arguments.
printf '%s\n' "$*" >"$LAB_APT_ARGS"
grep -v '^E:' "$LAB_APT_OUT"
grep '^E:' "$LAB_APT_OUT" >&2
exit "${LAB_APT_RC:-0}"
FAKE
chmod +x "$W/fakebin/dpkg-query" "$W/fakebin/apt-get"
pkg() { # name dpkg-state apt-out apt-rc [ansible args...]: returns ansible's rc
  local n=$1 rc=0
  rm -f "$W/out/$n".*
  (cd "$HERE" && PATH="$W/fakebin:$PATH" LAB_DPKG="$2" LAB_APT_OUT="$HERE/fixtures/$3" LAB_APT_RC="$4" \
    LAB_APT_ARGS="$W/out/$n.args" LC_ALL=C.UTF-8 ANSIBLE_ROLES_PATH="$ROOT/roles" ANSIBLE_LOCALHOST_WARNING=False \
    ANSIBLE_INVENTORY_UNPARSED_WARNING=False ANSIBLE_NOCOLOR=1 ANSIBLE_RETRY_FILES_ENABLED=False \
    ansible-playbook pkg.yml -e "lab_out=$W/out/$n.json" "${@:5}") >"$W/out/$n.log" 2>&1 || rc=$?
  return "$rc"
}
pkg_ok() { # test name ...
  local t=$1
  shift
  if pkg "$@"; then pass "$t" "$1: passes"; return 0; fi
  fail "$t" "$1: refused (log $W/out/$1.log)"; grep -E '"msg"' "$W/out/$1.log" | head -n 3 | cut -c1-400; return 1
}
pkg_refused() { # test name msg dpkg-state apt-out apt-rc [args...]
  local t=$1 n=$2 s=$3 rc=0
  shift 3
  pkg "$n" "$@" || rc=$?
  if [ "$rc" -eq 0 ]; then fail "$t" "$n: run succeeded, want a refusal"; return; fi
  if grep -Fq -- "$s" "$W/out/$n.log"; then pass "$t" "$n: refused with \"$s\""
  else fail "$t" "$n: refused (rc $rc) but without \"$s\" (log $W/out/$n.log)"; fi
}
if pkg_ok pkgs k-all "curl:ii unattended-upgrades:ii" pkg-clean.txt 0; then
  expect pkgs "everything installed: nothing to install, apt not asked" \
    "$(j k-all '[d["missing"], d["side"]]')/$(test -e "$W/out/k-all.args" && echo asked || echo not-asked)" "[[], []]/not-asked"
fi
if pkg_ok pkgs k-held "curl:hi unattended-upgrades:ii" pkg-clean.txt 0; then
  expect pkgs "a held package counts as installed" "$(j k-held 'd["missing"]')" "[]"
fi
if pkg_ok pkgs k-clean "unattended-upgrades:ii" pkg-clean.txt 0; then
  expect pkgs "curl missing, a clean install" "$(j k-clean '[d["missing"], d["side"]]')" '[["curl"], []]'
  expect pkgs "apt is asked without recommendations" "$(cat "$W/out/k-clean.args")" "-s -o Debug::NoLocking=true --no-install-recommends install curl"
fi
pkg_refused pkgs k-upgrade "would also change packages you have: libapparmor1 4.0.1really4.0.1-0ubuntu0.24.04.3 -> 4.0.1really4.0.1-0ubuntu0.24.04.7" \
  "unattended-upgrades:ii" pkg-upgrade.txt 0
pkg_refused pkgs k-upgrade-main "only the package lists were refreshed" "unattended-upgrades:ii" pkg-upgrade.txt 0 -e lab_ctx=main
if pkg_ok pkgs k-upgrade-full "unattended-upgrades:ii" pkg-upgrade.txt 0 -e lab_full_upgrade=true; then
  expect pkgs "apt_full_upgrade allows the upgrades" "$(j k-upgrade-full 'len(d["side"])')" 2
fi
pkg_refused pkgs k-remove "remove systemd-timesyncd 255.4-1ubuntu8.16" "unattended-upgrades:ii" pkg-remove.txt 0
if pkg_ok pkgs k-nolists "unattended-upgrades:ii" pkg-nolists.txt 100; then
  expect pkgs "no package lists yet (preflight): a note, checked again in main" "$(grep -c "NOTE: apt cannot plan the install of curl" "$W/out/k-nolists.log")" 1
fi
pkg_refused pkgs k-nolists-main "apt cannot install curl" "unattended-upgrades:ii" pkg-nolists.txt 100 -e lab_ctx=main
if pkg_ok pkgs k-uukeep "curl:ii" pkg-clean.txt 0 -e lab_uu_install=false; then
  expect pkgs "unattended-upgrades not wanted (keep, or removed in auto): not installed" "$(j k-uukeep 'd["missing"]')" "[]"
fi
if pkg_ok pkgs k-uufresh "curl:ii" pkg-clean.txt 0; then
  expect pkgs "unattended-upgrades missing (auto): installed" "$(j k-uufresh 'd["missing"]')" '["unattended-upgrades"]'
fi

echo
echo "$PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
