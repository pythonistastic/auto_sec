#!/usr/bin/env bash
# detection-semantics: lab tests of role 08 (login alerts). No root, nothing
# installed, and never the real Telegram: every message goes to
# tests/detection/fake_telegram.py on 127.0.0.1 or to a list in memory.
#   h  the login hook (test_hook.py): the event file; exit 0 at once when
#      the queue is missing, read-only or full; odd PAM values; no other
#      program is run; a hook that hangs is cut off after 1 second
#   p  PAM (test_pam.py), with the real code of the pinned .debs in debs.txt
#      (SHA256-checked, unpacked with dpkg-deb, never installed): each
#      release's pam_exec.so with the profile's own line, and each release's
#      pam-auth-update through role 08's trial helper (hand edits, a waiting
#      profile, real run = trial, removal byte for byte)
#   u  auto-sec-detect (test_detect.py): the journal reader on real log
#      lines (fixtures/journal-lines.txt), the sender, the quiet rules,
#      retries, bursts, Telegram's 429, the checker, the status line
#   a  role 08's task files with each --ansible (test_role.py, lab.yml):
#      variable checks, preflight, refusals, plan lines and plan id, an
#      install into a lab tree (journal reader only), changes, removal
#
# Usage: tests/detection/semantics/run.sh [--cache DIR]... [--ansible PLAYBOOK]...
#                                         [--only "h p u a"] [--keep]
#   --cache DIR          where the .debs are kept (searched 3 levels deep; a
#                        missing file is downloaded into the FIRST one).
#                        Default: ~/.cache/auto-sec-detection-semantics
#   --ansible PLAYBOOK   an ansible-playbook binary for the a checks (repeat
#                        for several versions). Without it they are skipped.
#   --only LIST          run only these parts
#   --keep               keep the work directory and print its path
# Needs: curl dpkg-deb sha256sum python3 perl with debconf's module (every
# Debian and Ubuntu has it), timeout. shellcheck is used when it is there.
# Exit 0 = every check passed, 1 = a check failed, 2 = setup problem.
set -u -o pipefail
export LC_ALL=C.UTF-8   # Ansible needs a UTF-8 locale

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
CACHES=()
ANSIBLES=()
ONLY="h p u a"
KEEP=0

die() { echo "ERROR: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case $1 in
    --cache) [ $# -ge 2 ] || die "--cache needs a directory"; CACHES+=("$2"); shift 2 ;;
    --ansible) [ $# -ge 2 ] || die "--ansible needs a path"; ANSIBLES+=("$2"); shift 2 ;;
    --only) [ $# -ge 2 ] || die "--only needs a list"; ONLY=$2; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[ ${#CACHES[@]} -gt 0 ] || CACHES=("${XDG_CACHE_HOME:-$HOME/.cache}/auto-sec-detection-semantics")
CACHE=${CACHES[0]}
for p in $ONLY; do
  case $p in h|p|u|a) ;; *) die "unknown part: $p" ;; esac
done
want() { case " $ONLY " in *" $1 "*) return 0 ;; esac; return 1; }
for t in python3 sha256sum timeout; do
  command -v "$t" >/dev/null 2>&1 || die "missing tool: $t"
done
if want p || want a; then
  for t in curl dpkg-deb perl; do
    command -v "$t" >/dev/null 2>&1 || die "missing tool: $t"
  done
  # (require, not use: importing the module would start debconf's frontend)
  perl -e 'require Debconf::Client::ConfModule' 2>/dev/null || die "perl cannot load Debconf::Client::ConfModule (package debconf)"
fi
for a in "${ANSIBLES[@]}"; do
  [ -x "$a" ] || die "not executable: $a"
done

W=$(mktemp -d "${TMPDIR:-/tmp}/detection-semantics.XXXXXX") || die "mktemp failed"
# shellcheck disable=SC2329  # called by the EXIT trap
cleanup() {
  chmod -R u+rwX "$W" 2>/dev/null
  if [ "$KEEP" = 1 ]; then echo "work dir kept: $W"; else rm -rf "$W"; fi
}
trap cleanup EXIT
mkdir -p "$CACHE" "$W/x" "$W/out" || die "cannot create directories"

PASSES=0
FAILS=0
pass() { PASSES=$((PASSES + 1)); printf 'PASS  %-9s %s\n' "$1" "$2"; }
fail() { FAILS=$((FAILS + 1)); printf 'FAIL  %-9s %s\n' "$1" "$2"; }
skip() { printf 'SKIP  %-9s %s\n' "$1" "$2"; }
# part NAME command...: run one test program; it prints PASS and FAIL lines.
part() {
  local name=$1 rc
  shift
  "$@" >"$W/out/$name.txt" 2>"$W/out/$name.err"
  rc=$?
  cat "$W/out/$name.txt"
  PASSES=$((PASSES + $(grep -c '^PASS' "$W/out/$name.txt")))
  FAILS=$((FAILS + $(grep -c '^FAIL' "$W/out/$name.txt")))
  if [ "$rc" != 0 ]; then
    # the reasons (tracebacks, assertion texts) go to stderr
    sed 's/^/      /' "$W/out/$name.err" | tail -n 120
    grep -q '^FAIL' "$W/out/$name.txt" || fail "$name" "the test program stopped (rc $rc)"
  fi
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

if want p || want a; then
  while read -r set fn sha rest; do
    case $set in ''|'#'*) continue ;; esac
    read -ra urls <<<"$rest"
    deb=$(fetch "$fn" "$sha" "${urls[@]}") || die "no verified copy of $fn (see debs.txt)"
    d="$W/x/$set/${fn%%_*}"
    mkdir -p "$d/root" "$d/control" || die "mkdir"
    dpkg-deb -x "$deb" "$d/root" || die "dpkg-deb -x $deb failed"
    dpkg-deb -e "$deb" "$d/control" || die "dpkg-deb -e $deb failed"
  done <"$HERE/debs.txt"
fi

# --- the checks ------------------------------------------------------------
if want h; then
  part hook python3 -I "$HERE/test_hook.py"
  if command -v shellcheck >/dev/null 2>&1; then
    if shellcheck -s sh "$ROOT/roles/08-detection/files/auto-sec-login-hook" >"$W/out/shellcheck.txt" 2>&1; then
      pass hook "shellcheck -s sh: the login hook is clean"
    else
      cat "$W/out/shellcheck.txt"
      fail hook "shellcheck -s sh on the login hook"
    fi
  else
    skip hook "shellcheck is not installed"
  fi
fi

if want p; then
  part pam python3 -I "$HERE/test_pam.py" --x "$W/x" --work "$W/pam"
fi

if want u; then
  part detect python3 -I "$HERE/test_detect.py"
fi

if want a; then
  if [ ${#ANSIBLES[@]} -eq 0 ]; then
    skip role "no --ansible given: role 08's task files were not run"
  fi
  # Every version runs in the same lab folder ($W/role), one after the
  # other, so the paths in the plan are the same and the plan id must be too.
  n=0
  ids=""
  for a in "${ANSIBLES[@]}"; do
    n=$((n + 1))
    part "role-$n" python3 -I "$HERE/test_role.py" --ansible "$a" --x "$W/x" --work "$W/role"
    ids="$ids $(sed -n 's/^INFO  role *plan id a4 = \([0-9a-f]\{12\}\)$/\1/p' "$W/out/role-$n.txt")"
    if [ "$KEEP" = 1 ]; then mv "$W/role" "$W/role-$n-kept"; fi
  done
  if [ "$n" -ge 2 ]; then
    # shellcheck disable=SC2086  # a list of ids, split on purpose
    set -- $ids
    if [ $# -eq "$n" ] && [ "$(printf '%s\n' "$@" | sort -u | wc -l)" = 1 ]; then
      pass role "the plan id of a first install is the same with every ansible-core: $1"
    else
      fail role "the plan id differs between ansible-core versions, or is missing:$ids"
    fi
  fi
fi

echo "detection-semantics: $PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ] || exit 1
[ "$PASSES" -gt 0 ] || die "no check ran"
exit 0
