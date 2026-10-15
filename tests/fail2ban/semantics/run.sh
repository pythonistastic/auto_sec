#!/usr/bin/env bash
# fail2ban-semantics golden tests (role 03, issue #2). Checks how real
# fail2ban builds read the file role 03 writes (jail.d/00-autosec.conf)
# next to an operator's own files, without root and without installing
# anything: the pinned .debs in debs.txt (SHA256-checked) are unpacked with
# dpkg-deb -x, and role 03's own trial helper
# (roles/03-firewall/files/auto-sec-f2b-check) runs their fail2ban-client
# (-d, -t, -vvv) on copies of their stock /etc/fail2ban. The templates are
# rendered by the real role files through render.yml. lab.py has the list
# of checks (S1-S16).
#
# With a Python that can import asyncore (Python 3.12+: pip install
# pyasyncore), a real fail2ban 1.0.2 server (noble build) also runs as this
# user, on a Unix socket in the work directory, with an action that only
# writes a log: reload/restart semantics (S13), the helper's drift check
# (S15) and, with --ansible, role 03's own task files run by
# ansible-playbook against that server (S16).
#
# Usage: tests/fail2ban/semantics/run.sh [--cache DIR]... [--dists "LIST"]
#          [--server-python PY] [--require-server] [--ansible PLAYBOOK]... [--keep]
#   --cache DIR          where the .debs are kept. Searched 3 levels deep. Repeatable:
#                        all are searched, a missing file is downloaded into the FIRST.
#                        Default: ~/.cache/auto-sec-fail2ban-semantics
#   --dists LIST         any of: jammy bookworm noble trixie resolute (default: all)
#   --server-python PY   Python for the lab server (default: python3 if it imports
#                        asyncore, else the server checks are skipped)
#   --require-server     fail instead of skipping the server checks
#   --ansible PLAYBOOK   an ansible-playbook binary for S16 (repeat for several versions)
#   --keep               keep the work directory and print its path
# Needs: curl dpkg-deb sha256sum python3 ansible-playbook.
# Exit 0 = every check passed, 1 = a check failed, 2 = setup problem.
set -u -o pipefail
export LC_ALL=C

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
ALL_DISTS="jammy bookworm noble trixie resolute"
CACHES=()
DISTS=$ALL_DISTS
KEEP=0
SERVER_PY=""
REQUIRE_SERVER=0
ANSIBLES=()

die() { echo "ERROR: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case $1 in
    --cache) [ $# -ge 2 ] || die "--cache needs a directory"; CACHES+=("$2"); shift 2 ;;
    --dists) [ $# -ge 2 ] || die "--dists needs a list"; DISTS=$2; shift 2 ;;
    --server-python) [ $# -ge 2 ] || die "--server-python needs a path"; SERVER_PY=$2; shift 2 ;;
    --require-server) REQUIRE_SERVER=1; shift ;;
    --ansible) [ $# -ge 2 ] || die "--ansible needs a path"; ANSIBLES+=("$2"); shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[ ${#CACHES[@]} -gt 0 ] || CACHES=("${XDG_CACHE_HOME:-$HOME/.cache}/auto-sec-fail2ban-semantics")
CACHE=${CACHES[0]}
for d in $DISTS; do
  case " $ALL_DISTS " in *" $d "*) ;; *) die "unknown dist: $d" ;; esac
done
for t in curl dpkg-deb sha256sum python3 ansible-playbook; do
  command -v "$t" >/dev/null 2>&1 || die "missing tool: $t"
done
if [ -z "$SERVER_PY" ] && python3 -c 'import asyncore' >/dev/null 2>&1; then
  SERVER_PY=$(command -v python3)
fi
if [ -n "$SERVER_PY" ]; then
  "$SERVER_PY" -c 'import asyncore' >/dev/null 2>&1 || die "$SERVER_PY cannot import asyncore (pip install pyasyncore)"
elif [ "$REQUIRE_SERVER" = 1 ]; then
  die "--require-server: no Python that imports asyncore (use --server-python)"
fi
for a in "${ANSIBLES[@]}"; do
  [ -x "$a" ] || die "not executable: $a"
done

W=$(mktemp -d "${TMPDIR:-/tmp}/fail2ban-semantics.XXXXXX") || die "mktemp failed"
cleanup() {
  # lab servers that a failed check left running (lab.py normally stops them)
  pkill -f "fail2banserver.*$W/x/" 2>/dev/null || true
  if [ "$KEEP" = 1 ]; then echo "work dir kept: $W"; else rm -rf "$W"; fi
}
trap cleanup EXIT
mkdir -p "$CACHE" "$W/x" "$W/ctrl" "$W/render" || die "cannot create directories"

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

while read -r set fn sha rest; do
  case $set in ''|'#'*) continue ;; esac
  case " $DISTS " in *" $set "*) ;; *) continue ;; esac
  read -ra urls <<<"$rest"
  deb=$(fetch "$fn" "$sha" "${urls[@]}") || die "no verified copy of $fn (see debs.txt)"
  mkdir -p "$W/x/$set" "$W/ctrl/$set" || die "mkdir"
  dpkg-deb -x "$deb" "$W/x/$set" || die "dpkg-deb -x $deb failed"
  dpkg-deb -e "$deb" "$W/ctrl/$set" || die "dpkg-deb -e $deb failed"
done <"$HERE/debs.txt"

for d in $DISTS; do
  [ -f "$W/x/$d/etc/fail2ban/jail.conf" ] || die "$d: no etc/fail2ban/jail.conf after unpacking"
  [ -d "$W/x/$d/usr/lib/python3/dist-packages/fail2ban" ] || die "$d: no fail2ban Python package"
  [ -f "$W/ctrl/$d/conffiles" ] || die "$d: no conffiles list"
done

# --- render the role's templates for each case -------------------------------
for c in default ips empty port2222 legacy04 backend nginx; do
  # Ansible refuses to start without a UTF-8 locale.
  LC_ALL=C.UTF-8 ANSIBLE_LOCALHOST_WARNING=False ANSIBLE_INVENTORY_UNPARSED_WARNING=False \
  ANSIBLE_NOCOLOR=1 ANSIBLE_RETRY_FILES_ENABLED=False \
    ansible-playbook "$HERE/render.yml" -e "@$HERE/cases/$c.yml" \
      -e "render_dest=$W/render/$c.conf" >"$W/render/$c.log" 2>&1 \
    || { cat "$W/render/$c.log" >&2; die "rendering case $c failed"; }
done

# --- the checks ----------------------------------------------------------------
args=(--work "$W" --dists "$DISTS" --rendered "$W/render" --here "$HERE" --roles "$ROOT/roles"
      --helper "$ROOT/roles/03-firewall/files/auto-sec-f2b-check" --fixtures "$HERE/fixtures")
[ -n "$SERVER_PY" ] && args+=(--server-python "$SERVER_PY")
for a in "${ANSIBLES[@]}"; do args+=(--ansible "$a"); done
python3 -I -B "$HERE/lab.py" "${args[@]}"
