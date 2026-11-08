#!/usr/bin/env bash
# ufw-semantics lab tests (role 03, #8). Runs role 03's ufw turn-on helper
# (roles/03-firewall/files/auto-sec-ufw-turnon) and, with --ansible, role
# 03's own ufw task files, against lab config trees driven by the REAL ufw
# code of the pinned .deb (debs.txt, SHA256-checked, unpacked with
# dpkg-deb -x). Unprivileged: ufw runs with --rootdir/--datadir on a copy;
# a lab-only patch of that copy points its iptables calls at a stub (the
# stub answers "loaded" only for trees marked active), turns off ufw's
# ownership checks (the files belong to this user) and assumes IPv6 rate
# limiting, as on a real root host. /proc, /sys, systemctl and ss come
# from fixtures. lab.py has the list of checks (u1-u24, a1-a5).
#
# Usage: tests/ufw/semantics/run.sh [--cache DIR]... [--ansible PLAYBOOK]... [--keep]
#   --cache DIR          where the .debs are kept (searched 3 levels deep;
#                        a missing file is downloaded into the FIRST one).
#                        Default: ~/.cache/auto-sec-ufw-semantics
#   --ansible PLAYBOOK   an ansible-playbook binary for the a* checks (repeat
#                        for several versions)
#   --keep               keep the work directory and print its path
# Needs: curl dpkg-deb sha256sum python3 (ansible-playbook for --ansible).
# Exit 0 = every check passed, 1 = a check failed, 2 = setup problem.
set -u -o pipefail
export LC_ALL=C

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
CACHES=()
KEEP=0
ANSIBLES=()

die() { echo "ERROR: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case $1 in
    --cache) [ $# -ge 2 ] || die "--cache needs a directory"; CACHES+=("$2"); shift 2 ;;
    --ansible) [ $# -ge 2 ] || die "--ansible needs a path"; ANSIBLES+=("$2"); shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[ ${#CACHES[@]} -gt 0 ] || CACHES=("${XDG_CACHE_HOME:-$HOME/.cache}/auto-sec-ufw-semantics")
CACHE=${CACHES[0]}
for t in curl dpkg-deb sha256sum python3; do
  command -v "$t" >/dev/null 2>&1 || die "missing tool: $t"
done
for a in "${ANSIBLES[@]}"; do
  [ -x "$a" ] || die "not executable: $a"
done

W=$(mktemp -d "${TMPDIR:-/tmp}/ufw-semantics.XXXXXX") || die "mktemp failed"
# shellcheck disable=SC2329  # called by the EXIT trap
cleanup() {
  if [ "$KEEP" = 1 ]; then echo "work dir kept: $W"; else rm -rf "$W"; fi
}
trap cleanup EXIT
mkdir -p "$CACHE" "$W/x" "$W/pkg" "$W/stub" || die "cannot create directories"

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

SETS=()
while read -r set fn sha rest; do
  case $set in ''|'#'*) continue ;; esac
  read -ra urls <<<"$rest"
  deb=$(fetch "$fn" "$sha" "${urls[@]}") || die "no verified copy of $fn (see debs.txt)"
  mkdir -p "$W/x/$set" || die "mkdir"
  dpkg-deb -x "$deb" "$W/x/$set" || die "dpkg-deb -x $deb failed"
  SETS+=("$set")
done <"$HERE/debs.txt"

# --- the lab-only copy of ufw ----------------------------------------------
# iptables stub: "-V" prints a version; "-L <chain>" answers "loaded" (rc 0)
# only when UFW_LAB_ACTIVE=1, so `ufw status` says active or inactive as the
# test wants. Nothing else is ever called by the commands the tests use.
for b in iptables ip6tables; do
  cat >"$W/stub/$b" <<'EOF'
#!/bin/sh
case "$1" in
  -V) echo "iptables v1.8.10 (nf_tables)" ;;
  -L) [ "${UFW_LAB_ACTIVE:-0}" = 1 ] || exit 1 ;;
esac
exit 0
EOF
  chmod 755 "$W/stub/$b"
done

for set in "${SETS[@]}"; do
  cp -a "$W/x/$set" "$W/pkg/$set" || die "copy $set"
  lib="$W/pkg/$set/usr/lib/python3/dist-packages/ufw"
  [ -f "$lib/common.py" ] && [ -f "$lib/backend.py" ] || die "$set: no ufw Python package"
  sed -i -e "s|^iptables_dir = .*|iptables_dir = \"$W/stub\"|" -e 's|^do_checks = True|do_checks = False|' "$lib/common.py"
  sed -i "s|self.caps\['limit'\]\['6'\] = False.*|self.caps['limit']['6'] = True  # LAB: as on a root host|" "$lib/backend.py"
  grep -q "^iptables_dir = \"$W/stub\"" "$lib/common.py" || die "$set: lab patch of common.py failed"
  grep -q "do_checks = False" "$lib/common.py" || die "$set: lab patch of common.py (do_checks) failed"
  grep -q "LAB: as on a root host" "$lib/backend.py" || die "$set: lab patch of backend.py failed"
done

# --- the checks ------------------------------------------------------------
rc=0
for set in "${SETS[@]}"; do
  args=(--helper "$ROOT/roles/03-firewall/files/auto-sec-ufw-turnon" --roles "$ROOT/roles"
        --src "$W/x/$set" --pkg "$W/pkg/$set" --work "$W/run-$set" --here "$HERE" --set "$set")
  for a in "${ANSIBLES[@]}"; do args+=(--ansible "$a"); done
  python3 -I "$HERE/lab.py" "${args[@]}" || rc=1
done
exit "$rc"
