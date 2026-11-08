#!/usr/bin/env bash
# cve-semantics: role 11 (CVE watch, opt-in) without root. lab.py has the
# checks: the known 0.2-0.5 hashes against git history (needs the history:
# a CI checkout with fetch-depth: 0), role 11's plan.yml on lab folders
# (current ansible-core and 2.16 with --ansible), and the scanner's OS
# count without an app folder.
# Usage: tests/cve/semantics/run.sh [--ansible PLAYBOOK]... [--keep]
set -u -o pipefail
export LC_ALL=C.UTF-8
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
ANSIBLES=()
KEEP=0
die() { echo "ERROR: $*" >&2; exit 2; }
while [ $# -gt 0 ]; do
  case $1 in
    --ansible) [ $# -ge 2 ] || die "--ansible needs a path"; ANSIBLES+=("$2"); shift 2 ;;
    --keep) KEEP=1; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done
[ ${#ANSIBLES[@]} -gt 0 ] || ANSIBLES=("$(command -v ansible-playbook)") || die "no ansible-playbook"
PY=python3
"$PY" -c 'import yaml' 2>/dev/null || PY=$(dirname "${ANSIBLES[0]}")/python3
"$PY" -c 'import yaml' 2>/dev/null || die "no Python with PyYAML"
W=$(mktemp -d "${TMPDIR:-/tmp}/cve-semantics.XXXXXX") || die "mktemp failed"
trap '[ "$KEEP" = 1 ] && echo "work dir kept: $W" || rm -rf "$W"' EXIT
args=(--root "$ROOT" --work "$W" --here "$HERE")
for a in "${ANSIBLES[@]}"; do args+=(--ansible "$a"); done
"$PY" "$HERE/lab.py" "${args[@]}"
