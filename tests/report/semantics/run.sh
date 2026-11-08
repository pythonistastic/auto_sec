#!/usr/bin/env bash
# report-semantics: role 10 (#10) renders and writes the report without root,
# on the current ansible-core and on 2.16 (--ansible, repeatable).
#   r1 nothing optional set (no client_name/client_domain, report_prepared_by
#      still "Your Company"), ufw not installed, fail2ban keep: no failure,
#      those header lines left out, "ufw is not installed"
#   r2 everything set, ufw active (status text with braces and a backtick),
#      fail2ban running: header lines present, host text filtered
#   r3 --check: nothing written
#   every case: none of the removed, unmeasured claims is in the file, and
#   the file is 0600 in a 0700 folder on this computer
# Usage: tests/report/semantics/run.sh [--ansible PLAYBOOK]... [--keep]
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
W=$(mktemp -d "${TMPDIR:-/tmp}/report-semantics.XXXXXX") || die "mktemp failed"
trap '[ "$KEEP" = 1 ] && echo "work dir kept: $W" || rm -rf "$W"' EXIT

pass=0; fail=0
ok() { if [ "$2" = 0 ]; then echo "PASS  $1"; pass=$((pass + 1)); else echo "FAIL  $1"; fail=$((fail + 1)); fi; }

mkdir -p "$W/stub-on" "$W/stub-off"
cat >"$W/stub-on/ufw" <<'S'
#!/bin/sh
printf 'Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\n'
printf 'To                         Action      From\n22/tcp                     LIMIT IN    Anywhere   # {{ x }} `id`\n'
S
cat >"$W/stub-on/fail2ban-client" <<'S'
#!/bin/sh
printf 'Status\n|- Number of jail:\t1\n`- Jail list:\tsshd\n'
S
chmod 755 "$W/stub-on/ufw" "$W/stub-on/fail2ban-client"

# Claims 0.1-0.5 printed without measuring them (#10, #15).
REMOVED='No database on this server|NO delete permission|Restore verification|Ransomware early warning|All alerts delivered|Web server hardened|least privilege|Response mode|default deny on all inbound traffic|is set up|Breach detection suite|Backup success/failure monitored'

for pb in "${ANSIBLES[@]}"; do
  tag=$(basename "$(dirname "$(dirname "$pb")")")
  for c in r1 r2 r3; do
    d="$W/$tag-$c"; mkdir -p "$d"; cp "$HERE/play.yml" "$d/play.yml"
    case $c in
      r1) ev='{"_f2b_report": "fail2ban is not managed by auto_sec (fail2ban_hardening_enabled: keep)", "report_prepared_by": "Your Company", "ssh_port": 22}'
          path="$W/stub-off:/usr/bin:/bin"; extra=() ;;
      r2) ev='{"client_name": "Example Client", "client_domain": "app.example.com", "report_prepared_by": "Example Ops", "_fw_report": "ufw is on. Default: deny (incoming), allow (outgoing), disabled (routed)", "_f2b_report": "sshd jail: maxretry 5", "ssh_port": 22, "paranoia_level": "high"}'
          path="$W/stub-on:/usr/bin:/bin"; extra=() ;;
      r3) ev='{"ssh_port": 22}'; path="$W/stub-on:/usr/bin:/bin"; extra=(--check) ;;
    esac
    (cd "$d" && PATH="$path" ANSIBLE_ROLES_PATH="$ROOT/roles" ANSIBLE_NOCOLOR=1 ANSIBLE_LOCALHOST_WARNING=False \
      ANSIBLE_INVENTORY_UNPARSED_WARNING=False ANSIBLE_DEPRECATION_WARNINGS=False \
      "$pb" -i localhost, play.yml -e "$ev" "${extra[@]}" >"$d/log" 2>&1)
    rc=$?
    f="$d/reports/security-report-localhost.md"
    ok "$tag $c: rc 0" "$rc"
    if [ "$c" = r3 ]; then
      if [ -e "$f" ]; then r=1; else r=0; fi; ok "$tag r3: --check wrote no report" "$r"
      continue
    fi
    if [ -f "$f" ]; then r=0; else r=1; fi; ok "$tag $c: report written on this computer" "$r"
    [ "$(stat -c %a "$f" 2>/dev/null)" = 600 ] && [ "$(stat -c %a "$d/reports" 2>/dev/null)" = 700 ]
    ok "$tag $c: file 0600, folder 0700" $?
    ! grep -Eq "$REMOVED" "$f"; ok "$tag $c: none of the removed claims" $?
    grep -q 'Detection: not managed by auto_sec 0.6' "$f" && grep -q 'Backups: not checked by auto_sec' "$f"
    ok "$tag $c: unmeasured parts say so" $?
    # shellcheck disable=SC2016  # a literal backtick, not an expansion
    ! grep -q '{{' "$f" && ! grep -q '`id`' "$f"; ok "$tag $c: no braces or backticks from the host" $?
    if [ "$c" = r1 ]; then
      ! grep -Eq '^\*\*(Client|Domain|Prepared by):' "$f"; ok "$tag r1: unset header lines left out" $?
      grep -q 'Firewall (ufw, read during this run): ufw is not installed' "$f"; ok "$tag r1: ufw not installed" $?
    else
      grep -q '^\*\*Client:\*\* Example Client' "$f" && grep -q '^\*\*Prepared by:\*\* Example Ops' "$f"
      ok "$tag r2: header lines present" $?
      grep -q 'ufw is on. Default: deny (incoming)' "$f" && grep -q 'Jail list' "$f"; ok "$tag r2: measured ufw and fail2ban" $?
    fi
  done
done
echo "== $pass passed, $fail failed"
[ "$fail" = 0 ]
