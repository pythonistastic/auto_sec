#!/usr/bin/env bash
# report-semantics: role 10 (#10) renders and writes the report without root,
# on the current ansible-core and on 2.16 (--ansible, repeatable).
#   r1 nothing optional set (no client_name/client_domain, report_prepared_by
#      still "Your Company"), ufw not installed, fail2ban keep: no failure,
#      those header lines left out, "ufw is not installed"
#   r2 everything set, ufw active (status text with braces and a backtick),
#      fail2ban running: header lines present, host text filtered
#   r3 --check: nothing written
#   r4-r16 the line about root's password (role 01's B14): the provider
#      note with and without the SSH sentence (root with keys only,
#      ssh_hardening_enabled false, an AuthenticationMethods list), changed
#      on a later day than a day cloud-init's log names root or than a mark,
#      an empty password, no record of cloud-init setting root's password,
#      and facts of an odd shape, which read "not checked"; r1 has no facts
#      (not checked), r2 a locked password
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

# Root's password (role 01's B14 sets _base_rootpw; here it comes from
# -e @<case>.json, with role 02's sshd values for root).
RPTEXT="root's password was set by cloud-init on 2026-05-11 (cloud-init's log names root), and it was not changed on a later day. The password file records only the day, so a change later that day does not show. The hosting provider's panel can set root's password through cloud-init, so the provider's systems may hold this password. Change it inside the server with \`passwd\`. A reset in the panel hands the new password to the provider again."
RPEMPTY="With the default settings of Ubuntu and Debian, anyone at the server's console, and any account on the server with \`su\`, can become root without a password. Set one inside the server with \`passwd\`."
sshd_json() { # permitrootlogin passwordauthentication [authenticationmethods]: role 02's _ssh_after
  printf '{"admin": {"permitrootlogin": "%s", "passwordauthentication": "%s", "pubkeyauthentication": "yes"}, "root": {"permitrootlogin": "%s", "passwordauthentication": "%s", "pubkeyauthentication": "yes", "authenticationmethods": "%s"}}' \
    "$1" "$2" "$1" "$2" "${3:-any}"
}
rp_json() { # case verdict changed cloud kind text [more JSON members]
  printf '{"_base_rootpw": {"verdict": "%s", "changed": "%s", "cloud": "%s", "kind": "%s", "text": "%s"}%s}\n' \
    "$2" "$3" "$4" "$5" "$6" "${7:+, $7}" >"$W/$1.json"
}
rp_json r4 provider 2026-05-11 2026-05-11 named "$RPTEXT" "\"_ssh_after\": $(sshd_json yes yes)"
rp_json r5 provider 2026-05-11 2026-05-11 named "$RPTEXT" "\"_ssh_after\": $(sshd_json prohibit-password yes)"
rp_json r6 provider 2026-05-11 2026-05-11 named "$RPTEXT" "\"_ssh_after\": $(sshd_json yes yes), \"ssh_hardening_enabled\": false"
rp_json r7 provider 2026-05-11 2026-05-11 named "$RPTEXT" "\"_ssh_after\": $(sshd_json yes yes publickey)"
rp_json r8 later 2026-07-01 2026-05-11 named ""
rp_json r9 empty 2026-05-11 2026-05-11 named "$RPEMPTY"
rp_json r10 no-evidence 2026-03-02 "" "" ""
rp_json r11 later "2026-07-01 <b>" 2026-05-11 named ""
rp_json r12 provider 2026-05-11 2026-05-11 named ""
rp_json r13 later 2026-07-01 2026-05-11 mark ""
rp_json r14 later 2026-07-01 2026-05-11 yes ""
rp_json r15 empty 2026-05-11 2026-05-11 named ""
printf '{"_base_rootpw": "provider"}\n' >"$W/r16.json"
RPLEAD="- **The hosting provider may know root's password** (read during this run): $RPTEXT"
RPSSH=" Root can also log in over SSH with this password."
rp_want() { # case: sets want, the one line about root's password the report must have
  case $1 in
    r1|r11|r12|r14|r15|r16) want="- Root's password: not checked in this run" ;;
    r2) want="- Root's password (read during this run): locked, so root cannot log in with a password" ;;
    r4) want="$RPLEAD$RPSSH" ;;
    r5|r6|r7) want="$RPLEAD" ;;
    r8) want="- Root's password (read during this run): last changed on 2026-07-01, after cloud-init set it on this server (2026-05-11)" ;;
    r9) want="- **Root's password is empty** (read during this run): $RPEMPTY" ;;
    r10) want="- Root's password (read during this run): root has one, last changed on 2026-03-02. Whether the hosting provider's panel set it was not checked: this server has no record of cloud-init setting a password for root" ;;
    r13) want="- Root's password (read during this run): last changed on 2026-07-01, after cloud-init's password step ran on this server (2026-05-11)" ;;
    *) want="(no such case)" ;;
  esac
}

for pb in "${ANSIBLES[@]}"; do
  tag=$(basename "$(dirname "$(dirname "$pb")")")
  for c in r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16; do
    d="$W/$tag-$c"; mkdir -p "$d"; cp "$HERE/play.yml" "$d/play.yml"
    case $c in
      r1) ev='{"_f2b_report": "fail2ban is not managed by auto_sec (fail2ban_hardening_enabled: keep)", "report_prepared_by": "Your Company", "ssh_port": 22}'
          path="$W/stub-off:/usr/bin:/bin"; extra=() ;;
      r2) ev='{"client_name": "Example Client", "client_domain": "app.example.com", "report_prepared_by": "Example Ops", "_fw_report": "ufw is on. Default: deny (incoming), allow (outgoing), disabled (routed)", "_f2b_report": "sshd jail: maxretry 5", "ssh_port": 22, "paranoia_level": "high", "_base_rootpw": {"verdict": "locked", "changed": "2026-05-11", "cloud": "2026-05-11", "kind": "named", "text": ""}}'
          path="$W/stub-on:/usr/bin:/bin"; extra=() ;;
      r3) ev='{"ssh_port": 22}'; path="$W/stub-on:/usr/bin:/bin"; extra=(--check) ;;
      *) ev='{"ssh_port": 22}'; path="$W/stub-on:/usr/bin:/bin"; extra=(-e "@$W/$c.json") ;;
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
    elif [ "$c" = r2 ]; then
      grep -q '^\*\*Client:\*\* Example Client' "$f" && grep -q '^\*\*Prepared by:\*\* Example Ops' "$f"
      ok "$tag r2: header lines present" $?
      grep -q 'ufw is on. Default: deny (incoming)' "$f" && grep -q 'Jail list' "$f"; ok "$tag r2: measured ufw and fail2ban" $?
    fi
    rp_want "$c"
    grep -Fxq -- "$want" "$f"; ok "$tag $c: root's password: ${want:0:58}..." $?
    if [ "$c" = r4 ]; then n=1; else n=0; fi
    awk -v n="$n" "/oot's password/ { a++ } /over SSH with this password/ { b++ } END { exit !(a == 1 && b + 0 == n) }" "$f"
    ok "$tag $c: one line about root's password; SSH is named only where sshd lets root in with a password" $?
    sed -n '/^## 1\. /,/^## 2\. /p' "$f" | awk "/oot's password/ { r = NR } /^- Firewall / { w = NR } END { exit !(r && w && r < w) }"
    ok "$tag $c: the line is in section 1 (preventive measures), before the firewall line" $?
  done
done
echo "== $pass passed, $fail failed"
[ "$fail" = 0 ]
