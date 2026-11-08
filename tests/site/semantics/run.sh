#!/usr/bin/env bash
# site-semantics: site.yml's run-wide checks and the run plan (roles/00-plan),
# without root and without a server, on the current ansible-core and on 2.16
# (--ansible, repeatable).
#
#   s*  site.yml against hosts in TEST-NET-1 (192.0.2.0/24, RFC 5737), where
#       nothing answers: what refuses BEFORE the first connection (no
#       UNREACHABLE in the log), and where the first connection happens
#       s1  three hosts, no -l: R00-2 (s1b: an empty -l, "" or ",")
#       s2  -e autosec_confirm_hosts with the wrong count: R00-2
#       s3  -l h1: no R00-2; the first connection is pre-task 3 (R00-3)
#       s4  -e autosec_confirm_hosts=3: h1 unreachable (s4b: refused), h2 and h3
#           are never touched (serial 1, max_fail_percentage 0)
#       s5-s7  autosec_server missing, yes (a YAML boolean), New: R00-1
#       s8-s9  existing, new: the variable checks pass
#       s10-s13  a bad autosec_approve, autosec_serial, firewall_state or
#           cve_watch_hour stops at pre-task 2 (no connection)
#       s14 old detector variables (watcher_mode) do not stop a run
#   p*  the plan summary (tests/site/semantics/plan.yml) with fixture facts
#       p1  the canary: every line, "no change", no approval needed
#       p2-p5  same input: same id; a changed note: same id; a changed item
#           or another host: another id; a package no role lists (p4c-d):
#           approval needed and another id
#       p6-p12  approval: plan only, R00-4, R00-5, the right id, a list of
#           ids, --check, autosec_require_approval false
#       p13 a configured layer without a plan: NO PLAN, approval needed
#       p14 an item that breaks the contract: refused as a bug
#       p15-p16 not selected by --tags; ssh_hardening_enabled false
#       x1  the canary's plan id is the same on every ansible-core
#   q*  role 02's plan lines (plan02.yml, a fake getent): keys present or
#       missing, deploy's key after role 01 creates it, a linked ~/.ssh, the
#       drop-in's lines from your values, comments only, the stock-file
#       migration, role 02 not selected
#   d*  the defaults that follow autosec_server (group_vars/all.yml)
#   t*  tests/site/semantics/static.py on the repository, and on a copy
#       with one planted violation per check (each must FAIL)
# Usage: tests/site/semantics/run.sh [--ansible PLAYBOOK]... [--keep]
# Each check is a condition followed by `ok "<what>" $?`: $? is meant to be
# the condition's status.
# shellcheck disable=SC2319
set -u -o pipefail
export LC_ALL=C.UTF-8
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
PY=${PYTHON:-python3}
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
"$PY" -c 'import yaml' 2>/dev/null || die "$PY cannot import yaml (set PYTHON=...)"
W=$(mktemp -d "${TMPDIR:-/tmp}/site-semantics.XXXXXX") || die "mktemp failed"
trap '[ "$KEEP" = 1 ] && echo "work dir kept: $W" || rm -rf "$W"' EXIT

pass=0; fail=0
ok() { if [ "$2" = 0 ]; then echo "PASS  $1"; pass=$((pass + 1)); else echo "FAIL  $1"; fail=$((fail + 1)); fi; }
has() { grep -Fq -- "$2" "$1"; }

export ANSIBLE_NOCOLOR=1 ANSIBLE_LOCALHOST_WARNING=False ANSIBLE_INVENTORY_UNPARSED_WARNING=False \
  ANSIBLE_DEPRECATION_WARNINGS=False ANSIBLE_INVENTORY_UNPARSED_FAILED=1 ANSIBLE_HOST_KEY_CHECKING=False \
  ANSIBLE_RETRY_FILES_ENABLED=False

site() { # log inventory args...: site.yml from the repository root; prints rc
  local log=$1 inv=$2 rc=0
  shift 2
  (cd "$ROOT" && "$PB" -i "$HERE/$inv" site.yml "$@") >"$log" 2>&1 || rc=$?
  echo "$rc"
}
plan() { # name host args...: the plan lab; prints rc, writes $W/<tag>-<name>.json
  local name=$1 host=$2 rc=0
  shift 2
  rm -f "$W/$tag-$name.json"
  (cd "$HERE" && ANSIBLE_ROLES_PATH="$ROOT/roles" "$PB" -i "$host," -c local plan.yml \
    -e "lab_out=$W/$tag-$name.json" "$@") >"$W/$tag-$name.log" 2>&1 || rc=$?
  echo "$rc"
}
js() { # file python-expression on d: prints the value
  "$PY" -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$1" "$2" 2>/dev/null
}
first_connect_task() { # log: the TASK line right before the first UNREACHABLE
  awk '/^TASK \[/ { t = $0 } /UNREACHABLE/ { print t; exit }' "$1"
}

# getent for the q cases: the lab accounts that have a folder under
# $LAB_HOME, and nobody else.
mkdir -p "$W/stub"
cat >"$W/stub/getent" <<'EOF'
#!/bin/sh
# lab stub: passwd entries for the lab accounts only
[ "$1" = passwd ] || exit 2
case $2 in
  labadmin|deploy) [ -d "$LAB_HOME/$2" ] || exit 2; printf '%s:x:4242:4242::%s:/bin/bash\n' "$2" "$LAB_HOME/$2" ;;
  *) exit 2 ;;
esac
EOF
chmod 755 "$W/stub/getent"

for PB in "${ANSIBLES[@]}"; do
  tag=$(basename "$(dirname "$(dirname "$PB")")")
  ver=$("$PB" --version 2>/dev/null | head -n 1)
  echo "== $tag: $ver"

  # --- s: site.yml before the first connection ---------------------------------
  L=$W/$tag-s1.log; rc=$(site "$L" three.yml)
  [ "$rc" != 0 ] && has "$L" "[R00-2]" && ! has "$L" UNREACHABLE; ok "$tag s1: three hosts without -l: R00-2, no connection" $?
  # An empty -l limits nothing in Ansible (an unset shell variable: -l "$SERVER").
  for lim in '' ',' ' , '; do
    L=$W/$tag-s1b.log; rc=$(site "$L" three.yml -l "$lim")
    [ "$rc" != 0 ] && has "$L" "[R00-2]" && ! has "$L" UNREACHABLE; ok "$tag s1b: -l '$lim' counts as no -l: R00-2, no connection" $?
  done
  L=$W/$tag-s2.log; rc=$(site "$L" three.yml -e autosec_confirm_hosts=2)
  [ "$rc" != 0 ] && has "$L" "[R00-2]" && has "$L" "autosec_confirm_hosts=3" && ! has "$L" UNREACHABLE
  ok "$tag s2: the wrong confirmed count: R00-2, no connection" $?
  L=$W/$tag-s3.log; rc=$(site "$L" three.yml -l h1)
  [ "$rc" != 0 ] && ! has "$L" "[R00-2]" && first_connect_task "$L" | grep -q 'R00-3'
  ok "$tag s3: -l h1 passes the guard and the variable checks; first connection at R00-3" $?
  L=$W/$tag-s4.log; rc=$(site "$L" three.yml -e autosec_confirm_hosts=3)
  [ "$rc" != 0 ] && ! has "$L" "[R00-2]" && grep -q 'h1.*UNREACHABLE' "$L" && ! grep -Eq '\[h[23]\]|^h[23] ' "$L"
  ok "$tag s4: confirmed count: h1 unreachable, h2 and h3 never run" $?
  L=$W/$tag-s4b.log; rc=$(site "$L" three.yml -e autosec_confirm_hosts=3 -e autosec_server=bogus)
  [ "$rc" != 0 ] && has "$L" "[R00-1]" && grep -q '\[h1\]' "$L" && ! grep -Eq '\[h[23]\]|^h[23] ' "$L"
  ok "$tag s4b: confirmed count: h1 refused, h2 and h3 never run" $?
  for c in v-missing v-yes v-cap; do
    L=$W/$tag-s5-$c.log; rc=$(site "$L" values.yml -l "$c")
    [ "$rc" != 0 ] && has "$L" "[R00-1]" && ! has "$L" UNREACHABLE; ok "$tag s5-7: autosec_server $c: R00-1, no connection" $?
  done
  grep -Eq 'or is \\?"True' "$W/$tag-s5-v-yes.log"; ok "$tag s6: R00-1 shows the boolean" $?
  for c in v-existing v-new; do
    L=$W/$tag-s8-$c.log; rc=$(site "$L" values.yml -l "$c")
    [ "$rc" != 0 ] && ! has "$L" "[R00-1]" && first_connect_task "$L" | grep -q 'R00-3'
    ok "$tag s8-9: autosec_server $c: variable checks pass, first connection at R00-3" $?
  done
  L=$W/$tag-s10.log; rc=$(site "$L" three.yml -l h1 -e autosec_approve=not-an-id)
  [ "$rc" != 0 ] && has "$L" "autosec_approve" && ! has "$L" UNREACHABLE; ok "$tag s10: a bad autosec_approve stops before any connection" $?
  L=$W/$tag-s11.log; rc=$(site "$L" three.yml -l h1 -e autosec_serial=0)
  [ "$rc" != 0 ] && has "$L" "autosec_serial" && ! has "$L" UNREACHABLE; ok "$tag s11: autosec_serial 0 stops before any connection" $?
  L=$W/$tag-s12.log; rc=$(site "$L" three.yml -l h1 -e '{"firewall_state": true}')
  [ "$rc" != 0 ] && has "$L" "a YAML boolean" && ! has "$L" UNREACHABLE; ok "$tag s12: firewall_state true stops before any connection" $?
  L=$W/$tag-s13.log; rc=$(site "$L" three.yml -l h1 -e cve_watch_hour=25)
  [ "$rc" != 0 ] && has "$L" "cve_watch_hour" && ! has "$L" UNREACHABLE; ok "$tag s13: a bad cve_watch_hour stops before any connection" $?
  L=$W/$tag-s14.log; rc=$(site "$L" three.yml -l h1 -e watcher_mode=active -e revshell_enabled=true)
  [ "$rc" != 0 ] && first_connect_task "$L" | grep -q 'R00-3'; ok "$tag s14: old detector variables stop nothing" $?

  # --- p: the plan summary ---------------------------------------------------------
  rc=$(plan p1 canary -e @cases/canary.json); F=$W/$tag-p1.json
  ok "$tag p1: canary plan: rc 0 with autosec_require_approval true" "$rc"
  want=$(cat <<'EOF'
  01 base:      no change
  02 ssh:       no change
  03 firewall:  ufw active, kept (no ufw command); fail2ban: keep (no install, no file, no reload)
  04-07:        skipped (not configured)
  08 detection: not managed in 0.6 (no change)
  09 watcher:   not managed in 0.6 (no change)
  10 report:    writes reports/security-report-canary.md on this computer; nothing on the server
  11 cve:       skipped (cve_watch_enabled: false)
  packages:     nothing to install
  server: 0 files, 0 packages, 0 services (re)started, 0 firewall rules
EOF
)
  got=$(js "$F" '"\n".join(d["lines"][1:-1])')
  [ "$got" = "$want" ]; ok "$tag p1: canary plan lines" $?
  [ "$(js "$F" 'd["lines"][0]')" = "auto_sec $(tr -d '[:space:]' <"$ROOT/VERSION") plan for canary (autosec_server: existing)" ]
  ok "$tag p1: header names the release and autosec_server" $?
  [ "$(js "$F" 'd["status"]')" = "no server change: approval not needed" ] && [ "$(js "$F" 'd["need_approval"]')" = False ]
  ok "$tag p1: no server change, approval not needed" $?
  js "$F" 'd["id"]' | grep -Eq '^[0-9a-f]{12}$'; ok "$tag p1: plan id is 12 hex digits" $?
  ID1=$(js "$F" 'd["id"]')
  eval "ID_CANARY_${tag//[^A-Za-z0-9]/_}=\$ID1"
  rc=$(plan p2 canary -e @cases/canary.json)
  [ "$(js "$W/$tag-p2.json" 'd["id"]')" = "$ID1" ]; ok "$tag p2: same input, same id" $?
  rc=$(plan p3 canary -e @cases/canary.json \
    -e '{"_plan_10": [{"role": "10", "part": "report", "do": "local-file", "what": "reports/security-report-canary.md on this computer; nothing on the server", "note": "another note"}]}')
  [ "$(js "$W/$tag-p3.json" 'd["id"]')" = "$ID1" ]; ok "$tag p3: a changed note keeps the id" $?
  P4='{"_plan_01": [{"role": "01", "part": "timezone", "do": "write", "what": "timezone UTC", "note": ""}]}'
  rc=$(plan p4 canary -e @cases/canary.json -e "$P4" -e autosec_require_approval=false)
  [ "$(js "$W/$tag-p4.json" 'd["id"]')" != "$ID1" ] && [ "$(js "$W/$tag-p4.json" 'd["server_changes"]')" = 1 ]
  ok "$tag p4: a changed item changes the id" $?
  rc=$(plan p4b canary -e @cases/canary.json -e "$P4")
  [ "$rc" != 0 ] && has "$W/$tag-p4b.log" "[R00-4]"; ok "$tag p4: and needs approval (R00-4)" $?
  # A package no role lists as an item (python3-systemd for fail2ban's
  # systemd backend) is still a server change, part of the id.
  rc=$(plan p4c canary -e @cases/canary.json -e '{"_aptg_pf_missing": ["python3-systemd"]}')
  [ "$rc" != 0 ] && has "$W/$tag-p4c.log" "[R00-4]"; ok "$tag p4c: a package to install alone needs approval (R00-4)" $?
  rc=$(plan p4d canary -e @cases/canary.json -e '{"_aptg_pf_missing": ["python3-systemd"]}' -e autosec_require_approval=false)
  [ "$(js "$W/$tag-p4d.json" 'd["id"]')" != "$ID1" ] && [ "$(js "$W/$tag-p4d.json" 'd["server_changes"]')" = 1 ]
  ok "$tag p4d: and changes the id" $?
  rc=$(plan p5 other-host -e @cases/canary.json)
  [ "$(js "$W/$tag-p5.json" 'd["id"]')" != "$ID1" ]; ok "$tag p5: another host, another id" $?

  rc=$(plan p6 fresh -e @cases/new.json -e autosec_plan_only=true)
  NID=$(js "$W/$tag-p6.json" 'd["id"]')
  [ "$rc" = 0 ] && [ "$(js "$W/$tag-p6.json" 'd["status"]')" = "plan only: nothing changes in this run" ] \
    && has "$W/$tag-p6.log" "server: 3 files, 2 packages, 1 services (re)started, 2 firewall rules, 1 account(s), ufw turned on"
  ok "$tag p6: plan only: rc 0, totals, stops" $?
  ! grep -q 'R00-4' "$W/$tag-p6.log"; ok "$tag p6: plan only asks no approval" $?
  rc=$(plan p7 fresh -e @cases/new.json)
  [ "$rc" != 0 ] && has "$W/$tag-p7.log" "[R00-4]" && has "$W/$tag-p7.log" "autosec_approve=$NID"
  ok "$tag p7: no approval: R00-4 names the id" $?
  rc=$(plan p8 fresh -e @cases/new.json -e autosec_approve=000000000000)
  [ "$rc" != 0 ] && has "$W/$tag-p8.log" "[R00-5]" && has "$W/$tag-p8.log" "approved 000000000000, now $NID"
  ok "$tag p8: another id: R00-5" $?
  rc=$(plan p9 fresh -e @cases/new.json -e "autosec_approve=$NID")
  [ "$rc" = 0 ] && [ "$(js "$W/$tag-p9.json" 'd["status"]')" = approved ]; ok "$tag p9: the right id: approved" $?
  rc=$(plan p10 fresh -e @cases/new.json -e "autosec_approve=000000000000,$NID")
  [ "$rc" = 0 ]; ok "$tag p10: a list of ids that holds this one" $?
  rc=$(plan p11 fresh -e @cases/new.json --check)
  [ "$rc" = 0 ] && [ "$(js "$W/$tag-p11.json" 'd["status"]')" = "--check: nothing changes, approval not needed" ]
  ok "$tag p11: --check needs no approval" $?
  rc=$(plan p12 fresh -e @cases/new.json -e autosec_require_approval=false)
  [ "$rc" = 0 ] && [ "$(js "$W/$tag-p12.json" 'd["need_approval"]')" = False ]; ok "$tag p12: autosec_require_approval false" $?
  rc=$(plan p13 canary -e @cases/canary.json -e '{"_layer_04": true}')
  [ "$rc" != 0 ] && grep -q '04 fwknop:    NO PLAN' "$W/$tag-p13.log" && has "$W/$tag-p13.log" "[R00-4]"
  ok "$tag p13: a configured layer without a plan: NO PLAN, needs approval" $?
  rc=$(plan p14 canary -e @cases/canary.json -e '{"_plan_01": [{"role": "01", "part": "x", "do": "delete", "what": "y", "note": ""}]}')
  [ "$rc" != 0 ] && has "$W/$tag-p14.log" "auto_sec bug"; ok "$tag p14: an item outside the contract is refused" $?
  rc=$(plan p15 canary -e @cases/canary.json -e '{"_sel_10": false, "_base_role_runs": false}')
  F=$W/$tag-p15.json
  js "$F" 'd["lines"]' | grep -q "10 report:    not selected by --tags" \
    && js "$F" 'd["lines"]' | grep -q "01 base:      not selected by --tags" \
    && [ "$(js "$F" 'd["id"]')" != "$ID1" ]
  ok "$tag p15: roles the tags leave out" $?
  rc=$(plan p16 canary -e @cases/canary.json -e '{"_ssh_enabled": false}')
  js "$W/$tag-p16.json" 'd["lines"]' | grep -q "02 ssh:       off (ssh_hardening_enabled: false)"
  ok "$tag p16: ssh_hardening_enabled false" $?

  # --- q: role 02's plan lines (roles/02-ssh-hardening/tasks/plan.yml) --------------
  q() { # name overrides-json: prints rc; writes $W/<tag>-<name>.json
    local name=$1 rc=0
    "$PY" - "$2" "$W/$tag-$name.vars.json" <<'PYQ'
import json, sys
k1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID4wyqWFtlxp6ylF6k1E2uurTRYwnUcK/mmCT8hwXSv/ lab-admin"
k2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMLGKwdZwDYLbvEntWLMv+Ta5BOLp0bz1wczfZk0+g9j lab-deploy"
f = {"_ssh_enabled": True, "_ssh_role_runs": True, "_ssh_admin": "labadmin", "_ssh_admin_keys": [k1],
     "_ssh_deploy_keys": [k2], "_ssh_needs_write": False, "_ssh_migrate_kind": "none", "_ssh_diff": [],
     "_ssh_deferred": False, "_ssh_deferred_reason": "", "_ssh_local_mode": False, "_ssh_controller_ip": "",
     "_base_role_runs": True, "_base_user_plan": "keep"}
v = {"deploy_user": "deploy", "ssh_permit_root_login": "keep", "ssh_password_authentication": "keep",
     "ssh_allow_users": [], "ssh_extra_settings": {}}
o = json.loads(sys.argv[1])
f.update(o.pop("lab_facts", {}))
v.update(o)
v["lab_facts"] = f
json.dump(v, open(sys.argv[2], "w"))
PYQ
    rm -f "$W/$tag-$name.json"
    (cd "$HERE" && PATH="$W/stub:$PATH" LAB_HOME="$W/home" ANSIBLE_ROLES_PATH="$ROOT/roles" \
      "$PB" -i localhost, plan02.yml -e "@$W/$tag-$name.vars.json" -e "lab_out=$W/$tag-$name.json") \
      >"$W/$tag-$name.log" 2>&1 || rc=$?
    echo "$rc"
  }
  K1B=AAAAC3NzaC1lZDI1NTE5AAAAID4wyqWFtlxp6ylF6k1E2uurTRYwnUcK/mmCT8hwXSv/
  rm -rf "${W:?}/home"; mkdir -p "$W/home/labadmin/.ssh"
  printf 'ssh-ed25519 %s hand-added\n' "$K1B" >"$W/home/labadmin/.ssh/authorized_keys"
  rc=$(q q1 '{}'); F=$W/$tag-q1.json
  [ "$rc" = 0 ] && [ "$(js "$F" 'd["items"]')" = "[]" ] && js "$F" 'd["notes"]' | grep -q 'deploy does not exist; its key waits'
  ok "$tag q1: keys present, nothing to write: no change; deploy's key waits (note)" $?
  rc=$(q q2 '{"lab_facts": {"_base_user_plan": "create"}}'); F=$W/$tag-q2.json
  [ "$(js "$F" '[(i["part"], i["do"], i["note"]) for i in d["items"]]')" = "[('keys', 'write', 'after role 01 creates the account')]" ] \
    && js "$F" 'd["items"][0]["what"]' | grep -q '^~deploy/.ssh/authorized_keys: add ssh-ed25519 key \.\.\.'
  ok "$tag q2: deploy created by role 01: its key is planned" $?
  printf 'ssh-ed25519 AAAAother other\n' >"$W/home/labadmin/.ssh/authorized_keys"
  rc=$(q q3 '{}'); F=$W/$tag-q3.json
  [ "$(js "$F" 'len(d["items"])')" = 1 ] \
    && [ "$(js "$F" 'd["items"][0]["what"]')" = "~labadmin/.ssh/authorized_keys: add ssh-ed25519 key ...${K1B: -12}" ]
  ok "$tag q3: a missing admin key is planned (its last 12 characters shown)" $?
  rm -rf "$W/home/labadmin/.ssh"; mkdir -p "$W/home/elsewhere"; ln -s "$W/home/elsewhere" "$W/home/labadmin/.ssh"
  rc=$(q q4 '{}'); F=$W/$tag-q4.json
  [ "$(js "$F" 'd["items"]')" = "[]" ] && js "$F" 'd["notes"]' | grep -q 'is a link or not a plain file'
  ok "$tag q4: a linked ~/.ssh: no item, a note" $?
  rm -f "$W/home/labadmin/.ssh"; mkdir -p "$W/home/labadmin/.ssh"
  printf 'ssh-ed25519 %s hand-added\n' "$K1B" >"$W/home/labadmin/.ssh/authorized_keys"
  rc=$(q q5 '{"ssh_permit_root_login": "prohibit-password", "ssh_password_authentication": "no", "ssh_extra_settings": {"MaxAuthTries": 4}, "lab_facts": {"_ssh_needs_write": true, "_ssh_diff": ["passwordauthentication", "permitrootlogin"], "_ssh_controller_ip": "203.0.113.9"}}')
  F=$W/$tag-q5.json
  [ "$(js "$F" '[(i["part"], i["do"]) for i in d["items"]]')" = "[('sshd', 'write'), ('undo', 'write'), ('sshd', 'reload')]" ] \
    && [ "$(js "$F" 'd["items"][0]["what"]')" = "/etc/ssh/sshd_config.d/00-autosec.conf: PermitRootLogin prohibit-password; PasswordAuthentication no; MaxAuthTries 4" ] \
    && [ "$(js "$F" 'd["items"][0]["note"]')" = "sshd -T changes passwordauthentication, permitrootlogin" ] \
    && js "$F" 'd["notes"]' | grep -q 'runtime only'
  ok "$tag q5: a write: the drop-in's lines from your values, the undo, the reload; sshd -T keys in the note" $?
  rc=$(q q6 '{"lab_facts": {"_ssh_needs_write": true}}'); F=$W/$tag-q6.json
  [ "$(js "$F" 'd["items"][0]["what"]')" = "/etc/ssh/sshd_config.d/00-autosec.conf: comments only (every setting keep)" ]
  ok "$tag q6: keep/keep on a host without the drop-in: a comments-only file" $?
  rc=$(q q7 '{"lab_facts": {"_ssh_needs_write": true, "_ssh_migrate_kind": "stock"}}'); F=$W/$tag-q7.json
  [ "$(js "$F" '[(i["part"], i["do"]) for i in d["items"]][0]')" = "('sshd', 'replace')" ]
  ok "$tag q7: migrating to the stock sshd_config is a replace" $?
  rc=$(q q8 '{"lab_facts": {"_ssh_role_runs": false, "_ssh_needs_write": true}}'); F=$W/$tag-q8.json
  [ "$(js "$F" 'd["items"]')" = "[]" ] && [ "$(js "$F" 'd["notes"]')" = "[]" ]
  ok "$tag q8: role 02 not selected: no lines" $?

  # --- d: defaults that follow autosec_server ---------------------------------------
  dflt() { # name args...: prints the rendered JSON
    (cd "$HERE" && "$PB" -i localhost, defaults.yml -e "lab_out=$W/$tag-$1.json" "${@:2}") >"$W/$tag-$1.log" 2>&1
    cat "$W/$tag-$1.json" 2>/dev/null
  }
  sel='[d["deploy_user_account"], d["unattended_upgrades_enabled"], d["fail2ban_hardening_enabled"], d["firewall_state"], d["cve_watch_enabled"], d["autosec_require_approval"], d["egress_lockdown"], d["firewall_inbound"]]'
  dflt d1 -e autosec_server=existing >/dev/null
  [ "$(js "$W/$tag-d1.json" "$sel")" = "['keep', 'keep', 'keep', 'keep', 'False', 'False', 'False', []]" ]
  ok "$tag d1: existing: keep everywhere, CVE watch off" $?
  dflt d2 -e autosec_server=new >/dev/null
  [ "$(js "$W/$tag-d2.json" "$sel")" = "['create', 'auto', 'true', 'enabled', 'False', 'False', 'False', []]" ]
  ok "$tag d2: new: create, auto, true, enabled; CVE watch off" $?
  dflt d3 -e autosec_server=new -e ssh_admin_user=root >/dev/null
  [ "$(js "$W/$tag-d3.json" 'd["deploy_user_account"]')" = keep ]; ok "$tag d3: new with root as the admin: no account" $?
  dflt d4 -e autosec_server=new -e deploy_user=root >/dev/null
  [ "$(js "$W/$tag-d4.json" 'd["deploy_user_account"]')" = keep ]; ok "$tag d4: new with deploy_user root: no account" $?
  dflt d5 -e autosec_server=new -e ssh_admin_user=alice >/dev/null
  [ "$(js "$W/$tag-d5.json" 'd["deploy_user_account"]')" = keep ]; ok "$tag d5: new with another admin account: no account" $?
done

# --- x: the plan id does not depend on the ansible-core version -----------------------
if [ ${#ANSIBLES[@]} -gt 1 ]; then
  ids=$(for v in $(compgen -v ID_CANARY_); do echo "${!v}"; done | sort -u | wc -l)
  [ "$ids" = 1 ]; ok "x1: the canary's plan id is the same on every ansible-core" $?
fi

# --- t: static checks ------------------------------------------------------------------
"$PY" "$HERE/static.py" "$ROOT" >"$W/t1.log" 2>&1
ok "t1: static checks on the repository" $?
grep -c '^PASS' "$W/t1.log" | grep -qx 19; ok "t1: all 19 static checks ran" $?
N=$W/neg
mkdir -p "$N"
cp -r "$ROOT/roles" "$ROOT/site.yml" "$N/"
cat >"$N/roles/03-firewall/tasks/zz-neg.yml" <<'EOF'
---
- name: neg apt
  ansible.builtin.apt: {name: curl}
- name: neg cron
  ansible.builtin.cron: {name: x, job: "true"}
- name: neg sysctl
  ansible.builtin.lineinfile: {path: /etc/sysctl.conf, line: x=1}
- name: neg audit
  ansible.builtin.command:
    argv: [sh, -c, "augenrules --load"]
- name: neg sudoers
  ansible.builtin.copy: {dest: /etc/sudoers.d/x, content: x}
- name: neg enable
  ansible.builtin.systemd: {name: x, enabled: true}
- name: neg id
  ansible.builtin.debug: {msg: "[R01-A3] not role 01"}
EOF
cat >"$N/roles/08-detection/tasks/zz-neg.yml" <<'EOF'
---
- name: neg absent
  ansible.builtin.file: {path: /etc/audit/rules.d/hardening.rules, state: absent}
EOF
sed -i 's/_plan_10:/_plan_x10:/' "$N/roles/10-report/tasks/plan.yml"
"$PY" "$HERE/static.py" "$N" >"$W/t2.log" 2>&1
[ $? = 1 ]; ok "t2: the planted violations fail the static checks" $?
for c in plan-10 ids modules sysctl audit absent sudoers enable; do
  grep -q "^FAIL  \[static\] $c" "$W/t2.log"; ok "t2: $c catches its planted violation" $?
done

echo "site-semantics: $pass passed, $fail failed"
[ "$fail" = 0 ]
