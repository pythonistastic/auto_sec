#!/usr/bin/env bash
# legacy-live (plan 6.2): auto_sec 0.6 on a runner that still has the
# detectors of an earlier release (roles 08 and 09 of --ref, default
# v0.3.2, the last tag; 0.3-0.5 install the same detectors). Over SSH to
# root@127.0.0.1, with every choice keep and ssh_hardening_enabled: false.
#   a  the detectors in active mode: the run stops at pre-task 3 (R00-3),
#      before fact gathering; Ansible's SSH session survives (no
#      UNREACHABLE) and the rc is not 0
#   b  the detectors in alert mode: the run goes through, warns (W08-1 for
#      the old audit rules file, W09-1 for the detectors) and changes
#      nothing on the server
#
# GITHUB-HOSTED RUNNERS ONLY (tests/full-live/lib.sh refuses elsewhere).
# Needs the git history with the tag (CI: actions/checkout fetch-depth: 0).
# Ran green on GitHub's Ubuntu 24.04 runner (0.6).
# Usage: bash tests/full-legacy-live/run.sh [--ref TAG]
# Logs: $RUNNER_TEMP/full-legacy-live/logs. Exit 0 = every check passed.
set -u -o pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
NAME=legacy-live
WORK=${RUNNER_TEMP:-/tmp}/full-legacy-live
REF=v0.3.2
while [ $# -gt 0 ]; do
  case $1 in
    --ref) [ $# -ge 2 ] || { echo "ERROR: --ref needs a tag" >&2; exit 2; }; REF=$2; shift 2 ;;
    *) echo "ERROR: unknown argument: $1" >&2; exit 2 ;;
  esac
done
# shellcheck source-path=SCRIPTDIR/..
# shellcheck source=full-live/lib.sh
. "$ROOT/tests/full-live/lib.sh"
HOST=legacy
OLD=$WORK/old

install_old() { # mode
  (cd "$HERE" && ANSIBLE_ROLES_PATH="$OLD/roles" ansible-playbook -i localhost, -c local install-old.yml \
    -e "old_vars=$OLD/group_vars/all.yml" -e "watcher_mode=$1" -e ansible_python_interpreter=/usr/bin/python3) \
    >"$LOGS/install-$1.log" 2>&1
}

setup() {
  echo "== setup (detectors of $REF)"
  command -v git >/dev/null 2>&1 || die "missing tool: git"
  git -C "$ROOT" rev-parse -q --verify "refs/tags/$REF" >/dev/null || die "no tag $REF in this checkout (fetch-depth: 0)"
  mkdir -p "$OLD"
  git -C "$ROOT" archive "$REF" roles/08-detection roles/09-watcher group_vars/all.yml | tar -x -C "$OLD" \
    || die "cannot unpack $REF"
  apt_update || die "apt-get update"
  ssh_setup
  install_old active || die "installing the $REF detectors failed (log $LOGS/install-active.log)"
  for u in recon-watch revshell-scan; do
    expect setup "$u" "$(systemctl is-active "$u" 2>/dev/null)" active
  done
  sudo -n grep -Eq '^[[:space:]]*mode[[:space:]]*=[[:space:]]*active' /opt/watcher/watcher.conf \
    || die "watcher.conf does not say mode = active"
  {
    echo "      autosec_server: existing"
    echo "      ssh_hardening_enabled: false"
    echo "      ssh_admin_user: root"
    echo "      ssh_permit_root_login: keep"
    echo "      ssh_password_authentication: keep"
    echo "      office_static_ip: \"\""
    echo "      paranoia_level: standard"
  } >"$WORK/vars.yml"
  write_inv "$HOST" "$WORK/vars.yml"
}

case_a() {
  local rc=0
  play a-active -l "$HOST" || rc=$?
  if [ "$rc" -ne 0 ]; then pass a "the run stops (rc $rc)"; else fail a "the run went through with active detectors"; fi
  log_has a a-active "Old detectors R00-3: refuse while they run in active mode" "stopped by R00-3"
  log_has a a-active "run in active mode on $HOST" "the message names active mode"
  log_lacks a a-active "Preflight: gather facts" "stopped before fact gathering"
  log_lacks a a-active "UNREACHABLE" "Ansible's SSH session survived"
  if ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -i "$KEYS/admin" root@127.0.0.1 true </dev/null; then
    pass a "a fresh SSH login still works"
  else
    fail a "a fresh SSH login fails"
  fi
}

case_b() {
  local rc=0 n u
  sudo -n sed -i -E 's/^([[:space:]]*mode[[:space:]]*=[[:space:]]*)active/\1alert/' /opt/watcher/watcher.conf
  for u in recon-watch revshell-scan login-watcher; do
    if systemctl is-active -q "$u"; then sudo -n systemctl restart "$u"; fi
  done
  snapshot b-before
  play b-alert -l "$HOST" || rc=$?
  expect b "alert mode: run rc" "$rc" 0
  log_has b b-alert "WARNING: auto_sec 0.1-0.5's detectors are on $HOST" "W09-1"
  log_has b b-alert "/etc/audit/rules.d/90-autosec.rules on $HOST is the audit rules file auto_sec" "W08-1"
  n=$(changed_tasks b-alert | grep -v '^10-report : Report: ' | paste -sd'|' -)
  expect b "tasks that changed something, apart from the report" "${n:-none}" none
  snapshot b-after
  same b b-before b-after
}

setup
echo "== case a"; case_a
echo "== case b"; case_b
finish
