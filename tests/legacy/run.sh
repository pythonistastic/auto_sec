#!/usr/bin/env bash
# legacy: unprivileged tests of roles 08 and 09 in auto_sec 0.6. Those roles
# install and write nothing in 0.6. They look for what auto_sec 0.1-0.5 left
# (W08-1, W09-1, N09-1) and stop the run while the old detectors run in
# active mode (R00-3, before fact gathering). No root, nothing installed:
#   static  the role files use only read-only tasks (static.py);
#   render  the 0.1-0.5 audit rules files, rendered by this ansible-core from
#           the old releases' own copy task (render.yml), hash to the
#           constants in roles/08-detection/defaults/main.yml;
#   lab     lab.yml runs the roles as site.yml wires them, against lab
#           trees: W08-1 only for 0.1-0.5's exact files and never for
#           yours, W09-1, N09-1, R00-3 (also against Python's configparser,
#           which the detectors use), the tags, --check, and every lab tree
#           byte-identical afterwards;
#   trace   with strace: the R00-3 tasks and the legacy reads start no
#           command that 0.5's recon detector counts; fact gathering does.
#
# Usage: tests/legacy/run.sh [--strace PATH] [--keep]
#   --strace PATH  the strace binary (default: strace in PATH; SKIP without)
#   --keep         keep the work directory and print its path
# Needs: ansible-playbook, python3, sha256sum, mkfifo.
# Exit 0 = every check passed, 1 = a check failed, 2 = setup problem.
set -u -o pipefail
export LC_ALL=C.UTF-8   # Ansible needs a UTF-8 locale

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
STRACE=""
KEEP=0

die() { echo "ERROR: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case $1 in
    --strace) [ $# -ge 2 ] || die "--strace needs a path"; STRACE=$2; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
for t in ansible-playbook python3 sha256sum mkfifo; do
  command -v "$t" >/dev/null 2>&1 || die "missing tool: $t"
done
[ -n "$STRACE" ] || STRACE=$(command -v strace 2>/dev/null || true)
# The Python that runs Ansible: it has PyYAML.
APY=$(ansible-playbook --version | sed -n 's/^  python version = .*(\(.*\))$/\1/p')
[ -x "$APY" ] || die "cannot find the Python that runs ansible-playbook"

W=$(mktemp -d "${TMPDIR:-/tmp}/legacy.XXXXXX") || die "mktemp failed"
cleanup() { chmod -R u+rwX "$W" 2>/dev/null; if [ "$KEEP" = 1 ]; then echo "work dir kept: $W"; else rm -rf "$W"; fi; }
trap cleanup EXIT
mkdir -p "$W/lab" "$W/out" "$W/render" "$W/trace" "$W/bin" || die "cannot create directories"
# The systemctl stub, as a copy: a checkout may lose the execute bit.
install -m 0755 "$HERE/stubs/systemctl" "$W/bin/systemctl" || die "cannot install the systemctl stub"

PASSES=0
FAILS=0
pass() { PASSES=$((PASSES + 1)); printf 'PASS  %-12s %s\n' "$1" "$2"; }
fail() { FAILS=$((FAILS + 1)); printf 'FAIL  %-12s %s\n' "$1" "$2"; }
skip() { printf 'SKIP  %-12s %s\n' "$1" "$2"; }
info() { printf 'INFO  %-12s %s\n' "$1" "$2"; }
expect() { # test what got want
  if [ "$3" = "$4" ]; then pass "$1" "$2: $3"; else fail "$1" "$2: got '$3', want '$4'"; fi
}

export ANSIBLE_ROLES_PATH="$ROOT/roles" ANSIBLE_NOCOLOR=1 ANSIBLE_LOCALHOST_WARNING=False \
  ANSIBLE_INVENTORY_UNPARSED_WARNING=False ANSIBLE_RETRY_FILES_ENABLED=False
info setup "$(ansible-playbook --version | head -1), python $APY"

# --- static -------------------------------------------------------------------
"$APY" -I "$HERE/static.py" "$ROOT" > "$W/out/static.txt" 2>&1
STATIC_RC=$?
cat "$W/out/static.txt"
PASSES=$((PASSES + $(grep -c '^PASS' "$W/out/static.txt")))
FAILS=$((FAILS + $(grep -c '^FAIL' "$W/out/static.txt")))
if [ "$STATIC_RC" != 0 ] && ! grep -q '^FAIL' "$W/out/static.txt"; then fail static "static.py stopped (rc $STATIC_RC)"; fi
expect static "recon patterns of 0.5 in fixtures/recon-patterns-0.5.txt" \
  "$(grep -cv '^#' "$HERE/fixtures/recon-patterns-0.5.txt")" 32

# --- render: the hash constants --------------------------------------------------
U32=abcdefghijklmnopqrstuvwxyz_-0123
render() { # dir user ak
  mkdir -p "$1"
  (cd "$HERE" && ansible-playbook -i localhost, render.yml \
    -e "{\"lab_out\": \"$1\", \"deploy_user\": \"$2\", \"deploy_authkeys\": {\"stat\": {\"exists\": $3}},
         \"ansible_python_interpreter\": \"$APY\"}" >"$1.log" 2>&1) || { fail render "render.yml failed ($1.log)"; return 1; }
}
normhash() { # file -> normalized sha256 (the rule in roles/08-detection/defaults/main.yml)
  "$APY" -I - "$ROOT/roles/08-detection/defaults/main.yml" "$1" <<'PY'
import hashlib, re, sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
t = open(sys.argv[2], "rb").read().decode("utf-8", "surrogateescape")
t = re.sub(d["_l08_ak_re"], d["_l08_ak_norm"], t)
print(hashlib.sha256(t.encode("utf-8", "surrogateescape")).hexdigest())
PY
}
want() { # file name -> its constant(s)
  "$APY" -I - "$ROOT/roles/08-detection/defaults/main.yml" "$1" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
print(" ".join(next(f["sha256"] for f in d["_l08_legacy_files"] if f["name"] == sys.argv[2])))
PY
}
H01=$(want hardening.rules)
H03=$(want 90-autosec.rules)
for u in deploy a_b-c "$U32"; do
  for ak in true false; do
    d="$W/render/$u-$ak"
    render "$d" "$u" "$ak" || continue
    h=$(normhash "$d/hardening.rules")
    case " $H01 " in
      *" $h "*) pass render "0.1-0.2 hardening.rules (user $u, authorized_keys $ak) is a constant" ;;
      *) fail render "0.1-0.2 hardening.rules (user $u, authorized_keys $ak): $h not in $H01" ;;
    esac
    h=$(normhash "$d/90-autosec.rules")
    case " $H03 " in
      *" $h "*) pass render "0.3-0.5 90-autosec.rules (user $u, authorized_keys $ak) is a constant" ;;
      *) fail render "0.3-0.5 90-autosec.rules (user $u, authorized_keys $ak): $h not in $H03" ;;
    esac
  done
done
expect render "0.1-0.2 wrote the authorized_keys line always" \
  "$(normhash "$W/render/deploy-false/hardening.rules")" "$(normhash "$W/render/deploy-true/hardening.rules")"
expect render "largest 0.1-0.5 file, 32-character user (bytes; role 08 reads up to 4096)" \
  "$(wc -c < "$W/render/$U32-true/90-autosec.rules" | tr -d ' ')" 920

# --- lab --------------------------------------------------------------------------
# lab NAME: a new lab tree; $L is its root, $N its name.
lab() { N=$1; L=$W/lab/$N/root; mkdir -p "$L"; : > "$W/lab/$N/states"; }
# state UNIT STATE: what the systemctl stub answers for that unit.
state() { printf '%s %s\n' "$1" "$2" >> "$W/lab/$N/states"; }
snap() { # the whole lab tree: type, mode, size, mtime, link target, content hash
  (cd "$W/lab/$N" && find root -printf '%p %y %m %s %T@ %l\n' | sort
   find root -type f -readable -print0 | sort -z | xargs -0 -r sha256sum)
}
# run [ansible-playbook args]: lab.yml against $L. Sets RC; the log is in
# $LOG, the facts in $OUT, the systemctl calls in $CALLS. A changed lab
# tree fails.
run() {
  LOG=$W/out/$N.log OUT=$W/out/$N.json CALLS=$W/out/$N.calls
  rm -f "$OUT"; : > "$CALLS"
  snap > "$W/out/$N.before" 2>/dev/null
  (cd "$HERE" && PATH="$W/bin:$PATH" LAB_CALLS="$CALLS" LAB_UNIT_STATES="$W/lab/$N/states" \
    ansible-playbook -i localhost, lab.yml -e "lab_root=$L" -e "lab_out=$OUT" \
      -e "{\"ansible_python_interpreter\": \"$APY\"}" "$@" >"$LOG" 2>&1)
  RC=$?
  snap > "$W/out/$N.after" 2>/dev/null
  if cmp -s "$W/out/$N.before" "$W/out/$N.after"; then pass "$N" "the lab tree is unchanged"
  else fail "$N" "the lab tree changed: $(diff "$W/out/$N.before" "$W/out/$N.after" | head -3 | tr '\n' ' ')"; fi
}
fact() { "$APY" -I -c 'import json, sys; print(json.dumps(json.load(open(sys.argv[1]))[sys.argv[2]]))' "$OUT" "$1" 2>/dev/null || echo "(no facts)"; }
count() { grep -c -- "$1" "$LOG"; }
has() { if grep -q -- "$2" "$LOG"; then pass "$N" "$1"; else fail "$N" "$1 (not in $LOG)"; fi; }
hasnt() { if grep -q -- "$2" "$LOG"; then fail "$N" "$1 (found in $LOG)"; else pass "$N" "$1"; fi; }
in_task() { # what task-name-part pattern: the pattern is in that task's output
  if awk -v t="$2" 'index($0, "TASK [") == 1 { on = index($0, t) > 0; next } on' "$LOG" | grep -q -- "$3"
  then pass "$N" "$1"; else fail "$N" "$1 (not in task '$2' of $LOG)"; fi
}
rc0() { expect "$N" "${1:-rc}" "$RC" 0; }
refused() { # the play stopped at R00-3 with this text
  if [ "$RC" != 0 ] && grep -q 'R00-3: refuse while they run in active mode' "$LOG" \
     && grep -q -- "$1" "$LOG" && grep -q 'Nothing has been changed.' "$LOG"; then
    pass "$N" "R00-3 refuses: ...$1"
  else fail "$N" "R00-3 refusal with '$1' (rc $RC, $LOG)"; fi
}
RULES=etc/audit/rules.d
W08='is the audit rules file auto_sec'
W09="WARNING: auto_sec 0.1-0.5's detectors are on"

# Role 08: W08-1 for 0.1-0.5's exact files only.
lab a08-none; run; rc0; expect "$N" "W08-1 lines" "$(count "$W08")" 0
expect "$N" _plan_08 "$(fact plan_08)" "[]"
expect "$N" _l08_report "$(fact l08_report)" '"not managed by auto_sec 0.6"'

lab a08-canary; mkdir -p "$L/$RULES"
cp "$HERE/fixtures/operator-audit.rules" "$L/$RULES/audit.rules"
cp "$HERE/fixtures/operator-hardening.rules" "$L/$RULES/hardening.rules"
run; rc0; expect "$N" "W08-1 for your audit.rules and hardening.rules" "$(count "$W08")" 0
expect "$N" _l08_legacy "$(fact l08_legacy)" "[]"

for v in deploy-true deploy-false a_b-c-true "$U32-false"; do
  lab "a08-03-$v"; mkdir -p "$L/$RULES"; cp "$W/render/$v/90-autosec.rules" "$L/$RULES/"
  cp "$HERE/fixtures/operator-hardening.rules" "$L/$RULES/hardening.rules"
  run; rc0; expect "$N" "W08-1 lines" "$(count "$W08")" 1
  has "W08-1 names 90-autosec.rules as 0.3-0.5's" \
    "$RULES/90-autosec.rules on localhost is the audit rules file auto_sec 0.3-0.5 wrote"
  has "W08-1 says it loads before your files" "It loads before your files"
  expect "$N" _l08_legacy "$(fact l08_legacy)" "[{\"file\": \"$L/$RULES/90-autosec.rules\", \"versions\": \"0.3-0.5\"}]"
done

lab a08-01; mkdir -p "$L/$RULES"; cp "$W/render/a_b-c-true/hardening.rules" "$L/$RULES/"
run; rc0
has "W08-1 names hardening.rules as 0.1-0.2's" "$RULES/hardening.rules on localhost is the audit rules file auto_sec 0.1-0.2 wrote"
has "W08-1 says it loads together with your files" "It loads together with your files"
has "W08-1 gives the removal command" "sudo rm $L/$RULES/hardening.rules && sudo augenrules --load"

lab a08-both; mkdir -p "$L/$RULES"; cp "$W/render/deploy-true/"*.rules "$L/$RULES/"
run; rc0; expect "$N" "W08-1 lines (one per file; the layer pass prints nothing)" "$(count "$W08")" 2
expect "$N" _l08_report "$(fact l08_report)" \
  "\"not managed by auto_sec 0.6; still there from auto_sec 0.1-0.5: $L/$RULES/hardening.rules, $L/$RULES/90-autosec.rules\""

# Yours, not auto_sec's: 0.3's text without the line under the 0.1 name, a
# changed byte, an added line, CRLF, bytes that are not UTF-8, a file over
# 4096 bytes, a symlink to 0.5's file, a directory.
lab a08-yours1; mkdir -p "$L/$RULES"
cp "$W/render/deploy-false/90-autosec.rules" "$L/$RULES/hardening.rules"
sed 's/-k cron/-k Cron/' "$W/render/deploy-true/90-autosec.rules" > "$L/$RULES/90-autosec.rules"
run; rc0; expect "$N" "W08-1 for 0.3's text named hardening.rules, and a changed byte" "$(count "$W08")" 0
lab a08-yours2; mkdir -p "$L/$RULES"
{ cat "$W/render/deploy-true/hardening.rules"; echo "-w /etc/hosts -p wa -k hosts"; } > "$L/$RULES/hardening.rules"
sed 's/$/\r/' "$W/render/deploy-true/90-autosec.rules" > "$L/$RULES/90-autosec.rules"
run; rc0; expect "$N" "W08-1 for an added line, and CRLF" "$(count "$W08")" 0
lab a08-yours3; mkdir -p "$L/$RULES"
{ cat "$W/render/deploy-true/90-autosec.rules"; printf '\377\376\200 not utf-8\n'; } > "$L/$RULES/90-autosec.rules"
{ cat "$W/render/deploy-true/hardening.rules"; head -c 5000 /dev/zero | tr '\0' '#'; } > "$L/$RULES/hardening.rules"
run; rc0; expect "$N" "W08-1 for bytes that are not UTF-8, and a file over 4096 bytes" "$(count "$W08")" 0
in_task "the file over 4096 bytes is not read" "read the small regular files" "skipping: \[localhost\] => (item=hardening.rules)"
in_task "the other one is read" "read the small regular files" "ok: \[localhost\] => (item=90-autosec.rules)"
lab a08-yours4; mkdir -p "$L/$RULES/hardening.rules" "$L/elsewhere"
cp "$W/render/deploy-true/90-autosec.rules" "$L/elsewhere/"
ln -s ../../../elsewhere/90-autosec.rules "$L/$RULES/90-autosec.rules"
run; rc0; expect "$N" "W08-1 for a symlink to 0.5's file, and a directory" "$(count "$W08")" 0

# Role 09: W09-1 and N09-1.
lab b09-none; run; rc0; expect "$N" "W09-1 lines" "$(count "$W09")" 0
expect "$N" "systemctl calls" "$(wc -l < "$CALLS" | tr -d ' ')" 0
expect "$N" _plan_09 "$(fact plan_09)" "[]"
hasnt "no N09-1 without detector variables" "INFO: .* set but"

lab b09-full; mkdir -p "$L/opt/watcher" "$L/opt/detect" "$L/etc/systemd/system" "$L/var/spool/cron/crontabs"
for u in login-watcher recon-watch revshell-scan ransomware-canary; do echo "[Unit]" > "$L/etc/systemd/system/$u.service"; done
printf '[watcher]\nmode = alert\n' > "$L/opt/watcher/watcher.conf"
printf '#Ansible: audit alert scan\n*/5 * * * * /opt/detect/detect-alert.sh >> /var/log/detect.log 2>&1\n' > "$L/var/spool/cron/crontabs/root"
state recon-watch.service active; state ransomware-canary.service activating
run; rc0; expect "$N" "W09-1 lines (once)" "$(count "$W09")" 1
expect "$N" _l09_found "$(fact l09_found)" "[\"$L/opt/watcher\", \"$L/opt/detect\", \"$L/etc/systemd/system/login-watcher.service\", \"$L/etc/systemd/system/recon-watch.service (active)\", \"$L/etc/systemd/system/revshell-scan.service\", \"$L/etc/systemd/system/ransomware-canary.service (activating)\", \"root crontab: #Ansible: audit alert scan\"]"
has "W09-1 points to the README" 'Remove them by hand: README \\"Removing the 0.1-0.5 detection suite\\"'
expect "$N" "systemctl calls" "$(tr '\n' '|' < "$CALLS")" \
  "systemctl is-active recon-watch.service revshell-scan.service login-watcher.service|systemctl is-active login-watcher.service recon-watch.service revshell-scan.service ransomware-canary.service|"
expect "$N" _l09_report "$(fact l09_report)" '"not managed by auto_sec 0.6; files of the auto_sec 0.1-0.5 detectors are still there"'

lab b09-cron; mkdir -p "$L/var/spool/cron/crontabs"
printf '0 3 * * * /usr/local/bin/pg-backup\n#Ansible: audit alert scan\n*/5 * * * * true\n' > "$L/var/spool/cron/crontabs/root"
run; rc0; expect "$N" _l09_found "$(fact l09_found)" '["root crontab: #Ansible: audit alert scan"]'
expect "$N" "systemctl calls (no unit file)" "$(wc -l < "$CALLS" | tr -d ' ')" 0
lab b09-cron-other; mkdir -p "$L/var/spool/cron/crontabs"
printf '#Ansible: audit alert scan2\n# #Ansible: audit alert scan\n#Ansible: audit alert scan \n' > "$L/var/spool/cron/crontabs/root"
run; rc0; expect "$N" "W09-1 for other crontab lines" "$(count "$W09")" 0

lab b09-vars; run -e watcher_mode=alert -e recon_threshold=3 -e telegram_bot_token=CHANGE_ME
rc0; has "N09-1 lists the detector variables that are set" "INFO: recon_threshold, watcher_mode are set but do nothing in 0.6"

# Tags: the host reads run only when the tags select the role; N09-1 always.
lab c-tags; mkdir -p "$L/$RULES" "$L/opt/watcher"; cp "$W/render/deploy-true/90-autosec.rules" "$L/$RULES/"
run --tags ssh -e watcher_mode=alert; rc0
expect "$N" "--tags ssh: W08-1, W09-1" "$(count "$W08") $(count "$W09")" "0 0"
expect "$N" "--tags ssh: role 08 and 09 read the host" "$(fact l08_role_runs) $(fact l09_role_runs)" "false false"
has "--tags ssh: N09-1 still shows" "INFO: watcher_mode is set but does nothing in 0.6"
run --tags detection; rc0; expect "$N" "--tags detection: W08-1, W09-1" "$(count "$W08") $(count "$W09")" "1 1"
run --tags watcher; rc0; expect "$N" "--tags watcher: W08-1, W09-1" "$(count "$W08") $(count "$W09")" "0 1"
run --skip-tags detection; rc0; expect "$N" "--skip-tags detection: W08-1, W09-1" "$(count "$W08") $(count "$W09")" "0 0"
run --check; rc0; expect "$N" "--check: W08-1, W09-1" "$(count "$W08") $(count "$W09")" "1 1"
hasnt "--check: nothing changed" "changed: \[localhost\] =>"

# R00-3. The detectors' own reading of watcher.conf (sentinel_lib.py:
# configparser, section [watcher], mode stripped, exactly "active") must
# never say active where R00-3 lets the run go on.
detector_mode() { # file -> active | alert | crash
  "$APY" -I - "$1" <<'PY'
import configparser, sys
try:
    c = configparser.ConfigParser()
    c.read(sys.argv[1])
    print("active" if c.get("watcher", "mode", fallback="alert").strip() == "active" else "alert")
except Exception:
    print("crash")
PY
}
r00() { # name content(printf format) running-unit refuse|pass [ansible-playbook args]
  local name=$1 conf=$2 unit=$3 want=$4 m
  shift 4
  lab "$name"; mkdir -p "$L/opt/watcher"
  # shellcheck disable=SC2059
  printf "$conf" > "$L/opt/watcher/watcher.conf"
  if [ -n "$unit" ]; then state "$unit" active; fi
  run "$@"
  if [ "$want" = refuse ]; then refused "mode = active; running: ${unit%.service})"; else rc0 "runs on"; fi
  m=$(detector_mode "$L/opt/watcher/watcher.conf")
  if [ "$m" = active ] && [ -n "$unit" ] && [ "$RC" = 0 ]; then
    fail "$N" "the detectors read mode = active, but R00-3 let the run go on"
  else pass "$N" "the detectors read: $m"; fi
}
REAL='# Managed by Ansible. Permissions 0600, root only.\n# Rotate the pattern quarterly. Never commit real values to git.\n\n# [watcher] holds values shared by ALL detectors plus the SSH pattern.\n[watcher]\npattern = cd /opt/app\nwindow_seconds = 60\nmode = %s\ntelegram_bot_token = 123456:LABTOKENxxxxxxxxxxxxxxxxxxxx\ntelegram_chat_id = 42\nhost_label = h1\nwhitelist_ips = 203.0.113.7\nskip_non_interactive = true\n\n[revshell]\nenabled = true\nscan_interval = 5\n\n[recon]\nenabled = true\nthreshold = 4\n'
# shellcheck disable=SC2059
r00 r-0.5-active "$(printf "$REAL" active)" recon-watch.service refuse -v
hasnt "the Telegram token never shows (also with -v)" LABTOKEN
# shellcheck disable=SC2059
r00 r-0.5-alert "$(printf "$REAL" alert)" recon-watch.service pass
r00 r-active-stopped '[watcher]\nmode = active\n' "" pass
r00 r-crlf '[watcher]\r\nmode = active\r\n' revshell-scan.service refuse
r00 r-nospace '[watcher]\nmode=active\n' login-watcher.service refuse
r00 r-colon '[watcher]\nMODE : active\n' recon-watch.service refuse
r00 r-default '[DEFAULT]\nmode = active\n[watcher]\npattern = x\n' recon-watch.service refuse
r00 r-other-section '[watcher]\nmode = alert\n[recon]\nmode = active\n' recon-watch.service refuse
r00 r-capital '[watcher]\nmode = Active\n' recon-watch.service pass
r00 r-comment '[watcher]\n# mode = active\nmode = alert\n' recon-watch.service pass
r00 r-inline '[watcher]\nmode = active # on\n' recon-watch.service pass
r00 r-check '[watcher]\nmode = active\n' recon-watch.service refuse --check
r00 r-tags '[watcher]\nmode = active\n' recon-watch.service refuse --tags ssh
lab r-activating; mkdir -p "$L/opt/watcher"; printf '[watcher]\nmode = active\n' > "$L/opt/watcher/watcher.conf"
state login-watcher.service activating; run; refused "mode = active; running: login-watcher)"
lab r-missing; mkdir -p "$L/opt/watcher"; state recon-watch.service active; run; rc0
expect "$N" "systemctl calls without watcher.conf" "$(wc -l < "$CALLS" | tr -d ' ')" 0
lab r-dangling; mkdir -p "$L/opt/watcher"; ln -s ../nowhere.conf "$L/opt/watcher/watcher.conf"
state recon-watch.service active; run; rc0
lab r-symlink; mkdir -p "$L/opt/watcher" "$L/etc"; printf '[watcher]\nmode = active\n' > "$L/etc/w.conf"
ln -s ../../etc/w.conf "$L/opt/watcher/watcher.conf"; state recon-watch.service active; run
refused "mode = active; running: recon-watch)"
lab r-fifo; mkdir -p "$L/opt/watcher"; mkfifo "$L/opt/watcher/watcher.conf"
state recon-watch.service active; run
refused "cannot read their mode in $L/opt/watcher/watcher.conf (not a regular file)"
lab r-fifo-stopped; mkdir -p "$L/opt/watcher"; mkfifo "$L/opt/watcher/watcher.conf"; run; rc0
if [ "$(id -u)" != 0 ]; then
  lab r-noperm; mkdir -p "$L/opt/watcher"; printf '[watcher]\nmode = alert\n' > "$L/opt/watcher/watcher.conf"
  chmod 000 "$L/opt/watcher/watcher.conf"; state revshell-scan.service active; run
  refused "cannot read their mode in $L/opt/watcher/watcher.conf (grep cannot read it)"
else
  info r-noperm "not run: root reads a mode 000 file"
fi

# --- trace: what the old recon detector would see ---------------------------------
if [ -z "$STRACE" ] || ! "$STRACE" -V >/dev/null 2>&1; then
  skip trace "strace not found (--strace PATH)"
else
  lab t-trace; mkdir -p "$L/opt/watcher" "$L/opt/detect" "$L/$RULES" "$L/etc/systemd/system" "$L/var/spool/cron/crontabs"
  # shellcheck disable=SC2059
  printf "$REAL" alert > "$L/opt/watcher/watcher.conf"
  cp "$W/render/deploy-true/90-autosec.rules" "$L/$RULES/"
  echo "[Unit]" > "$L/etc/systemd/system/recon-watch.service"
  printf '#Ansible: audit alert scan\n' > "$L/var/spool/cron/crontabs/root"
  state recon-watch.service active
  tr_run() { # name [ansible-playbook args]: lab.yml under strace
    local t=$1
    shift
    (cd "$HERE" && PATH="$W/bin:$PATH" LAB_CALLS=/dev/null LAB_UNIT_STATES="$W/lab/$N/states" \
      "$STRACE" -f -ff -qq -s 4096 -e trace=execve -e signal=none -o "$W/trace/$t" \
      ansible-playbook -i localhost, lab.yml -e "lab_root=$L" -e "lab_out=$W/out/$t.json" "$@" \
      >"$W/out/$t.log" 2>&1) || fail trace "$t: lab.yml failed under strace ($W/out/$t.log)"
    "$APY" -I "$HERE/recon_count.py" "$HERE/fixtures/recon-patterns-0.5.txt" "$W/trace/$t" > "$W/out/$t.count"
  }
  tr_run lab -e "{\"ansible_python_interpreter\": \"$APY\"}"
  expect trace "R00-3, role 08 and role 09 reads: indicators of 0.5's recon detector" \
    "$(sed -n 's/^indicators: //p' "$W/out/lab.count")" 0
  info trace "lab.yml: $(head -1 "$W/out/lab.count") traced"
  # The same with interpreter discovery, as on a server without
  # ansible_python_interpreter. Ansible's own probe may run `uname` (2.16
  # does, 2.21 does not): at most that one indicator, and the detector
  # needs 4 within 45 s.
  tr_run discovery -e ansible_python_interpreter=auto_silent
  expect trace "the same with interpreter discovery: indicators other than Ansible's uname probe" \
    "$(sed -n 's/^  indicator \([^ ]*\) in:.*/\1/p' "$W/out/discovery.count" | grep -vxF '\buname\b' | tr '\n' ' ')" ""
  info trace "with interpreter discovery: $(tail -1 "$W/out/discovery.count")"
  (cd "$W" && "$STRACE" -f -ff -qq -s 4096 -e trace=execve -e signal=none -o "$W/trace/setup" \
    ansible -i localhost, -c local -m ansible.builtin.setup -e "ansible_python_interpreter=$APY" localhost \
    >"$W/out/setup.log" 2>&1) || fail trace "ansible -m setup failed under strace"
  "$APY" -I "$HERE/recon_count.py" "$HERE/fixtures/recon-patterns-0.5.txt" "$W/trace/setup" > "$W/out/setup.count"
  n=$(sed -n 's/^indicators: //p' "$W/out/setup.count")
  if [ "${n:-0}" -ge 4 ]; then pass trace "fact gathering: $n indicators (why R00-3 runs before it)"
  else fail trace "fact gathering: ${n:-?} indicators, want 4 or more (is the counter blind?)"; fi
fi

echo "legacy: $PASSES passed, $FAILS failed"
[ "$FAILS" = 0 ]
