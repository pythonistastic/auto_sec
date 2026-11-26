#!/usr/bin/env bash
# detection-live: role 08 (login alerts) for real, on a GitHub runner, as
# root@127.0.0.1 over SSH with autosec_ci: true. Every message goes to a
# fake Telegram on the runner itself (tests/detection/fake_telegram.py,
# through the CI-only switch autosec_ci_detect_api). The real Telegram is
# never called.
#   p  plan only: the plan lists the PAM line, the profile and the undo;
#      nothing changes
#   i  CI's injected failure of the login test after the PAM change
#      (autosec_ci_inject_pam_fail, AUTOSEC_CI_INJECT_FAILURE=pam): the run
#      fails, the common PAM files are byte for byte as before, the undo is
#      idle, a new SSH login works, the journal reader and sender stay on
#   a  the install, under the undo: one line in common-session, five units
#      active, no daemon-reload, the test message with the id the run
#      printed, "detection: on"
#   b  the second run changes nothing and sends nothing
#   l  logins, each with the message or the silence it must give: root with
#      the quiet key (silence), root with another key, an account with a
#      password, root with a password, a quiet account with a password
#      (silence), su - to root, su started by root (silence), sudo -i,
#      sudo -s, the console (login on a pty: never quiet, also for a quiet
#      account), the daily message
#   h  a hook that hangs holds a login up for about 1 second, never 2, and
#      the alert for that login still goes out (from the journal)
#   s  the sender is stopped: the stop message goes out, status says DEAD,
#      the checker's own message goes out, the plan says DEAD (W08-2), the
#      next run starts it again; a killed journal reader comes back by
#      itself and the stop message goes out
#   r  removal (-e detection_remove=true): the common PAM files and
#      pam-auth-update's records are byte for byte what they were before
#      the install; no unit, no file and no login message is left
#   j  journal reader only (detection_login_hook: false): no PAM file is
#      touched, a login still sends its message; removed again
#
# GITHUB-HOSTED RUNNERS ONLY (tests/full-live/lib.sh refuses elsewhere).
# NOT RUN YET: written with 0.7; it has not run on a runner.
# Usage: bash tests/detection/live/run.sh
# Logs: $RUNNER_TEMP/detection-live/logs. Exit 0 = every check passed.
set -u -o pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
NAME=detection-live
WORK=${RUNNER_TEMP:-/tmp}/detection-live
# shellcheck source-path=SCRIPTDIR/../..
# shellcheck source=full-live/lib.sh
. "$ROOT/tests/full-live/lib.sh"
HOST=watched
SINK=$WORK/sink
TOOLS=/usr/local/lib/ci-detect-live          # world-readable: the test accounts run pty_run.py
BIN=/usr/local/sbin/auto-sec-detect
HOOK=/usr/local/sbin/auto-sec-login-hook
PROFILE=/usr/share/pam-configs/auto-sec-login-alert
PENDING=/var/lib/auto-sec/ssh-guard/pending
PAM_FILES="/etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-password /etc/pam.d/common-session
/etc/pam.d/common-session-noninteractive /var/lib/pam/auth /var/lib/pam/account /var/lib/pam/password
/var/lib/pam/session /var/lib/pam/session-noninteractive /var/lib/pam/seen"
UNITS="auto-sec-alert.service auto-sec-login-watch.service auto-sec-alert.path auto-sec-alive.timer auto-sec-check.timer"
LINE=$(printf 'session\toptional\tpam_exec.so quiet seteuid type=open_session /usr/bin/timeout -s KILL 1 %s' "$HOOK")
export AUTOSEC_CI_DETECT=fake-telegram
SINK_PID=""

# shellcheck disable=SC2329  # called by the EXIT trap
cleanup() { [ -z "$SINK_PID" ] || kill "$SINK_PID" 2>/dev/null; }
trap cleanup EXIT

# --- helpers -----------------------------------------------------------------------
pam_sums() { local f; for f in $PAM_FILES $PROFILE; do sudo -n sha256sum "$f" 2>/dev/null || echo "absent $f"; done; }
detect() { sudo -n /usr/bin/python3 -I "$BIN" "$@"; }
jget() { # key... : a value of `auto-sec-detect status --json`
  detect status --json 2>/dev/null | python3 -c 'import json, sys
d = json.load(sys.stdin)
for k in sys.argv[1:]:
    d = d.get(k, "") if isinstance(d, dict) else ""
print(d)' "$@" 2>/dev/null
}
msg_count() { if [ -f "$SINK/messages" ]; then wc -l <"$SINK/messages" | tr -d ' '; else echo 0; fi; }
new_msgs() { # base: the messages after number <base>, one per line (" | " for a line break)
  tail -n "+$(( $1 + 1 ))" "$SINK/messages" 2>/dev/null | python3 -c 'import json, sys
for ln in sys.stdin:
    if ln.strip():
        print(json.loads(ln)["text"].replace("\n", " | "))'
}
expect_msg() { # case what base regex [fixed-string]: a new message matches, within 45 s
  local i=0 got
  while [ "$i" -lt 45 ]; do
    got=$(new_msgs "$3" | grep -E -- "$4" | head -n 1)
    if [ -n "$got" ] && { [ -z "${5:-}" ] || printf '%s\n' "$got" | grep -Fq -- "$5"; }; then
      pass "$1" "$2"
      return 0
    fi
    sleep 1
    i=$((i + 1))
  done
  fail "$1" "$2 (no new message matches /$4/ with \"${5:-}\"; new: $(new_msgs "$3" | head -n 3 | cut -c1-400 | paste -sd'#' -))"
  return 1
}
expect_quiet() { # case what base seconds: no new message at all
  sleep "$4"
  if [ "$(new_msgs "$3" | wc -l)" -eq 0 ]; then pass "$1" "$2"
  else fail "$1" "$2 (got: $(new_msgs "$3" | head -n 3 | cut -c1-400 | paste -sd'#' -))"; fi
}
others_since() { # base: how many new messages are not the checker's own
  new_msgs "$1" | grep -Evc '^auto_sec detection (problem:|is working again)' || true
}
settle() { # let the sender finish what waits, then return the message count
  local a b i=0
  a=$(msg_count)
  while [ "$i" -lt 10 ]; do
    sleep 3
    b=$(msg_count)
    [ "$a" = "$b" ] && break
    a=$b
    i=$((i + 1))
  done
  echo "$b"
}
SSHO=(-F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o ControlMaster=no -o ControlPath=none)
ssh_key() { ssh "${SSHO[@]}" -i "$1" "$2@127.0.0.1" true </dev/null; }                # key file, account
ssh_pw() { # account: one password login
  python3 "$TOOLS/pty_run.py" --answer-file "$WORK/pw.$1" -- ssh -F /dev/null -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 -o ControlMaster=no -o ControlPath=none "$1@127.0.0.1" true \
    >"$LOGS/ssh-pw-$1.out" 2>&1
}
# pam-auth-update's own answer in debconf's database: the list of enabled profiles.
debconf_profiles() {
  sudo -n sed -n '/^Name: libpam-runtime\/profiles$/,/^$/p' /var/cache/debconf/config.dat 2>/dev/null | sed -n 's/^Value: //p'
}
units_active() { local u n=0; for u in $UNITS; do [ "$(systemctl is-active "$u" 2>/dev/null)" = active ] && n=$((n + 1)); done; echo "$n"; }
mark_out() { # wait until the mark of the last auto_sec run has run out (20 s after it): stop messages are quiet until then
  local i=0 t
  while [ "$i" -lt 40 ]; do
    t=$(sudo -n stat -c %Y /run/auto-sec/detect-planned 2>/dev/null) || return 0
    # 902, not 900: both times here are whole seconds, so 900 can be a
    # real 899.1 s, and a stop right then is still quiet (the first run on
    # GitHub's runners lost that race on two of three machines).
    [ $(( $(date +%s) - t )) -ge 902 ] && return 0
    sleep 1
    i=$((i + 1))
  done
}
dplay() { local name=$1; shift; play "$name" -l "$HOST" --tags detection "$@"; }

setup() {
  echo "== setup"
  ssh_setup
  sudo_ready
  # Unit edits that the runner image left unloaded would stop a run that has
  # to reload systemd (R08-5). An operator would load them first.
  sudo -n systemctl daemon-reload
  # Two accounts with passwords, a password for root, a second key for root.
  local u
  for u in ci-visitor ci-quiet; do
    id "$u" >/dev/null 2>&1 || sudo -n useradd -m -s /bin/sh "$u" || die "useradd $u"
  done
  for u in ci-visitor ci-quiet root; do
    printf 'assword:\t%s\n' "pw-$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')" >"$WORK/pw.$u"
    chmod 600 "$WORK/pw.$u"
    printf '%s:%s\n' "$u" "$(cut -f2 "$WORK/pw.$u")" | sudo -n chpasswd || die "chpasswd $u"
  done
  ssh-keygen -q -t ed25519 -N '' -C "ci-$NAME-other" -f "$KEYS/other" || die "ssh-keygen"
  printf '%s\n' "$(cat "$KEYS/other.pub")" | sudo -n tee -a /root/.ssh/authorized_keys >/dev/null
  FP_ADMIN=$(ssh-keygen -lf "$KEYS/admin.pub" | awk '{print $2}')
  FP_OTHER=$(ssh-keygen -lf "$KEYS/other.pub" | awk '{print $2}')
  # Password logins, also for root (this runner only).
  printf '%s\n' 'PasswordAuthentication yes' 'KbdInteractiveAuthentication no' 'PermitRootLogin yes' 'UsePAM yes' \
    | sudo -n tee /etc/ssh/sshd_config.d/00-ci-detect-live.conf >/dev/null
  sudo -n /usr/sbin/sshd -t || die "sshd -t fails with the test's drop-in"
  sudo -n systemctl reload ssh.service >/dev/null 2>&1 || true
  # pty_run.py where the test accounts can read it, with their answers.
  sudo -n install -d -m 0755 "$TOOLS"
  sudo -n install -m 0755 "$HERE/pty_run.py" "$TOOLS/pty_run.py"
  sudo -n install -m 0600 -o ci-visitor "$WORK/pw.root" "$TOOLS/su-root.answers"
  printf 'login:\tci-quiet\n%s\n' "$(cat "$WORK/pw.ci-quiet")" | sudo -n tee "$TOOLS/console.answers" >/dev/null
  sudo -n chmod 600 "$TOOLS/console.answers"
  ssh_pw ci-visitor || die "a password login as ci-visitor does not work on this runner ($(tail -n 3 "$LOGS/ssh-pw-ci-visitor.out" | tr '\n' ' '))"
  ssh_pw root || die "a password login as root does not work on this runner"
  ssh_key "$KEYS/other" root || die "the second key does not log in as root"
  # The fake Telegram.
  mkdir -p "$SINK"
  python3 "$ROOT/tests/detection/fake_telegram.py" --dir "$SINK" --port 0 >/dev/null 2>&1 &
  SINK_PID=$!
  for _ in $(seq 30); do [ -s "$SINK/port" ] && break; sleep 0.5; done
  [ -s "$SINK/port" ] || die "the fake Telegram did not start"
  API="http://127.0.0.1:$(cat "$SINK/port")"
  # The daily message's time: 12 hours from now, so it never falls into the test.
  ALIVE_AT=$(date -d '+12 hours' +%H:%M)
  cat >"$WORK/vars.yml" <<EOF
      autosec_server: existing
      autosec_ci: true
      autosec_ci_detect_api: "$API"
      deploy_user_account: keep
      unattended_upgrades_enabled: keep
      fail2ban_hardening_enabled: keep
      firewall_state: keep
      cve_watch_enabled: false
      ssh_admin_user: root
      ssh_admin_public_keys:
        - "$ADMIN_PUB"
      ssh_permit_root_login: keep
      ssh_password_authentication: keep
      office_static_ip: ""
      paranoia_level: standard
      telegram_bot_token: "12345678:TEST-TOKEN-ONLY-for-the-fake-sink"
      telegram_chat_id: "-100123"
      detection_enabled: true
      detection_heartbeat_time: "$ALIVE_AT"
      detection_revert_seconds: 180
      detection_quiet_accounts: [ci-quiet]
      detection_quiet_ssh_keys:
        - { fingerprint: "$FP_ADMIN", label: "ci run" }
EOF
  write_inv "$HOST" "$WORK/vars.yml"
  pam_sums >"$WORK/pam.before"
  debconf_profiles >"$WORK/debconf.before"
  info setup "$(lsb_release -ds 2>/dev/null), $(systemctl --version | head -n 1), libpam-runtime $(dpkg-query -W -f='${Version}' libpam-runtime)"
  info setup "common-session before: $(grep -vc '^#' /etc/pam.d/common-session) lines; profiles: $(find /usr/share/pam-configs -maxdepth 1 -type f -printf '%f ' | sort)"
}

case_p() {
  local rc=0
  echo "== p: plan only"
  dplay p-plan -e autosec_plan_only=true || rc=$?
  expect p "plan only: rc" "$rc" 0
  log_has p p-plan "one line added with pam-auth-update --enable: 'session optional pam_exec.so quiet seteuid type=open_session /usr/bin/timeout -s KILL 1 $HOOK' (it also updates its own records in /var/lib/pam and in debconf's database)" "the plan shows the one PAM line"
  log_has p p-plan "$PROFILE (the PAM profile" "the plan lists the PAM profile"
  log_has p p-plan "(the automatic undo)" "the plan lists the undo guard"
  log_has p p-plan "one test message now" "the plan lists the test message"
  log_has p p-plan "TEST MODE: messages go to http://127.0.0.1:" "the plan says that messages go to the test sink"
  if grep -Fq '[N08-6]' "$LOGS/p-plan.log"; then
    info p "this pam-auth-update cannot try a new profile on a copy (N08-6): the trial runs at apply time"
  else
    log_has p p-plan "tried on a copy with this server's own pam-auth-update: exactly this one line is added" "the trial on a copy added exactly the one line"
  fi
  expect p "the PAM files are unchanged" "$(pam_sums | sha256sum)" "$(sha256sum <"$WORK/pam.before")"
  expect p "debconf's record of pam-auth-update is as before (the trial has a database of its own)" \
    "$(debconf_profiles)" "$(cat "$WORK/debconf.before")"
  expect p "nothing is installed" "$(sudo -n test -e "$BIN" && echo there || echo absent)" absent
  expect p "no message was sent" "$(msg_count)" 0
}

case_i() {
  local rc=0 t0
  echo "== i: the login test after the PAM change fails (injected)"
  t0=$(date +%s)
  AUTOSEC_CI_INJECT_FAILURE=pam dplay i-inject -e autosec_ci_inject_pam_fail=true || rc=$?
  if [ "$rc" -ne 0 ]; then pass i "the run stops (rc $rc)"; else fail i "the run succeeded"; fi
  log_has i i-inject "[M08-4]" "M08-4 is said"
  log_has i i-inject "injected by autosec_ci_inject_pam_fail (CI only)" "... as the injected failure"
  log_has i i-inject "put the common PAM files, /var/lib/pam and" "the run says that the files are back"
  expect i "the common PAM files, pam-auth-update's records: byte for byte as before; no profile" \
    "$(pam_sums | sha256sum)" "$(sha256sum <"$WORK/pam.before")"
  expect i "the undo guard is idle" "$(sudo -n /usr/local/sbin/auto-sec-ssh-guard status | head -n 1)" idle
  expect i "no undo is pending" "$(sudo -n test -e "$PENDING" && echo pending || echo none)" none
  if ssh_key "$KEYS/admin" root; then pass i "a new SSH login works"; else fail i "a new SSH login fails"; fi
  expect i "the journal reader and the sender stay installed and running" "$(units_active)" 5
  expect i "status: on" "$(jget verdict)" on
  if detect status | grep -Fq "the login hook's line is no longer in /etc/pam.d/common-session"; then
    pass i "status names the missing hook line"
  else fail i "status does not name the missing hook line: $(detect status | head -n 12 | tr '\n' '#')"; fi
  expect i "no daemon-reload for the new unit files" "$(reloads_since "$t0")" 0
  expect i "no test message (it comes after the PAM step) and no login alert" "$(others_since 0)" 0
  # The settings say "login hook", and the hook is not in PAM: the checker says so.
  sudo -n systemctl start auto-sec-check.service || true
  expect_msg i "the checker tells the chat that the login hook is not in PAM" 0 \
    "auto_sec detection problem: $HOST .*the login hook's line is no longer in /etc/pam.d/common-session"
}

case_a() {
  local rc=0 t0 base id
  echo "== a: the install"
  t0=$(date +%s)
  base=$(msg_count)
  dplay a-install || rc=$?
  expect a "the run: rc" "$rc" 0
  expect a "common-session holds auto_sec's line once" "$(sudo -n grep -cFx -- "$LINE" /etc/pam.d/common-session)" 1
  expect a "no other common PAM file names the hook" \
    "$(sudo -n grep -l auto-sec-login-hook /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-password /etc/pam.d/common-session-noninteractive 2>/dev/null | wc -l)" 0
  expect a "of the PAM files only common-session and pam-auth-update's two records changed, and the profile is new" \
    "$(pam_sums | diff - "$WORK/pam.before" | sed -n 's/^< [0-9a-f]* *//p' | paste -sd' ' -)" \
    "/etc/pam.d/common-session /var/lib/pam/session /var/lib/pam/seen $PROFILE"
  expect a "the profile: 0644 root, the role's file" \
    "$(stat -c '%a %U' "$PROFILE") $(sha256sum <"$PROFILE")" \
    "644 root $(sha256sum <"$ROOT/roles/08-detection/files/auto-sec-login-alert")"
  case "$(debconf_profiles)" in
    *auto-sec-login-alert*) pass a "debconf's record of pam-auth-update lists the profile (the plan said: and in debconf's database)" ;;
    *) fail a "debconf's record of pam-auth-update does not list the profile: $(debconf_profiles | cut -c1-200)" ;;
  esac
  expect a "the hook and the program: 0700 root" "$(sudo -n stat -c '%a %U' "$HOOK" "$BIN" | paste -sd' ' -)" "700 root 700 root"
  expect a "the settings: 0600 root" "$(sudo -n stat -c '%a %U' /etc/auto-sec/detect.conf)" "600 root"
  expect a "the queue: 0700 root" "$(sudo -n stat -c '%a %U' /var/spool/auto-sec/events)" "700 root"
  expect a "five units are active" "$(units_active)" 5
  expect a "the undo guard is idle" "$(sudo -n /usr/local/sbin/auto-sec-ssh-guard status | head -n 1)" idle
  expect a "no daemon-reload" "$(reloads_since "$t0")" 0
  log_has a a-install "Check Telegram for auto_sec test " "the run prints the id of its test message"
  id=$(grep -o 'Check Telegram for auto_sec test [0-9a-f]\{8\}' "$LOGS/a-install.log" | tail -n 1 | awk '{print $NF}')
  expect_msg a "that test message is in the chat" "$base" "^auto_sec test ${id:-none}: alerts from $HOST reach this chat"
  expect a "status: on, both sensors" "$(jget verdict) $(jget mode)" "on hook+journal"
  expect a "status: no problem" "$(jget problems)" "[]"
  sudo -n systemctl start auto-sec-check.service || true
  expect_msg a "the checker says that detection works again" "$base" "auto_sec detection is working again on $HOST"
  settle >/dev/null
  expect a "the run's own logins (root with the quiet key, and its su) sent no alert: the test message and the checker's, nothing else" \
    "$(others_since "$base")" 1
  log_lacks a a-install "12345678:TEST-TOKEN" "the token is not in the run's output"
  pam_sums >"$WORK/pam.installed"
}

case_b() {
  local rc=0 base pids
  echo "== b: the second run"
  base=$(msg_count)
  pids=$(systemctl show -p MainPID --value auto-sec-alert.service auto-sec-login-watch.service | paste -sd' ' -)
  dplay b-again || rc=$?
  expect b "the run: rc" "$rc" 0
  log_has b b-again "08 detection: no change" "the plan: no change"
  if grep -Eq 'detection: on, last alive message (never|20[0-9-]+ [0-9:]+ UTC)' "$LOGS/b-again.log"; then
    pass b "the plan says: detection: on, last alive message <time>"
  else fail b "the plan does not say 'detection: on, last alive message'"; fi
  expect b "the PAM files are unchanged" "$(pam_sums | sha256sum)" "$(sha256sum <"$WORK/pam.installed")"
  expect b "the sender and the journal reader were not restarted" \
    "$(systemctl show -p MainPID --value auto-sec-alert.service auto-sec-login-watch.service | paste -sd' ' -)" "$pids"
  expect b "no message" "$(settle)" "$base"
}

case_l() {
  local base n
  echo "== l: logins"
  base=$(settle)
  n=$(jget day quiet)
  ssh_key "$KEYS/admin" root || fail l "login with the quiet key failed"
  expect_quiet l "root over SSH with the quiet key: silence" "$base" 8
  expect l "... and it is counted as a quiet login" "$(jget day quiet)" $((n + 1))

  ssh_key "$KEYS/other" root || fail l "login with the other key failed"
  expect_msg l "root over SSH with a key that is not on the list: a message with its fingerprint, seen by both sensors" "$base" \
    'root logged in over SSH with a key \(ED25519 SHA256:.*from: 127\.0\.0\.1 .*seen by: login hook and journal$' "$FP_OTHER"

  base=$(settle)
  ssh_pw ci-visitor || fail l "the password login as ci-visitor failed"
  expect_msg l "an account over SSH with a password: a message, seen by both sensors" "$base" \
    'ci-visitor logged in over SSH with a PASSWORD .*seen by: login hook and journal$'

  base=$(settle)
  ssh_pw root || fail l "the password login as root failed"
  expect_msg l "root over SSH with a password: a message" "$base" 'root logged in over SSH with a PASSWORD '

  base=$(settle)
  n=$(jget day quiet)
  ssh_pw ci-quiet || fail l "the password login as ci-quiet failed"
  expect_quiet l "a quiet account over SSH: silence" "$base" 8
  expect l "... and it is counted" "$(jget day quiet)" $((n + 1))

  # shellcheck disable=SC2024 # the output goes to this user's work folder
  sudo -n -u ci-visitor python3 "$TOOLS/pty_run.py" --answer-file "$TOOLS/su-root.answers" -- su - root -c true \
    >"$LOGS/su.out" 2>&1 || fail l "su - root as ci-visitor failed ($(tail -n 2 "$LOGS/su.out" | tr '\n' ' '))"
  expect_msg l "su - to root by an account: a message" "$base" 'ci-visitor became root with su .*seen by: login hook and journal$'

  base=$(settle)
  n=$(jget day by_root)
  sudo -n su - ci-visitor -c true || fail l "su - ci-visitor as root failed"
  expect_quiet l "su started by root: silence" "$base" 8
  if [ "$(jget day by_root)" -gt "$n" ]; then pass l "... counted as started by root"; else fail l "... not counted as started by root"; fi

  sudo -n -i </dev/null >/dev/null 2>&1 || fail l "sudo -i failed"
  expect_msg l "sudo -i: a message, seen by both sensors" "$base" \
    "$(id -un) opened a shell as root with sudo -i.*seen by: login hook and journal\$"

  base=$(settle)
  sudo -n -s </dev/null >/dev/null 2>&1 || fail l "sudo -s failed"
  expect_msg l "sudo -s: a message from the journal reader (plain sudo opens no login session for the hook)" "$base" \
    "$(id -un) opened a shell as root with sudo .*seen by: journal\$"

  base=$(settle)
  sudo -n "$(command -v true)" || true
  sudo -n /usr/bin/id -u >/dev/null
  expect_quiet l "sudo with a command that is not a shell: silence" "$base" 8

  # The console's door: login on a new terminal. Never quiet, also for a quiet account.
  # shellcheck disable=SC2024 # the output goes to this user's work folder
  sudo -n python3 "$TOOLS/pty_run.py" --answer-file "$TOOLS/console.answers" --then exit --timeout 40 -- login \
    >"$LOGS/console.out" 2>&1 || info l "login on a pty ended with rc $? ($(tail -n 2 "$LOGS/console.out" | tr -d '\r' | tr '\n' ' '))"
  expect_msg l "a console login (login on a new terminal) of a QUIET account: a message all the same" "$base" \
    'ci-quiet logged in on the console \('

  base=$(settle)
  sudo -n systemctl start auto-sec-alive.service
  expect_msg l "the daily message, with the counts" "$base" "^auto_sec alive: $HOST \| Detection is running: login hook and journal reader\. .*logins that sent an alert: [1-9]"
  if detect status | head -n 1 | grep -Eq '^detection: on, last alive message 20[0-9-]+ [0-9:]+ UTC'; then
    pass l "status: detection: on, last alive message <time>"
  else fail l "status after the daily message: $(detect status | head -n 1)"; fi
}

case_h() {
  local base t0 t1 t2 t3 slow n
  echo "== h: a hook that hangs"
  base=$(settle)
  n=$(jget day hook_failed)
  t0=$(date +%s%N)
  ssh_key "$KEYS/admin" root
  t1=$(date +%s%N)
  sudo -n cp -p "$HOOK" "$HOOK.ci-orig"
  printf '%s\n' '#!/bin/sh' "trap '' TERM INT HUP" 'sleep 60' | sudo -n tee "$HOOK" >/dev/null
  t2=$(date +%s%N)
  ssh_key "$KEYS/other" root || fail h "the login failed while the hook hangs"
  t3=$(date +%s%N)
  sudo -n mv -f "$HOOK.ci-orig" "$HOOK"
  slow=$(( (t3 - t2 - (t1 - t0)) / 1000000 ))
  info h "a login took $(( (t1 - t0) / 1000000 )) ms with the hook, $(( (t3 - t2) / 1000000 )) ms with a hook that hangs"
  if [ "$slow" -ge 500 ] && [ "$slow" -lt 2000 ]; then pass h "the hanging hook cost that login about 1 s, less than 2 ($slow ms)"
  else fail h "the hanging hook cost that login $slow ms (want 500 to 2000)"; fi
  expect_msg h "the alert for that login still goes out, from the journal, and says that the hook did not report it" "$base" \
    'root logged in over SSH with a key .*seen by: journal \(the login hook did not report this login\)$'
  expect h "the hook file is the role's again" "$(sudo -n sha256sum "$HOOK" | cut -d' ' -f1)" \
    "$(sha256sum "$ROOT/roles/08-detection/files/auto-sec-login-hook" | cut -d' ' -f1)"
  sleep 3
  if [ "$(jget day hook_failed)" -gt "$n" ]; then pass h "the cut-off hook is counted (pam_exec's own line in the journal)"
  else fail h "the cut-off hook is not counted: $(sudo -n journalctl -t sshd -t sshd-session --since '-2min' --no-pager -o cat 2>/dev/null | grep pam_exec | tail -n 2 | tr '\n' '#')"; fi
  expect h "no hook process is left" "$(pgrep -fc 'sleep 60' || true)" 0
}

case_s() {
  local base rc=0
  echo "== s: the watcher's own health"
  base=$(settle)
  mark_out
  sudo -n systemctl stop auto-sec-alert.service
  expect_msg s "the sender is stopped: the stop message goes out (from a unit of its own)" "$base" \
    "auto_sec: the watcher on $HOST was stopped\. \| Unit: auto-sec-alert\.service"
  # The next login leaves an event in the queue: the path unit starts the sender again.
  base=$(settle)
  ssh_key "$KEYS/other" root || fail s "the login failed"
  expect_msg s "the next login wakes the sender (auto-sec-alert.path), and its alert goes out" "$base" \
    'root logged in over SSH with a key '
  expect s "... the sender is active again" "$(systemctl is-active auto-sec-alert.service)" active

  # Now the sender and its wake-up are both stopped: nothing brings it back.
  base=$(settle)
  mark_out
  sudo -n systemctl stop auto-sec-alert.path auto-sec-alert.service
  expect_msg s "the sender's wake-up is stopped too: its stop message goes out" "$base" \
    "auto_sec: the watcher on $HOST was stopped\. \| Unit: auto-sec-alert\.path"
  detect status >"$LOGS/status-dead.out" 2>&1 || rc=$?
  expect s "status: exit code 3" "$rc" 3
  if head -n 1 "$LOGS/status-dead.out" | grep -Eq '^detection: DEAD since 20[0-9-]+ [0-9:]+ UTC \(the sender is not running'; then
    pass s "status: detection: DEAD since <time>"
  else fail s "status says: $(head -n 1 "$LOGS/status-dead.out")"; fi
  base=$(settle)
  sudo -n systemctl start auto-sec-check.service || true
  expect_msg s "the independent checker says so by itself" "$base" \
    "auto_sec detection problem: $HOST \| - the sender is not running .*repeats every hour"
  rc=0
  dplay s-plan -e autosec_plan_only=true || rc=$?
  expect s "plan only on the dead server: rc" "$rc" 0
  log_has s s-plan "[W08-2] WARNING: detection: DEAD since" "the plan says DEAD (W08-2)"
  log_has s s-plan "start: auto-sec-alert.service: the sender (start)" "the plan starts the sender again"
  log_has s s-plan "start: auto-sec-alert.path: wakes the sender when an event waits (start)" "... and its wake-up"
  rc=0
  dplay s-fix -e detection_test_alert=false || rc=$?
  expect s "the next run: rc" "$rc" 0
  expect s "status: on again" "$(jget verdict)" on
  base=$(settle)
  sudo -n systemctl start auto-sec-check.service || true
  expect_msg s "the checker says that it works again" "$base" "auto_sec detection is working again on $HOST"

  base=$(settle)
  mark_out
  sudo -n systemctl kill -s KILL auto-sec-login-watch.service
  expect_msg s "the journal reader is killed: the stop message goes out" "$base" \
    "auto_sec: the watcher on $HOST was stopped\. \| Unit: auto-sec-login-watch\.service"
  sleep 10
  expect s "... and it is running again by itself" "$(systemctl is-active auto-sec-login-watch.service)" active
  base=$(settle)
  ssh_pw ci-visitor || fail s "the password login failed"
  expect_msg s "... and reads the journal again: a login sends its message, seen by both sensors" "$base" \
    'ci-visitor logged in over SSH with a PASSWORD .*seen by: login hook and journal$'
  expect s "the timers are active" "$(systemctl is-active auto-sec-alive.timer auto-sec-check.timer | paste -sd' ' -)" "active active"
}

case_r() {
  local rc=0 base
  echo "== r: removal"
  base=$(settle)
  dplay r-plan -e detection_enabled=false -e detection_remove=true -e autosec_plan_only=true || rc=$?
  expect r "removal, plan only: rc" "$rc" 0
  log_has r r-plan "auto_sec's line taken out with pam-auth-update --remove" "the plan lists the PAM line"
  log_has r r-plan "remove: $PROFILE" "the plan lists the profile"
  log_has r r-plan "byte for byte as they were before detection was installed" "the note promises byte for byte"
  expect r "the plan changed nothing" "$(pam_sums | sha256sum) $(units_active)" "$(sha256sum <"$WORK/pam.installed") 5"
  rc=0
  dplay r-remove -e detection_enabled=false -e detection_remove=true || rc=$?
  expect r "the removal: rc" "$rc" 0
  expect r "the common PAM files and pam-auth-update's records are byte for byte what they were before the install; the profile is gone" \
    "$(pam_sums | diff - "$WORK/pam.before" | head -n 6 | paste -sd' ' -)" ""
  expect r "debconf's record of pam-auth-update is as before the install" "$(debconf_profiles)" "$(cat "$WORK/debconf.before")"
  expect r "no unit is active" "$(units_active)" 0
  expect r "no file of auto_sec's detection is left" \
    "$(sudo -n sh -c 'ls -d /usr/local/sbin/auto-sec-detect /usr/local/sbin/auto-sec-login-hook /etc/auto-sec /var/spool/auto-sec /var/lib/auto-sec/detect /etc/systemd/system/auto-sec-alert.* /etc/systemd/system/auto-sec-login-watch.service /etc/systemd/system/auto-sec-alive.* /etc/systemd/system/auto-sec-check.* /etc/systemd/system/auto-sec-notify@.service /etc/systemd/system/*.wants/auto-sec-a* /etc/systemd/system/*.wants/auto-sec-login-watch.service /etc/systemd/system/*.wants/auto-sec-check.timer 2>/dev/null' | paste -sd' ' -)" ""
  expect r "the undo guard is idle (it stays installed: roles 02 and 03 use it too)" \
    "$(sudo -n /usr/local/sbin/auto-sec-ssh-guard status | head -n 1)" idle
  expect_msg r "one last message says that login alerts were taken out" "$base" \
    "auto_sec: login alerts are being taken out of $HOST by an auto_sec run"
  base=$(settle)
  ssh_pw ci-visitor || fail r "a password login fails after the removal"
  ssh_key "$KEYS/other" root || fail r "a key login fails after the removal"
  expect_quiet r "logins work and send nothing any more" "$base" 8
  expect r "no failed unit of auto_sec is left" "$(systemctl list-units --state=failed --no-legend --plain 'auto-sec-*' | wc -l)" 0
  rc=0
  dplay r-again -e detection_enabled=false -e detection_remove=true || rc=$?
  expect r "a second removal run: rc" "$rc" 0
  log_has r r-again "removal: nothing of auto_sec's detection is on this server" "... and it says that nothing is there"
}

case_j() {
  local rc=0 base
  echo "== j: journal reader only"
  base=$(settle)
  dplay j-install -e detection_login_hook=false || rc=$?
  expect j "the install: rc" "$rc" 0
  log_has j j-install "[N08-2] journal reader only" "the plan says journal reader only (N08-2)"
  expect j "no PAM file changed, no profile, no hook file" \
    "$(pam_sums | sha256sum) $(sudo -n test -e "$HOOK" && echo hook || echo none)" "$(sha256sum <"$WORK/pam.before") none"
  expect j "status: on, journal reader only" "$(jget verdict) $(jget mode)" "on journal"
  base=$(settle)
  ssh_pw ci-visitor || fail j "the password login failed"
  expect_msg j "a login sends its message from the journal alone, with no complaint about the hook" "$base" \
    'ci-visitor logged in over SSH with a PASSWORD .*seen by: journal$'
  rc=0
  dplay j-remove -e detection_enabled=false -e detection_remove=true || rc=$?
  expect j "the removal: rc" "$rc" 0
  expect j "nothing is left, and the PAM files were never touched" \
    "$(units_active) $(sudo -n test -e "$BIN" && echo there || echo absent) $(pam_sums | sha256sum)" "0 absent $(sha256sum <"$WORK/pam.before")"
}

setup
case_p
case_i
case_a
case_b
case_l
case_h
case_s
case_r
case_j
finish
