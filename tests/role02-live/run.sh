#!/usr/bin/env bash
# role02-live: live tests of role 02 (plus role 03's SSH rule) against the
# GitHub runner itself: ansible-playbook site.yml --tags ssh,firewall to
# root@127.0.0.1, then checks of sshd -T, the drop-in, the undo guard and a
# fresh key login.
#
# GITHUB-HOSTED RUNNERS ONLY. It installs openssh-server, rewrites sshd
# drop-ins, enables ufw, denies root logins on purpose and kills
# ansible-playbook in the middle of a run. It refuses to start anywhere else.
#
# Usage: bash tests/role02-live/run.sh --ssh-mode service|socket [--cases "LIST"]
#   service   ssh.service listens itself (Ubuntu 22.04 default)
#   socket    ssh.socket activation and port generator (Ubuntu 24.04 default)
#   --cases   a subset of: i h g l d a m b p e f (always run in this order;
#             m, b, p, e and f need a; p, e and f need b). Default: all.
# Cases (final.md section 6 item 4; j and k are cut from 0.4.0, m is new):
#   i  --check changes nothing (find -newer)
#   h  a file changed after sshd last loaded its config: refused
#   g  Port 2222 written but not live: refused before any role runs
#   l  more changing hosts than ssh_max_hosts_per_run: refused
#   d  wrong pinned key + a stricter setting: fails before any write
#   a  keep-everything: sshd -T unchanged, reload logged, guard idle
#   c  (checked after a and b) a hand-added key and a from= line survive
#   m  local mode: a change to sshd -T is refused; no change succeeds
#   b  stage 2: exactly 2 values change
#   p  the trial run (P8) refuses: back to keep after stage 2 (b), an earlier
#      drop-in that wins (a), a stray AllowUsers drop-in (a)
#   e  CI-only injected DenyUsers: the login test fails, the rescue undoes it
#   f  ansible-playbook killed after the write: the timer undoes it at the
#      deadline, across a daemon-reload
# The injected failure uses autosec_ci_inject_deny_user, which role 02
# honours only with autosec_ci: true AND AUTOSEC_CI_INJECT_FAILURE=deny-user
# AND GITHUB_ACTIONS=true in the controller's environment. The same autosec_ci:
# true on a GitHub runner is what lets role 02 change sshd over an SSH login
# to 127.0.0.1, which it otherwise refuses like local mode.
# Logs: $RUNNER_TEMP/role02-live/logs. Exit 0 = every check passed.
set -u -o pipefail
export LC_ALL=C.UTF-8   # ansible needs a UTF-8 locale

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
ALL_CASES="i h g l d a m b p e f"
MODE=""
CASES=$ALL_CASES

die() { echo "ERROR: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case $1 in
    --ssh-mode) [ $# -ge 2 ] || die "--ssh-mode needs service or socket"; MODE=$2; shift 2 ;;
    --cases) [ $# -ge 2 ] || die "--cases needs a list"; CASES=$2; shift 2 ;;
    -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
if [ "${GITHUB_ACTIONS:-}" != true ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ]; then
  die "GitHub-hosted runners only: this reconfigures sshd and the firewall of the machine it runs on"
fi
case $MODE in service|socket) ;; *) die "--ssh-mode service|socket is required" ;; esac
for c in $CASES; do
  case " $ALL_CASES " in *" $c "*) ;; *) die "unknown case: $c" ;; esac
done
for t in ansible-playbook ssh ssh-keygen ssh-keyscan ssh-agent ssh-add setsid sudo journalctl; do
  command -v "$t" >/dev/null 2>&1 || die "missing tool: $t"
done

WORK=${RUNNER_TEMP:-/tmp}/role02-live
LOGS=$WORK/logs
KEYS=$WORK/keys
INV=$WORK/inventory.yml
DROPIN=/etc/ssh/sshd_config.d/00-autosec.conf
PENDING=/var/lib/auto-sec/ssh-guard/pending
GUARD=/usr/local/sbin/auto-sec-ssh-guard
BOOT_LINK=/etc/systemd/system/sysinit.target.wants/auto-sec-ssh-guard-boot.service
REVERT_SECONDS=120
STAGE2=$HERE/cases/stage2.yml
KEEP=$HERE/cases/keep.yml
rm -rf "$WORK"
mkdir -p "$LOGS" "$KEYS" || die "cannot create $WORK"
chmod 700 "$KEYS"

BG_PID=""
cleanup() {
  [ -n "$BG_PID" ] && kill -9 "$BG_PID" 2>/dev/null
  [ -n "${SSH_AGENT_PID:-}" ] && kill "$SSH_AGENT_PID" 2>/dev/null
}
trap cleanup EXIT

PASSES=0
FAILS=0
pass() { PASSES=$((PASSES + 1)); printf 'PASS  [%s] %s\n' "$1" "$2"; }
fail() { FAILS=$((FAILS + 1)); printf 'FAIL  [%s] %s\n' "$1" "$2"; }
info() { printf 'INFO  [%s] %s\n' "$1" "$2"; }
expect() { # case what got want
  if [ "$3" = "$4" ]; then pass "$1" "$2: $3"; else fail "$1" "$2: got '$3', want '$4'"; fi
}
expect_refused() { # case rc
  if [ "$2" -ne 0 ]; then pass "$1" "run refused (rc $2)"; else fail "$1" "run succeeded, want a refusal"; fi
}
log_has() { # case log-name fixed-string what
  if grep -Fq -- "$3" "$LOGS/$2.log"; then pass "$1" "$4"; else fail "$1" "$4 (no '$3' in $2.log)"; fi
}

# --- host probes --------------------------------------------------------------
eff() { # file: effective root view of the live config, sorted
  sudo -n /usr/sbin/sshd -T -C user=root,host=autosec-check,addr=127.0.0.1 2>/dev/null | sort >"$1"
}
changed() { comm -3 "$1" "$2" | awk '{print $1}' | sort -u | paste -sd' ' -; }
val() { awk -v k="$2" '$1 == k { $1 = ""; sub(/^ /, ""); print }' "$1" | sort | paste -sd' ' -; }
dropin_sum() {
  local s
  s=$(sudo -n sha256sum "$DROPIN" 2>/dev/null) || { echo absent; return; }
  echo "${s%% *}"
}
guard_state() { # "idle" when nothing is armed and no revert timer exists
  local s=idle t
  sudo -n test -e "$PENDING" && s="pending $(sudo -n cat "$PENDING" 2>/dev/null)"
  t=$(systemctl list-units --all --plain --no-legend 'auto-sec-ssh-guard-*.timer' 2>/dev/null \
    | awk '{print $1}' | paste -sd' ' -)
  echo "$s${t:+, timers: $t}"
}
login() { # a brand-new key-only login as root
  ssh -F /dev/null -o BatchMode=yes -o ControlMaster=no -o ControlPath=none \
    -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -o ConnectTimeout=10 \
    -o UserKnownHostsFile="$HOME/.ssh/known_hosts" -o StrictHostKeyChecking=yes \
    -i "$KEYS/admin" root@127.0.0.1 true </dev/null >/dev/null 2>&1
}
expect_login() { # case
  if login; then pass "$1" "fresh key login as root works"; else fail "$1" "fresh key login as root FAILS"; fi
}
sighups_since() { # epoch: reloads ssh.service logged since then
  sudo -n journalctl -u ssh.service --since "@$1" -o cat 2>/dev/null | grep -c 'Received SIGHUP; restarting'
}
settle() { # make sshd's last load newer than an edit under /etc/ssh (preflight P6)
  sleep 1.2
  sudo -n /usr/sbin/sshd -t || die "sshd -t fails after a test edit"
  sudo -n systemctl try-reload-or-restart ssh.service
  sleep 1.2
}
unchanged() { # case expected-drop-in-sum expected-eff-file
  local e=$WORK/now.eff
  eff "$e"
  expect "$1" "drop-in unchanged" "$(dropin_sum)" "$2"
  expect "$1" "sshd -T keys changed" "$(changed "$3" "$e")" ""
  expect "$1" "undo guard" "$(guard_state)" idle
}
check_keys() { # case: keys are only ever added (case c)
  local n
  expect "$1/c" "root authorized_keys byte-identical (from= line and hand-added key kept)" \
    "$(sudo -n sha256sum /root/.ssh/authorized_keys | cut -d' ' -f1)" "$ROOT_AK_SUM"
  if sudo -n grep -Fxq -- "$(cat "$WORK/deploy_ak")" /home/deploy/.ssh/authorized_keys; then
    pass "$1/c" "hand-added deploy key line kept"
  else
    fail "$1/c" "hand-added deploy key line is gone"
  fi
  n=$(sudo -n grep -cF -- "$(cut -d' ' -f2 "$KEYS/admin.pub")" /home/deploy/.ssh/authorized_keys)
  expect "$1/c" "deploy_ssh_public_key lines for deploy" "$n" 1
}
play() { # log-name ansible-playbook-args...: site.yml --tags ssh,firewall; returns its rc
  local name=$1 rc=0
  shift
  (cd "$ROOT" && ANSIBLE_NOCOLOR=1 ansible-playbook -i "$INV" site.yml \
    --tags "${PLAY_TAGS:-ssh,firewall}" "$@") >"$LOGS/$name.log" 2>&1 || rc=$?
  echo "      ansible-playbook rc=$rc, log $LOGS/$name.log"
  return "$rc"
}

# --- setup ----------------------------------------------------------------------
host_vars() { # hostname extra-lines: one inventory host with the shared test vars
  cat <<EOF
    $1:
      deploy_user: deploy
      deploy_ssh_public_key: "$ADMIN_PUB"
      ssh_admin_user: root
      ssh_admin_public_keys:
        - "$ADMIN_PUB"
      ssh_revert_seconds: $REVERT_SECONDS
      paranoia_level: standard
      office_static_ip: ""
      autosec_ci: true
$2
EOF
}

setup() {
  echo "== setup ($MODE mode)"
  # Role 03 installs ufw and fail2ban without refreshing the package lists.
  for _ in 1 2 3; do sudo -n apt-get update -qq && break; sleep 10; done
  if [ ! -x /usr/sbin/sshd ]; then
    sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server \
      || die "cannot install openssh-server"
  fi
  if [ "$MODE" = socket ]; then
    sudo -n systemctl disable --now ssh.service >/dev/null 2>&1
    sudo -n systemctl enable --now ssh.socket || die "cannot enable ssh.socket"
  else
    sudo -n systemctl disable --now ssh.socket >/dev/null 2>&1
    sudo -n systemctl enable ssh.service >/dev/null 2>&1
    sudo -n systemctl restart ssh.service || die "cannot start ssh.service"
  fi
  sudo -n grep -Eq '^[[:space:]]*Include[[:space:]]+(/etc/ssh/)?sshd_config\.d/\*\.conf' /etc/ssh/sshd_config \
    || die "this runner's /etc/ssh/sshd_config has no Include line"

  id deploy >/dev/null 2>&1 || sudo -n useradd -m -s /bin/bash deploy || die "useradd deploy"
  local k
  for k in admin wrong hand; do
    ssh-keygen -q -t ed25519 -N '' -C "ci-$k" -f "$KEYS/$k" || die "ssh-keygen $k"
  done
  ADMIN_PUB=$(cat "$KEYS/admin.pub")
  # root: the admin key only inside a from= line, plus an unrelated hand-added key.
  printf 'from="127.0.0.1,::1" %s ci-from-line\n%s hand-added-root\n' \
    "$(cut -d' ' -f1,2 "$KEYS/admin.pub")" "$(cut -d' ' -f1,2 "$KEYS/hand.pub")" >"$WORK/root_ak"
  sudo -n install -d -m 700 -o root -g root /root/.ssh
  sudo -n install -m 600 -o root -g root "$WORK/root_ak" /root/.ssh/authorized_keys || die "root keys"
  ROOT_AK_SUM=$(sha256sum "$WORK/root_ak" | cut -d' ' -f1)
  # deploy: one hand-added key.
  printf '%s hand-added-deploy\n' "$(cut -d' ' -f1,2 "$KEYS/hand.pub")" >"$WORK/deploy_ak"
  sudo -n install -d -m 700 -o deploy -g deploy /home/deploy/.ssh
  sudo -n install -m 600 -o deploy -g deploy "$WORK/deploy_ak" /home/deploy/.ssh/authorized_keys || die "deploy keys"

  # A known baseline: root and password logins on, so stage 2 has work to do.
  printf '%s\n' '# role02-live baseline (sorts after 00-autosec.conf)' \
    'PermitRootLogin yes' 'PasswordAuthentication yes' >"$WORK/baseline.conf"
  sudo -n install -m 644 "$WORK/baseline.conf" /etc/ssh/sshd_config.d/01-ci-baseline.conf
  sudo -n rm -f "$DROPIN"
  settle

  mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
  for _ in $(seq 20); do
    ssh-keyscan -T 5 127.0.0.1 >"$WORK/kh" 2>/dev/null && [ -s "$WORK/kh" ] && break
    sleep 1
  done
  [ -s "$WORK/kh" ] || die "ssh-keyscan 127.0.0.1 found no host key"
  cat "$WORK/kh" >>"$HOME/.ssh/known_hosts"

  # The agent holds the right key, so case d's wrong key file still lets
  # Ansible's normal connection in while the pinned test must fail.
  eval "$(ssh-agent -s)" >/dev/null || die "ssh-agent"
  ssh-add -q "$KEYS/admin" || die "ssh-add"

  # Host vars, not group vars: the repo's group_vars/all.yml beats any
  # group vars set in an inventory file.
  {
    echo "all:"
    echo "  children:"
    echo "    remote:"
    echo "      hosts:"
    host_vars live "      ansible_host: 127.0.0.1
      ansible_user: root
      ansible_ssh_private_key_file: $KEYS/admin" | sed 's/^/    /'
    host_vars live2 "      ansible_host: 127.0.0.1
      ansible_user: root
      ansible_ssh_private_key_file: $KEYS/admin" | sed 's/^/    /'
    echo "    localmode:"
    echo "      hosts:"
    host_vars local "      ansible_connection: local
      ansible_python_interpreter: /usr/bin/python3" | sed 's/^/    /'
  } >"$INV"

  BASE_EFF=$WORK/base.eff
  eff "$BASE_EFF"
  expect setup "baseline permitrootlogin/passwordauthentication" \
    "$(val "$BASE_EFF" permitrootlogin)/$(val "$BASE_EFF" passwordauthentication)" "yes/yes"
  expect setup "port" "$(val "$BASE_EFF" port)" 22
  if [ "$MODE" = socket ]; then
    expect setup "ssh.socket" "$(systemctl is-active ssh.socket)" active
  else
    expect setup "ssh.service" "$(systemctl is-active ssh.service)" active
  fi
  expect_login setup
  # Later cases compare against these; a and b move them forward.
  A_SUM=absent A_EFF=$BASE_EFF B_SUM=absent B_EFF=$BASE_EFF
}

# --- cases ------------------------------------------------------------------------
case_i() {
  local rc tags found
  # --tags ssh is the canary's first command; ssh,firewall adds role 03 on a
  # host where ufw is off. Role 03 in --check needs ufw and fail2ban already
  # installed (its jail.local task fails in check mode without
  # /etc/fail2ban, a limitation older than 0.4.0), so that variant only runs
  # when both are present.
  for tags in ssh ssh,firewall; do
    if [ "$tags" = ssh,firewall ] && ! { [ -x /usr/sbin/ufw ] && [ -d /etc/fail2ban ]; }; then
      info i "--check --tags $tags skipped: ufw or fail2ban is not installed on this runner"
      continue
    fi
    rc=0
    touch "$WORK/stamp"
    sleep 1.2
    PLAY_TAGS=$tags play "i-check-${tags/,/-}" --check -l live -e "@$STAGE2" || rc=$?
    expect i "--check --tags $tags: run rc" "$rc" 0
    found=$(sudo -n find /etc /usr/local/sbin /usr/local/bin /var/lib/auto-sec /root/.ssh \
      /home/deploy -xdev -newer "$WORK/stamp" 2>/dev/null | paste -sd' ' -)
    expect i "--check --tags $tags: paths changed under /etc /usr/local/{s,}bin /var/lib/auto-sec /root/.ssh /home/deploy" \
      "${found:-none}" none
    unchanged i absent "$BASE_EFF"
  done
}

case_h() {
  local rc=0
  sleep 1.2
  echo '# role02-live: changed after sshd last loaded its config' \
    | sudo -n tee /etc/ssh/sshd_config.d/20-ci-unloaded.conf >/dev/null
  play h-unloaded -l live -e "@$KEEP" || rc=$?
  expect_refused h "$rc"
  log_has h h-unloaded 20-ci-unloaded.conf "the refusal names the changed file"
  unchanged h absent "$BASE_EFF"
  sudo -n rm -f /etc/ssh/sshd_config.d/20-ci-unloaded.conf
  settle
}

case_g() {
  local rc=0
  sleep 1.2
  echo 'Port 2222' | sudo -n tee /etc/ssh/sshd_config.d/10-ci-port.conf >/dev/null
  if [ "$MODE" = socket ]; then
    # Loaded by sshd, but ssh.socket still listens on 22 (no daemon-reload):
    # the hidden port switch of issue #5. P7 must refuse.
    settle
    play g-port -l live -e "@$KEEP" || rc=$?
    expect_refused g "$rc"
    log_has g g-port 2222 "the refusal names port 2222"
  else
    # Service mode: reloading would really move sshd. Written, not loaded:
    # P6 (file newer than the last load) or P7 (config port is not ssh_port)
    # must refuse.
    play g-port -l live -e "@$KEEP" || rc=$?
    expect_refused g "$rc"
    if grep -Eq '2222|10-ci-port\.conf' "$LOGS/g-port.log"; then
      pass g "the refusal names port 2222 or the unloaded file"
    else
      fail g "the refusal names neither port 2222 nor 10-ci-port.conf"
    fi
  fi
  if grep -Eq 'TASK \[(01-base|03-firewall) :' "$LOGS/g-port.log"; then
    fail g "a role task ran after the refusal"
  else
    pass g "refused in pre_tasks: no role 01/03 task ran"
  fi
  expect g "drop-in unchanged" "$(dropin_sum)" absent
  expect g "undo guard" "$(guard_state)" idle
  sudo -n rm -f /etc/ssh/sshd_config.d/10-ci-port.conf
  settle
  expect_login g
}

case_l() {
  local rc=0
  play l-hostcap -l live,live2 -f 1 -e "@$STAGE2" -e ssh_max_hosts_per_run=1 || rc=$?
  expect_refused l "$rc"
  log_has l l-hostcap ssh_max_hosts_per_run "the refusal names ssh_max_hosts_per_run"
  unchanged l absent "$BASE_EFF"
}

case_d() {
  local rc=0
  play d-wrongkey -l live -e "@$STAGE2" -e "ansible_ssh_private_key_file=$KEYS/wrong" || rc=$?
  expect_refused d "$rc"
  unchanged d absent "$BASE_EFF"
  expect_login d
}

case_a() {
  local rc=0 t0 n e=$WORK/a.eff
  t0=$(date +%s)
  sleep 1
  play a-keep -l live -e "@$KEEP" || rc=$?
  expect a "run rc" "$rc" 0
  eff "$e"
  expect a "sshd -T keys changed" "$(changed "$BASE_EFF" "$e")" ""
  expect a "drop-in active (non-comment) lines" \
    "$(sudo -n grep -Evc '^[[:space:]]*(#|$)' "$DROPIN" 2>/dev/null)" 0
  expect a "drop-in mode and owner" "$(sudo -n stat -c '%a %U' "$DROPIN" 2>/dev/null)" "600 root"
  n=$(sighups_since "$t0")
  if [ "${n:-0}" -ge 1 ]; then pass a "sshd reload logged ($n)"; else fail a "no 'Received SIGHUP' from ssh.service since the run started"; fi
  expect a "undo guard" "$(guard_state)" idle
  expect a "guard script mode and owner" "$(sudo -n stat -c '%a %U' "$GUARD" 2>/dev/null)" "700 root"
  if sudo -n test -L "$BOOT_LINK"; then pass a "boot unit linked in sysinit.target.wants"; else fail a "no $BOOT_LINK"; fi
  info a "guard status: $(sudo -n "$GUARD" status 2>&1 | head -1)"
  expect_login a
  check_keys a
  A_SUM=$(dropin_sum) A_EFF=$e B_SUM=$(dropin_sum) B_EFF=$e
}

case_m() {
  local rc=0
  play m-local-stage2 -l local -e "@$STAGE2" || rc=$?
  expect_refused m "$rc"
  log_has m m-local-stage2 "must be run from your own computer" "the refusal says to use remote mode"
  unchanged m "$A_SUM" "$A_EFF"
  rc=0
  play m-local-keep -l local -e "@$KEEP" || rc=$?
  expect m "local mode, nothing to change: run rc" "$rc" 0
  unchanged m "$A_SUM" "$A_EFF"
}

case_b() {
  local rc=0 t0 n x e=$WORK/b.eff
  t0=$(date +%s)
  sleep 1
  play b-stage2 -l live -e "@$STAGE2" || rc=$?
  expect b "run rc" "$rc" 0
  eff "$e"
  expect b "sshd -T keys changed" "$(changed "$A_EFF" "$e")" "passwordauthentication permitrootlogin"
  expect b "passwordauthentication" "$(val "$e" passwordauthentication)" no
  x=$(val "$e" permitrootlogin)
  case $x in
    prohibit-password|without-password) pass b "permitrootlogin $x" ;;
    *) fail b "permitrootlogin '$x'" ;;
  esac
  n=$(sighups_since "$t0")
  if [ "${n:-0}" -ge 1 ]; then pass b "sshd reload logged ($n)"; else fail b "no reload logged"; fi
  expect b "undo guard" "$(guard_state)" idle
  expect_login b
  check_keys b
  B_SUM=$(dropin_sum) B_EFF=$e
}

case_p() {
  local rc e=$WORK/p.eff
  # p1. Back to "keep" after stage 2: permitrootlogin and passwordauthentication
  #     would change although they were not chosen. Trial-run check (b).
  rc=0
  play p1-keep-after-stage2 -l live -e "@$KEEP" || rc=$?
  expect_refused p1 "$rc"
  log_has p1 p1-keep-after-stage2 "login settings you did not choose" "the refusal names the unrequested change"
  unchanged p1 "$B_SUM" "$B_EFF"
  # p2. A drop-in that sorts before 00-autosec.conf wins, so the chosen value
  #     would not take effect. Trial-run check (a), naming the winning file.
  printf '%s\n' '# role02-live: sorts before 00-autosec.conf' 'PermitRootLogin yes' \
    | sudo -n tee /etc/ssh/sshd_config.d/00-ci-early.conf >/dev/null
  settle
  eff "$e"
  rc=0
  play p2-earlier-dropin -l live -e "@$STAGE2" || rc=$?
  expect_refused p2 "$rc"
  log_has p2 p2-earlier-dropin "would NOT use what you chose" "the refusal says the choice would not take effect"
  log_has p2 p2-earlier-dropin "00-ci-early.conf" "the refusal names the winning file"
  unchanged p2 "$B_SUM" "$e"
  sudo -n rm -f /etc/ssh/sshd_config.d/00-ci-early.conf
  # p3. A stray AllowUsers drop-in adds a user to the chosen list (sshd adds
  #     AllowUsers lines up). Trial-run check (a): the exact set must match.
  printf '%s\n' '# role02-live: stray AllowUsers' 'AllowUsers root alice' \
    | sudo -n tee /etc/ssh/sshd_config.d/10-ci-stray.conf >/dev/null
  settle
  eff "$e"
  rc=0
  play p3-stray-allowusers -l live -e "@$STAGE2" -e '{"ssh_allow_users": ["root"]}' || rc=$?
  expect_refused p3 "$rc"
  log_has p3 p3-stray-allowusers "would NOT use what you chose" "the refusal says the AllowUsers set would differ"
  unchanged p3 "$B_SUM" "$e"
  sudo -n rm -f /etc/ssh/sshd_config.d/10-ci-stray.conf
  settle
  unchanged p "$B_SUM" "$B_EFF"
  expect_login p
}

case_e() {
  local rc=0 t0 n
  # Without the runner-side switch the CI-only variable must be refused.
  play e0-unguarded -l live -e "@$STAGE2" -e autosec_ci_inject_deny_user=root || rc=$?
  expect_refused e0 "$rc"
  unchanged e0 "$B_SUM" "$B_EFF"
  rc=0
  t0=$(date +%s)
  sleep 1
  AUTOSEC_CI_INJECT_FAILURE=deny-user play e-inject -l live -e "@$STAGE2" \
    -e autosec_ci_inject_deny_user=root || rc=$?
  expect_refused e "$rc"
  # One reload loads the injected file, a second one (the guard) undoes it.
  n=$(sighups_since "$t0")
  if [ "${n:-0}" -ge 2 ]; then pass e "sshd reloaded twice: change loaded, then undone ($n)"; else fail e "want >= 2 sshd reloads since the run started, got ${n:-0}"; fi
  unchanged e "$B_SUM" "$B_EFF"
  expect_login e
  n=$(sudo -n journalctl -t auto-sec-ssh-guard --since "@$t0" -o cat 2>/dev/null | grep -ci revert)
  if [ "${n:-0}" -ge 1 ]; then pass e "guard logged a revert"; else fail e "no revert in the guard's journal"; fi
}

case_f() {
  local t0 tw pgid ok=0 n
  t0=$(date +%s)
  sleep 1
  (cd "$ROOT" && AUTOSEC_CI_INJECT_FAILURE=deny-user ANSIBLE_NOCOLOR=1 exec setsid \
    ansible-playbook -i "$INV" site.yml --tags ssh,firewall -l live -e "@$STAGE2" \
    -e autosec_ci_inject_deny_user=root) >"$LOGS/f-killed.log" 2>&1 &
  BG_PID=$!
  for _ in $(seq 900); do
    if sudo -n grep -q '^DenyUsers' "$DROPIN" 2>/dev/null; then ok=1; break; fi
    kill -0 "$BG_PID" 2>/dev/null || break
    sleep 0.2
  done
  if [ "$ok" != 1 ]; then
    fail f "the run never wrote DenyUsers (log $LOGS/f-killed.log)"
    kill -9 "$BG_PID" 2>/dev/null
    BG_PID=""
    return
  fi
  # Kill once sshd has loaded the bad file: the failed login test then waits
  # 10 s before its retry, so the play's own rescue has not run yet.
  tw=$(($(date +%s) - 1))
  for _ in $(seq 40); do
    [ "$(sighups_since "$tw")" -ge 1 ] && break
    sleep 0.5
  done
  pgid=$(ps -o pgid= -p "$BG_PID" | tr -d ' ')
  kill -9 -- "-${pgid:-$BG_PID}" 2>/dev/null
  wait "$BG_PID" 2>/dev/null
  BG_PID=""
  if [ "$(sighups_since "$tw")" -ge 1 ]; then
    pass f "ansible-playbook killed after the write and the reload"
    if login; then fail f "fresh login still works with DenyUsers root loaded"; else pass f "DenyUsers root is live after the kill: fresh login refused"; fi
  else
    fail f "no sshd reload within 20 s of the write; killed anyway"
  fi
  if sudo -n test -e "$PENDING"; then pass f "undo still pending after the kill"; else fail f "nothing pending after the kill"; fi
  sudo -n systemctl daemon-reload
  if [ "$(guard_state)" != idle ] && systemctl list-units --all --plain --no-legend 'auto-sec-ssh-guard-*.timer' | grep -q .; then
    pass f "revert timer still there after daemon-reload: $(guard_state)"
  else
    fail f "no revert timer after daemon-reload: $(guard_state)"
  fi
  for _ in $(seq $(((REVERT_SECONDS + 150) / 5))); do
    [ "$(guard_state)" = idle ] && break
    sleep 5
  done
  info f "waited $(( $(date +%s) - t0 )) s for the timer (ssh_revert_seconds $REVERT_SECONDS)"
  unchanged f "$B_SUM" "$B_EFF"
  expect_login f
  n=$(sudo -n journalctl -t auto-sec-ssh-guard --since "@$t0" -o cat 2>/dev/null | grep -ci revert)
  if [ "${n:-0}" -ge 1 ]; then pass f "guard logged a revert"; else fail f "no revert in the guard's journal"; fi
}

# --- main ---------------------------------------------------------------------------
setup
for c in $ALL_CASES; do
  case " $CASES " in *" $c "*) ;; *) continue ;; esac
  echo "== case $c"
  "case_$c"
done
echo
echo "role02-live ($MODE mode): $PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
