#!/bin/bash
#
# run.sh - unit tests for the SSH undo guard
#          (roles/02-ssh-hardening/files/auto-sec-ssh-guard and its boot unit).
#
#   tests/guard/run.sh [--user]        systemd --user timers, unprivileged
#                                      (WSL, a laptop)
#   sudo tests/guard/run.sh --system   system manager timers (CI runner)
#
# Every test gets a private copy of the guard whose paths block points at a
# temp state dir and stub binaries (tests/guard/stubs): sshd (its -t result
# is set per test), systemctl (logs calls; timer calls go to the real
# systemctl), fail2ban-client and logger. The revert timers are REAL
# systemd-run timers. Nothing outside the temp dir is touched, except one
# daemon-reload of the chosen manager (it must not move the deadline) and,
# with --system, /run/sshd, which the guard creates when it is missing.
# Takes about 80 s: the earliest allowed deadline is 60 s ahead.
set -uo pipefail
export LC_ALL=C

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
GUARD_SRC=$ROOT/roles/02-ssh-hardening/files/auto-sec-ssh-guard
UNIT_SRC=$ROOT/roles/02-ssh-hardening/files/auto-sec-ssh-guard-boot.service

case "${1:-}" in
  ""|--user) SCOPE=user ;;
  --system)  SCOPE=system ;;
  *) echo "usage: $0 [--user|--system]" >&2; exit 2 ;;
esac

# shellcheck source=/dev/null
. "$HERE/lib.sh"

# ------------------------------------------------------------- preconditions
REAL_SYSTEMCTL=$(command -v systemctl) || die "systemctl not found"
REAL_SYSTEMD_RUN=$(command -v systemd-run) || die "systemd-run not found"
for c in flock sha256sum awk od; do
  command -v "$c" >/dev/null || die "$c not found"
done
[ -f "$GUARD_SRC" ] || die "guard script missing: $GUARD_SRC"
[ -f "$UNIT_SRC" ] || die "boot unit missing: $UNIT_SRC"

if [ "$SCOPE" = system ]; then
  [ "$(id -u)" -eq 0 ] || die "--system needs root: sudo $0 --system"
  SC=()
else
  SC=(--user)
  export XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
  # A WSL user manager can take a moment to come up on first use.
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    st=$("$REAL_SYSTEMCTL" --user is-system-running 2>/dev/null)
    case $st in running|degraded|starting) break ;; esac
    sleep 1
  done
  case ${st:-} in
    running|degraded|starting) ;;
    *) die "no systemd --user manager (is-system-running: '${st:-none}'); use --system as root" ;;
  esac
fi

W=$(mktemp -d "${TMPDIR:-/tmp}/auto-sec-guard-test.XXXXXX") || die "mktemp failed"
chmod 0700 "$W"

cleanup() {
  "$REAL_SYSTEMCTL" "${SC[@]}" stop "auto-sec-ssh-guard-$TAGP-*.timer" \
    "auto-sec-ssh-guard-$TAGP-*.service" >/dev/null 2>&1 || true
  if [ "$FAIL" -gt 0 ]; then
    echo "work dir kept for inspection: $W"
  else
    rm -rf -- "$W"
  fi
}
trap cleanup EXIT

echo "auto-sec-ssh-guard tests: $SCOPE manager ($REAL_SYSTEMCTL, $REAL_SYSTEMD_RUN), ids $TAGP-*, work dir $W"

# ------------------------------------------------------------- static checks
section "static: guard script"
expected_block='readonly STATE_DIR=/var/lib/auto-sec/ssh-guard
readonly SSHD=/usr/sbin/sshd
readonly SYSTEMCTL=systemctl
readonly SYSTEMD_RUN=systemd-run
readonly F2B=fail2ban-client
readonly LOGGER=logger'
block=$(sed -n '/^# --- paths (tests rewrite this block) ---$/,/^# --- end paths ---$/p' "$GUARD_SRC" | sed '1d;$d')
expect_eq "$expected_block" "$block" "paths block holds exactly the six fixed lines"
expect_eq 1 "$(count "$GUARD_SRC" '^# --- paths (tests rewrite this block) ---$')" "exactly one paths block"
expect_eq 0 "$(grep -c -E 'AUTOSEC_|\$\{[A-Z][A-Z0-9_]*:[-=]' "$GUARD_SRC")" "no environment-variable overrides"
expect_eq 0 "$(grep -c -i 'ufw' "$GUARD_SRC")" "no ufw handling"
expect_true "bash -n passes" bash -n "$GUARD_SRC"
if command -v shellcheck >/dev/null; then
  expect_true "shellcheck (default severity) is clean on the guard, run.sh, lib.sh and stubs" \
    shellcheck "$GUARD_SRC" "$HERE/run.sh" "$HERE/lib.sh" "$HERE"/stubs/*
else
  echo "  skip  shellcheck not installed"
fi
new_instance probe
expect_true "test copy points its paths block at the stubs" \
  grep -qxF "readonly SYSTEMCTL=$W/probe/bin/systemctl" "$W/probe/guard"
gd probe status
expect_rc 0 $? "status on a fresh state dir"
expect_eq idle "$(cat "$W/probe/out")" "fresh status prints exactly 'idle'"

section "static: boot unit"
for line in '[Unit]' 'DefaultDependencies=no' 'After=local-fs.target' \
    'Before=ssh.socket ssh.service sysinit.target' \
    'ConditionPathExists=/var/lib/auto-sec/ssh-guard/pending' \
    'Type=oneshot' 'ExecStart=/usr/local/sbin/auto-sec-ssh-guard revert --boot' \
    'WantedBy=sysinit.target'; do
  expect_true "unit has: $line" grep -qxF -- "$line" "$UNIT_SRC"
done
expect_eq 0 "$(grep -c -i 'ufw' "$UNIT_SRC")" "unit does not mention ufw"
expect_eq 1 "$(grep -c '^Exec' "$UNIT_SRC")" "unit has a single Exec line (no reload)"
if command -v systemd-analyze >/dev/null; then
  # The real ExecStart does not exist here; point it at the test copy.
  sed "s#^ExecStart=/usr/local/sbin/auto-sec-ssh-guard #ExecStart=$W/probe/guard #" \
    "$UNIT_SRC" > "$W/auto-sec-ssh-guard-boot.service"
  chmod 0644 "$W/auto-sec-ssh-guard-boot.service"
  if systemd-analyze verify "$W/auto-sec-ssh-guard-boot.service" > "$W/verify.out" 2>&1 &&
     ! grep -q -i -E 'cycle|unknown|invalid|ignoring' "$W/verify.out"; then
    ok "systemd-analyze verify passes"
  else
    bad "systemd-analyze verify: $(tr '\n' ' ' < "$W/verify.out")"
  fi
else
  echo "  skip  systemd-analyze not installed"
fi

# ------------------------------------------- real timers, part 1: arm them
# Two changes nobody disarms. tok: the restored config passes sshd -t.
# tbad: it fails sshd -t at revert time. Both should go back at the deadline,
# even across a daemon-reload; only tok may reload sshd.
section "real timers: arm two changes that nobody disarms"
ID_TOK=$(id_for tok)
ID_TBAD=$(id_for tbad)
for n in tok tbad; do
  new_instance "$n"
  mkdir -p "$W/$n/etc/sshd_config.d"
  echo "orig main" > "$W/$n/etc/sshd_config"
done
DL_T=$(dl 63)
gd tok arm "$ID_TOK" "$DL_T" --f2b-ignore 192.0.2.10 -- \
  "$W/tok/etc/sshd_config.d/00-autosec.conf" "$W/tok/etc/sshd_config"
expect_rc 0 $? "arm tok (deadline +63 s, fail2ban ignore recorded)"
gd tbad arm "$ID_TBAD" "$DL_T" -- "$W/tbad/etc/sshd_config"
expect_rc 0 $? "arm tbad"
expect_true "tok revert timer is active" timer_active "$ID_TOK"
expect_true "systemd-run got the absolute UTC deadline as --on-calendar" \
  has "$W/tok/calls" "systemd-run .*--on-calendar=$(date -u -d "@$DL_T" '+%Y-%m-%d %H:%M:%S') UTC"
expect_true "systemd-run got --collect and AccuracySec=1s" \
  has "$W/tok/calls" "systemd-run .*--collect.*--timer-property=AccuracySec=1s"
echo "PermitRootLogin prohibit-password" > "$W/tok/etc/sshd_config.d/00-autosec.conf"
echo "new main" > "$W/tok/etc/sshd_config"
echo "new main" > "$W/tbad/etc/sshd_config"
gd tok check "$ID_TOK"
expect_rc 0 $? "check tok after the write"
gd tbad check "$ID_TBAD"
expect_rc 0 $? "check tbad after the write"
echo 1 > "$W/tbad/sshd_t_rc"

# ------------------------------------------------- arguments and refusals
section "usage errors (rc 2)"
new_instance use
U=$W/use/etc
mkdir -p "$U/dir"
echo x > "$U/real"
ln -s "$U/real" "$U/link"
UID1=$(id_for u1)
gd use;                                     expect_rc 2 $? "no arguments"
gd use frobnicate;                          expect_rc 2 $? "unknown subcommand"
gd use check;                               expect_rc 2 $? "check without an id"
gd use status extra;                        expect_rc 2 $? "status with an extra argument"
gd use arm "$UID1";                         expect_rc 2 $? "arm without a deadline"
gd use arm "$UID1" "$(dl)";                 expect_rc 2 $? "arm without -- and paths"
gd use arm "$UID1" "$(dl)" --;              expect_rc 2 $? "arm with no path after --"
gd use arm "$UID1" "$(dl)" "$U/a";          expect_rc 2 $? "arm with a path but no --"
gd use arm "$UID1" "$(dl)" -- etc/a;        expect_rc 2 $? "relative path"
gd use arm "$UID1" "$(dl)" -- "$U/../a";    expect_rc 2 $? "path with .."
gd use arm "$UID1" "$(dl)" -- "$U/a" "$U/a"; expect_rc 2 $? "same path twice"
gd use arm "$UID1" "$(dl)" -- "$U/dir";     expect_rc 2 $? "directory refused"
gd use arm "$UID1" "$(dl)" -- "$U/link";    expect_rc 2 $? "symlink refused"
for ip in 1.2.3.256 -1.2.3.4 '1.2.3.4;id' '' a.b.c.d 1.2.3 '1.2.3.4 5.6.7.8' ':::::::::'; do
  gd use arm "$UID1" "$(dl)" --f2b-ignore "$ip" -- "$U/a"
  expect_rc 2 $? "--f2b-ignore '$ip' refused"
done
expect_eq idle "$(status_line1 use)" "refused arms leave nothing pending"
expect_false "refused arms start no timer" has "$W/use/calls" 'systemd-run'

section "bad ids are refused before any state is touched (rc 2)"
new_instance ids
long65=$(printf 'a%.0s' $(seq 1 65))
for bid in 'a/b' '../x' 'a b' 'x;y' '-lead' '--boot' boot "$long65" '' 'caf'$'\xc3\xa9' 'a.b'; do
  gd ids arm "$bid" "$(dl)" -- "$W/ids/etc/a"
  expect_rc 2 $? "arm id '$bid'"
done
gd ids check '../x';  expect_rc 2 $? "check id '../x'"
gd ids disarm 'a b';  expect_rc 2 $? "disarm id 'a b'"
gd ids revert 'x;y';  expect_rc 2 $? "revert id 'x;y'"
gd ids revert --bootx; expect_rc 2 $? "revert --bootx"
gd ids revert '';     expect_rc 2 $? "revert with an empty id"
expect_false "no state dir was created" test -e "$W/ids/state"
# The longest allowed id (64 characters) works.
id64=$TAGP-$(printf 'x%.0s' $(seq 1 $(( 63 - ${#TAGP} ))))
gd ids arm "$id64" "$(dl)" -- "$W/ids/etc/a"
expect_rc 0 $? "arm with a 64-character id"
gd ids disarm "$id64"
expect_rc 0 $? "disarm the 64-character id"

section "deadline checks (rc 9)"
new_instance dlc
for d in "$(dl 30)" "$(dl 3700)" "$(( $(now) - 10 ))" abc 0 '' '-5' '1e9'; do
  gd dlc arm "$(id_for d1)" "$d" -- "$W/dlc/etc/a"
  expect_rc 9 $? "deadline '$d'"
done
expect_eq idle "$(status_line1 dlc)" "nothing pending after bad deadlines"
gd dlc arm "$(id_for d2)" "$(dl 3590)" -- "$W/dlc/etc/a"
expect_rc 0 $? "deadline now+3590 s accepted"
gd dlc disarm "$(id_for d2)"
expect_rc 0 $? "disarm it"

section "arm refuses a broken CURRENT config (rc 8)"
new_instance brk
echo 1 > "$W/brk/sshd_t_rc"
gd brk arm "$(id_for brk)" "$(dl)" -- "$W/brk/etc/a"
expect_rc 8 $? "arm while sshd -t fails"
expect_true "sshd -t was run" has "$W/brk/calls" 'sshd -t'
expect_false "no timer started" has "$W/brk/calls" 'systemd-run'
expect_eq idle "$(status_line1 brk)" "nothing pending"

# ------------------------------------------------------------ happy path
section "happy path: arm, check, write, check, disarm"
new_instance hp
I=$W/hp
mkdir -p "$I/etc/sshd_config.d"
echo "orig main" > "$I/etc/sshd_config"
A=$I/etc/sshd_config.d/00-autosec.conf
M=$I/etc/sshd_config
ID=$(id_for hp)
gd hp arm "$ID" "$(dl 600)" -- "$A" "$M"
expect_rc 0 $? "arm"
expect_true "arm prints 'armed <id> until <UTC time>'" has "$I/out" "^armed $ID until .* UTC\$"
expect_eq "pending $ID" "$(status_line1 hp)" "status line 1 while armed"
expect_true "status shows the deadline" has "$I/out" '^deadline: .* UTC (in [0-9]*s)$'
expect_true "status shows the timer active" has "$I/out" '^timer:    active'
expect_true "revert timer is active" timer_active "$ID"
gd hp check "$ID"
expect_rc 0 $? "check before the write"
echo "PermitRootLogin prohibit-password" > "$A"
echo "new main" > "$M"
gd hp check "$ID"
expect_rc 0 $? "check after the write"
gd hp status
expect_eq 2 "$(count "$I/out" 'written by this run')" "status: both files written by this run"
gd hp disarm "$ID"
expect_rc 0 $? "disarm"
expect_eq idle "$(status_line1 hp)" "status idle after disarm"
expect_true "status keeps a record of the disarm" has "$I/out" "^last:     disarmed $ID at "
expect_false "revert timer gone after disarm" timer_active "$ID"
expect_eq "new main" "$(content "$M")" "the change stays (main file)"
expect_eq "PermitRootLogin prohibit-password" "$(content "$A")" "the change stays (drop-in)"
gd hp check "$ID";  expect_rc 4 $? "check after disarm"
gd hp disarm "$ID"; expect_rc 4 $? "disarm again"
gd hp revert "$ID"; expect_rc 0 $? "revert after disarm does nothing"
expect_eq "new main" "$(content "$M")" "still in place after that revert"
expect_false "no sshd reload on the happy path" has "$I/calls" 'try-reload-or-restart'
expect_false "no fail2ban call on the happy path" has "$I/calls" 'fail2ban-client'
gd hp arm "$ID" "$(dl 600)" -- "$A"
expect_rc 0 $? "the same id can be armed again after a disarm"
gd hp disarm "$ID"
expect_rc 0 $? "and disarmed"

section "a second arm while a change is pending (rc 7)"
new_instance two
gd two arm "$(id_for two1)" "$(dl)" -- "$W/two/etc/a"
expect_rc 0 $? "first arm"
gd two arm "$(id_for two2)" "$(dl)" -- "$W/two/etc/b"
expect_rc 7 $? "second arm"
expect_eq "pending $(id_for two1)" "$(status_line1 two)" "the first change is still the pending one"
gd two disarm "$(id_for two1)"
expect_rc 0 $? "disarm the first"

section "nothing pending"
new_instance none
gd none disarm "$(id_for none)"; expect_rc 4 $? "disarm when nothing is pending"
gd none check "$(id_for none)";  expect_rc 4 $? "check when nothing is pending"
gd none revert "$(id_for none)"; expect_rc 0 $? "revert when nothing is pending"
gd none revert --boot;           expect_rc 0 $? "revert --boot when nothing is pending"

# ------------------------------------------------------------- reverting
section "rescue: revert <id> right after writes that check never saw"
new_instance rs
I=$W/rs
mkdir -p "$I/etc/sshd_config.d"
echo "orig main" > "$I/etc/sshd_config"
chmod 0644 "$I/etc/sshd_config"
A=$I/etc/sshd_config.d/00-autosec.conf
M=$I/etc/sshd_config
ID=$(id_for rs)
gd rs arm "$ID" "$(dl 600)" --f2b-ignore 203.0.113.9 -- "$A" "$M"
expect_rc 0 $? "arm with --f2b-ignore"
expect_true "the address is kept in the pending state while armed" grep -rqF 203.0.113.9 "$I/state"
gd rs check "$ID"
expect_rc 0 $? "check before the writes"
echo "PasswordAuthentication no" > "$A"
echo "new main" > "$M"
chmod 0600 "$M"
gd rs revert "$ID"
expect_rc 0 $? "revert"
expect_false "the drop-in this run created is removed (absent marker)" test -e "$A"
expect_eq "orig main" "$(content "$M")" "the main file is restored"
expect_eq 644 "$(stat -c %a "$M")" "its mode is restored"
expect_true "sshd -t ran" has "$I/calls" 'sshd -t'
expect_true "sshd reloaded with try-reload-or-restart ssh.service" \
  has "$I/calls" 'systemctl try-reload-or-restart ssh.service$'
expect_true "the fail2ban ignore is removed" \
  has "$I/calls" 'fail2ban-client set sshd delignoreip 203.0.113.9$'
expect_true "the revert timer is stopped" has "$I/calls" "systemctl stop auto-sec-ssh-guard-$ID.timer"
expect_false "revert timer gone" timer_active "$ID"
expect_false "the address is gone from the state dir" grep -rqF 203.0.113.9 "$I/state"
expect_eq idle "$(status_line1 rs)" "status idle"
expect_true "status records the revert" has "$I/out" "^last:     reverted $ID at "
gd rs disarm "$ID"; expect_rc 3 $? "disarm after the revert"
gd rs check "$ID";  expect_rc 3 $? "check after the revert"
gd rs revert "$ID"; expect_rc 0 $? "a second revert is a no-op"

section "revert does not reload sshd when sshd -t fails"
new_instance rb
I=$W/rb
echo "orig main" > "$I/etc/sshd_config"
ID=$(id_for rb)
gd rb arm "$ID" "$(dl 600)" -- "$I/etc/sshd_config"
expect_rc 0 $? "arm"
echo "new main" > "$I/etc/sshd_config"
gd rb check "$ID"
expect_rc 0 $? "check after the write"
echo 1 > "$I/sshd_t_rc"
gd rb revert "$ID"
expect_rc 1 $? "revert reports the problem"
expect_eq "orig main" "$(content "$I/etc/sshd_config")" "the file is restored anyway"
expect_false "no sshd reload" has "$I/calls" 'try-reload-or-restart'
expect_true "logged: NOT reloading" has "$I/log" 'NOT reloading'
expect_eq idle "$(status_line1 rb)" "the change is closed"

section "files changed by someone else after the run wrote them are left alone"
new_instance se
I=$W/se
mkdir -p "$I/etc/sshd_config.d"
echo "orig main" > "$I/etc/sshd_config"
echo "keep me" > "$I/etc/other"
A=$I/etc/sshd_config.d/00-autosec.conf
M=$I/etc/sshd_config
K=$I/etc/other
ID=$(id_for se)
gd se arm "$ID" "$(dl 600)" -- "$A" "$M" "$K"
expect_rc 0 $? "arm three paths"
echo "PermitRootLogin no" > "$A"
echo "new main" > "$M"
gd se check "$ID"
expect_rc 0 $? "check after the run's writes"
echo "admin edit" > "$M"
gd se status
expect_true "status flags the foreign edit" has "$I/out" 'changed by someone else'
gd se revert "$ID"
expect_rc 1 $? "revert reports the file it left alone"
expect_eq "admin edit" "$(content "$M")" "the foreign edit is NOT overwritten"
expect_false "the drop-in this run created is still removed" test -e "$A"
expect_eq "keep me" "$(content "$K")" "the untouched path is unchanged"
expect_true "logged: changed by someone else" has "$I/log" "$M was changed by someone else"
expect_true "the revert record names it" has "$I/state/reverted.$ID" "^left $M (changed by someone else)"
expect_eq idle "$(status_line1 se)" "the change is closed"

section "an unconfirmed change older than deadline + 300 s is left alone"
new_instance st
I=$W/st
echo "orig main" > "$I/etc/sshd_config"
ID=$(id_for st)
gd st arm "$ID" "$(dl 600)" -- "$I/etc/sshd_config"
expect_rc 0 $? "arm"
echo "new main" > "$I/etc/sshd_config"
stop_timer "$ID"
echo $(( $(now) - 1000 )) > "$I/state/run/deadline"
gd st revert --boot
expect_rc 1 $? "revert --boot on a stale snapshot reports the problem"
expect_eq "new main" "$(content "$I/etc/sshd_config")" "the unconfirmed content is NOT overwritten"
expect_true "logged: never confirmed" has "$I/log" 'never confirmed writing it'
expect_eq idle "$(status_line1 st)" "the change is closed"

section "revert --boot: files only (no sshd -t, no reload, no fail2ban)"
new_instance bt
I=$W/bt
mkdir -p "$I/etc/sshd_config.d"
echo "orig main" > "$I/etc/sshd_config"
A=$I/etc/sshd_config.d/00-autosec.conf
M=$I/etc/sshd_config
ID=$(id_for bt)
gd bt arm "$ID" "$(dl 600)" --f2b-ignore 198.51.100.4 -- "$A" "$M"
expect_rc 0 $? "arm"
echo "PermitRootLogin no" > "$A"
echo "new main" > "$M"
gd bt check "$ID"
expect_rc 0 $? "check after the writes"
stop_timer "$ID"     # a reboot loses the transient timer
n_calls=$(wc -l < "$I/calls")
gd bt revert --boot
expect_rc 0 $? "revert --boot"
expect_false "the created drop-in is removed" test -e "$A"
expect_eq "orig main" "$(content "$M")" "the main file is restored"
expect_eq "" "$(lines_after "$I/calls" "$n_calls")" "no sshd, systemctl or fail2ban call during boot revert"
expect_false "the address is gone from the state dir" grep -rqF 198.51.100.4 "$I/state"
expect_true "the revert record says boot" has "$I/state/reverted.$ID" "^reverted $ID at .* (boot)\$"
expect_eq idle "$(status_line1 bt)" "status idle"
gd bt revert --boot
expect_rc 0 $? "a second boot revert finds nothing pending"
gd bt disarm "$ID"
expect_rc 3 $? "disarm after the boot revert"

section "arm fails cleanly when the revert timer cannot be started"
new_instance nr
echo 1 > "$W/nr/systemd_run_rc"
gd nr arm "$(id_for nr)" "$(dl 600)" --f2b-ignore 192.0.2.77 -- "$W/nr/etc/a"
expect_rc 1 $? "arm when systemd-run fails"
expect_eq idle "$(status_line1 nr)" "nothing pending"
expect_false "the address is not kept" grep -rqF 192.0.2.77 "$W/nr/state"

section "a damaged snapshot is never half-reverted"
new_instance dm
I=$W/dm
echo "orig main" > "$I/etc/sshd_config"
ID=$(id_for dm)
gd dm arm "$ID" "$(dl 600)" -- "$I/etc/sshd_config"
expect_rc 0 $? "arm"
echo "new main" > "$I/etc/sshd_config"
stop_timer "$ID"
rm -f "$I/state/run/count"
gd dm status
expect_true "status says DAMAGED" has "$I/out" '^state:    DAMAGED'
gd dm revert "$ID"
expect_rc 1 $? "revert refuses"
expect_eq "pending $ID" "$(status_line1 dm)" "the change stays pending for a human"
expect_eq "new main" "$(content "$I/etc/sshd_config")" "nothing was touched"
gd dm disarm "$ID"
expect_rc 1 $? "disarm refuses too"
rm -f "$I/state/pending"

section "check reports a missing revert timer (rc 6)"
new_instance nt
ID=$(id_for nt)
gd nt arm "$ID" "$(dl 600)" -- "$W/nt/etc/a"
expect_rc 0 $? "arm"
stop_timer "$ID"
gd nt check "$ID"
expect_rc 6 $? "check with the timer gone"
gd nt status
expect_true "status says the timer is not active" has "$W/nt/out" '^timer:    NOT active'
gd nt revert "$ID"
expect_rc 0 $? "revert by hand"

section "disarm after the deadline reverts instead (rc 3)"
new_instance ld
I=$W/ld
echo "orig main" > "$I/etc/sshd_config"
ID=$(id_for ld)
gd ld arm "$ID" "$(dl 600)" -- "$I/etc/sshd_config"
expect_rc 0 $? "arm"
echo "new main" > "$I/etc/sshd_config"
gd ld check "$ID"
expect_rc 0 $? "check"
stop_timer "$ID"
echo $(( $(now) - 5 )) > "$I/state/run/deadline"
gd ld check "$ID"
expect_rc 3 $? "check after the deadline"
gd ld disarm "$ID"
expect_rc 3 $? "late disarm"
expect_eq "orig main" "$(content "$I/etc/sshd_config")" "the late disarm reverted the change"
expect_true "and reloaded sshd" has "$I/calls" 'try-reload-or-restart ssh.service'
expect_eq idle "$(status_line1 ld)" "status idle"

# ----------------------------------------------------------------- flock
section "flock serialises the subcommands"
new_instance lk
ID=$(id_for lk)
gd lk arm "$ID" "$(dl 600)" -- "$W/lk/etc/a"
expect_rc 0 $? "arm"
( exec 8>"$W/lk/state/.lock"; flock 8; sleep 3 ) &
holder=$!
sleep 0.5
t0=$(date +%s%N)
gd lk disarm "$ID"
rc=$?
t1=$(date +%s%N)
wait "$holder"
expect_rc 0 "$rc" "disarm while another process holds the lock"
waited=$(( (t1 - t0) / 1000000 ))
expect_true "disarm waited for the lock (${waited} ms >= 2000 ms)" test "$waited" -ge 2000

new_instance race
gd race arm "$(id_for ra)" "$(dl 600)" -- "$W/race/etc/a" &
p1=$!
gd race arm "$(id_for rb)" "$(dl 600)" -- "$W/race/etc/a" &
p2=$!
wait "$p1"; r1=$?
wait "$p2"; r2=$?
expect_eq "0 7" "$(printf '%s\n' "$r1" "$r2" | sort | paste -sd ' ')" "two arms at once: one wins, one gets 7"
expect_eq 1 "$(count "$W/race/calls" 'systemd-run')" "only one timer started"
winner=$(status_line1 race)
gd race disarm "${winner#pending }"
expect_rc 0 $? "disarm the winner"

# ------------------------------------ real timers, part 2: let them fire
section "real timers: daemon-reload inside the window, then the deadline"
if [ "$(now)" -lt "$DL_T" ]; then
  ok "deadline not reached yet ($(( DL_T - $(now) )) s left)"
else
  bad "the other tests took too long: deadline already passed"
fi
"$REAL_SYSTEMCTL" "${SC[@]}" daemon-reload
expect_rc 0 $? "daemon-reload of the $SCOPE manager"
gd tok check "$ID_TOK"
expect_rc 0 $? "tok still armed after daemon-reload"
expect_eq "new main" "$(content "$W/tok/etc/sshd_config")" "nothing reverted before the deadline"
echo "  ..    waiting for the deadline ($(( DL_T - $(now) )) s)"
while [ "$(now)" -le $(( DL_T + 40 )) ]; do
  if [ -e "$W/tok/state/reverted.$ID_TOK" ] && [ -e "$W/tbad/state/reverted.$ID_TBAD" ]; then break; fi
  sleep 1
done
fired=$(awk -v m="reverted change $ID_TOK" 'index($0, m) { print $1; exit }' "$W/tok/log")
if [ -n "$fired" ] && [ "$fired" -ge "$DL_T" ] && [ "$fired" -le $(( DL_T + 15 )) ]; then
  ok "tok reverted by its timer $(( fired - DL_T )) s after the deadline"
else
  bad "tok revert time '${fired:-never}', deadline $DL_T"
fi
expect_false "tok: the created drop-in is removed" test -e "$W/tok/etc/sshd_config.d/00-autosec.conf"
expect_eq "orig main" "$(content "$W/tok/etc/sshd_config")" "tok: the main file is restored"
expect_true "tok: sshd reloaded" has "$W/tok/calls" 'try-reload-or-restart ssh.service$'
expect_true "tok: the fail2ban ignore is removed" has "$W/tok/calls" 'fail2ban-client set sshd delignoreip 192.0.2.10$'
gd tok disarm "$ID_TOK"; expect_rc 3 $? "tok: late disarm"
gd tok check "$ID_TOK";  expect_rc 3 $? "tok: check after the timer fired"
expect_eq idle "$(status_line1 tok)" "tok: status idle"
expect_false "tok: timer gone" timer_active "$ID_TOK"
expect_true "tbad reverted by its timer" test -e "$W/tbad/state/reverted.$ID_TBAD"
expect_eq "orig main" "$(content "$W/tbad/etc/sshd_config")" "tbad: the file is restored"
expect_false "tbad: no sshd reload (sshd -t failed)" has "$W/tbad/calls" 'try-reload-or-restart'
expect_true "tbad: logged NOT reloading" has "$W/tbad/log" 'NOT reloading'
gd tbad disarm "$ID_TBAD"; expect_rc 3 $? "tbad: late disarm"

section "no transient units left behind"
left=$("$REAL_SYSTEMCTL" "${SC[@]}" list-units --all --no-legend --plain "auto-sec-ssh-guard-$TAGP-*" 2>/dev/null)
expect_eq "" "$left" "no auto-sec-ssh-guard-$TAGP-* units loaded"

# ---------------------------------------------------------------- summary
printf '\n%d passed, %d failed (%s manager)\n' "$PASS" "$FAIL" "$SCOPE"
if [ "$FAIL" -gt 0 ]; then
  printf '  failed: %s\n' "${FAILED[@]}"
  exit 1
fi
