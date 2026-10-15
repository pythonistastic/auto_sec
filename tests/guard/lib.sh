#!/bin/bash
#
# lib.sh - helpers for tests/guard/run.sh (sourced, never run directly).
#
# run.sh sets these before sourcing:
#   HERE            tests/guard
#   GUARD_SRC       roles/02-ssh-hardening/files/auto-sec-ssh-guard
#   W               private work dir (removed at exit)
#   SCOPE           "user" or "system"
#   SC              array: (--user) or ()
#   REAL_SYSTEMCTL  REAL_SYSTEMD_RUN   absolute paths of the real binaries

PASS=0
FAIL=0
FAILED=()

ok()      { PASS=$((PASS + 1)); printf '  ok    %s\n' "$*"; }
bad()     { FAIL=$((FAIL + 1)); FAILED+=("$*"); printf '  FAIL  %s\n' "$*"; }
section() { printf '\n== %s\n' "$*"; }
die()     { printf 'ERROR: %s\n' "$*" >&2; exit 2; }

expect_rc() {  # <want> <got> <what>
  if [ "$1" = "$2" ]; then ok "$3 (rc $2)"; else bad "$3: rc $2, want $1"; fi
}

expect_eq() {  # <want> <got> <what>
  if [ "$1" = "$2" ]; then ok "$3"; else bad "$3: got '$2', want '$1'"; fi
}

expect_true() {  # <what> <command...>
  local what=$1
  shift
  if "$@"; then ok "$what"; else bad "$what"; fi
}

expect_false() {  # <what> <command...>
  local what=$1
  shift
  if "$@"; then bad "$what"; else ok "$what"; fi
}

has()     { grep -q -e "$2" -- "$1" 2>/dev/null; }      # <file> <regex>
count()   { grep -c -e "$2" -- "$1" 2>/dev/null; }      # <file> <regex>
content() { cat -- "$1" 2>/dev/null || echo '<absent>'; }

now() { date +%s; }
dl()  { echo $(( $(date +%s) + ${1:-600} )); }           # deadline n s ahead

# Unique ids per test run, so units of a crashed earlier run never clash.
TAGP="gt$$$(od -An -N2 -tx1 /dev/urandom | tr -d ' \n')"
id_for() { echo "$TAGP-$1"; }

timer_active() {  # <id>
  "$REAL_SYSTEMCTL" "${SC[@]}" is-active --quiet "auto-sec-ssh-guard-$1.timer"
}

stop_timer() {  # <id>  (simulates a lost timer, e.g. after a reboot)
  "$REAL_SYSTEMCTL" "${SC[@]}" stop "auto-sec-ssh-guard-$1.timer" >/dev/null 2>&1 || true
}

# Copy the guard and point its paths block at <dir>. The block must be the
# exact one the contract fixes; check_paths_block tests that separately.
rewrite_paths() {  # <src> <dst> <instance dir>
  awk -v d="$3" '
    /^# --- paths \(tests rewrite this block\) ---$/ {
      print; skip = 1
      printf "readonly STATE_DIR=%s/state\n", d
      printf "readonly SSHD=%s/bin/sshd\n", d
      printf "readonly SYSTEMCTL=%s/bin/systemctl\n", d
      printf "readonly SYSTEMD_RUN=%s/bin/systemd-run\n", d
      printf "readonly F2B=%s/bin/fail2ban-client\n", d
      printf "readonly LOGGER=%s/bin/logger\n", d
      next
    }
    /^# --- end paths ---$/ { skip = 0 }
    !skip { print }' "$1" > "$2"
}

# new_instance <name>: $W/<name>/ with its own guard copy, stub binaries,
# state dir and etc/ tree. Files written there:
#   calls        every stub call as "<epoch> <binary> <args>"
#   log          the guard's logger messages as "<epoch> <args>"
#   out, err     stdout / stderr of the last / all guard calls
#   sshd_t_rc    exit code of "sshd -t" (0 valid, 1 broken)
#   reload_rc    exit code of "systemctl try-reload-or-restart ssh.service"
#   systemd_run_rc  nonzero: systemd-run fails without starting a timer
new_instance() {
  local d="$W/$1" s
  mkdir -p "$d/bin" "$d/etc"
  for s in sshd systemctl systemd-run fail2ban-client logger; do
    cp "$HERE/stubs/$s" "$d/bin/$s"
    chmod 0755 "$d/bin/$s"
  done
  echo 0 > "$d/sshd_t_rc"
  echo 0 > "$d/reload_rc"
  echo "$SCOPE" > "$d/scope"
  echo "$REAL_SYSTEMCTL" > "$d/real_systemctl"
  echo "$REAL_SYSTEMD_RUN" > "$d/real_systemd_run"
  : > "$d/calls"
  : > "$d/log"
  : > "$d/err"
  rewrite_paths "$GUARD_SRC" "$d/guard" "$d"
  chmod 0700 "$d/guard"
}

# gd <name> <args...>: run that instance's guard. stdout goes to ./out,
# stderr is appended to ./err. Returns the guard's exit code.
gd() {
  local d="$W/$1"
  shift
  "$d/guard" "$@" > "$d/out" 2>> "$d/err"
}

status_line1() { gd "$1" status; head -n 1 "$W/$1/out"; }

# Lines of a file added after line <n> (for "nothing new was called").
lines_after() { tail -n "+$(( $2 + 1 ))" -- "$1"; }
