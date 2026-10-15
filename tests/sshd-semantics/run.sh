#!/usr/bin/env bash
# sshd-semantics golden tests. Checks how real OpenSSH builds read the
# drop-in role 02 writes (00-autosec.conf), without root and without
# installing anything: the pinned .debs in debs.txt (SHA256-checked) are
# unpacked with dpkg-deb -x and run as
#   sshd -t / -T -f <config copy> -h <throwaway host key> -C user=..,host=..,addr=..
# Only the MaxAuthTries check starts an sshd: as this user, on 127.0.0.1.
# The template is rendered by the real role file through render.yml.
#
# Usage: tests/sshd-semantics/run.sh [--cache DIR]... [--dists "LIST"] [--keep]
#   --cache DIR   where the .debs are kept. Searched 3 levels deep by package
#                 and version (an apt download dir works too). Repeatable: all
#                 are searched, a missing file is downloaded into the FIRST.
#                 Default: ~/.cache/auto-sec-sshd-semantics
#   --dists LIST  any of: jammy bookworm noble trixie resolute (default: all)
#   --keep        keep the work directory and print its path
# Needs: curl dpkg-deb sha256sum ssh-keygen setsid ansible-playbook.
# Exit 0 = every check passed, 1 = a check failed, 2 = setup problem.
set -u -o pipefail
export LC_ALL=C

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ALL_DISTS="jammy bookworm noble trixie resolute"
# Monolithic sshd (no sshd-session helper): these can run as a daemon here.
DAEMON_DISTS="jammy bookworm noble"
CACHES=()
DISTS=$ALL_DISTS
KEEP=0

die() { echo "ERROR: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case $1 in
    --cache) [ $# -ge 2 ] || die "--cache needs a directory"; CACHES+=("$2"); shift 2 ;;
    --dists) [ $# -ge 2 ] || die "--dists needs a list"; DISTS=$2; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[ ${#CACHES[@]} -gt 0 ] || CACHES=("${XDG_CACHE_HOME:-$HOME/.cache}/auto-sec-sshd-semantics")
CACHE=${CACHES[0]}
for d in $DISTS; do
  case " $ALL_DISTS " in *" $d "*) ;; *) die "unknown dist: $d" ;; esac
done
for t in curl dpkg-deb sha256sum ssh-keygen setsid ansible-playbook; do
  command -v "$t" >/dev/null 2>&1 || die "missing tool: $t"
done

W=$(mktemp -d "${TMPDIR:-/tmp}/sshd-semantics.XXXXXX") || die "mktemp failed"
DAEMON_PIDS=()
cleanup() {
  local p
  for p in "${DAEMON_PIDS[@]}"; do kill "$p" 2>/dev/null; done
  if [ "$KEEP" = 1 ]; then echo "work dir kept: $W"; else rm -rf "$W"; fi
}
trap cleanup EXIT
mkdir -p "$CACHE" "$W/x/common" "$W/render" "$W/t" || die "cannot create directories"

PASSES=0
FAILS=0
pass() { PASSES=$((PASSES + 1)); printf 'PASS  %-9s %s\n' "$1" "$2"; }
fail() { FAILS=$((FAILS + 1)); printf 'FAIL  %-9s %s\n' "$1" "$2"; }
skip() { printf 'SKIP  %-9s %s\n' "$1" "$2"; }
expect() { # dist what got want
  if [ "$3" = "$4" ]; then pass "$1" "$2: $3"; else fail "$1" "$2: got '$3', want '$4'"; fi
}

# --- fetch and unpack the pinned packages ----------------------------------
sha_of() { sha256sum "$1" | cut -d' ' -f1; }

fetch() { # file sha url... -> prints the path of a verified copy
  local fn=$1 sha=$2 f u
  shift 2
  while IFS= read -r f; do
    if [ "$(sha_of "$f")" = "$sha" ]; then printf '%s\n' "$f"; return 0; fi
  done < <(find "${CACHES[@]}" -maxdepth 3 -type f -name "${fn%%_*}_*${fn#*_}" 2>/dev/null)
  for u in "$@"; do
    echo "download $u" >&2
    if curl -fsSL --retry 3 --retry-all-errors --retry-delay 3 --max-time 300 \
         -o "$CACHE/$fn.part" "$u" && [ "$(sha_of "$CACHE/$fn.part")" = "$sha" ]; then
      mv -f "$CACHE/$fn.part" "$CACHE/$fn" && printf '%s\n' "$CACHE/$fn" && return 0
    fi
    echo "  download failed or SHA256 mismatch: $u" >&2
  done
  rm -f "$CACHE/$fn.part"
  return 1
}

while read -r set fn sha rest; do
  case $set in ''|'#'*) continue ;; esac
  case " common $DISTS " in *" $set "*) ;; *) continue ;; esac
  read -ra urls <<<"$rest"
  deb=$(fetch "$fn" "$sha" "${urls[@]}") || die "no verified copy of $fn (see debs.txt)"
  if ! { mkdir -p "$W/x/$set" && dpkg-deb -x "$deb" "$W/x/$set"; }; then
    die "dpkg-deb -x $deb failed"
  fi
done <"$HERE/debs.txt"

LIBS="$W/x/common/usr/lib/x86_64-linux-gnu:$W/x/common/lib/x86_64-linux-gnu"
sshd_x() { local d=$1; shift; LD_LIBRARY_PATH=$LIBS "$W/x/$d/usr/sbin/sshd" "$@"; }

for d in $DISTS; do
  [ -x "$W/x/$d/usr/sbin/sshd" ] || die "$d: no usr/sbin/sshd after unpacking"
  [ -f "$W/x/$d/usr/share/openssh/sshd_config" ] || die "$d: no stock sshd_config"
  if LD_LIBRARY_PATH=$LIBS ldd "$W/x/$d/usr/sbin/sshd" 2>&1 | grep -q 'not found'; then
    LD_LIBRARY_PATH=$LIBS ldd "$W/x/$d/usr/sbin/sshd" >&2
    die "$d: sshd needs a library this machine does not have"
  fi
done

HK=$W/hostkey
ssh-keygen -q -t ed25519 -N '' -C sshd-semantics -f "$HK" || die "ssh-keygen failed"

# --- render the role's template for each case -------------------------------
CASES="keep stage2 extra allow v03 full"
for c in $CASES; do
  # Ansible refuses to start without a UTF-8 locale.
  LC_ALL=C.UTF-8 ANSIBLE_LOCALHOST_WARNING=False ANSIBLE_INVENTORY_UNPARSED_WARNING=False \
  ANSIBLE_NOCOLOR=1 ANSIBLE_RETRY_FILES_ENABLED=False \
    ansible-playbook "$HERE/render.yml" -e "@$HERE/cases/$c.yml" \
      -e "render_dest=$W/render/$c.conf" >"$W/render/$c.log" 2>&1 \
    || { cat "$W/render/$c.log" >&2; die "rendering case $c failed"; }
done

# --- helpers ----------------------------------------------------------------
# The settings role 02's trial run (P8) treats as login-critical
# (_ssh_login_critical_keys in roles/02-ssh-hardening/defaults/main.yml).
LOGIN_CRITICAL="port listenaddress permitrootlogin passwordauthentication"
LOGIN_CRITICAL+=" kbdinteractiveauthentication challengeresponseauthentication"
LOGIN_CRITICAL+=" pubkeyauthentication authenticationmethods usepam permitemptypasswords"
LOGIN_CRITICAL+=" authorizedkeysfile authorizedkeyscommand authorizedkeyscommanduser"
LOGIN_CRITICAL+=" allowusers denyusers allowgroups denygroups maxauthtries logingracetime"
LOGIN_CRITICAL+=" maxsessions allowtcpforwarding"
# ssh_extra_settings keys as sshd -T prints them.
EXTRA_KEYS="maxauthtries logingracetime maxsessions x11forwarding allowagentforwarding"
EXTRA_KEYS+=" allowtcpforwarding clientaliveinterval clientalivecountmax loglevel"

in_list() { # word "space separated list"
  case " $2 " in *" $1 "*) return 0 ;; esac
  return 1
}

mk_tree() { # dist dir layout(stock|canary|v03)
  local d=$1 t=$2 lay=$3
  rm -rf "$t"
  mkdir -p "$t/sshd_config.d" || die "mkdir $t"
  if [ "$lay" = v03 ]; then
    cp "$HERE/fixtures/sshd_config.v0.3" "$t/sshd_config" || die "copy fixture"
  else
    stock_main "$d" "$t"
  fi
  # Present on cloud images; dormant while the main file has no Include.
  echo 'PasswordAuthentication yes' >"$t/sshd_config.d/50-cloud-init.conf"
  if [ "$lay" = canary ]; then
    sed -i 's/^#PermitRootLogin prohibit-password/PermitRootLogin yes/' "$t/sshd_config"
    grep -q '^PermitRootLogin yes' "$t/sshd_config" || die "$d: canary layout: no PermitRootLogin line to set"
    printf '%s\n' 'MaxAuthTries 3' 'LoginGraceTime 30' 'MaxSessions 10' 'PermitEmptyPasswords no' \
      'X11Forwarding no' 'ClientAliveInterval 300' 'ClientAliveCountMax 2' 'LogLevel VERBOSE' \
      >"$t/sshd_config.d/00-hardening.conf"
    echo 'PasswordAuthentication no' >"$t/sshd_config.d/60-cloudimg-settings.conf"
  fi
}

stock_main() { # dist dir: the distro's main file, Include pointed at dir
  sed "s#^Include /etc/ssh/sshd_config.d/\*\.conf#Include $2/sshd_config.d/*.conf#" \
    "$W/x/$1/usr/share/openssh/sshd_config" >"$2/sshd_config"
  grep -q "^Include $2/sshd_config.d/" "$2/sshd_config" || die "$1: stock sshd_config has no Include line"
}

T() { # dist dir user out: effective config; returns sshd's rc
  sshd_x "$1" -T -f "$2/sshd_config" -h "$HK" -C "user=$3,host=autosec-check,addr=192.0.2.1" \
    >"$4" 2>"$4.err"
}
syntax() { # dist dir: sshd -t on the whole merged config; returns rc
  sshd_x "$1" -t -f "$2/sshd_config" -h "$HK" >"$W/syntax.out" 2>&1
}
put() { cp "$W/render/$1.conf" "$2/sshd_config.d/00-autosec.conf" || die "copy render $1"; }

changed() { # before after: keys whose effective value differs
  comm -3 <(sort -u "$1") <(sort -u "$2") | awk '{print $1}' | sort -u | paste -sd' ' -
}
val() { # file key: value(s), multi-value keys sorted and joined
  awk -v k="$2" '$1 == k { $1 = ""; sub(/^ /, ""); print }' "$1" | sort | paste -sd' ' -
}
unrequested() { # before after "chosen keys": login-critical keys that changed but were not chosen
  local k out=""
  for k in $(changed "$1" "$2"); do
    in_list "$k" "$LOGIN_CRITICAL" || continue
    in_list "$k" "$3" && continue
    out="$out $k"
  done
  echo "${out# }"
}
is_prohibit() { [ "$1" = prohibit-password ] || [ "$1" = without-password ]; }

# --- static checks on the rendered files (distro independent) ---------------
for c in $CASES; do
  bad=$(grep -Ein '^[[:space:]]*(port|listenaddress|subsystem|kbdinteractiveauthentication|challengeresponseauthentication|usepam|include|match|hostkey)([[:space:]]|$)' "$W/render/$c.conf")
  expect template "case $c: never writes Port/ListenAddress/Subsystem/KbdInteractive/UsePAM/Include/Match" "${bad:-none}" none
  unknown=$(grep -Ev '^[[:space:]]*(#|$)' "$W/render/$c.conf" | awk '{print $1}' \
    | grep -Evx 'PermitRootLogin|PasswordAuthentication|AllowUsers|MaxAuthTries|LoginGraceTime|MaxSessions|X11Forwarding|AllowAgentForwarding|AllowTcpForwarding|ClientAliveInterval|ClientAliveCountMax|LogLevel' \
    | paste -sd' ' -)
  expect template "case $c: only keywords from the allowed list" "${unknown:-none}" none
  if grep -Eiq '^[[:space:]]*permitrootlogin[[:space:]]+yes' "$W/render/$c.conf"; then
    fail template "case $c: writes PermitRootLogin yes"
  fi
done
active=$(grep -Evc '^[[:space:]]*(#|$)' "$W/render/keep.conf")
expect template "case keep: comments only (active lines)" "$active" 0
expect template "case stage2: active lines" \
  "$(grep -Ev '^[[:space:]]*(#|$)' "$W/render/stage2.conf" | sort | paste -sd'|' -)" \
  "PasswordAuthentication no|PermitRootLogin prohibit-password"

# --- per-distro golden checks -----------------------------------------------
maxauth_test() { # dist: does a password user with 3 agent keys reach the password prompt?
  local d=$1 c=$W/ma/$1 bin=$W/x/$1/usr/bin m p i ok out prompt
  mkdir -p "$c" && chmod 700 "$c"
  LD_LIBRARY_PATH=$LIBS "$bin/ssh-keygen" -q -t ed25519 -N '' -f "$c/hk" || { fail "$d" "maxauth: ssh-keygen"; return; }
  for i in 1 2 3; do LD_LIBRARY_PATH=$LIBS "$bin/ssh-keygen" -q -t ed25519 -N '' -C "unrelated$i" -f "$c/k$i"; done
  : >"$c/authorized_keys"; chmod 600 "$c/authorized_keys"   # a password user: no key authorized
  printf '#!/bin/sh\necho CALLED >> "%s"\necho not-the-password\n' "$c/askpass.log" >"$c/askpass"
  chmod 700 "$c/askpass"
  out=$(LD_LIBRARY_PATH=$LIBS "$bin/ssh-agent" -s -a "$c/agent.sock") || { fail "$d" "maxauth: ssh-agent"; return; }
  local agent_pid
  agent_pid=$(printf '%s\n' "$out" | sed -n 's/^SSH_AGENT_PID=\([0-9]*\);.*/\1/p')
  DAEMON_PIDS+=("$agent_pid")
  SSH_AUTH_SOCK=$c/agent.sock LD_LIBRARY_PATH=$LIBS "$bin/ssh-add" -q "$c/k1" "$c/k2" "$c/k3" 2>/dev/null \
    || { fail "$d" "maxauth: ssh-add"; return; }
  for m in 6 3; do
    p=$((20000 + RANDOM % 40000))
    cat >"$c/sshd_config" <<EOF
Port $p
ListenAddress 127.0.0.1
HostKey $c/hk
PidFile $c/sshd.pid
AuthorizedKeysFile $c/authorized_keys
UsePAM no
StrictModes no
PubkeyAuthentication yes
PasswordAuthentication yes
KbdInteractiveAuthentication no
MaxAuthTries $m
LogLevel VERBOSE
EOF
    rm -f "$c/sshd.pid" "$c/sshd.log" "$c/askpass.log"
    sshd_x "$d" -f "$c/sshd_config" -E "$c/sshd.log" || { fail "$d" "maxauth: sshd did not start ($(tail -1 "$c/sshd.log"))"; return; }
    ok=0
    for i in $(seq 50); do
      if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then ok=1; break; fi
      sleep 0.1
    done
    [ -s "$c/sshd.pid" ] && DAEMON_PIDS+=("$(cat "$c/sshd.pid")")
    if [ "$ok" != 1 ]; then fail "$d" "maxauth: sshd not listening on 127.0.0.1:$p"; return; fi
    SSH_AUTH_SOCK=$c/agent.sock SSH_ASKPASS=$c/askpass SSH_ASKPASS_REQUIRE=force DISPLAY=:0 \
      LD_LIBRARY_PATH=$LIBS setsid -w "$bin/ssh" -F /dev/null -p "$p" -o IdentityFile="$c/k1" \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null \
      -o PreferredAuthentications=publickey,password -o NumberOfPasswordPrompts=1 \
      -o ConnectTimeout=10 -o LogLevel=ERROR 127.0.0.1 true </dev/null >"$c/ssh.out" 2>&1
    if [ -s "$c/askpass.log" ]; then prompt=reached; else prompt=never; fi
    kill "$(cat "$c/sshd.pid")" 2>/dev/null
    if [ "$m" = 6 ]; then
      expect "$d" "MaxAuthTries 6, agent holds 3 other keys: password prompt" "$prompt" reached
    else
      expect "$d" "MaxAuthTries 3, agent holds 3 other keys: password prompt" "$prompt" never
      if grep -q 'maximum authentication attempts exceeded' "$c/sshd.log"; then
        pass "$d" "MaxAuthTries 3: sshd logged 'maximum authentication attempts exceeded'"
      else
        fail "$d" "MaxAuthTries 3: no 'maximum authentication attempts exceeded' in the sshd log"
      fi
    fi
  done
  kill "$agent_pid" 2>/dev/null
}

run_dist() {
  local d=$1 t lay u rc_b rc_t rc_a n ch want b a x

  # P6 recognises a reload by this journal line: it must exist in every build.
  if grep -qa 'Received SIGHUP; restarting' "$W/x/$d/usr/sbin/sshd"; then
    pass "$d" "reload log line 'Received SIGHUP; restarting' is in sshd"
  else
    fail "$d" "reload log line 'Received SIGHUP; restarting' is NOT in sshd"
  fi

  for lay in stock canary; do
    t=$W/t/$d-$lay
    mk_tree "$d" "$t" "$lay"
    b=$W/t/$d-$lay.before a=$W/t/$d-$lay.after

    # 1. keep-everything: no effective change; works for a user not created yet.
    for u in root deploy-not-created-yet; do
      rm -f "$t/sshd_config.d/00-autosec.conf"
      rc_b=0; T "$d" "$t" "$u" "$b" || rc_b=$?
      put keep "$t"
      rc_t=0; syntax "$d" "$t" || rc_t=$?
      rc_a=0; T "$d" "$t" "$u" "$a" || rc_a=$?
      n=$(diff "$b" "$a" | grep -c '^[<>]')
      expect "$d" "keep-all, $lay layout, -C user=$u: -T rc / -t rc / -T rc / changed lines" \
        "$rc_b/$rc_t/$rc_a/$n" "0/0/0/0"
    done

    # 2. stage 2: exactly the two login keys change (stock already has root key-only).
    rm -f "$t/sshd_config.d/00-autosec.conf"
    T "$d" "$t" root "$b"
    put stage2 "$t"
    T "$d" "$t" root "$a"
    if [ "$lay" = canary ]; then want="passwordauthentication permitrootlogin"; else want="passwordauthentication"; fi
    expect "$d" "stage 2, $lay layout: changed keys" "$(changed "$b" "$a")" "$want"
    expect "$d" "stage 2, $lay layout: passwordauthentication" "$(val "$a" passwordauthentication)" no
    x=$(val "$a" permitrootlogin)
    if is_prohibit "$x"; then pass "$d" "stage 2, $lay layout: permitrootlogin $x"; else fail "$d" "stage 2, $lay layout: permitrootlogin '$x'"; fi
    rm -f "$t/sshd_config.d/00-autosec.conf"
  done

  # 3. 00-autosec.conf beats 00-hardening.conf for ssh_extra_settings.
  t=$W/t/$d-canary b=$W/t/$d-extra.before a=$W/t/$d-extra.after
  T "$d" "$t" root "$b"
  put extra "$t"
  T "$d" "$t" root "$a"
  expect "$d" "extra settings over 00-hardening: before" \
    "$(val "$b" maxauthtries)/$(val "$b" logingracetime)/$(val "$b" clientaliveinterval)" "3/30/300"
  expect "$d" "extra settings over 00-hardening: after" \
    "$(val "$a" maxauthtries)/$(val "$a" logingracetime)/$(val "$a" clientaliveinterval)" "5/45/120"
  expect "$d" "extra settings over 00-hardening: changed keys" "$(changed "$b" "$a")" \
    "clientaliveinterval logingracetime maxauthtries"
  rm -f "$t/sshd_config.d/00-autosec.conf"

  # 4. AllowUsers: exact set on a clean host; a stray drop-in ADDS users
  #    (sshd appends AllowUsers lines), so P8 must compare the exact set.
  t=$W/t/$d-stock b=$W/t/$d-allow.before a=$W/t/$d-allow.after
  put allow "$t"
  T "$d" "$t" deploy "$a"
  expect "$d" "AllowUsers [deploy], clean host: effective set" "$(val "$a" allowusers)" deploy
  echo 'AllowUsers alice' >"$t/sshd_config.d/10-stray-allowusers.conf"
  T "$d" "$t" deploy "$a"
  x=$(val "$a" allowusers)
  expect "$d" "AllowUsers [deploy] + stray 'AllowUsers alice' drop-in: effective set (sshd only; role 02 P8 is expected to refuse this)" "$x" "alice deploy"
  rm -f "$t/sshd_config.d/10-stray-allowusers.conf" "$t/sshd_config.d/00-autosec.conf"

  # 5. A drop-in that sorts before 00-autosec wins: the chosen value does not
  #    take effect, so P8 (a) must refuse and name that file.
  echo 'PermitRootLogin yes' >"$t/sshd_config.d/00-ansible_system_role.conf"
  put stage2 "$t"
  T "$d" "$t" root "$a"
  expect "$d" "stage 2 + earlier 00-ansible_system_role.conf: permitrootlogin (sshd only; role 02 P8 is expected to refuse this)" \
    "$(val "$a" permitrootlogin)" yes
  rm -f "$t/sshd_config.d/00-ansible_system_role.conf" "$t/sshd_config.d/00-autosec.conf"

  # 6. Every option set: sshd -t passes (no duplicate Subsystem), Subsystem
  #    and other unchosen keys are untouched, chosen values take effect.
  T "$d" "$t" deploy "$b"
  put full "$t"
  rc_t=0; syntax "$d" "$t" || rc_t=$?
  expect "$d" "all options set: sshd -t rc" "$rc_t" 0
  T "$d" "$t" deploy "$a"
  expect "$d" "all options set: subsystem unchanged" "$(val "$a" subsystem)" "$(val "$b" subsystem)"
  expect "$d" "all options set: login-critical keys changed but not chosen" \
    "$(unrequested "$b" "$a" "permitrootlogin passwordauthentication allowusers maxauthtries logingracetime maxsessions allowtcpforwarding")" ""
  ch=$(changed "$b" "$a")
  x=""
  for n in $ch; do
    in_list "$n" "permitrootlogin passwordauthentication allowusers $EXTRA_KEYS" || x="$x $n"
  done
  expect "$d" "all options set: keys changed that are not in the file" "${x# }" ""
  expect "$d" "all options set: effective values" \
    "$(val "$a" passwordauthentication)/$(val "$a" allowusers)/$(val "$a" maxauthtries)/$(val "$a" logingracetime)/$(val "$a" maxsessions)/$(val "$a" x11forwarding)/$(val "$a" allowagentforwarding)/$(val "$a" allowtcpforwarding)/$(val "$a" clientaliveinterval)/$(val "$a" clientalivecountmax)/$(val "$a" loglevel)" \
    "no/deploy ops/4/25/4/no/no/no/240/3/VERBOSE"
  rm -f "$t/sshd_config.d/00-autosec.conf"

  # 7. Migration of a 0.3 host (main file without Include, dormant 50-cloud-init).
  t=$W/t/$d-v03 b=$W/t/$d-v03.before a=$W/t/$d-v03.after
  mk_tree "$d" "$t" v03
  rc_b=0; T "$d" "$t" deploy "$b" || rc_b=$?
  expect "$d" "0.3 main file: sshd -T rc" "$rc_b" 0
  expect "$d" "0.3 main file: 50-cloud-init.conf is dormant (passwordauthentication)" "$(val "$b" passwordauthentication)" no
  # 7a. Migrating with "keep" wakes 50-cloud-init: P8 must refuse.
  stock_main "$d" "$t"
  put keep "$t"
  T "$d" "$t" deploy "$a"
  x=$(unrequested "$b" "$a" "")
  case " $x " in
    *" passwordauthentication "*) pass "$d" "migrate with keep: Include wakes 50-cloud-init, unrequested login changes: $x" ;;
    *) fail "$d" "migrate with keep: expected passwordauthentication among unrequested changes, got '$x'" ;;
  esac
  # 7b. Migrating with the 0.3-equivalent block keeps every login setting.
  put v03 "$t"
  rc_t=0; syntax "$d" "$t" || rc_t=$?
  expect "$d" "migrate with the 0.3 block: sshd -t rc" "$rc_t" 0
  T "$d" "$t" deploy "$a"
  expect "$d" "migrate with the 0.3 block: login-critical keys that change" "$(unrequested "$b" "$a" "")" ""
  ch=$(changed "$b" "$a")
  x=""
  for n in $ch; do
    in_list "$n" "acceptenv printmotd subsystem" || x="$x $n"
  done
  expect "$d" "migrate with the 0.3 block: other changes beyond acceptenv/printmotd/subsystem" "${x# }" ""
  echo "INFO  $d  migrate with the 0.3 block: all changed keys: ${ch:-none}"

  # 8. MaxAuthTries below the number of agent keys hides the password prompt.
  case " $DAEMON_DISTS " in
    *" $d "*) maxauth_test "$d" ;;
    *) skip "$d" "MaxAuthTries daemon test: sshd-session cannot run unpacked on this machine" ;;
  esac
}

for d in $DISTS; do
  echo "== $d: $(sshd_x "$d" -V 2>&1 | grep -m1 OpenSSH)"
  run_dist "$d"
done

echo
echo "sshd-semantics: $PASSES passed, $FAILS failed (dists: $DISTS)"
[ "$FAILS" -eq 0 ]
