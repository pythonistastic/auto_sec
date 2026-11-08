# shellcheck shell=bash
# tests/full-live/lib.sh - shared helpers of the full-run live tests
# (tests/full-adopt-live, tests/full-new-live, tests/full-legacy-live).
# Sourced, never run. The caller sets HERE, ROOT, NAME and WORK before
# sourcing it.
#
# GITHUB-HOSTED RUNNERS ONLY: these tests run site.yml for real against the
# runner itself (root@127.0.0.1 over SSH), install and remove packages and
# change the firewall. lib.sh refuses to go on anywhere else.

: "${HERE:?}" "${ROOT:?}" "${WORK:?}"
# shellcheck disable=SC2153 # NAME is set by the caller
: "${NAME:?}"

# --- results ------------------------------------------------------------------------
PASSES=0
FAILS=0
die() { echo "ERROR: $*" >&2; exit 2; }
pass() { PASSES=$((PASSES + 1)); printf 'PASS  [%s] %s\n' "$1" "$2"; }
fail() { FAILS=$((FAILS + 1)); printf 'FAIL  [%s] %s\n' "$1" "$2"; }
info() { printf 'INFO  [%s] %s\n' "$1" "$2"; }
expect() { # case what got want
  if [ "$3" = "$4" ]; then pass "$1" "$2: $3"; else fail "$1" "$2: got '$3', want '$4'"; fi
}
log_has() { # case log-name fixed-string what
  if grep -Fq -- "$3" "$LOGS/$2.log"; then pass "$1" "$4"; else fail "$1" "$4 (no '$3' in $2.log)"; fi
}
log_lacks() { # case log-name fixed-string what
  if grep -Fq -- "$3" "$LOGS/$2.log"; then fail "$1" "$4 ('$3' in $2.log)"; else pass "$1" "$4"; fi
}
finish() {
  echo
  echo "$NAME: $PASSES passed, $FAILS failed"
  [ "$FAILS" -eq 0 ]
}

if [ "${GITHUB_ACTIONS:-}" != true ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ]; then
  die "GitHub-hosted runners only: this test changes the machine it runs on"
fi
for t in ansible-playbook ssh ssh-keygen ssh-keyscan sudo sha256sum systemctl journalctl; do
  command -v "$t" >/dev/null 2>&1 || die "missing tool: $t"
done
export LC_ALL=C.UTF-8 ANSIBLE_NOCOLOR=1 ANSIBLE_INVENTORY_UNPARSED_FAILED=1 ANSIBLE_RETRY_FILES_ENABLED=False

LOGS=$WORK/logs
KEYS=$WORK/keys
INV=$WORK/inventory.yml
rm -rf "$WORK"
mkdir -p "$LOGS" "$KEYS" || die "cannot create $WORK"
chmod 700 "$KEYS"

# --- packages -------------------------------------------------------------------------
apt_update() { local _; for _ in 1 2 3; do sudo -n apt-get update -qq && return 0; sleep 10; done; return 1; }
# Setup installs must not restart the runner's services (needrestart -r l).
apt_install() { sudo -n env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install -y -qq "$@" >/dev/null; }
apt_purge() { sudo -n env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get purge -y -qq "$@" >/dev/null 2>&1; }

# --- SSH to root@127.0.0.1 --------------------------------------------------------------
# Like tests/role02-live: sshd as the image runs it, a fresh key for root,
# the host key in known_hosts. ADMIN_PUB is the public key line.
ssh_setup() {
  local _
  [ -x /usr/sbin/sshd ] || apt_install openssh-server || die "cannot install openssh-server"
  sudo -n systemctl start ssh.socket >/dev/null 2>&1 || true
  sudo -n systemctl start ssh.service >/dev/null 2>&1 || true
  ssh-keygen -q -t ed25519 -N '' -C "ci-$NAME" -f "$KEYS/admin" || die "ssh-keygen"
  ADMIN_PUB=$(cat "$KEYS/admin.pub")
  sudo -n install -d -m 700 -o root -g root /root/.ssh
  printf '%s\n' "$ADMIN_PUB" | sudo -n tee -a /root/.ssh/authorized_keys >/dev/null
  sudo -n chmod 600 /root/.ssh/authorized_keys
  mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
  for _ in $(seq 20); do
    ssh-keyscan -T 5 127.0.0.1 >"$WORK/kh" 2>/dev/null && [ -s "$WORK/kh" ] && break
    sleep 1
  done
  [ -s "$WORK/kh" ] || die "ssh-keyscan 127.0.0.1 found no host key"
  cat "$WORK/kh" >>"$HOME/.ssh/known_hosts"
  ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -i "$KEYS/admin" root@127.0.0.1 true </dev/null \
    || die "key login as root@127.0.0.1 does not work"
}

# write_inv host vars-file: one host, root@127.0.0.1, plus the YAML lines in
# vars-file (indented by the caller as host vars, 6 spaces).
write_inv() {
  {
    echo "all:"
    echo "  hosts:"
    echo "    $1:"
    echo "      ansible_host: 127.0.0.1"
    echo "      ansible_user: root"
    echo "      ansible_ssh_private_key_file: $KEYS/admin"
    echo "      ansible_python_interpreter: /usr/bin/python3"
    cat "$2"
  } >"$INV"
}

# play log-name args...: site.yml from the repository root; returns its rc.
play() {
  local name=$1 rc=0
  shift
  (cd "$ROOT" && ansible-playbook -i "$INV" site.yml "$@") >"$LOGS/$name.log" 2>&1 || rc=$?
  echo "      ansible-playbook rc=$rc, log $LOGS/$name.log"
  return "$rc"
}

# changed_tasks log-name: the TASK names that reported "changed", one per line.
changed_tasks() {
  awk '/^TASK \[/ { t = $0; sub(/^TASK \[/, "", t); sub(/\] \**$/, "", t) } /^changed: \[/ { print t }' "$LOGS/$1.log" | sort -u
}

# plan_id log-name: the plan id the run printed.
plan_id() { grep -o 'Plan id: [0-9a-f]\{12\}' "$LOGS/$1.log" | tail -n 1 | cut -d' ' -f3; }

# --- snapshot of the server --------------------------------------------------------------
# On-demand services that start and stop by themselves (hostnamectl,
# timedatectl and polkit start them over D-Bus): their PIDs may change.
VOLATILE_UNITS='^(systemd-(hostnamed|timedated|localed)|packagekit|fwupd|man-db|apt-daily(-upgrade)?|motd-news|udisks2|polkit|session-.*|user@.*|user-runtime-dir@.*|run-.*|sysstat-collect|walinuxagent)\.service$'
SYSCTL_KEYS='net.ipv4.tcp_syncookies net.ipv4.icmp_echo_ignore_broadcasts net.ipv4.icmp_ignore_bogus_error_responses
net.ipv4.icmp_echo_ignore_all net.ipv4.conf.all.log_martians net.ipv4.conf.default.log_martians
net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects net.ipv6.conf.all.accept_redirects
net.ipv6.conf.default.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.all.accept_source_route
net.ipv4.conf.all.rp_filter net.ipv4.ip_forward kernel.dmesg_restrict'

# snapshot name: files under /etc /opt and auto_sec's own places (sha256),
# symlinks, packages, accounts, running services (MainPID and start time),
# firewall rules (without counters) and counters, audit rules, kernel
# values, root's crontab, apt's history.
snapshot() {
  local d=$WORK/snap-$1 units
  mkdir -p "$d"
  sudo -n find /etc /opt /usr/local/sbin /usr/local/bin /var/lib/auto-sec /root/.ssh -xdev -type f -print0 2>/dev/null \
    | sudo -n xargs -0 -r sha256sum 2>/dev/null | sort -k2 >"$d/files"
  sudo -n find /etc /opt -xdev -type l -printf '%p -> %l\n' 2>/dev/null | sort >"$d/links"
  dpkg-query -W -f='${Package}:${Architecture} ${Version} ${db:Status-Abbrev}\n' | sort >"$d/packages"
  getent passwd | sort >"$d/passwd"
  getent group | sort >"$d/group"
  units=$(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}' \
    | grep -Ev "$VOLATILE_UNITS")
  # shellcheck disable=SC2086 # one unit name per word
  { systemctl show -p Id,MainPID,ActiveEnterTimestampMonotonic -- $units ufw.service 2>/dev/null; } \
    | awk -v RS= '{ gsub(/\n/, " "); print }' | sort >"$d/units"
  sudo -n iptables-save 2>/dev/null | grep -v '^#' | sed 's/\[[0-9]*:[0-9]*\]//' >"$d/iptables"
  sudo -n ip6tables-save 2>/dev/null | grep -v '^#' | sed 's/\[[0-9]*:[0-9]*\]//' >"$d/ip6tables"
  sudo -n iptables -v -x -n -L ufw-user-input 2>/dev/null | awk 'NR > 2 { print NR, $1 }' >"$d/counters"
  # shellcheck disable=SC2024 # the output goes to this user's work folder
  sudo -n auditctl -l 2>/dev/null >"$d/audit" || true
  # shellcheck disable=SC2086 # one key per word
  sysctl -n $SYSCTL_KEYS 2>/dev/null | paste -sd' ' - >"$d/sysctl"
  # shellcheck disable=SC2024 # the output goes to this user's work folder
  sudo -n crontab -l -u root >"$d/crontab" 2>/dev/null || echo none >"$d/crontab"
  sudo -n sha256sum /var/log/apt/history.log 2>/dev/null | cut -d' ' -f1 >"$d/apt-history"
}

# same case a b: every part of snapshot b equals a, except the counters,
# which may only grow. Prints the first differing lines on a failure.
same() {
  local c=$1 a=$WORK/snap-$2 b=$WORK/snap-$3 part
  for part in files links packages passwd group units iptables ip6tables audit sysctl crontab apt-history; do
    if cmp -s "$a/$part" "$b/$part"; then
      pass "$c" "$part unchanged"
    else
      fail "$c" "$part changed: $(diff "$a/$part" "$b/$part" | grep '^[<>]' | head -n 6 | tr '\n' ' ')"
    fi
  done
  if paste "$a/counters" "$b/counters" | awk '$4 < $2 { bad = 1 } END { exit bad }'; then
    pass "$c" "ufw-user-input counters were not reset"
  else
    fail "$c" "ufw-user-input counters went down (ufw restarted?)"
  fi
}

# Number of systemd daemon-reloads since an epoch (systemd logs "Reloading").
reloads_since() { sudo -n journalctl _PID=1 --since "@$1" -o cat 2>/dev/null | grep -c '^Reloading'; }
