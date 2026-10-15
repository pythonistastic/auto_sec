#!/usr/bin/env bash
# Interactive configuration wizard for secure-deploy.
#
# Asks plain-language questions, generates every secret it can
# (age keypair, fwknop keys, DB password, watcher pattern suggestion),
# writes host_vars/<server>.yml + inventory/<server>.yml, and prints
# the exact command to harden the server.
#
# Two modes:
#   local   you are running this ON the server to be hardened
#   remote  you are on your workstation, managing the server over SSH
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_DIR}"

# Read from the terminal even if the script was piped in.
if [ ! -t 0 ] && [ -r /dev/tty ]; then exec < /dev/tty; fi

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
warn() { printf '\033[1;33mWARNING:\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# Emit a value as a single-quoted YAML scalar for host_vars.
#
# Values used to be written as  echo "key: \"${VAR}\""  - so a typed " or \
# broke out of the string and could inject arbitrary extra keys into
# host_vars, including keys the playbook preflight never checks. Inside
# single quotes YAML interprets nothing except '' (an escaped quote), so ",
# \, $, # and : are all literal. Newlines are refused: `read -r` cannot
# produce one, so a value carrying one came from a file or a network
# response, and would otherwise be folded silently.
yaml_str() {
  case "$1" in
    *$'\n'*|*$'\r'*) die "refusing a value containing a newline: $(printf '%q' "$1")" ;;
  esac
  printf "'%s'" "${1//\'/\'\'}"
}

banner() {
  printf '\033[1;32m'
  cat <<'ART'
 █████╗ ██╗   ██╗████████╗ ██████╗         ███████╗███████╗ ██████╗
██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗        ██╔════╝██╔════╝██╔════╝
███████║██║   ██║   ██║   ██║   ██║        ███████╗█████╗  ██║
██╔══██║██║   ██║   ██║   ██║   ██║        ╚════██║██╔══╝  ██║
██║  ██║╚██████╔╝   ██║   ╚██████╔╝███████╗███████║███████╗╚██████╗
╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚══════╝╚══════╝╚══════╝ ╚═════╝
ART
  local ver
  ver="$(cat "${REPO_DIR}/VERSION" 2>/dev/null || echo '?')"
  printf '\033[0m\033[2m   one-command server hardening + breach detection  \033[0m'
  printf '\033[2mv%s\033[0m\n' "$ver"
}

ask() { # ask "Prompt" "default" -> REPLY
  local prompt="$1" default="${2:-}"
  if [ -n "$default" ]; then
    read -r -p "$prompt [$default]: " REPLY
    REPLY="${REPLY:-$default}"
  else
    read -r -p "$prompt: " REPLY
  fi
}

ask_required() {
  while :; do
    ask "$1" "${2:-}"
    [ -n "$REPLY" ] && return
    warn "This value is required."
  done
}

confirm() { # confirm "Question" [y|n] -> 0 yes / 1 no
  local default="${2:-y}" hint="[Y/n]" ans
  [ "$default" = "n" ] && hint="[y/N]"
  read -r -p "$1 $hint: " ans
  ans="${ans:-$default}"
  case "$ans" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

command -v openssl >/dev/null || die "openssl is required (run bootstrap.sh first)."
command -v age-keygen >/dev/null || die "age is required (run bootstrap.sh first)."

echo
banner
echo
say "Configuration wizard"
note "Answers are written to host_vars/<server>.yml (gitignored)."
echo

# ------------------------------------------------------------------ mode
say "Where are you running this?"
note "1) local  - this machine IS the server to harden"
note "2) remote - I am on my workstation, the server is elsewhere"
ask "Choose" "2"
MODE="remote"; [ "$REPLY" = "1" ] && MODE="local"

ask_required "Short server name (lowercase, no spaces, e.g. acme-prod)"
SERVER="$REPLY"
[[ "$SERVER" =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "Name must be lowercase letters, digits, dashes."
HOSTVARS="host_vars/${SERVER}.yml"
[ -f "$HOSTVARS" ] && ! confirm "$HOSTVARS exists. Overwrite?" n && die "Aborted."

SERVER_IP="127.0.0.1"
SSH_KEY_FILE=""
if [ "$MODE" = "remote" ]; then
  ask_required "Server public IP address"
  SERVER_IP="$REPLY"
  # Becomes ansible_host. An IP or a plain hostname, nothing else.
  [[ "$SERVER_IP" =~ ^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$ ]] \
    || die "Not a valid IP address or hostname: $SERVER_IP"
fi

# ------------------------------------------------------------- identity
say "Basics"
ask_required "Organization / client name (for the report)" "My Company"
CLIENT_NAME="$REPLY"
ask_required "App domain (e.g. app.example.com)"
DOMAIN="$REPLY"
ask_required "Email for Let's Encrypt TLS registration"
LE_EMAIL="$REPLY"

# ------------------------------------------------------------------ ssh key
say "SSH access"
note "New to SSH keys? Here is all you need to know:"
note "  A key comes in a PAIR - a PRIVATE key that stays secret on your"
note "  computer, and a PUBLIC key that is safe to share and gets installed"
note "  on the server. You log in by proving you hold the private key."
note "  Keys are far safer than passwords."
note "auto_sec adds your PUBLIC key to the server. It only ever adds keys;"
note "it never removes a key that is already there."
echo

validate_pubkey() {  # $1 = key string
  case "$1" in
    ssh-ed25519\ *|ssh-rsa\ *|ecdsa-*\ *|sk-ssh-*) return 0 ;;
    *) return 1 ;;
  esac
}

DEPLOY_PUBKEY=""
if [ "$MODE" = "local" ]; then
  # Wizard runs ON the server; the key must be made on the user's OWN
  # computer (the one they will connect FROM), so we can only guide them.
  note "You will connect FROM another computer (your laptop). Create the"
  note "key THERE, not on this server. On your laptop, open a terminal:"
  note ""
  note "  ssh-keygen -t ed25519 -C \"${SERVER}\""
  note "     (press Enter to accept the defaults; a passphrase is optional)"
  note ""
  note "Then print the PUBLIC half and copy the whole line:"
  note "  macOS/Linux:  cat ~/.ssh/id_ed25519.pub"
  note "  Windows:      type \$env:USERPROFILE\\.ssh\\id_ed25519.pub"
  note ""
  while :; do
    ask_required "Paste the public key (starts with 'ssh-ed25519')"
    if validate_pubkey "$REPLY"; then DEPLOY_PUBKEY="$REPLY"; break; fi
    warn "That does not look like a public key. It should start with"
    warn "'ssh-ed25519' (or 'ssh-rsa') and be a single line."
  done
else
  # Remote mode: the wizard runs on the machine the user connects FROM,
  # so we can find or CREATE the key right here.
  mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
  EXISTING=()
  for k in "$HOME"/.ssh/*.pub; do [ -e "$k" ] && EXISTING+=("$k"); done

  if [ "${#EXISTING[@]}" -gt 0 ]; then
    note "Found existing SSH key(s) on this machine:"
    for k in "${EXISTING[@]}"; do note "  ${k%.pub}"; done
    ask "Path to the PRIVATE key to use for this server" "${EXISTING[0]%.pub}"
    SSH_KEY_FILE="${REPLY/#\~/$HOME}"
  else
    note "No SSH key found on this machine yet."
    if confirm "Generate a new one now (recommended)?"; then
      SSH_KEY_FILE="$HOME/.ssh/${SERVER}_key"
      ssh-keygen -t ed25519 -N "" -C "${SERVER}" -f "$SSH_KEY_FILE" >/dev/null
      say "Created your key pair:"
      note "  private: ${SSH_KEY_FILE}   (keep secret, never share/commit)"
      note "  public:  ${SSH_KEY_FILE}.pub (this is what goes on the server)"
    else
      ask_required "OK - path to an existing PRIVATE key"
      SSH_KEY_FILE="${REPLY/#\~/$HOME}"
    fi
  fi

  # Make sure we have the matching public key (derive it if missing).
  PUB_PATH="${SSH_KEY_FILE}.pub"
  if [ ! -f "$PUB_PATH" ] && [ -f "$SSH_KEY_FILE" ]; then
    ssh-keygen -y -f "$SSH_KEY_FILE" > "$PUB_PATH" 2>/dev/null || true
  fi
  [ -f "$PUB_PATH" ] || die "Could not find or derive the public key ${PUB_PATH}."
  DEPLOY_PUBKEY="$(cat "$PUB_PATH")"
  validate_pubkey "$DEPLOY_PUBKEY" || die "\"$PUB_PATH\" does not look like a valid public key."
  case "$SSH_KEY_FILE" in
    /mnt/*)
      warn "This key is in a Windows folder (${SSH_KEY_FILE})."
      warn "In WSL those files look readable by everyone, and ssh may refuse"
      warn "the key. Copy it into ~/.ssh inside WSL and use that path." ;;
  esac
fi

# ------------------------------------------------------------ login account
# ssh_admin_user is the account you AND Ansible log in as after setup. Its
# keys are added, and tested on a brand-new connection, before any login
# rule gets stricter. Same shape rule as preflight: it reaches file paths.
valid_user() { [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; }

say "Login account"
NOW_USER="root"
if [ "$MODE" = "remote" ]; then
  note "Which account do you use to log in to this server today?"
  note "On a new VPS this is usually root."
  ask "Account you log in as today" "root"
  NOW_USER="$REPLY"
  valid_user "$NOW_USER" || die "Not a valid user name: $NOW_USER"
fi
ADMIN_DEFAULT="deploy"
[ "$NOW_USER" = "root" ] && ADMIN_DEFAULT="root"
if [ "$MODE" = "local" ]; then
  note "Which account will you log in as, from your laptop, from now on?"
else
  note "Which account should you (and Ansible) log in as from now on?"
fi
note "  root    - keep logging in as root, with your key."
note "  deploy  - a separate account with sudo. auto_sec creates it."
note "  You can also type an existing account that has passwordless sudo."
ask "Admin login account" "$ADMIN_DEFAULT"
ADMIN_USER="$REPLY"
valid_user "$ADMIN_USER" || die "Not a valid user name: $ADMIN_USER"

# -------------------------------------------------------------- login rules
# These two have no default on purpose: preflight stops until they are set.
say "Login rules"
note "auto_sec can make SSH logins stricter. You choose. Nothing gets"
note "stricter until a key login as ${ADMIN_USER} works on a new connection."
note "Our advice: choose 'keep' for both now. Run once. Check that your key"
note "login works. Then change them in ${HOSTVARS} and run again."
echo
note "Root login over SSH:"
note "  keep              - leave it as the server has it now (recommended first)"
note "  prohibit-password - root may log in with a key, never with a password"
if [ "$ADMIN_USER" != "root" ]; then
  note "  no                - root may not log in over SSH at all"
fi
ask "Root login" "keep"
PERMIT_ROOT="$REPLY"
case "$PERMIT_ROOT" in
  keep|prohibit-password) ;;
  no) [ "$ADMIN_USER" != "root" ] \
        || die "You log in as root, so root login cannot be 'no'. Choose keep or prohibit-password." ;;
  *) die "Must be keep, prohibit-password or no." ;;
esac
echo
note "Password login over SSH (for every account):"
note "  keep - leave it as the server has it now (recommended first)"
note "  no   - keys only. Passwords stop working over SSH for everyone,"
note "         including tools like VS Code that log in with a password."
note "         Move those tools to a key first."
ask "Password login" "keep"
PASSWORD_AUTH="$REPLY"
case "$PASSWORD_AUTH" in
  keep|no) ;;
  *) die "Must be keep or no." ;;
esac

# Local mode cannot test a new login from your own computer, so role 02
# only applies SSH settings that change nothing there (preflight refuses).
if [ "$MODE" = "local" ] && { [ "$PERMIT_ROOT" != "keep" ] || [ "$PASSWORD_AUTH" != "keep" ]; }; then
  warn "You are on the server itself (local mode). From here auto_sec cannot"
  warn "test a new login from your computer, so it only applies SSH settings"
  warn "that change nothing. If your choice would change how SSH works today,"
  warn "the whole run stops before changing anything. To tighten logins, run"
  warn "auto_sec from your own computer (remote mode)."
  if confirm "Use 'keep' for both for now (recommended)?"; then
    PERMIT_ROOT="keep"; PASSWORD_AUTH="keep"
  fi
fi

# --------------------------------------------------------------------- app
say "Application runtime"
ask "App type: node or docker" "node"
APP_TYPE="$REPLY"
[ "$APP_TYPE" = "node" ] || [ "$APP_TYPE" = "docker" ] || die "Must be node or docker."
ask "App listen port (Nginx proxies to it)" "3000"
APP_PORT="$REPLY"
# Rendered into the nginx vhost's proxy_pass line.
if ! [[ "$APP_PORT" =~ ^[0-9]{1,5}$ ]] || [ "$APP_PORT" -lt 1 ] || [ "$APP_PORT" -gt 65535 ]; then
  die "Port must be a number between 1 and 65535."
fi
NODE_VERSION="20"
[ "$APP_TYPE" = "node" ] && { ask "Node.js major version" "20"; NODE_VERSION="$REPLY"; }

# ---------------------------------------------------------------- database
say "Database"
ask "Database engine: postgres, mysql, or none" "postgres"
DB_ENGINE="$REPLY"
DB_NAME=""; DB_USER=""; DB_PASSWORD=""
if [ "$DB_ENGINE" != "none" ]; then
  [ "$DB_ENGINE" = "postgres" ] || [ "$DB_ENGINE" = "mysql" ] || die "Must be postgres, mysql or none."
  ask "Database name" "appdb"
  DB_NAME="$REPLY"
  ask "Database user" "appuser"
  DB_USER="$REPLY"
  DB_PASSWORD="$(openssl rand -base64 24 | tr -d '/+=' | head -c 28)"
  note "Generated a random DB password (stored in $HOSTVARS)."
fi

# ------------------------------------------------------------------ alerts
say "Telegram alerts (breach alerts, backup status, watcher)"
note "1) In Telegram, open @BotFather and run /newbot to get a bot TOKEN."
note "2) Open your new bot and press START / send it any message"
note "   (Telegram won't let a bot message you until you do)."
ask "Telegram bot token (empty to skip alerts for now)" ""
TG_TOKEN="$REPLY"
TG_CHAT=""
[ -z "$TG_TOKEN" ] || [[ "$TG_TOKEN" =~ ^[0-9]{5,}:[A-Za-z0-9_-]{20,}$ ]] \
  || die "That doesn't look like a bot token (expected 123456789:AAH...)."

# Call the Telegram API without putting the token on a command line. The
# token lives in the URL path, and a process's argv is readable by every
# local user via `ps` - which matters because in local mode this wizard runs
# on the server itself. curl -K - takes its config (here, the URL) on stdin.
tg_api() {  # tg_api <method> [extra curl args...]
  local method="$1"; shift
  printf 'url = "https://api.telegram.org/bot%s/%s"\n' "$TG_TOKEN" "$method" \
    | curl -s --max-time 10 -K - "$@"
}

# Ask Telegram for the chat id from the message the user just sent the bot.
detect_chat_id() {
  tg_api getUpdates \
    | grep -oE '"chat":\{"id":-?[0-9]+' | grep -oE '\-?[0-9]+$' | tail -1
}

if [ -n "$TG_TOKEN" ]; then
  note "Looking up your chat id from the message you sent the bot..."
  TG_CHAT="$(detect_chat_id || true)"
  if [ -z "$TG_CHAT" ]; then
    warn "No message found yet. Open your bot in Telegram and press START,"
    warn "then press Enter here to retry."
    read -r _
    TG_CHAT="$(detect_chat_id || true)"
  fi

  if [ -n "$TG_CHAT" ]; then
    say "Detected chat id: ${TG_CHAT}"
  else
    warn "Still couldn't auto-detect it. You can enter it manually"
    warn "(from https://api.telegram.org/bot<TOKEN>/getUpdates) or leave blank."
    ask "Telegram chat id" ""
    TG_CHAT="$REPLY"
    [ -z "$TG_CHAT" ] || [[ "$TG_CHAT" =~ ^-?[0-9]{1,32}$ ]] \
      || die "A chat id is a number (groups are negative)."
  fi

  if [ -n "$TG_CHAT" ]; then
    RESP="$(tg_api sendMessage -X POST \
      -d chat_id="${TG_CHAT}" --data-urlencode "text=auto_sec wizard: test OK for ${SERVER}")"
    if echo "$RESP" | grep -q '"ok":true'; then
      say "Test message delivered — check your Telegram."
    elif echo "$RESP" | grep -q 'chat not found'; then
      warn "Telegram says 'chat not found' — open the bot and press START,"
      warn "then re-run the wizard or edit $HOSTVARS. Continuing for now."
    else
      warn "Telegram test failed: $(echo "$RESP" | head -c 160)"
    fi
  fi
fi

if [ -z "$TG_TOKEN" ] || [ -z "$TG_CHAT" ]; then
  [ -n "$TG_TOKEN" ] && warn "Alerts left unconfigured; you can edit $HOSTVARS later."
  [ -z "$TG_TOKEN" ] && warn "Alerts disabled. The detectors still write incident files to /var/log/sentinel, but nobody gets pinged."
  TG_TOKEN="${TG_TOKEN:-CHANGE_ME}"; TG_CHAT="${TG_CHAT:-CHANGE_ME}"
fi

# ----------------------------------------------------------------- backups
say "Encrypted off-site backups (Backblaze B2)"
note "Uses a B2 application key WITHOUT delete permission, so ransomware"
note "on the server cannot destroy backup history."
BACKUPS=0
B2_BUCKET=""; B2_KEY_ID=""; B2_APP_KEY=""; AGE_PUBLIC=""
if confirm "Enable backups now?"; then
  BACKUPS=1
  ask_required "B2 bucket name"
  B2_BUCKET="$REPLY"
  ask_required "B2 application key id (scoped: read+write, NO delete)"
  B2_KEY_ID="$REPLY"
  ask_required "B2 application key"
  B2_APP_KEY="$REPLY"

  mkdir -p secrets
  AGE_KEY_FILE="secrets/${SERVER}-age.key"
  if [ ! -f "$AGE_KEY_FILE" ]; then
    age-keygen -o "$AGE_KEY_FILE" 2>/dev/null
    chmod 600 "$AGE_KEY_FILE"
  fi
  AGE_PUBLIC="$(grep -oE 'age1[0-9a-z]+' "$AGE_KEY_FILE" | head -1)"
  say "Generated age keypair. Public key: ${AGE_PUBLIC}"
  warn "PRIVATE key saved to ${AGE_KEY_FILE} - back it up OFFLINE (password"
  warn "manager / USB). Without it, backups are unrecoverable."
  [ "$MODE" = "local" ] && warn "You are on the server: MOVE ${AGE_KEY_FILE} OFF this machine after setup."
else
  warn "Backups skipped. Re-run this wizard or edit $HOSTVARS to enable later."
fi

# ---------------------------------------------------------------- paranoia
say "Paranoia level"
note "standard: SSH port open, rate-limited, with fail2ban"
note "high:     also installs fwknop (Single Packet Authorization)."
note "          In this version the SSH port stays visible in high mode."
note "          Hiding it behind a knock returns in a later release."
ask "Level: standard or high" "standard"
PARANOIA="$REPLY"
[ "$PARANOIA" = "standard" ] || [ "$PARANOIA" = "high" ] || die "Must be standard or high."
FWKNOP_KEY=""; FWKNOP_HMAC=""
if [ "$PARANOIA" = "high" ]; then
  FWKNOP_KEY="$(openssl rand -base64 32)"
  FWKNOP_HMAC="$(openssl rand -base64 64 | tr -d '\n')"
  warn "Before the first 'high' run, make sure you have provider console"
  warn "access (VNC) as break-glass. The knock client is not needed yet,"
  warn "because SSH stays visible. To get ready for later, see"
  warn "roles/04-fwknop/CLIENT-SIDE.md."
fi

# Local mode only: this machine's own addresses. Used only to refuse an
# office IP that is the server itself; never written anywhere.
is_own_ip() {  # $1 = address without /prefix
  local ip
  for ip in $(hostname -I 2>/dev/null || true) \
            $(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || true); do
    [ "$ip" = "$1" ] && return 0
  done
  return 1
}

OFFICE_IP=""
note "A break-glass IP is your office or home STATIC IP. It may always"
note "reach the SSH port without the rate limit, and fail2ban never bans it."
if confirm "Add a break-glass IP (recommended if you have a static IP)?"; then
  DETECTED_IP=""
  if [ "$MODE" = "remote" ]; then
    DETECTED_IP="$(curl -s --max-time 5 https://api.ipify.org || true)"
    # A network response is not trusted input: only offer it as the default
    # if it actually looks like an IP address.
    [[ "$DETECTED_IP" =~ ^[0-9a-fA-F:.]{2,45}$ ]] || DETECTED_IP=""
  else
    # On the server, "my public IP" is the server itself. Never offer it.
    note "Type the IP of your office or home, NOT this server's IP."
    FROM_IP="${SSH_CONNECTION:-}"; FROM_IP="${FROM_IP%% *}"
    if [[ "$FROM_IP" =~ ^[0-9a-fA-F:.]{2,45}$ ]]; then
      note "(Your SSH session comes from ${FROM_IP}. Type it only if that is"
      note "a static IP of yours.)"
    fi
  fi
  ask "Break-glass IP (your office/home static IP)" "${DETECTED_IP}"
  OFFICE_IP="$REPLY"
  [ -z "$OFFICE_IP" ] || [[ "$OFFICE_IP" =~ ^[0-9a-fA-F:.]{2,45}(/[0-9]{1,3})?$ ]] \
    || die "Not a valid IP address or CIDR: $OFFICE_IP"
  if [ "$MODE" = "local" ] && [ -n "$OFFICE_IP" ] && is_own_ip "${OFFICE_IP%/*}"; then
    die "${OFFICE_IP} is this server's own address. Use your office/home IP, or leave it empty."
  fi
fi

# ------------------------------------------------------------ egress lockdown
say "Egress lockdown (outbound firewall)"
note "Default-deny OUTBOUND traffic, allowing only DNS/NTP/HTTP/HTTPS."
note "Blocks the most common reverse shells (callbacks to random high"
note "ports). Can break apps that call external services on odd ports;"
note "you can add allowed ports later in host_vars (egress_allow_extra)."
EGRESS="false"
confirm "Enable egress lockdown?" n && EGRESS="true"

# ----------------------------------------------------------------- watcher
say "Detection suite"
note "Two robust detectors run automatically (in the mode you pick below):"
note "  - reverse-shell scanner (catches shells with a network socket, and"
note "    the app/service user spawning a shell - i.e. a web exploit)"
note "  - recon-burst detector (fires when a session runs many enumeration"
note "    commands fast - 'looking around', any entry vector)"
echo
note "There is also an EXPERIMENTAL SSH login-pattern watcher (a tripwire"
note "second factor). It is off by default because it can false-positive on"
note "automation (Ansible/CI). You can enable it below."
SSH_WATCHER="false"
if confirm "Enable the experimental SSH login-pattern watcher?" n; then
  SSH_WATCHER="true"
  note "Every interactive SSH login must run a secret command within a time"
  note "window, or it is treated as a breach. Pick something natural you"
  note "will actually type, and keep it secret (it is your duress signal)."
  ask "Secret pattern (substring of a command)" "cd /opt/app"
  WATCHER_PATTERN="$REPLY"
else
  WATCHER_PATTERN="cd /opt/app"
fi

# Response mode applies to ALL detectors.
say "Response mode (applies to every detector)"
ask "Mode: alert (notify only) or active (kill session/process + block IP)" "alert"
WATCHER_MODE="$REPLY"
[ "$WATCHER_MODE" = "alert" ] || [ "$WATCHER_MODE" = "active" ] || die "Must be alert or active."
if [ "$WATCHER_MODE" = "active" ]; then
  warn "active mode terminates offending sessions/processes and blocks IPs."
  warn "Run in alert mode for at least a week first to tune false positives."
fi

# ------------------------------------------------------------------- write
# yaml_str refuses newlines, but it runs inside $(...), where `die` only ends
# the subshell - the wizard would carry on and write an empty value. So check
# every value here, in the main shell, before anything is written. The usual
# source of a newline is a .pub file holding more than one key.
for v in ADMIN_USER AGE_PUBLIC APP_PORT APP_TYPE B2_APP_KEY B2_BUCKET \
         B2_KEY_ID CLIENT_NAME DB_ENGINE DB_NAME DB_PASSWORD DB_USER \
         DEPLOY_PUBKEY DOMAIN FWKNOP_HMAC FWKNOP_KEY LE_EMAIL NODE_VERSION \
         NOW_USER OFFICE_IP PARANOIA PASSWORD_AUTH PERMIT_ROOT SERVER_IP \
         SSH_KEY_FILE TG_CHAT TG_TOKEN WATCHER_MODE WATCHER_PATTERN; do
  case "${!v-}" in
    *$'\n'*|*$'\r'*) die "$v contains a newline; refusing to write $HOSTVARS. (A .pub file with several keys? Pick one.)" ;;
  esac
done

say "Writing ${HOSTVARS}"
{
  echo "---"
  echo "# Generated by scripts/configure.sh on $(date -u +%F)"
  echo "# This file contains secrets. It is gitignored - keep it that way."
  echo
  echo "client_name: $(yaml_str "${CLIENT_NAME}")"
  echo "client_domain: $(yaml_str "${DOMAIN}")"
  echo "letsencrypt_email: $(yaml_str "${LE_EMAIL}")"
  echo
  echo "paranoia_level: $(yaml_str "${PARANOIA}")"
  echo "office_static_ip: $(yaml_str "${OFFICE_IP}")"
  echo "egress_lockdown: ${EGRESS}"
  echo
  echo "# SSH login (role 02). Root login: keep | prohibit-password | 'no'."
  echo "# Password login: keep | 'no'. Always quote 'no': unquoted, YAML"
  echo "# reads it as false and preflight stops."
  echo "ssh_admin_user: $(yaml_str "${ADMIN_USER}")"
  echo "ssh_admin_public_keys:"
  echo "  - $(yaml_str "${DEPLOY_PUBKEY}")"
  echo "ssh_permit_root_login: $(yaml_str "${PERMIT_ROOT}")"
  echo "ssh_password_authentication: $(yaml_str "${PASSWORD_AUTH}")"
  echo
  echo "# Also added (never exclusively) for the deploy user."
  echo "deploy_ssh_public_key: $(yaml_str "${DEPLOY_PUBKEY}")"
  echo
  echo "app_type: $(yaml_str "${APP_TYPE}")"
  echo "app_dir: \"/opt/app\""
  echo "app_port: $(yaml_str "${APP_PORT}")"
  echo "node_version: $(yaml_str "${NODE_VERSION}")"
  if [ "$DB_ENGINE" != "none" ]; then
    echo
    echo "db_engine: $(yaml_str "${DB_ENGINE}")"
    echo "db_name: $(yaml_str "${DB_NAME}")"
    echo "db_user: $(yaml_str "${DB_USER}")"
    echo "db_password: $(yaml_str "${DB_PASSWORD}")"
  fi
  echo
  echo "telegram_bot_token: $(yaml_str "${TG_TOKEN}")"
  echo "telegram_chat_id: $(yaml_str "${TG_CHAT}")"
  if [ "$BACKUPS" = "1" ]; then
    echo
    echo "b2_bucket: $(yaml_str "${B2_BUCKET}")"
    echo "b2_key_id: $(yaml_str "${B2_KEY_ID}")"
    echo "b2_app_key: $(yaml_str "${B2_APP_KEY}")"
    echo "age_public_key: $(yaml_str "${AGE_PUBLIC}")"
  fi
  if [ "$PARANOIA" = "high" ]; then
    echo
    echo "fwknop_key: $(yaml_str "${FWKNOP_KEY}")"
    echo "fwknop_hmac_key: $(yaml_str "${FWKNOP_HMAC}")"
    echo "fwknop_open_seconds: 30"
  fi
  echo
  echo "watcher_pattern: $(yaml_str "${WATCHER_PATTERN}")"
  echo "watcher_mode: $(yaml_str "${WATCHER_MODE}")"
  echo "watcher_whitelist_ips: []"
  echo "ssh_pattern_watcher_enabled: ${SSH_WATCHER}"
} > "$HOSTVARS"
chmod 600 "$HOSTVARS"

say "Writing inventory/${SERVER}.yml"
{
  echo "---"
  echo "all:"
  echo "  children:"
  echo "    clients:"
  echo "      hosts:"
  echo "        ${SERVER}:"
  if [ "$MODE" = "local" ]; then
    echo "          ansible_host: 127.0.0.1"
    echo "          ansible_connection: local"
  else
    echo "          ansible_host: $(yaml_str "${SERVER_IP}")"
    echo "          ansible_user: $(yaml_str "${ADMIN_USER}")"
    echo "          ansible_ssh_private_key_file: $(yaml_str "${SSH_KEY_FILE}")"
  fi
} > "inventory/${SERVER}.yml"

# -------------------------------------------------------------------- next
# What the run will do to SSH logins, in plain words.
describe_rules() {
  note "SSH login rules once your choices are applied:"
  if [ "$MODE" = "local" ]; then
    note "  - You log in as ${ADMIN_USER}, with your laptop key."
  else
    note "  - You and Ansible log in as ${ADMIN_USER}, with your key."
  fi
  case "$PERMIT_ROOT" in
    keep) note "  - Root login: not changed. It stays as the server has it now." ;;
    prohibit-password) note "  - Root login: with a key only. Root passwords stop working over SSH." ;;
    no) note "  - Root login over SSH: off." ;;
  esac
  case "$PASSWORD_AUTH" in
    keep) note "  - Password login: not changed. It stays as the server has it now." ;;
    no) note "  - Password login: off for every account. Only keys work." ;;
  esac
  if [ "$PERMIT_ROOT" = "keep" ] || [ "$PASSWORD_AUTH" = "keep" ]; then
    note "  The run prints the real values. While root or password login is"
    note "  still on, it says 'SSH login NOT hardened'. That is expected in"
    note "  this first stage."
  fi
  if [ "$MODE" = "remote" ]; then
    note "  If an SSH change locks Ansible out, it is undone by itself within"
    note "  5 minutes. Do not reboot or edit /etc/ssh while a run is going."
  fi
}

# Local mode only: today's effective values. Display only, never written.
show_current_rules() {
  local out line
  if [ "$(id -u)" != "0" ] || [ ! -x /usr/sbin/sshd ]; then return 0; fi
  out="$(/usr/sbin/sshd -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication) ' || true)"
  [ -n "$out" ] || return 0
  note "This server allows today (from sshd -T):"
  while IFS= read -r line; do note "  ${line}"; done <<<"$out"
}

echo
echo "===================================================================="
say "Configuration complete."
echo
# RUN_CMD is eval'd below. It is built only from the validated server name
# and the validated login user name.
if [ "$MODE" = "local" ]; then
  RUN_CMD="sudo ansible-playbook -i inventory site.yml -l ${SERVER}"
  note "Harden this server now with:"
  note "  ${RUN_CMD}"
  note "To preview the SSH part first (it writes no config files), add:"
  note "  --check --diff --tags ssh"
  echo
  show_current_rules
  describe_rules
  echo
  note "On the server itself, auto_sec only applies SSH settings that change"
  note "nothing. To tighten logins later, run auto_sec from your own computer."
  note "After the run, test your laptop key from a NEW terminal on your laptop:"
  note "  ssh ${ADMIN_USER}@<this server's IP>"
else
  BASE_CMD="ansible-playbook -i inventory site.yml -l ${SERVER}"
  RUN_CMD="${BASE_CMD}"
  [ "$NOW_USER" = "$ADMIN_USER" ] || RUN_CMD="${BASE_CMD} -e ansible_user=${NOW_USER}"
  note "Step 1. Connect once by hand. This records the server's host key"
  note "and puts your key on the account you use today:"
  note "  ssh-copy-id -i ${SSH_KEY_FILE}.pub ${NOW_USER}@${SERVER_IP}"
  note "  (Type the password if asked. If the key is already there, it adds nothing.)"
  note ""
  note "Step 2. See what the SSH part would change. This writes no config files:"
  note "  ${RUN_CMD} --check --diff --tags ssh"
  note "  (A full --check stops at the firewall role on a new server: ufw and"
  note "  fail2ban are not installed yet. The real run installs them.)"
  note ""
  note "Step 3. The real run:"
  note "  ${RUN_CMD}"
  if [ "$NOW_USER" != "$ADMIN_USER" ]; then
    note ""
    note "This first run logs in as ${NOW_USER}, because ${ADMIN_USER} does not"
    note "exist yet or has no key. '-e ansible_user=${NOW_USER}' makes Ansible use"
    note "${NOW_USER}. ('-u ${NOW_USER}' would not work: the inventory wins over -u.)"
    note "Stricter login rules wait until Ansible logs in as ${ADMIN_USER}."
    note "So run a SECOND time, without -e. It logs in as ${ADMIN_USER} with your key:"
    note "  ${BASE_CMD}"
  fi
  note ""
  note "Later runs:"
  note "  ${BASE_CMD}"
  echo
  describe_rules
  echo
  note "Connect with:"
  note "  ssh -i ${SSH_KEY_FILE} ${ADMIN_USER}@${SERVER_IP}"
fi
echo
note "Is this server already in production? Then run only the SSH part for"
note "now: add --tags ssh. A full run still overwrites jail.local, turns on"
note "automatic reboots and changes the hostname (issues #2, #3, #7)."
note "Do not put the full playbook in cron."
echo
if confirm "Run the playbook now?" n; then
  eval "$RUN_CMD"
fi
