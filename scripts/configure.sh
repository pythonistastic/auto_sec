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
echo "===================================================================="
echo " secure-deploy configuration wizard"
echo " Answers are written to host_vars/<server>.yml (gitignored)."
echo "===================================================================="
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
fi

# ------------------------------------------------------------- identity
say "Basics"
ask_required "Organization / client name (for the report)" "My Company"
CLIENT_NAME="$REPLY"
ask_required "App domain (e.g. app.example.com)"
DOMAIN="$REPLY"
ask_required "Email for Let's Encrypt TLS registration"
LE_EMAIL="$REPLY"

# ---------------------------------------------------------------- deploy key
say "SSH access"
note "New to SSH keys? Here is all you need to know:"
note "  A key comes in a PAIR - a PRIVATE key that stays secret on your"
note "  computer, and a PUBLIC key that is safe to share and gets installed"
note "  on the server. You log in by proving you hold the private key. This"
note "  is far safer than a password, so the playbook turns passwords OFF."
note "The playbook creates a 'deploy' user and installs your PUBLIC key."
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
fi

# --------------------------------------------------------------------- app
say "Application runtime"
ask "App type: node or docker" "node"
APP_TYPE="$REPLY"
[ "$APP_TYPE" = "node" ] || [ "$APP_TYPE" = "docker" ] || die "Must be node or docker."
ask "App listen port (Nginx proxies to it)" "3000"
APP_PORT="$REPLY"
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
note "Create a bot with @BotFather, then message it once and get your"
note "chat id from https://api.telegram.org/bot<TOKEN>/getUpdates"
ask "Telegram bot token (empty to skip alerts for now)" ""
TG_TOKEN="$REPLY"
TG_CHAT=""
if [ -n "$TG_TOKEN" ]; then
  ask_required "Telegram chat id"
  TG_CHAT="$REPLY"
  if confirm "Send a test message now?"; then
    if curl -s -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
        -d chat_id="${TG_CHAT}" -d text="secure-deploy wizard: test OK for ${SERVER}" \
        | grep -q '"ok":true'; then
      say "Test message delivered."
    else
      warn "Telegram test failed. Check token/chat id (you can edit $HOSTVARS later)."
    fi
  fi
else
  warn "Alerts disabled. The detection layers lose most of their value without them."
  TG_TOKEN="CHANGE_ME"; TG_CHAT="CHANGE_ME"
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
note "standard: SSH port open (rate-limited, keys only)"
note "high:     SSH port INVISIBLE until a valid fwknop knock packet (SPA)"
ask "Level: standard or high" "standard"
PARANOIA="$REPLY"
[ "$PARANOIA" = "standard" ] || [ "$PARANOIA" = "high" ] || die "Must be standard or high."
FWKNOP_KEY=""; FWKNOP_HMAC=""
if [ "$PARANOIA" = "high" ]; then
  FWKNOP_KEY="$(openssl rand -base64 32)"
  FWKNOP_HMAC="$(openssl rand -base64 64 | tr -d '\n')"
  warn "Before the first 'high' run, make sure you have provider console"
  warn "access (VNC) as break-glass. See roles/04-fwknop/CLIENT-SIDE.md"
  warn "for setting up the knock client on your machine."
fi

OFFICE_IP=""
if confirm "Keep a break-glass IP allowed on the SSH port (recommended)?"; then
  DETECTED_IP="$(curl -s --max-time 5 https://api.ipify.org || true)"
  ask "Break-glass IP (your office/home static IP)" "${DETECTED_IP}"
  OFFICE_IP="$REPLY"
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
say "Writing ${HOSTVARS}"
{
  echo "---"
  echo "# Generated by scripts/configure.sh on $(date -u +%F)"
  echo "# This file contains secrets. It is gitignored - keep it that way."
  echo
  echo "client_name: \"${CLIENT_NAME}\""
  echo "client_domain: \"${DOMAIN}\""
  echo "letsencrypt_email: \"${LE_EMAIL}\""
  echo
  echo "paranoia_level: \"${PARANOIA}\""
  echo "office_static_ip: \"${OFFICE_IP}\""
  echo "egress_lockdown: ${EGRESS}"
  echo
  echo "deploy_ssh_public_key: \"${DEPLOY_PUBKEY}\""
  echo
  echo "app_type: \"${APP_TYPE}\""
  echo "app_dir: \"/opt/app\""
  echo "app_port: ${APP_PORT}"
  echo "node_version: \"${NODE_VERSION}\""
  if [ "$DB_ENGINE" != "none" ]; then
    echo
    echo "db_engine: \"${DB_ENGINE}\""
    echo "db_name: \"${DB_NAME}\""
    echo "db_user: \"${DB_USER}\""
    echo "db_password: \"${DB_PASSWORD}\""
  fi
  echo
  echo "telegram_bot_token: \"${TG_TOKEN}\""
  echo "telegram_chat_id: \"${TG_CHAT}\""
  if [ "$BACKUPS" = "1" ]; then
    echo
    echo "b2_bucket: \"${B2_BUCKET}\""
    echo "b2_key_id: \"${B2_KEY_ID}\""
    echo "b2_app_key: \"${B2_APP_KEY}\""
    echo "age_public_key: \"${AGE_PUBLIC}\""
  fi
  if [ "$PARANOIA" = "high" ]; then
    echo
    echo "fwknop_key: \"${FWKNOP_KEY}\""
    echo "fwknop_hmac_key: \"${FWKNOP_HMAC}\""
    echo "fwknop_open_seconds: 30"
  fi
  echo
  echo "watcher_pattern: \"${WATCHER_PATTERN}\""
  echo "watcher_mode: \"${WATCHER_MODE}\""
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
    echo "          ansible_host: ${SERVER_IP}"
    echo "          ansible_user: deploy"
    echo "          ansible_ssh_private_key_file: ${SSH_KEY_FILE}"
  fi
} > "inventory/${SERVER}.yml"

# -------------------------------------------------------------------- next
echo
echo "===================================================================="
say "Configuration complete."
echo
if [ "$MODE" = "local" ]; then
  RUN_CMD="sudo ansible-playbook -i inventory site.yml -l ${SERVER}"
  note "Harden this server now with:"
  note "  ${RUN_CMD}"
else
  RUN_CMD="ansible-playbook -i inventory site.yml -l ${SERVER} -u root"
  note "First run on a fresh VPS (connects as root):"
  note "  ${RUN_CMD}"
  note "If your provider gave you a ROOT PASSWORD (not a key), add"
  note "--ask-pass so Ansible can log in the first time (needs 'sshpass'):"
  note "  ${RUN_CMD} --ask-pass"
  note ""
  note "Subsequent runs use the deploy user + your key automatically:"
  note "  ansible-playbook -i inventory site.yml -l ${SERVER}"
  note ""
  note "After hardening, passwords and root login are OFF. Connect with:"
  note "  ssh -i ${SSH_KEY_FILE} deploy@${SERVER_IP}"
fi
echo
note "Re-running is always safe: the playbook is idempotent and"
note "self-corrects drift. Add it to cron for continuous enforcement."
echo
if confirm "Run the playbook now?" n; then
  eval "$RUN_CMD"
fi
