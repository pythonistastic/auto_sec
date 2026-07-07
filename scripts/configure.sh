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
  ask "Path to YOUR private SSH key for this server" "$HOME/.ssh/id_ed25519"
  SSH_KEY_FILE="$REPLY"
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
note "The playbook creates a 'deploy' user and installs ONE public key"
note "for it (password logins and root logins are disabled)."
DEPLOY_PUBKEY=""
if [ "$MODE" = "local" ]; then
  note "Paste the public key of the machine you will SSH in FROM"
  note "(your laptop), e.g. the contents of ~/.ssh/id_ed25519.pub there."
  ask_required "Public key"
  DEPLOY_PUBKEY="$REPLY"
else
  DEFAULT_PUB="${SSH_KEY_FILE}.pub"
  ask "Path to the PUBLIC key to install for the deploy user" "$DEFAULT_PUB"
  PUB_PATH="${REPLY/#\~/$HOME}"
  [ -f "$PUB_PATH" ] || die "File not found: $PUB_PATH"
  DEPLOY_PUBKEY="$(cat "$PUB_PATH")"
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

# ----------------------------------------------------------------- watcher
say "Behavioral login watcher"
note "Every interactive SSH login must run a secret command within a time"
note "window, or it is treated as a breach. Pick something natural you"
note "will actually type, and keep it secret (it is your duress signal)."
ask "Secret pattern (substring of a command)" "cd /opt/app"
WATCHER_PATTERN="$REPLY"
ask "Watcher mode: alert (notify only) or active (kill session + block IP)" "alert"
WATCHER_MODE="$REPLY"
[ "$WATCHER_MODE" = "alert" ] || [ "$WATCHER_MODE" = "active" ] || die "Must be alert or active."
if [ "$WATCHER_MODE" = "active" ]; then
  warn "active mode will terminate sessions that miss the pattern."
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
  note "First run on a fresh VPS (as root):"
  note "  ${RUN_CMD}"
  note "Subsequent runs (deploy user):"
  note "  ansible-playbook -i inventory site.yml -l ${SERVER}"
fi
echo
note "Re-running is always safe: the playbook is idempotent and"
note "self-corrects drift. Add it to cron for continuous enforcement."
echo
if confirm "Run the playbook now?" n; then
  eval "$RUN_CMD"
fi
