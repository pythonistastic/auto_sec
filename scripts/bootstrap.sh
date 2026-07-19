#!/usr/bin/env bash
# One-command bootstrap for secure-deploy.
#
# On your workstation (managing a remote server) or directly on a fresh
# Ubuntu/Debian server (self-host mode):
#
#   git clone https://github.com/pythonistastic/auto_sec.git
#   cd auto_sec && ./scripts/bootstrap.sh
#
# Installs Ansible + required tools, pulls the Galaxy collections,
# then hands off to the interactive configuration wizard.
set -euo pipefail

REPO_URL="${SECURE_DEPLOY_REPO:-https://github.com/pythonistastic/auto_sec.git}"

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARNING:\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- locate repo
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${SCRIPT_DIR}/../site.yml" ]; then
  REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
else
  # Running standalone (e.g. curl | bash): clone the repo first.
  REPO_DIR="${HOME}/auto_sec"
  if [ ! -d "${REPO_DIR}" ]; then
    say "Cloning ${REPO_URL} into ${REPO_DIR}"
    git clone "${REPO_URL}" "${REPO_DIR}" 2>/dev/null \
      || die "git clone failed. Install git or clone manually, then re-run."
  fi
fi
cd "${REPO_DIR}"

# ------------------------------------------------------------- prerequisites
if ! command -v apt-get >/dev/null 2>&1; then
  warn "Non-apt system detected. Install manually: ansible, git, age, openssl, curl."
else
  say "Installing prerequisites (ansible, git, age, curl, openssl)"
  MISSING=()
  for pkg in ansible git age curl openssl; do
    command -v "$pkg" >/dev/null 2>&1 || MISSING+=("$pkg")
  done
  if [ "${#MISSING[@]}" -gt 0 ]; then
    SUDO=""
    [ "$(id -u)" -ne 0 ] && SUDO="sudo"
    $SUDO apt-get update -qq
    $SUDO apt-get install -y -qq "${MISSING[@]}" \
      || die "Package install failed: ${MISSING[*]}"
  fi
fi

command -v ansible-playbook >/dev/null 2>&1 || die "ansible-playbook not found after install."

say "Installing Ansible Galaxy collections"
ansible-galaxy collection install -r requirements.yml >/dev/null

# ------------------------------------------------------------------- wizard
say "Starting the configuration wizard"
bash "${REPO_DIR}/scripts/configure.sh"
