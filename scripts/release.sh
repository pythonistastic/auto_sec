#!/usr/bin/env bash
#
# release.sh - cut a new auto_sec release in one command.
#
#   ./scripts/release.sh patch      # 0.1.0 -> 0.1.1
#   ./scripts/release.sh minor      # 0.1.0 -> 0.2.0
#   ./scripts/release.sh major      # 0.1.0 -> 1.0.0
#   ./scripts/release.sh 0.3.0      # explicit version
#
# It bumps VERSION, rolls the CHANGELOG "[Unreleased]" section into the
# new version (dated), updates the README badge and changelog footer
# links, commits, and creates an annotated git tag. It does NOT push -
# it prints the exact push command so you can review first.
#
# Portable: POSIX-ish bash + awk/sed, no GNU-only flags (works on Linux
# and macOS).
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# Portable in-place edit (avoids GNU vs BSD `sed -i` differences).
inplace() { local f="$1"; shift; local t; t="$(mktemp)"; sed "$@" "$f" >"$t" && mv "$t" "$f"; }

[ -f VERSION ] || die "VERSION file not found - run from the repo."
[ -f CHANGELOG.md ] || die "CHANGELOG.md not found."
command -v git >/dev/null || die "git is required."

# Refuse to run on a dirty tree: the release commit must contain only the
# version bump, and we don't want to sweep in unrelated changes.
if [ -n "$(git status --porcelain)" ]; then
  die "Working tree is not clean. Commit or stash your changes first."
fi

[ "$#" -eq 1 ] || die "usage: release.sh <patch|minor|major|X.Y.Z>"
CUR="$(tr -d '[:space:]' < VERSION)"
echo "$CUR" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || die "VERSION ('$CUR') is not X.Y.Z"
IFS='.' read -r MA MI PA <<EOF
$CUR
EOF

case "$1" in
  patch) NEW="${MA}.${MI}.$((PA + 1))" ;;
  minor) NEW="${MA}.$((MI + 1)).0" ;;
  major) NEW="$((MA + 1)).0.0" ;;
  [0-9]*.[0-9]*.[0-9]*)
    echo "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || die "bad version: $1"
    NEW="$1" ;;
  *) die "usage: release.sh <patch|minor|major|X.Y.Z>" ;;
esac
[ "$NEW" != "$CUR" ] || die "new version equals current ($CUR)."

DATE="$(date +%F)"
TAG="v${NEW}"
git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null && die "tag ${TAG} already exists."

# Repo slug for changelog links (fallback to the known repo).
REMOTE="$(git remote get-url origin 2>/dev/null || echo '')"
SLUG="$(printf '%s' "$REMOTE" | sed -E 's#(git@github.com:|https://github.com/)##; s#\.git$##')"
[ -n "$SLUG" ] || SLUG="pythonistastic/auto_sec"
BASE="https://github.com/${SLUG}"

say "Releasing ${CUR} -> ${NEW}  (tag ${TAG}, ${DATE})"

# Warn if there's nothing under [Unreleased].
UNREL="$(awk '/^## \[Unreleased\]/{f=1;next} /^## \[/{f=0} f' CHANGELOG.md \
         | grep -vE '^\s*$' | grep -vE '^_Nothing yet\._$' || true)"
[ -n "$UNREL" ] || note "Note: [Unreleased] is empty - the new section will have no entries."

# 1) VERSION
printf '%s\n' "$NEW" > VERSION

# 2) README badge + "Version X.Y.Z" line (if present)
if [ -f README.md ]; then
  inplace README.md -E "s#version-[0-9]+\.[0-9]+\.[0-9]+-blue#version-${NEW}-blue#g"
  inplace README.md -E "s/\*\*Version [0-9]+\.[0-9]+\.[0-9]+\*\*/**Version ${NEW}**/g"
fi

# 3) CHANGELOG: move [Unreleased] body under a new dated version section,
#    reset [Unreleased], then fix the footer links.
awk -v ver="$NEW" -v date="$DATE" '
  /^## \[Unreleased\]/ {
    print "## [Unreleased]"; print ""; print "_Nothing yet._"; print "";
    print "## [" ver "] - " date;
    inrel = 1; next
  }
  inrel && /^## \[/ { inrel = 0 }          # next version header ends the block
  inrel && /^_Nothing yet\._$/ { next }    # drop the old placeholder
  { print }
' CHANGELOG.md > CHANGELOG.tmp && mv CHANGELOG.tmp CHANGELOG.md

awk -v ver="$NEW" -v base="$BASE" '
  /^\[Unreleased\]:/ {
    print "[Unreleased]: " base "/compare/v" ver "...HEAD"
    print "[" ver "]: " base "/releases/tag/v" ver
    next
  }
  { print }
' CHANGELOG.md > CHANGELOG.tmp && mv CHANGELOG.tmp CHANGELOG.md

say "Updated VERSION, README badge, and CHANGELOG. Review the diff:"
git --no-pager diff --stat

printf '\nCommit and tag %s now? [y/N]: ' "$TAG"
read -r ans
case "$ans" in
  y|Y|yes|YES) ;;
  *) die "Aborted. Files were changed but nothing was committed - 'git checkout .' to undo." ;;
esac

git add VERSION CHANGELOG.md README.md
git commit -q -m "Release ${TAG}"
git tag -a "${TAG}" -m "auto_sec ${TAG}"

say "Done. Tag ${TAG} created locally."
note "Review, then publish with:"
note "  git push origin main --tags"
note "Then draft a GitHub Release from tag ${TAG} (paste the ${NEW} changelog section)."
