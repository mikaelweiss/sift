#!/usr/bin/env bash
# Bumps the version, tags it, and pushes. The tag triggers the release workflow.
set -euo pipefail

VERSION="${1:?usage: release.sh <version, e.g. 0.2.0>}"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SPEC="$ROOT_DIR/macos/project.yml"

if [ "$(git -C "$ROOT_DIR" branch --show-current)" != "main" ]; then
  echo "Release from main." >&2
  exit 1
fi
if [ -n "$(git -C "$ROOT_DIR" status --porcelain)" ]; then
  echo "Commit or stash your changes first." >&2
  exit 1
fi

BUILD=$(( $(awk '/CURRENT_PROJECT_VERSION:/ {gsub(/"/, "", $2); print $2}' "$SPEC") + 1 ))
sed -i '' -E "s/(MARKETING_VERSION: )\"[^\"]*\"/\1\"$VERSION\"/" "$SPEC"
sed -i '' -E "s/(CURRENT_PROJECT_VERSION: )\"[^\"]*\"/\1\"$BUILD\"/" "$SPEC"
xcodegen generate --spec "$SPEC" --quiet

git -C "$ROOT_DIR" add macos
git -C "$ROOT_DIR" commit -m "chore: release v$VERSION"
git -C "$ROOT_DIR" tag "v$VERSION"
git -C "$ROOT_DIR" push origin main "v$VERSION"
