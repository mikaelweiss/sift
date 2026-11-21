#!/usr/bin/env bash
# Publishes site/ to the gh-pages branch, which GitHub Pages serves at
# sift.weisssolutions.org. appcast.xml lives only on gh-pages so release
# history survives site edits. Set the APPCAST_* variables to add a release.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PAGES_DIR="${RUNNER_TEMP:-$(mktemp -d)}/gh-pages"
MESSAGE="${1:?usage: publish-site.sh <commit message>}"

if git -C "$ROOT_DIR" ls-remote --exit-code --heads origin gh-pages > /dev/null; then
  git -C "$ROOT_DIR" fetch --depth 1 origin gh-pages
  git -C "$ROOT_DIR" worktree add -B gh-pages "$PAGES_DIR" FETCH_HEAD
else
  git -C "$ROOT_DIR" worktree add --orphan -b gh-pages "$PAGES_DIR"
fi

rsync -a --delete --exclude .git --exclude appcast.xml "$ROOT_DIR/site/" "$PAGES_DIR/"

if [ -n "${APPCAST_VERSION:-}" ]; then
  python3 "$ROOT_DIR/scripts/append-appcast.py" "$PAGES_DIR/appcast.xml"
fi

git -C "$PAGES_DIR" add -A
if git -C "$PAGES_DIR" diff --cached --quiet; then
  echo "gh-pages is already up to date"
  exit 0
fi
git -C "$PAGES_DIR" -c user.name="github-actions[bot]" \
  -c user.email="github-actions[bot]@users.noreply.github.com" \
  commit -m "$MESSAGE"
git -C "$PAGES_DIR" push origin gh-pages
