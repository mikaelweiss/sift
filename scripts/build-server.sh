#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SERVER_DIR="$ROOT_DIR/server"
OUT_DIR="$ROOT_DIR/macos/Sift/Resources/Binaries"
VERSION="${SIFT_VERSION:-0.1.10}"

mkdir -p "$OUT_DIR"

targets=(
  "darwin arm64"
  "darwin amd64"
  "linux amd64"
  "linux arm64"
)

for target in "${targets[@]}"; do
  read -r goos goarch <<< "$target"
  out="$OUT_DIR/sift-${goos}-${goarch}"
  echo "Building $out (version $VERSION)..."
  (
    cd "$SERVER_DIR"
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
      go build -trimpath -ldflags "-s -w -X main.Version=${VERSION}" \
      -o "$out" ./cmd/sift
  )
done

echo "Built all sift server binaries in $OUT_DIR"
