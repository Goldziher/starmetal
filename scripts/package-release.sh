#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <target-triple>" >&2
  exit 1
fi

TRIPLE="$1"

case "$TRIPLE" in
x86_64-unknown-linux-gnu | aarch64-unknown-linux-gnu | x86_64-apple-darwin | aarch64-apple-darwin)
  BINEXT=""
  ARCHIVE="starmetal-${TRIPLE}.tar.gz"
  ;;
x86_64-pc-windows-msvc)
  BINEXT=".exe"
  ARCHIVE="starmetal-${TRIPLE}.zip"
  ;;
*)
  echo "Unknown target triple: $TRIPLE" >&2
  exit 1
  ;;
esac

RELEASE_DIR="target/${TRIPLE}/release"
BINARY_PATH="${RELEASE_DIR}/sm${BINEXT}"

if [[ ! -f "$BINARY_PATH" ]]; then
  echo "Binary not found at $BINARY_PATH" >&2
  exit 1
fi

STAGING_DIR="$(mktemp -d "starmetal-${TRIPLE}.XXXXXX")"
cleanup() {
  rm -rf "$STAGING_DIR"
}
trap cleanup EXIT

cp "$BINARY_PATH" "$STAGING_DIR/sm${BINEXT}"

if [[ "$TRIPLE" == *-apple-darwin ]]; then
  codesign --force --sign - "$STAGING_DIR/sm${BINEXT}"
fi

case "$ARCHIVE" in
*.tar.gz)
  tar czf "$ARCHIVE" -C "$STAGING_DIR" .
  ;;
*.zip)
  if command -v 7z >/dev/null 2>&1; then
    (cd "$STAGING_DIR" && 7z a -tzip "../$ARCHIVE" . >/dev/null)
  elif command -v zip >/dev/null 2>&1; then
    (cd "$STAGING_DIR" && zip -q -r "../$ARCHIVE" .)
  elif command -v powershell >/dev/null 2>&1; then
    (cd "$STAGING_DIR" &&
      powershell -NoProfile -Command \
        "Compress-Archive -Path '*' -DestinationPath '../$ARCHIVE' -Force")
  elif command -v pwsh >/dev/null 2>&1; then
    (cd "$STAGING_DIR" &&
      pwsh -NoProfile -Command \
        "Compress-Archive -Path '*' -DestinationPath '../$ARCHIVE' -Force")
  else
    echo "No zip tool available" >&2
    exit 1
  fi
  ;;
esac

echo "Created $ARCHIVE"
