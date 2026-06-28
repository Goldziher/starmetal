#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <version-or-tag>" >&2
  echo "Example: $0 0.1.0" >&2
  exit 1
fi

VERSION="${1#v}"
TAG="v$VERSION"

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree is dirty; commit changes before tagging $TAG." >&2
  exit 1
fi

current_version="$(grep -E '^\[workspace\.package\]' -A3 Cargo.toml | grep -E '^version = ' | head -1 | cut -d'"' -f2)"
if [[ "$current_version" != "$VERSION" ]]; then
  echo "Cargo workspace version is $current_version, expected $VERSION." >&2
  echo "Run: task release:sync-version VERSION=$VERSION" >&2
  exit 1
fi

git fetch origin main --tags
git tag -a "$TAG" -m "$TAG"
git push origin main "$TAG"

echo "Pushed $TAG. Package and Docker workflows will publish from the tag."
