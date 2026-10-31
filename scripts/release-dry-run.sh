#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 <version-or-tag> [ref]" >&2
  echo "Example: $0 0.1.0 main" >&2
  exit 1
fi

VERSION_OR_TAG="$1"
REF="${2:-main}"
TAG="$VERSION_OR_TAG"
if [[ "$TAG" != v* ]]; then
  TAG="v$TAG"
fi

gh workflow run publish.yaml -f "tag=$TAG" -f "ref=$REF" -f dry_run=true
gh workflow run publish-docker.yaml -f "tag=$TAG" -f "ref=$REF" -f dry_run=true

echo "Started dry-run workflows for $TAG at ref $REF"
echo "Monitor with: gh run list --workflow publish.yaml --limit 5"
echo "Monitor Docker with: gh run list --workflow publish-docker.yaml --limit 5"
