#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-0.0.1}"
GHCR_REGISTRY="${GHCR_REGISTRY:-ghcr.io}"
GHCR_OWNER="${GHCR_OWNER:-goldziher}"
IMAGE_NAME="${IMAGE_NAME:-starmetal}"
MODE="dry-run"

usage() {
  cat <<'USAGE'
Usage: scripts/publish-docker-ghcr.sh [--dry-run|--push]

Builds the StarMetal Docker image and optionally pushes it to GitHub Container Registry.

Optional:
  VERSION=0.0.1
  GHCR_REGISTRY=ghcr.io
  GHCR_OWNER=goldziher
  IMAGE_NAME=starmetal
  DOCKER_IMAGE=ghcr.io/goldziher/starmetal
  GHCR_USERNAME=<github-user>
  GHCR_TOKEN=<token-with-package-write>
USAGE
}

for arg in "$@"; do
  case "$arg" in
  --dry-run) MODE="dry-run" ;;
  --push) MODE="push" ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    echo "unknown argument: $arg" >&2
    usage >&2
    exit 2
    ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${DOCKER_IMAGE:-}" ]]; then
  DOCKER_IMAGE="${GHCR_REGISTRY}/${GHCR_OWNER,,}/${IMAGE_NAME}"
fi

cd "$REPO_ROOT"

docker build --tag "${DOCKER_IMAGE}:${VERSION}" --tag "${DOCKER_IMAGE}:latest" .
docker run --rm "${DOCKER_IMAGE}:${VERSION}" --version
docker run --rm "${DOCKER_IMAGE}:${VERSION}" config validate

if [[ "$MODE" == "dry-run" ]]; then
  echo "dry-run complete; not pushing ${DOCKER_IMAGE}:${VERSION}"
  exit 0
fi

registry_host="${DOCKER_IMAGE%%/*}"
username="${GHCR_USERNAME:-${GITHUB_ACTOR:-}}"
token="${GHCR_TOKEN:-${GITHUB_TOKEN:-}}"
if [[ -n "$username" && -n "$token" ]]; then
  printf %s "$token" | docker login "$registry_host" --username "$username" --password-stdin
else
  echo "GHCR_USERNAME/GHCR_TOKEN not set; assuming docker is already logged in to ${registry_host}"
fi

docker push "${DOCKER_IMAGE}:${VERSION}"
docker push "${DOCKER_IMAGE}:latest"
