#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-0.0.1}"
GCP_REGION="${GCP_REGION:-us-central1}"
GCP_ARTIFACT_REGISTRY_REPOSITORY="${GCP_ARTIFACT_REGISTRY_REPOSITORY:-starmetal}"
IMAGE_NAME="${IMAGE_NAME:-starmetal}"
MODE="dry-run"

usage() {
  cat <<'USAGE'
Usage: scripts/publish-docker-gcr.sh [--dry-run|--push]

Builds the StarMetal Docker image and optionally pushes it to GCP Artifact Registry.

Required for --push unless DOCKER_IMAGE is set:
  GCP_PROJECT_ID

Optional:
  VERSION=0.0.1
  GCP_REGION=us-central1
  GCP_ARTIFACT_REGISTRY_REPOSITORY=starmetal
  IMAGE_NAME=starmetal
  DOCKER_IMAGE=us-central1-docker.pkg.dev/<project>/<repo>/starmetal
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
  if [[ -n "${GCP_PROJECT_ID:-}" ]]; then
    DOCKER_IMAGE="${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/${GCP_ARTIFACT_REGISTRY_REPOSITORY}/${IMAGE_NAME}"
  elif [[ "$MODE" == "dry-run" ]]; then
    DOCKER_IMAGE="$IMAGE_NAME"
  else
    echo "GCP_PROJECT_ID is required for --push when DOCKER_IMAGE is not set" >&2
    exit 1
  fi
fi

cd "$REPO_ROOT"

docker build --tag "${DOCKER_IMAGE}:${VERSION}" --tag "${DOCKER_IMAGE}:latest" .
docker run --rm "${DOCKER_IMAGE}:${VERSION}" --version
docker run --rm "${DOCKER_IMAGE}:${VERSION}" config validate

if [[ "$MODE" == "dry-run" ]]; then
  echo "dry-run complete; not pushing ${DOCKER_IMAGE}:${VERSION}"
  exit 0
fi

if command -v gcloud >/dev/null 2>&1; then
  registry_host="${DOCKER_IMAGE%%/*}"
  gcloud auth configure-docker "$registry_host" --quiet
fi

docker push "${DOCKER_IMAGE}:${VERSION}"
docker push "${DOCKER_IMAGE}:latest"
