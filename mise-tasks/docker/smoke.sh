#!/usr/bin/env bash
#MISE description="Build the image and smoke-test CLI and API container modes"
#MISE depends=["docker:build"]
set -euo pipefail

docker run --rm starmetal:local --version
docker run --rm starmetal:local config validate

container_id="$(docker run --rm --detach --publish 127.0.0.1::8080 starmetal:local)"
cleanup() {
  docker logs "$container_id" >/dev/null 2>&1 || true
  docker rm --force "$container_id" >/dev/null 2>&1 || true
}
trap cleanup EXIT
port="$(docker port "$container_id" 8080/tcp | awk -F: '{print $NF}')"
for _ in $(seq 1 30); do
  if curl --fail --silent --show-error --output /dev/null "http://127.0.0.1:${port}/healthz"; then
    exit 0
  fi
  sleep 1
done
docker logs "$container_id"
exit 1
