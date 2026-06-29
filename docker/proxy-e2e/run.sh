#!/usr/bin/env bash
set -Eeuo pipefail

mode="http"
case "${1:---http}" in
--http) mode="http" ;;
--native)
  mode="native"
  ;;
--pnpm)
  mode="pnpm"
  ;;
--live)
  mode="live"
  ;;
-h | --help)
  cat <<'USAGE'
Usage: docker/proxy-e2e/run.sh [--http|--native|--pnpm|--live]

Runs deterministic Docker-based StarMetal proxy E2E tests:
  - builds starmetal:local from the current checkout
  - starts a local fixture upstream and StarMetal on an isolated Docker network
  - exercises proxy routes with HTTP assertions or native client containers
  - restarts StarMetal with the same OpenDAL filesystem volume
  - repeats the route checks with the fixture upstream stopped

Environment:
  STARMETAL_PROXY_IMAGE       Image tag to build and test (default: starmetal:local)
  PYTHON_IMAGE                Python client/upstream image (default: python:3.12-slim)
  INSPECT_IMAGE               Volume inspection image (default: cgr.dev/chainguard/busybox:latest)
  NODE_IMAGE                  npm client image (default: node:22-slim)
  RUST_CLIENT_IMAGE           Cargo client image (default: rust:1-slim)
  MAVEN_IMAGE                 Maven client image (default: maven:3.9-eclipse-temurin-21)
  RUBY_IMAGE                  RubyGems/Bundler client image (default: ruby:3.3-slim)
  DOTNET_IMAGE                NuGet client image (default: mcr.microsoft.com/dotnet/sdk:8.0)
  DART_IMAGE                  pub.dev client image (default: dart:stable)
  PNPM_IMAGE                  pnpm base image (default: ghcr.io/pnpm/pnpm:11)
  PNPM_NODE_VERSION           Node.js version installed into pnpm client image (default: 22)
  STARMETAL_PNPM_PUBLISH_TOKEN npm publish token for --pnpm mode (default: pnpm-publish-token)
  KEEP_DOCKER_PROXY_E2E=1     Keep containers/network/volume/tempdir for debugging
  SM_PROXY_E2E_ARTIFACTS      Directory for logs and stored-file listings

Notes:
  task docker:proxy:e2e runs --http, --native, and --pnpm.
  --http covers Bearer auth, CORS, response limits, URL rewriting, and cache assertions.
  --live runs the existing live PyPI Docker pressure test against the built image.
  --native uses no read-auth because package-manager support for Bearer read auth is uneven.
  --pnpm proves npm read-through caching and experimental local publish/install with pnpm.
USAGE
  exit 0
  ;;
*)
  echo "unknown argument: $1" >&2
  exit 2
  ;;
esac

if [[ "$mode" != "http" && "$mode" != "native" && "$mode" != "pnpm" && "$mode" != "live" ]]; then
  echo "unsupported mode: $mode" >&2
  exit 2
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "missing required command: docker" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image="${STARMETAL_PROXY_IMAGE:-starmetal:local}"
skip_build="${STARMETAL_PROXY_E2E_SKIP_BUILD:-0}"
python_image="${PYTHON_IMAGE:-python:3.12-slim}"
inspect_image="${INSPECT_IMAGE:-cgr.dev/chainguard/busybox:latest}"
node_image="${NODE_IMAGE:-node:22-slim}"
rust_client_image="${RUST_CLIENT_IMAGE:-rust:1-slim}"
maven_image="${MAVEN_IMAGE:-maven:3.9-eclipse-temurin-21}"
ruby_image="${RUBY_IMAGE:-ruby:3.3-slim}"
dotnet_image="${DOTNET_IMAGE:-mcr.microsoft.com/dotnet/sdk:8.0}"
dart_image="${DART_IMAGE:-dart:stable}"
pnpm_image="${PNPM_IMAGE:-ghcr.io/pnpm/pnpm:11}"
pnpm_node_version="${PNPM_NODE_VERSION:-22}"
token="${STARMETAL_PROXY_E2E_TOKEN:-proxy-e2e-token}"
pnpm_publish_token="${STARMETAL_PNPM_PUBLISH_TOKEN:-pnpm-publish-token}"
run_id="${RANDOM}-${RANDOM}"
network="starmetal-proxy-e2e-${run_id}"
starmetal_container="starmetal-proxy-e2e-app-${run_id}"
fixture_container="starmetal-proxy-e2e-upstream-${run_id}"
volume="starmetal-proxy-e2e-data-${run_id}"
client_cache_volume="starmetal-proxy-e2e-client-cache-${run_id}"
pnpm_client_image="starmetal-proxy-e2e-pnpm-client-${run_id}"
pnpm_client_image_built="0"
tmp_dir="$(mktemp -d)"
artifact_root="${SM_PROXY_E2E_ARTIFACTS:-${repo_root}/.artifacts/docker-proxy-e2e}"
artifact_dir="${artifact_root%/}/${mode}-${run_id}"
config_file="${tmp_dir}/starmetal.toml"
stored_files="${artifact_dir}/stored-files.txt"

collect_container_logs() {
  local container="$1"
  local output="$2"
  if docker inspect "$container" >/dev/null 2>&1; then
    docker logs "$container" >"$output" 2>&1 || true
  fi
}

collect_artifacts() {
  mkdir -p "$artifact_dir"
  collect_container_logs "$starmetal_container" "${artifact_dir}/starmetal.log"
  collect_container_logs "$fixture_container" "${artifact_dir}/fixture-upstream.log"
  cp "$config_file" "${artifact_dir}/starmetal.toml" 2>/dev/null || true
  cp "${tmp_dir}/Dockerfile.pnpm-client" "${artifact_dir}/Dockerfile.pnpm-client" 2>/dev/null || true
}

cleanup() {
  local status="$1"
  collect_artifacts
  if [[ "$status" != "0" ]]; then
    echo "docker proxy E2E failed; recent StarMetal logs:" >&2
    sed -n '1,220p' "${artifact_dir}/starmetal.log" >&2 || true
    echo "docker proxy E2E failed; recent fixture upstream logs:" >&2
    sed -n '1,220p' "${artifact_dir}/fixture-upstream.log" >&2 || true
    echo "docker proxy E2E artifacts: ${artifact_dir}" >&2
  fi
  if [[ "${KEEP_DOCKER_PROXY_E2E:-0}" != "1" ]]; then
    docker rm -f "$starmetal_container" "$fixture_container" >/dev/null 2>&1 || true
    docker network rm "$network" >/dev/null 2>&1 || true
    docker volume rm "$volume" >/dev/null 2>&1 || true
    docker volume rm "$client_cache_volume" >/dev/null 2>&1 || true
    if [[ "$pnpm_client_image_built" == "1" ]]; then
      docker image rm "$pnpm_client_image" >/dev/null 2>&1 || true
    fi
    rm -rf "$tmp_dir"
    if [[ "$status" == "0" && -z "${SM_PROXY_E2E_ARTIFACTS:-}" ]]; then
      rm -rf "$artifact_dir"
    fi
  else
    echo "kept Docker proxy E2E resources:" >&2
    echo "  temp dir: $tmp_dir" >&2
    echo "  network:  $network" >&2
    echo "  volume:   $volume" >&2
    echo "  cache:    $client_cache_volume" >&2
  fi
}
trap 'status=$?; cleanup "$status"; exit "$status"' EXIT

write_config() {
  local auth_enabled="true"
  local auth_tokens="[\"${token}\"]"
  local max_response_bytes="16384"
  local max_upload_bytes="4096"
  local publishing_enabled="false"
  if [[ "$mode" == "native" || "$mode" == "pnpm" ]]; then
    auth_enabled="false"
    auth_tokens="[]"
    max_response_bytes="65536"
  fi
  if [[ "$mode" == "pnpm" ]]; then
    max_upload_bytes="1048576"
    publishing_enabled="true"
  fi

  cat >"$config_file" <<EOF
[server]
bind = "0.0.0.0:8080"
public_base_url = "http://starmetal:8080"
cors_allowed_origins = ["http://client.local"]
max_upload_bytes = ${max_upload_bytes}

[storage]
backend = "fs"

[storage.options]
root = "/var/lib/starmetal"

[auth]
enabled = ${auth_enabled}
tokens = ${auth_tokens}

[publishing]
enabled = ${publishing_enabled}
mode = "local"
allow_shadowing = false
allow_overwrite = false
EOF

  if [[ "$mode" == "pnpm" ]]; then
    cat >>"$config_file" <<EOF

[[publishing.tokens]]
token = "${pnpm_publish_token}"
scopes = ["publish"]
ecosystems = ["npm"]
packages = ["local-pnpm"]
EOF
  fi

  cat >>"$config_file" <<EOF
[upstream.pypi]
url = "http://fixture-upstream:8081/pypi"
allow_insecure = true
allow_private_network = true
max_response_bytes = ${max_response_bytes}

[upstream.npm]
url = "http://fixture-upstream:8081/npm"
allow_insecure = true
allow_private_network = true
max_response_bytes = ${max_response_bytes}

[upstream.cargo]
url = "http://fixture-upstream:8081/cargo-index"
artifact_url = "http://fixture-upstream:8081/cargo-crates"
allow_insecure = true
allow_private_network = true
max_response_bytes = ${max_response_bytes}

[upstream.hex]
url = "http://fixture-upstream:8081/hex"
artifact_url = "http://fixture-upstream:8081/hex-repo"
allow_insecure = true
allow_private_network = true
max_response_bytes = ${max_response_bytes}

[upstream.maven]
url = "http://fixture-upstream:8081/maven"
allow_insecure = true
allow_private_network = true
max_response_bytes = ${max_response_bytes}

[upstream.rubygems]
url = "http://fixture-upstream:8081/rubygems"
artifact_url = "http://fixture-upstream:8081/rubygems"
allow_insecure = true
allow_private_network = true
max_response_bytes = ${max_response_bytes}

[upstream.nuget]
url = "http://fixture-upstream:8081/nuget/v3/index.json"
allow_insecure = true
allow_private_network = true
max_response_bytes = ${max_response_bytes}

[upstream.pub]
url = "http://fixture-upstream:8081/pub"
allow_insecure = true
allow_private_network = true
max_response_bytes = ${max_response_bytes}
EOF
}

build_pnpm_client_image() {
  local dockerfile="${tmp_dir}/Dockerfile.pnpm-client"
  cat >"$dockerfile" <<'EOF'
ARG PNPM_BASE_IMAGE=ghcr.io/pnpm/pnpm:11
ARG PNPM_NODE_VERSION=22
FROM ${PNPM_BASE_IMAGE}
RUN pnpm runtime set node "${PNPM_NODE_VERSION}" -g
WORKDIR /workspace
EOF
  docker build \
    --build-arg "PNPM_BASE_IMAGE=${pnpm_image}" \
    --build-arg "PNPM_NODE_VERSION=${pnpm_node_version}" \
    --tag "$pnpm_client_image" \
    --file "$dockerfile" \
    "$tmp_dir"
  pnpm_client_image_built="1"
}

run_python() {
  docker run --rm \
    --network "$network" \
    --volume "${repo_root}/docker/proxy-e2e:/work:ro" \
    "$python_image" \
    "$@"
}

wait_for_fixture() {
  for _ in $(seq 1 60); do
    if run_python python - <<'PY' >/dev/null 2>&1; then
from urllib.request import urlopen
with urlopen("http://fixture-upstream:8081/__health", timeout=2) as response:
    raise SystemExit(0 if response.read() == b"ok" else 1)
PY
      return 0
    fi
    sleep 1
  done
  echo "fixture upstream did not become healthy" >&2
  docker logs "$fixture_container" >&2 || true
  exit 1
}

wait_for_starmetal() {
  local header=""
  if [[ "$mode" == "http" ]]; then
    header="Bearer ${token}"
  fi
  for _ in $(seq 1 60); do
    if run_python python - "$header" <<'PY' >/dev/null 2>&1; then
import sys
from urllib.request import Request, urlopen

headers = {}
if sys.argv[1]:
    headers["Authorization"] = sys.argv[1]
request = Request("http://starmetal:8080/healthz", headers=headers)
with urlopen(request, timeout=2) as response:
    raise SystemExit(0 if response.read() == b"ok" else 1)
PY
      return 0
    fi
    sleep 1
  done
  echo "StarMetal did not become healthy" >&2
  docker logs "$starmetal_container" >&2 || true
  exit 1
}

start_starmetal() {
  docker rm -f "$starmetal_container" >/dev/null 2>&1 || true
  docker run \
    --detach \
    --name "$starmetal_container" \
    --network "$network" \
    --network-alias starmetal \
    --volume "${config_file}:/etc/starmetal/starmetal.toml:ro" \
    --volume "${volume}:/var/lib/starmetal" \
    "$image" >/dev/null
}

run_client() {
  local image_name="$1"
  local client="$2"
  local phase="$3"
  local log_file="${artifact_dir}/client-${phase}-${client}.log"
  docker run --rm \
    --network "$network" \
    --volume "${repo_root}/docker/proxy-e2e:/work:ro" \
    --volume "${client_cache_volume}:/client-cache" \
    -e STARMETAL_URL="http://starmetal:8080" \
    "$image_name" \
    sh /work/native_clients.sh "$client" "$phase" 2>&1 | tee "$log_file"
}

run_native_clients() {
  local phase="$1"
  run_client "$python_image" pypi "$phase"
  run_client "$node_image" npm "$phase"
  run_client "$rust_client_image" cargo "$phase"
  run_client "$maven_image" maven "$phase"
  run_client "$ruby_image" rubygems "$phase"
  run_client "$dotnet_image" nuget "$phase"
  run_client "$dart_image" pub "$phase"
}

run_pnpm_client() {
  local action="$1"
  local log_file="${artifact_dir}/pnpm-${action}.log"
  docker run --rm \
    --network "$network" \
    --volume "${repo_root}/docker/proxy-e2e:/work:ro" \
    -e STARMETAL_URL="http://starmetal:8080" \
    -e STARMETAL_PUBLISH_TOKEN="$pnpm_publish_token" \
    "$pnpm_client_image" \
    sh /work/pnpm_client.sh "$action" 2>&1 | tee "$log_file"
}

run_assertions() {
  local phase="$1"
  shift || true
  local log_file="${artifact_dir}/http-${phase}.log"
  run_python python /work/http_assertions.py \
    --base-url "http://starmetal:8080" \
    --token "$token" \
    --phase "$phase" \
    "$@" 2>&1 | tee "$log_file"
}

require_stored() {
  local pattern="$1"
  if ! grep -F "$pattern" "$stored_files" >/dev/null; then
    echo "expected stored file pattern not found: $pattern" >&2
    sed -n '1,240p' "$stored_files" >&2 || true
    exit 1
  fi
}

require_stored_contains() {
  local path="$1"
  local text="$2"
  if ! docker run \
    --rm \
    --volume "${volume}:/data:ro" \
    --entrypoint /bin/sh \
    "$inspect_image" \
    -c "grep -F '$text' '/data$path' >/dev/null"; then
    echo "expected stored file to contain text: ${path} -> ${text}" >&2
    exit 1
  fi
}

cd "$repo_root"

if [[ "$mode" == "live" ]]; then
  echo "building $image"
  docker build --tag "$image" .
  SM_PRESSURE_IMAGE="$image" ./docker/pressure-test.sh
  exit 0
fi

mkdir -p "$artifact_dir"
write_config

if [[ "$skip_build" == "1" ]]; then
  echo "using existing $image"
else
  echo "building $image"
  docker build --tag "$image" .
fi

expected_version="$(grep -E '^version = "' Cargo.toml | head -1 | cut -d'"' -f2)"
actual_version="$(docker run --rm "$image" --version)"
if [[ "$actual_version" != "sm ${expected_version}" ]]; then
  echo "image version mismatch: expected sm ${expected_version}, got ${actual_version}" >&2
  exit 1
fi
docker run \
  --rm \
  --volume "${config_file}:/etc/starmetal/starmetal.toml:ro" \
  "$image" \
  config validate >/dev/null

if [[ "$mode" == "pnpm" ]]; then
  echo "building $pnpm_client_image from $pnpm_image"
  build_pnpm_client_image
fi

docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null
if [[ "$mode" == "native" ]]; then
  docker volume create "$client_cache_volume" >/dev/null
fi

docker run \
  --detach \
  --name "$fixture_container" \
  --network "$network" \
  --network-alias fixture-upstream \
  --volume "${repo_root}/docker/proxy-e2e:/work:ro" \
  "$python_image" \
  python /work/fixture_server.py >/dev/null
wait_for_fixture

start_starmetal
wait_for_starmetal
if [[ "$mode" == "native" ]]; then
  run_native_clients online
elif [[ "$mode" == "pnpm" ]]; then
  run_pnpm_client read-through-online
  run_pnpm_client local-publish
  run_pnpm_client local-install-online
else
  run_assertions online --fixture-url "http://fixture-upstream:8081"
fi

collect_container_logs "$starmetal_container" "${artifact_dir}/starmetal-online.log"
collect_container_logs "$fixture_container" "${artifact_dir}/fixture-upstream.log"
docker rm -f "$fixture_container" >/dev/null
docker rm -f "$starmetal_container" >/dev/null
start_starmetal
wait_for_starmetal
if [[ "$mode" == "native" ]]; then
  run_native_clients cached
elif [[ "$mode" == "pnpm" ]]; then
  run_pnpm_client read-through-cached
  run_pnpm_client local-install-cached
else
  run_assertions cached
fi

docker run \
  --rm \
  --volume "${volume}:/data:ro" \
  --entrypoint /bin/sh \
  "$inspect_image" \
  -c 'find /data -maxdepth 6 -type f | sort' >"$stored_files"

require_stored "/pypi/sample-project/1.0.0/sample_project-1.0.0-py3-none-any.whl"
require_stored "/pypi/sample-project/1.0.0/sample_project-1.0.0-py3-none-any.whl.blake3"
require_stored "/pypi/sample-project/_raw_upstream"
require_stored "/npm/sample-npm/1.0.0/sample-npm-1.0.0.tgz"
require_stored "/npm/sample-npm/1.0.0/sample-npm-1.0.0.tgz.blake3"
require_stored "/npm/sample-npm/_raw_upstream"
require_stored "/cargo/sample-crate/1.0.0/sample-crate-1.0.0.crate"
if [[ "$mode" == "http" ]]; then
  require_stored "/hex/sample_hex/1.0.0/sample_hex-1.0.0.tar"
  require_stored "/hex/registry%2Fsample_hex/_raw_upstream"
fi
require_stored "/maven/com.example:sample-lib/1.0.0/sample-lib-1.0.0.jar"
require_stored "/rubygems/samplegem/1.0.0/samplegem-1.0.0.gem"
require_stored "/nuget/sample.nuget/1.0.0/sample.nuget.1.0.0.nupkg"
require_stored "/pub/sample_pub/1.0.0/sample_pub-1.0.0.tar.gz"
require_stored_contains "/npm/sample-npm/_raw_upstream" "sample-npm"
if [[ "$mode" == "pnpm" ]]; then
  require_stored "/npm/local-pnpm/1.0.0/local-pnpm-1.0.0.tgz"
  require_stored "/npm/local-pnpm/1.0.0/local-pnpm-1.0.0.tgz.blake3"
  require_stored "/npm/local-pnpm/1.0.0/_metadata.json"
  require_stored "/npm/local-pnpm/_versions.json"
  require_stored "/_starmetal/published/npm/local-pnpm/1.0.0.json"
fi

echo "docker proxy E2E passed"
echo "stored files:"
sed -n '1,120p' "$stored_files"
