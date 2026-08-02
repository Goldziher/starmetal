#!/usr/bin/env bash
set -Eeuo pipefail

# Deterministic Docker E2E for the git-as-source ecosystems (Go GOPROXY, Zig tarball, Swift Package
# Registry). Mirrors docker/proxy-e2e/run.sh, but the "upstream" is three hermetic bare git repos on
# an ephemeral volume served over `file://` (gix has no HTTP git transport, so a network sidecar is
# not viable). The flow:
#   1. build starmetal:local from the checkout
#   2. build three bare git fixtures on an ephemeral `upstream` volume
#   3. start Starmetal with the upstream volume (ro) + a persistent mirror volume, run go/zig/swift
#      clients ONLINE
#   4. remove the upstream volume, restart Starmetal with ONLY the mirror volume, re-run the clients
#      -- proving they are served entirely from the mirror cache with the upstream gone
#   5. inspect the mirror volume for a bare repo + fetch stamp per ecosystem

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
	cat <<'USAGE'
Usage: docker/git-e2e/run.sh

Runs the deterministic Docker-based git-as-source E2E:
  - builds starmetal:local (unless STARMETAL_GIT_E2E_SKIP_BUILD=1)
  - builds three bare git fixtures (go/zig/swift) on an ephemeral volume
  - drives real go/zig/swift toolchains through Starmetal online, then again offline from the mirror

Environment:
  STARMETAL_GIT_E2E_IMAGE        Image tag to build and test (default: starmetal:local)
  STARMETAL_GIT_E2E_SKIP_BUILD   Skip `docker build` and reuse the existing image (default: 0)
  GIT_BUILDER_IMAGE              git-CLI image that builds the fixtures (default: alpine/git:latest)
  GO_CLIENT_IMAGE               Go toolchain image (default: golang:1.26-bookworm)
  SWIFT_CLIENT_IMAGE            Swift toolchain image (default: swift:6.1)
  ZIG_VERSION                    Zig version for the self-built client image (default: 0.16.0)
  ZIG_SHA256                     sha256 of the Zig x86_64-linux tarball (pinned; must match ZIG_VERSION)
  INSPECT_IMAGE                  Volume-inspection image (default: cgr.dev/chainguard/busybox:latest)
  KEEP_DOCKER_GIT_E2E=1          Keep containers/network/volumes/tempdir for debugging
  SM_GIT_E2E_ARTIFACTS           Directory for logs
USAGE
	exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
	echo "missing required command: docker" >&2
	exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image="${STARMETAL_GIT_E2E_IMAGE:-starmetal:local}"
skip_build="${STARMETAL_GIT_E2E_SKIP_BUILD:-0}"
git_builder_image="${GIT_BUILDER_IMAGE:-alpine/git:latest}"
go_client_image="${GO_CLIENT_IMAGE:-golang:1.26-bookworm}"
swift_client_image="${SWIFT_CLIENT_IMAGE:-swift:6.1}"
zig_version="${ZIG_VERSION:-0.16.0}"
zig_sha256="${ZIG_SHA256:-70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00}"
inspect_image="${INSPECT_IMAGE:-cgr.dev/chainguard/busybox:latest}"
runtime_uid="65532"

run_id="${RANDOM}-${RANDOM}"
network="starmetal-git-e2e-${run_id}"
starmetal_container="starmetal-git-e2e-app-${run_id}"
builder_container="starmetal-git-e2e-builder-${run_id}"
upstream_volume="starmetal-git-e2e-upstream-${run_id}"
mirror_volume="starmetal-git-e2e-mirror-${run_id}"
zig_client_image="starmetal-git-e2e-zig-client-${run_id}"
zig_client_image_built="0"
tmp_dir="$(mktemp -d)"
artifact_root="${SM_GIT_E2E_ARTIFACTS:-${repo_root}/.artifacts/docker-git-e2e}"
artifact_dir="${artifact_root%/}/${run_id}"
config_file="${tmp_dir}/starmetal.toml"

collect_container_logs() {
	local container="$1"
	local output="$2"
	if docker inspect "$container" >/dev/null 2>&1; then
		docker logs "$container" >"$output" 2>&1 || true
	fi
}

cleanup() {
	local status="$1"
	mkdir -p "$artifact_dir"
	collect_container_logs "$starmetal_container" "${artifact_dir}/starmetal.log"
	cp "$config_file" "${artifact_dir}/starmetal.toml" 2>/dev/null || true
	if [[ "$status" != "0" ]]; then
		echo "docker git E2E failed; recent Starmetal logs:" >&2
		sed -n '1,220p' "${artifact_dir}/starmetal.log" >&2 || true
		echo "docker git E2E artifacts: ${artifact_dir}" >&2
	fi
	if [[ "${KEEP_DOCKER_GIT_E2E:-0}" != "1" ]]; then
		docker rm -f "$starmetal_container" "$builder_container" >/dev/null 2>&1 || true
		docker network rm "$network" >/dev/null 2>&1 || true
		docker volume rm "$upstream_volume" "$mirror_volume" >/dev/null 2>&1 || true
		if [[ "$zig_client_image_built" == "1" ]]; then
			docker image rm "$zig_client_image" >/dev/null 2>&1 || true
		fi
		rm -rf "$tmp_dir"
		if [[ "$status" == "0" && -z "${SM_GIT_E2E_ARTIFACTS:-}" ]]; then
			rm -rf "$artifact_dir"
		fi
	else
		echo "kept Docker git E2E resources:" >&2
		echo "  temp dir:  $tmp_dir" >&2
		echo "  network:   $network" >&2
		echo "  upstream:  $upstream_volume" >&2
		echo "  mirror:    $mirror_volume" >&2
	fi
}
trap 'status=$?; cleanup "$status"; exit "$status"' EXIT

write_config() {
	# The mirror cache lives on the persistent volume at the image-owned /var/lib/starmetal, so it
	# survives the restart. A one-day refresh interval means the offline restart never tries to
	# re-fetch the (by then deleted) file:// upstream: a fresh stamp keeps every mirror "fresh".
	cat >"$config_file" <<EOF
[server]
bind = "0.0.0.0:8080"
public_base_url = "http://starmetal:8080"
cors_allowed_origins = []
max_upload_bytes = 536870912

[storage]
backend = "fs"

[storage.options]
root = "/var/lib/starmetal"

[auth]
enabled = false
tokens = []

[publishing]
enabled = false

[go]
enabled = true
mirror_cache_dir = "/var/lib/starmetal/git-mirrors"
mirror_refresh_interval_secs = 86400

[go.module_overrides]
"example.com/mod" = "file:///srv/upstream/go.git"

[zig]
enabled = true
mirror_cache_dir = "/var/lib/starmetal/git-mirrors"
mirror_refresh_interval_secs = 86400

[zig.repo_overrides]
"example.com/pkg" = "file:///srv/upstream/zig.git"

[swift]
enabled = true
mirror_cache_dir = "/var/lib/starmetal/git-mirrors"
mirror_refresh_interval_secs = 86400

[swift.package_overrides]
"test.fixture" = "file:///srv/upstream/swift.git"
EOF
}

build_zig_client_image() {
	local dockerfile="${tmp_dir}/Dockerfile.zig-client"
	# No official Zig image exists, so build a minimal one from a pinned tarball (version + sha256).
	cat >"$dockerfile" <<'EOF'
FROM debian:bookworm-slim
ARG ZIG_VERSION
ARG ZIG_SHA256
RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates curl xz-utils \
	&& rm -rf /var/lib/apt/lists/* \
	&& curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz" -o /tmp/zig.tar.xz \
	&& echo "${ZIG_SHA256}  /tmp/zig.tar.xz" | sha256sum -c - \
	&& mkdir -p /opt/zig \
	&& tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1 \
	&& rm /tmp/zig.tar.xz \
	&& ln -s /opt/zig/zig /usr/local/bin/zig
WORKDIR /workspace
EOF
	docker build \
		--build-arg "ZIG_VERSION=${zig_version}" \
		--build-arg "ZIG_SHA256=${zig_sha256}" \
		--tag "$zig_client_image" \
		--file "$dockerfile" \
		"$tmp_dir"
	zig_client_image_built="1"
}

start_starmetal() {
	# $1: "online" mounts the upstream volume (ro); "offline" omits it, leaving only the mirror.
	local phase="$1"
	docker rm -f "$starmetal_container" >/dev/null 2>&1 || true
	local upstream_mount=()
	if [[ "$phase" == "online" ]]; then
		upstream_mount=(--volume "${upstream_volume}:/srv/upstream:ro")
	fi
	docker run \
		--detach \
		--name "$starmetal_container" \
		--network "$network" \
		--network-alias starmetal \
		--volume "${config_file}:/etc/starmetal/starmetal.toml:ro" \
		--volume "${mirror_volume}:/var/lib/starmetal" \
		"${upstream_mount[@]}" \
		"$image" >/dev/null
}

wait_for_starmetal() {
	# The chainguard busybox inspect image ships no wget, so probe health from the alpine-based git
	# builder image (already pulled), which does. `find` for the final inspection stays on busybox.
	for _ in $(seq 1 60); do
		if docker run --rm --network "$network" --entrypoint wget "$git_builder_image" \
			-q -O - "http://starmetal:8080/healthz" 2>/dev/null | grep -q "ok"; then
			return 0
		fi
		sleep 1
	done
	echo "Starmetal did not become healthy" >&2
	docker logs "$starmetal_container" >&2 || true
	exit 1
}

run_client() {
	local image_name="$1"
	local client="$2"
	local phase="$3"
	local log_file="${artifact_dir}/client-${phase}-${client}.log"
	docker run --rm \
		--network "$network" \
		--volume "${repo_root}/docker/git-e2e:/work:ro" \
		-e STARMETAL_URL="http://starmetal:8080" \
		"$image_name" \
		sh /work/git_clients.sh "$client" "$phase" 2>&1 | tee "$log_file"
}

run_all_clients() {
	local phase="$1"
	run_client "$go_client_image" go "$phase"
	run_client "$zig_client_image" zig "$phase"
	run_client "$swift_client_image" swift "$phase"
}

cd "$repo_root"
mkdir -p "$artifact_dir"
write_config

if [[ "$skip_build" == "1" ]]; then
	echo "using existing $image"
else
	echo "building $image"
	docker build --tag "$image" .
fi

docker run \
	--rm \
	--volume "${config_file}:/etc/starmetal/starmetal.toml:ro" \
	"$image" \
	config validate >/dev/null

echo "building $zig_client_image (Zig ${zig_version})"
build_zig_client_image

docker network create "$network" >/dev/null
docker volume create "$upstream_volume" >/dev/null
docker volume create "$mirror_volume" >/dev/null

echo "building git fixtures on $upstream_volume"
docker run \
	--rm \
	--name "$builder_container" \
	--volume "${upstream_volume}:/srv/upstream" \
	--volume "${repo_root}/docker/git-e2e:/work:ro" \
	-e STARMETAL_RUNTIME_UID="$runtime_uid" \
	--entrypoint /bin/sh \
	"$git_builder_image" \
	/work/build_fixtures.sh

echo "=== online phase: clients served through the file:// upstream ==="
start_starmetal online
wait_for_starmetal
run_all_clients online
collect_container_logs "$starmetal_container" "${artifact_dir}/starmetal-online.log"

echo "=== flip: removing the upstream volume, restarting from the mirror only ==="
docker rm -f "$starmetal_container" >/dev/null
docker volume rm "$upstream_volume" >/dev/null
start_starmetal offline
wait_for_starmetal

echo "=== offline phase: clients served entirely from the mirror cache ==="
run_all_clients cached

echo "=== inspecting the mirror volume for a bare repo + fetch stamp per ecosystem ==="
mirror_listing="${artifact_dir}/mirror-listing.txt"
docker run \
	--rm \
	--volume "${mirror_volume}:/data:ro" \
	"$inspect_image" \
	sh -c 'find /data/git-mirrors -maxdepth 1 | sort' >"$mirror_listing"
git_dirs="$(grep -c '\.git$' "$mirror_listing" || true)"
stamps="$(grep -c '\.stamp$' "$mirror_listing" || true)"
if [[ "$git_dirs" -lt 3 || "$stamps" -lt 3 ]]; then
	echo "expected >=3 bare mirror repos and >=3 fetch stamps, found ${git_dirs} repos / ${stamps} stamps" >&2
	sed -n '1,80p' "$mirror_listing" >&2
	exit 1
fi

echo "docker git E2E passed"
echo "mirror cache:"
sed -n '1,80p' "$mirror_listing"
