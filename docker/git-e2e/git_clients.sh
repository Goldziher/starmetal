#!/usr/bin/env sh
# Drive a real go/zig/swift toolchain against Starmetal's git-as-source proxies, mirroring the
# `#[ignore]`d live E2Es in tests/integration/tests/{go,zig,swift}.rs verbatim. Invoked once per
# client per phase (online, then cached) by run.sh inside the matching toolchain container.
set -eu

client="${1:?client name required}"
phase="${2:-online}"
base_url="${STARMETAL_URL:-http://starmetal:8080}"

log() {
	printf '[git-client:%s:%s] %s\n' "$client" "$phase" "$*" >&2
}

case "$client" in
go)
	log "downloading example.com/mod@v1.0.0 through the Go module proxy"
	project="$(mktemp -d)"
	gomodcache="$(mktemp -d)"
	gopath="$(mktemp -d)"
	printf 'module scratch\n\ngo 1.21\n' >"${project}/go.mod"
	cd "$project"
	# GOSUMDB=off: no checksum-database lookups (offline). GOTOOLCHAIN=local: never fetch a
	# toolchain. GOMODCACHE is a fresh temp dir every run, so the module is always re-fetched
	# through Starmetal rather than served from a warm client-side cache.
	GOPROXY="${base_url}/go" \
		GOSUMDB=off \
		GOTOOLCHAIN=local \
		GOMODCACHE="$gomodcache" \
		GOPATH="$gopath" \
		GOFLAGS=-mod=mod \
		go mod download example.com/mod@v1.0.0
	test -f "${gomodcache}/example.com/mod@v1.0.0/go.mod"
	test -f "${gomodcache}/example.com/mod@v1.0.0/greet.go"
	;;

zig)
	log "fetching example.com/pkg/v1.0.0 through the Zig tarball proxy"
	project="$(mktemp -d)"
	global_cache="$(mktemp -d)"
	# `zig fetch` needs a build.zig in scope, so scaffold a minimal consumer project with
	# `zig init` first, matching how zig.rs runs the fetch from inside an initialized project.
	cd "$project"
	zig init
	hash="$(ZIG_GLOBAL_CACHE_DIR="$global_cache" zig fetch "${base_url}/zig/example.com/pkg/v1.0.0.tar.gz")"
	test -n "$hash"
	log "zig fetch produced package hash: $hash"
	;;

swift)
	log "resolving and building test.fixture through the Swift Package Registry proxy"
	project="$(mktemp -d)"
	cache_path="$(mktemp -d)"
	security_path="$(mktemp -d)"
	mkdir -p "${project}/Sources/consumer"
	cat >"${project}/Package.swift" <<'EOF'
// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "consumer",
    dependencies: [
        .package(id: "test.fixture", from: "1.0.0")
    ],
    targets: [
        .executableTarget(name: "consumer", dependencies: [.product(name: "fixture", package: "test.fixture")])
    ]
)
EOF
	cat >"${project}/Sources/consumer/main.swift" <<'EOF'
import fixture
print(Fixture().hello())
EOF
	cd "$project"
	swift package-registry set --allow-insecure-http \
		--cache-path "$cache_path" --security-path "$security_path" \
		"${base_url}/swift"
	swift package resolve --cache-path "$cache_path" --security-path "$security_path"
	grep -q "test.fixture" Package.resolved
	swift build --cache-path "$cache_path" --security-path "$security_path"
	;;

*)
	echo "unknown git client: $client" >&2
	exit 2
	;;
esac

log "passed"
