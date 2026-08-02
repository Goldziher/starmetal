#!/usr/bin/env sh
# Build the three deterministic git fixtures the git-as-source Docker E2E serves.
#
# Runs inside a git-CLI container (see run.sh) with /srv/upstream bind-mounted from the ephemeral
# `upstream` volume. For each ecosystem it commits a small working tree with a FIXED identity and
# FIXED author/committer dates -- byte-for-byte matching the Rust `GitFixture` helper
# (tests/integration/src/git_fixture.rs) so the served archives are reproducible -- then bare-clones
# it to /srv/upstream/<eco>.git. Starmetal references those bare repos via `file:///srv/upstream/...`
# overrides; there is no HTTP git sidecar because gix is built blocking-network-client only (no HTTP
# git transport), so `file://` is the only viable offline transport.
#
# The repos are chown'd to the image's runtime UID (65532) so gix reads them without tripping git's
# dubious-ownership guard when Starmetal mounts the volume read-only.
set -eu

# Fixed identity + dates, matching git_fixture.rs's FIXTURE_* constants exactly.
FIXTURE_COMMIT_DATE="2020-01-01T00:00:00Z"
export GIT_AUTHOR_NAME="Fixture"
export GIT_AUTHOR_EMAIL="fixture@example.test"
export GIT_AUTHOR_DATE="$FIXTURE_COMMIT_DATE"
export GIT_COMMITTER_NAME="Fixture"
export GIT_COMMITTER_EMAIL="fixture@example.test"
export GIT_COMMITTER_DATE="$FIXTURE_COMMIT_DATE"
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null

runtime_uid="${STARMETAL_RUNTIME_UID:-65532}"
upstream_dir="/srv/upstream"
mkdir -p "$upstream_dir"

# Commit the working tree at $1 into a fresh repo, tag it $2, and bare-clone it to
# $upstream_dir/$3.git. `git clone --bare` copies HEAD, branches, and tags.
build_repo() {
	work="$1"
	tag="$2"
	name="$3"
	git -C "$work" init -q -b main
	git -C "$work" add -A
	git -C "$work" commit -q -m "release 1.0.0"
	git -C "$work" tag "$tag"
	git clone -q --bare "$work" "${upstream_dir}/${name}.git"
}

# --- Go module: example.com/mod, tag v1.0.0 ------------------------------------------------------
go_work="$(mktemp -d)"
printf 'module example.com/mod\n\ngo 1.21\n' >"${go_work}/go.mod"
printf 'package mod\n\n// Greet returns a fixed greeting.\nfunc Greet() string { return "hello" }\n' \
	>"${go_work}/greet.go"
build_repo "$go_work" "v1.0.0" "go"

# --- Zig package: example.com/pkg, tag v1.0.0 ----------------------------------------------------
zig_work="$(mktemp -d)"
printf '.{\n    .name = .fixture,\n    .version = "1.0.0",\n    .fingerprint = 0x5e540eeeedcbb0d,\n    .paths = .{""},\n}\n' \
	>"${zig_work}/build.zig.zon"
printf 'const std = @import("std");\npub fn build(b: *std.Build) void {\n    _ = b;\n}\n' \
	>"${zig_work}/build.zig"
mkdir -p "${zig_work}/src"
printf 'pub fn main() void {}\n' >"${zig_work}/src/main.zig"
build_repo "$zig_work" "v1.0.0" "zig"

# --- Swift package: test.fixture, tag 1.0.0 ------------------------------------------------------
swift_work="$(mktemp -d)"
cat >"${swift_work}/Package.swift" <<'EOF'
// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "fixture",
    products: [
        .library(name: "fixture", targets: ["fixture"])
    ],
    targets: [
        .target(name: "fixture", path: "Sources/fixture")
    ]
)
EOF
mkdir -p "${swift_work}/Sources/fixture"
cat >"${swift_work}/Sources/fixture/fixture.swift" <<'EOF'
public struct Fixture {
    public init() {}
    public func hello() -> String { "hello" }
}
EOF
build_repo "$swift_work" "1.0.0" "swift"

# Hand the bare repos to the runtime UID so gix reads them without a dubious-ownership rejection.
chown -R "${runtime_uid}:${runtime_uid}" "$upstream_dir"

echo "built git fixtures:"
ls -1 "$upstream_dir"
