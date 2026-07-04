#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "Usage: $0 <version>" >&2
	echo "Example: $0 0.1.0" >&2
	exit 1
fi

VERSION="${1#v}"
PY_VERSION="${VERSION//-rc./rc}"

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.]+)?$ ]]; then
	echo "Invalid version: $VERSION" >&2
	exit 1
fi

node - "$VERSION" <<'NODE'
const fs = require("node:fs");
const version = process.argv[2];
for (const file of ["packages/npm/package.json"]) {
  const current = fs.readFileSync(file, "utf8");
  const versionPattern = /("version": ")[^"]+(")/;
  if (!versionPattern.test(current)) {
    throw new Error(`failed to update version in ${file}`);
  }
  const next = current.replace(versionPattern, `$1${version}$2`);
  fs.writeFileSync(file, next);
}
NODE

perl -0pi -e \
	's/(\[workspace\.package\]\s+version = ")[^"]+(")/${1}'"$VERSION"'$2/s' \
	Cargo.toml
perl -0pi -e \
	's/(\[package\]\s+name = "starmetal"\s+version = ")[^"]+(")/${1}'"$VERSION"'$2/s' \
	packages/crates/starmetal/Cargo.toml
perl -0pi -e \
	's/const VERSION: &str = "[^"]+";/const VERSION: \&str = "'"$VERSION"'";/' \
	packages/crates/starmetal/src/main.rs
perl -0pi -e \
	's/^version = "[^"]+"/version = "'"$PY_VERSION"'"/m' \
	packages/pypi/pyproject.toml
perl -0pi -e \
	's/^__version__ = "[^"]+"/__version__ = "'"$PY_VERSION"'"/m' \
	packages/pypi/src/starmetal/__init__.py

metadata_file="$(mktemp)"
trap 'rm -f "$metadata_file"' EXIT
cargo metadata --format-version 1 --no-deps >"$metadata_file"
node - "$VERSION" "$metadata_file" <<'NODE'
const fs = require("node:fs");
const version = process.argv[2];
const metadata = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
const workspaceMembers = new Set(metadata.workspace_members);
const workspacePackageNames = new Set(
  metadata.packages.filter((pkg) => workspaceMembers.has(pkg.id)).map((pkg) => pkg.name)
);
const lockfile = "Cargo.lock";
const current = fs.readFileSync(lockfile, "utf8");
let matchedWorkspacePackage = false;
const next = current.replace(
  /(\[\[package\]\]\nname = "([^"]+)"\nversion = ")[^"]+(")/g,
  (match, prefix, name, suffix) => {
    if (!workspacePackageNames.has(name)) {
      return match;
    }
    matchedWorkspacePackage = true;
    return `${prefix}${version}${suffix}`;
  }
);
if (!matchedWorkspacePackage) {
  throw new Error(`failed to update workspace package versions in ${lockfile}`);
}
fs.writeFileSync(lockfile, next);
NODE
(cd packages/crates/starmetal && cargo generate-lockfile)
cargo metadata --locked --format-version 1 --no-deps >/dev/null

echo "Synced StarMetal release version to $VERSION"
echo "Release tag: v$VERSION"
echo "Docker tags: ghcr.io/goldziher/starmetal:$VERSION and :latest for stable releases"
