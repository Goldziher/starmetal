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
  const json = JSON.parse(fs.readFileSync(file, "utf8"));
  json.version = version;
  fs.writeFileSync(file, `${JSON.stringify(json, null, 2)}\n`);
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

cargo metadata --format-version 1 --no-deps >/dev/null
(cd packages/crates/starmetal && cargo metadata --format-version 1 --no-deps >/dev/null)

echo "Synced StarMetal release version to $VERSION"
echo "Release tag: v$VERSION"
echo "Docker tags: ghcr.io/goldziher/starmetal:$VERSION and :latest for stable releases"
