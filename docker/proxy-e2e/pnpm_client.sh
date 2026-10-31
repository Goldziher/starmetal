#!/usr/bin/env sh
set -eu

action="${1:?pnpm action required}"
base_url="${STARMETAL_URL:-http://starmetal:8080}"
publish_token="${STARMETAL_PUBLISH_TOKEN:-pnpm-publish-token}"

log() {
  printf '[pnpm:%s] %s\n' "$action" "$*" >&2
}

write_project_manifest() {
  project="$1"
  name="$2"
  cat >"$project/package.json" <<EOF
{
  "name": "${name}",
  "private": true
}
EOF
}

assert_installed() {
  project="$1"
  package="$2"
  version="$3"
  expected_export="$4"

  PACKAGE_NAME="$package" EXPECTED_VERSION="$version" EXPECTED_EXPORT="$expected_export" \
    node <<'NODE'
const fs = require("node:fs");
const packageName = process.env.PACKAGE_NAME;
const expectedVersion = process.env.EXPECTED_VERSION;
const expectedExport = process.env.EXPECTED_EXPORT;
const manifest = JSON.parse(fs.readFileSync("package.json", "utf8"));

if (!manifest.dependencies || manifest.dependencies[packageName] !== expectedVersion) {
  throw new Error(`package.json did not pin ${packageName}@${expectedVersion}`);
}

const installedManifest = require(`./node_modules/${packageName}/package.json`);
if (installedManifest.version !== expectedVersion) {
  throw new Error(`installed ${packageName} version was ${installedManifest.version}`);
}

const actualExport = require(packageName);
if (actualExport !== expectedExport) {
  throw new Error(`${packageName} export was ${actualExport}`);
}
NODE

  test -f "$project/pnpm-lock.yaml"
  grep -F "$package" "$project/pnpm-lock.yaml" >/dev/null
  grep -F "$version" "$project/pnpm-lock.yaml" >/dev/null
}

install_package() {
  package="$1"
  version="$2"
  expected_export="$3"
  project_name="$4"

  project="$(mktemp -d)"
  store="$(mktemp -d)"
  write_project_manifest "$project" "$project_name"

  cd "$project"
  pnpm add "${package}@${version}" \
    --save-exact \
    --registry "${base_url}/npm" \
    --store-dir "$store" \
    --reporter append-only

  assert_installed "$project" "$package" "$version" "$expected_export"
  log "installed ${package}@${version} with fresh pnpm store ${store}"
}

publish_local_package() {
  project="$(mktemp -d)"

  cat >"$project/package.json" <<'EOF'
{
  "name": "local-pnpm",
  "version": "1.0.0",
  "description": "StarMetal pnpm local publish fixture",
  "main": "index.js",
  "license": "MIT",
  "files": ["index.js"]
}
EOF
  printf "module.exports = 'starmetal-local-publish';\n" >"$project/index.js"
  cat >"$project/.npmrc" <<EOF
registry=${base_url}/npm
//starmetal:8080/:_authToken=${publish_token}
//starmetal:8080/npm/:_authToken=${publish_token}
always-auth=true
EOF

  cd "$project"
  pnpm publish \
    --registry "${base_url}/npm" \
    --no-git-checks \
    --access public \
    --reporter append-only

  log "published local-pnpm@1.0.0"
}

case "$action" in
read-through-online | read-through-cached)
  install_package "sample-npm" "1.0.0" "starmetal-proxy-e2e" "starmetal-pnpm-read-through"
  ;;
local-publish)
  publish_local_package
  ;;
local-install-online | local-install-cached)
  install_package "local-pnpm" "1.0.0" "starmetal-local-publish" "starmetal-pnpm-local-install"
  ;;
*)
  echo "unknown pnpm action: $action" >&2
  exit 2
  ;;
esac

log "passed"
