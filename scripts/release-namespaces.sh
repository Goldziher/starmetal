#!/usr/bin/env bash
set -euo pipefail

VERSION="0.0.1"
PACKAGE_NAME="starmetal"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NPM_DIR="${REPO_ROOT}/packages/npm"
PYPI_DIR="${REPO_ROOT}/packages/pypi"
CRATE_MANIFEST="${REPO_ROOT}/packages/crates/starmetal/Cargo.toml"

MODE="dry-run"
YES="false"
SKIP_NPM="false"
SKIP_PYPI="false"
SKIP_CARGO="false"

usage() {
  cat <<'USAGE'
Usage: scripts/release-namespaces.sh [--dry-run|--publish] [--yes] [--skip-npm] [--skip-pypi] [--skip-cargo]

Publishes the StarMetal v0.0.1 namespace packages:
  npm:       starmetal@0.0.1, exposing the sm command
  PyPI:      starmetal==0.0.1, exposing the sm command
  crates.io: starmetal 0.0.1, exposing the sm binary

Credentials:
  npm:   run npm login before publishing, or let the script prompt via npm login
  PyPI:  legacy local publish only; future releases use trusted publishing
  Cargo: run cargo login first, or set CARGO_REGISTRY_TOKEN
USAGE
}

for arg in "$@"; do
  case "$arg" in
  --dry-run) MODE="dry-run" ;;
  --publish) MODE="publish" ;;
  --yes) YES="true" ;;
  --skip-npm) SKIP_NPM="true" ;;
  --skip-pypi) SKIP_PYPI="true" ;;
  --skip-cargo) SKIP_CARGO="true" ;;
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

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_cmd cargo
require_cmd curl
require_cmd npm
require_cmd uv

read_root_version() {
  grep -E '^version = "' "${REPO_ROOT}/Cargo.toml" | head -1 | cut -d'"' -f2
}

read_npm_version() {
  node -p "require('${NPM_DIR}/package.json').version"
}

read_pypi_version() {
  grep -E '^version = "' "${PYPI_DIR}/pyproject.toml" | head -1 | cut -d'"' -f2
}

read_crate_version() {
  grep -E '^version = "' "$CRATE_MANIFEST" | head -1 | cut -d'"' -f2
}

assert_version() {
  local label="$1"
  local actual="$2"
  if [[ "$actual" != "$VERSION" ]]; then
    echo "$label version mismatch: expected $VERSION, got $actual" >&2
    exit 1
  fi
}

npm_version_exists() {
  npm view "${PACKAGE_NAME}@${VERSION}" version >/dev/null 2>&1
}

pypi_version_exists() {
  curl -fsS "https://pypi.org/pypi/${PACKAGE_NAME}/${VERSION}/json" >/dev/null 2>&1
}

cargo_version_exists() {
  curl -fsS "https://crates.io/api/v1/crates/${PACKAGE_NAME}/${VERSION}" >/dev/null 2>&1
}

assert_version "workspace" "$(read_root_version)"
assert_version "npm" "$(read_npm_version)"
assert_version "PyPI" "$(read_pypi_version)"
assert_version "crates.io" "$(read_crate_version)"

echo "StarMetal namespace release: ${PACKAGE_NAME} ${VERSION}"
echo "Mode: ${MODE}"
echo

if [[ "$MODE" == "publish" && "$YES" != "true" ]]; then
  read -r -p "Publish ${PACKAGE_NAME} ${VERSION} to npm, PyPI, and crates.io? [y/N] " answer
  case "$answer" in
  y | Y | yes | YES) ;;
  *)
    echo "aborted"
    exit 1
    ;;
  esac
fi

if [[ "$SKIP_NPM" != "true" ]]; then
  echo "== npm =="
  if npm_version_exists; then
    echo "npm ${PACKAGE_NAME}@${VERSION} already exists; skipping"
  elif [[ "$MODE" == "dry-run" ]]; then
    (cd "$NPM_DIR" && npm publish --dry-run --access public)
  else
    if ! npm whoami >/dev/null 2>&1; then
      echo "npm login required"
      npm login
    fi
    (cd "$NPM_DIR" && npm publish --access public --tag latest)
  fi
  echo
fi

if [[ "$SKIP_PYPI" != "true" ]]; then
  echo "== PyPI =="
  if pypi_version_exists; then
    echo "PyPI ${PACKAGE_NAME}==${VERSION} already exists; skipping"
  else
    uv build "$PYPI_DIR" --out-dir "${PYPI_DIR}/dist" --clear
    if [[ "$MODE" == "dry-run" ]]; then
      uv publish --dry-run --token "${UV_PUBLISH_TOKEN:-dry-run-token}" "${PYPI_DIR}"/dist/*
    else
      publish_token="${UV_PUBLISH_TOKEN:-${PYPI_TOKEN:-}}"
      if [[ -z "$publish_token" ]]; then
        read -r -s -p "PyPI API token: " publish_token
        echo
      fi
      UV_PUBLISH_TOKEN="$publish_token" uv publish "${PYPI_DIR}"/dist/*
    fi
  fi
  echo
fi

if [[ "$SKIP_CARGO" != "true" ]]; then
  echo "== crates.io =="
  if cargo_version_exists; then
    echo "crates.io ${PACKAGE_NAME} ${VERSION} already exists; skipping"
  elif [[ "$MODE" == "dry-run" ]]; then
    cargo publish --dry-run --allow-dirty --manifest-path "$CRATE_MANIFEST"
  else
    cargo publish --allow-dirty --manifest-path "$CRATE_MANIFEST"
  fi
  echo
fi

echo "namespace release ${MODE} complete"
