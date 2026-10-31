#!/usr/bin/env bash
#MISE description="Check representative feature flag combinations"
set -euo pipefail

cargo check -p starmetal-cli --no-default-features --features backend-memory
for feature in pypi npm cargo-registry hex maven rubygems nuget pub go zig swift signing-x509 pq metadata scanner-osv; do
  cargo check -p starmetal-cli --no-default-features --features "${feature},backend-memory"
done
cargo check -p starmetal-git
cargo check -p starmetal-git --all-features
cargo check -p starmetal-cli --all-features
