#!/usr/bin/env sh
set -eu

client="${1:?client name required}"
phase="${2:-online}"
base_url="${STARMETAL_URL:-http://starmetal:8080}"

log() {
  printf '[native:%s:%s] %s\n' "$client" "$phase" "$*" >&2
}

case "$client" in
pypi)
  log "installing sample-project through pip"
  target="$(mktemp -d)"
  cache="$(mktemp -d)"
  python -m pip install \
    --disable-pip-version-check \
    --index-url "${base_url}/pypi/simple/" \
    --trusted-host starmetal \
    --target "$target" \
    --cache-dir "$cache" \
    --no-deps \
    --timeout 60 \
    "sample-project==1.0.0"
  test -f "$target/sample_project/__init__.py"
  ;;

npm)
  log "installing sample-npm through npm"
  project="$(mktemp -d)"
  cache="$(mktemp -d)"
  npm install \
    --registry "${base_url}/npm" \
    --prefix "$project" \
    --cache "$cache" \
    --no-audit \
    --no-fund \
    --no-package-lock \
    "sample-npm@1.0.0"
  test -f "$project/node_modules/sample-npm/package.json"
  ;;

cargo)
  log "fetching sample-crate through cargo sparse registry"
  project="$(mktemp -d)"
  cargo_home="$(mktemp -d)"
  mkdir -p "$project/src" "$project/.cargo"
  cat >"$project/Cargo.toml" <<EOF
[package]
name = "starmetal-native-cargo-e2e"
version = "0.0.0"
edition = "2021"

[dependencies]
sample-crate = { version = "=1.0.0", registry = "starmetal" }
EOF
  printf 'pub fn marker() {}\n' >"$project/src/lib.rs"
  cat >"$project/.cargo/config.toml" <<EOF
[registries.starmetal]
index = "sparse+${base_url}/cargo/"
EOF
  cd "$project"
  CARGO_HOME="$cargo_home" CARGO_HTTP_TIMEOUT=60 cargo fetch
  ;;

maven)
  log "resolving com.example:sample-lib through Maven"
  repo="/client-cache/maven-repo"
  mkdir -p "$repo"
  rm -rf "$repo/com/example/sample-lib"
  project="$(mktemp -d)"
  cat >"$project/pom.xml" <<EOF
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>starmetal.native</groupId>
  <artifactId>maven-e2e</artifactId>
  <version>0.0.0</version>
  <repositories>
    <repository>
      <id>starmetal</id>
      <url>${base_url}/maven</url>
    </repository>
  </repositories>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>sample-lib</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>
EOF
  cat >"$project/settings.xml" <<EOF
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">
  <mirrors>
    <mirror>
      <id>starmetal-http</id>
      <mirrorOf>starmetal</mirrorOf>
      <url>${base_url}/maven</url>
    </mirror>
  </mirrors>
</settings>
EOF
  mvn -B -q -s "$project/settings.xml" -f "$project/pom.xml" -Dmaven.repo.local="$repo" \
    -Dmaven.wagon.http.retryHandler.count=1 \
    dependency:resolve -DexcludeTransitive=true
  test -f "$repo/com/example/sample-lib/1.0.0/sample-lib-1.0.0.jar"
  ;;

rubygems)
  log "installing samplegem through Bundler"
  project="$(mktemp -d)"
  bundle_path="$(mktemp -d)"
  gem_home="$(mktemp -d)"
  cat >"$project/Gemfile" <<EOF
source "${base_url}/rubygems"
gem "samplegem", "1.0.0"
EOF
  cd "$project"
  GEM_HOME="$gem_home" BUNDLE_PATH="$bundle_path" BUNDLE_USER_HOME="$project/.bundle-home" \
    BUNDLE_SILENCE_ROOT_WARNING=1 bundle install
  find "$bundle_path" -name samplegem.rb -print -quit | grep samplegem.rb >/dev/null
  ;;

nuget)
  log "restoring sample.nuget through dotnet"
  project="$(mktemp -d)"
  packages="$(mktemp -d)"
  cli_home="$(mktemp -d)"
  cat >"$project/nuget.config" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="starmetal" value="${base_url}/nuget/v3/index.json" allowInsecureConnections="true" />
  </packageSources>
</configuration>
EOF
  cat >"$project/starmetal-nuget-e2e.csproj" <<'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="sample.nuget" Version="1.0.0" />
  </ItemGroup>
</Project>
EOF
  DOTNET_CLI_HOME="$cli_home" NUGET_PACKAGES="$packages" \
    dotnet restore "$project/starmetal-nuget-e2e.csproj" --packages "$packages"
  test -d "$packages/sample.nuget/1.0.0"
  ;;

pub)
  log "resolving sample_pub through dart pub"
  project="$(mktemp -d)"
  pub_cache="$(mktemp -d)"
  cat >"$project/pubspec.yaml" <<'EOF'
name: starmetal_native_pub_e2e
publish_to: none
environment:
  sdk: ">=3.0.0 <4.0.0"
dependencies:
  sample_pub: 1.0.0
EOF
  cd "$project"
  PUB_HOSTED_URL="${base_url}/pub" PUB_CACHE="$pub_cache" dart pub get
  find "$pub_cache" -path '*sample_pub-1.0.0*' -print -quit | grep sample_pub >/dev/null
  ;;

*)
  echo "unknown native client: $client" >&2
  exit 2
  ;;
esac

log "passed"
