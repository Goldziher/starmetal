#!/usr/bin/env node

const version = "0.0.1";
const args = process.argv.slice(2);

if (args.includes("--version") || args.includes("-V")) {
  console.log(`sm ${version}`);
  process.exit(0);
}

console.log(`StarMetal ${version}

This npm package reserves the public starmetal namespace while the native sm CLI distribution is finalized.
Use the Docker image or build from source for the current registry server:

  docker run --rm -p 8080:8080 starmetal:${version}
  cargo build --release -p depot-cli --bin sm

Repository: https://github.com/Goldziher/starmetal`);
