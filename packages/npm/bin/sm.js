#!/usr/bin/env node

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const binaryName = os.type() === "Windows_NT" ? "sm.exe" : "sm";
const binaryPath = path.join(__dirname, binaryName);
const installScriptPath = path.join(__dirname, "..", "install.js");

function ensureBinaryExists() {
  if (fs.existsSync(binaryPath)) {
    return true;
  }

  console.error(`sm: binary not found at ${binaryPath}; running installer...`);
  if (!fs.existsSync(installScriptPath)) {
    console.error(`sm: installer not found at ${installScriptPath}`);
    return false;
  }

  const installResult = spawnSync(process.execPath, [installScriptPath], {
    stdio: "inherit",
    cwd: path.dirname(installScriptPath),
  });

  return installResult.status === 0 && fs.existsSync(binaryPath);
}

if (!ensureBinaryExists()) {
  console.error(
    "sm: native binary is unavailable.\n" +
      "The postinstall step that downloads the binary from GitHub releases may have failed.\n" +
      "Try reinstalling with `npm install -g starmetal`, or use Homebrew, Docker, or cargo from source.",
  );
  process.exit(1);
}

const result = spawnSync(binaryPath, process.argv.slice(2), { stdio: "inherit" });
if (result.error) {
  console.error(`sm: failed to spawn binary: ${result.error.message}`);
  process.exit(1);
}

process.exit(result.status ?? 0);
