const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const https = require("node:https");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");
const AdmZip = require("adm-zip");

const { version } = require("./package.json");

function isAppleSilicon() {
  if (os.type() !== "Darwin") return false;
  if (os.arch() === "arm64") return true;
  try {
    return execFileSync("sysctl", ["-n", "hw.optional.arm64"], { encoding: "utf8" }).trim() === "1";
  } catch {
    return false;
  }
}

function getPlatformTriple() {
  const type = os.type();
  const arch = os.arch();

  if (type === "Windows_NT") {
    if (arch === "x64") return "x86_64-pc-windows-msvc";
    throw new Error(`Unsupported Windows architecture: ${arch}`);
  }

  if (type === "Linux") {
    if (arch === "x64") return "x86_64-unknown-linux-gnu";
    if (arch === "arm64") return "aarch64-unknown-linux-gnu";
    throw new Error(`Unsupported Linux architecture: ${arch}`);
  }

  if (type === "Darwin") {
    if (isAppleSilicon()) return "aarch64-apple-darwin";
    if (arch === "x64") throw new Error("macOS Intel is not supported by StarMetal release binaries");
    throw new Error(`Unsupported macOS architecture: ${arch}`);
  }

  throw new Error(`Unsupported platform: ${type} ${arch}`);
}

function getReleaseAssets() {
  const triple = getPlatformTriple();
  const ext = triple.includes("windows") ? "zip" : "tar.gz";
  const assetName = `starmetal-${triple}.${ext}`;
  const baseUrl = `https://github.com/Goldziher/starmetal/releases/download/v${version}`;
  return {
    assetName,
    archiveUrl: `${baseUrl}/${assetName}`,
    checksumsUrl: `${baseUrl}/starmetal_${version}_checksums.txt`,
  };
}

function downloadWithRedirects(url, dest, maxRedirects = 5) {
  return new Promise((resolve, reject) => {
    if (maxRedirects <= 0) {
      reject(new Error("too many redirects"));
      return;
    }

    const urlObject = new URL(url);
    if (urlObject.protocol !== "https:") {
      reject(new Error(`refusing non-HTTPS download URL: ${url}`));
      return;
    }

    const request = https.get(
      urlObject,
      { headers: { "User-Agent": "starmetal-npm-wrapper" } },
      (response) => {
        if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
          const nextUrl = new URL(response.headers.location, urlObject).toString();
          downloadWithRedirects(nextUrl, dest, maxRedirects - 1).then(resolve).catch(reject);
          return;
        }

        if (response.statusCode !== 200) {
          reject(new Error(`HTTP ${response.statusCode}: ${response.statusMessage}`));
          return;
        }

        const file = fs.createWriteStream(dest);
        response.pipe(file);
        file.on("finish", () => {
          file.close(resolve);
        });
        file.on("error", (error) => {
          fs.unlink(dest, () => {});
          reject(error);
        });
      },
    );

    request.on("error", reject);
    request.setTimeout(30000, () => {
      request.destroy();
      reject(new Error("download timeout"));
    });
  });
}

function fetchTextWithRedirects(url, maxRedirects = 5) {
  return new Promise((resolve, reject) => {
    if (maxRedirects <= 0) {
      reject(new Error("too many redirects"));
      return;
    }

    const urlObject = new URL(url);
    if (urlObject.protocol !== "https:") {
      reject(new Error(`refusing non-HTTPS download URL: ${url}`));
      return;
    }

    const request = https.get(
      urlObject,
      { headers: { "User-Agent": "starmetal-npm-wrapper" } },
      (response) => {
        if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
          const nextUrl = new URL(response.headers.location, urlObject).toString();
          fetchTextWithRedirects(nextUrl, maxRedirects - 1).then(resolve).catch(reject);
          return;
        }

        if (response.statusCode !== 200) {
          reject(new Error(`HTTP ${response.statusCode}: ${response.statusMessage}`));
          return;
        }

        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
        response.on("error", reject);
      },
    );

    request.on("error", reject);
    request.setTimeout(30000, () => {
      request.destroy();
      reject(new Error("download timeout"));
    });
  });
}

function retryWithBackoff(fn, maxAttempts = 3) {
  const delays = [1000, 2000, 4000];
  return (async function attempt(index = 0) {
    try {
      return await fn();
    } catch (error) {
      const message = String(error.message || error);
      const httpMatch = message.match(/HTTP ([0-9]+)/);
      const retryable =
        message.includes("timeout") ||
        message.includes("ECONNRESET") ||
        message.includes("ECONNREFUSED") ||
        message.includes("ETIMEDOUT") ||
        (httpMatch && Number(httpMatch[1]) >= 500);

      if (!retryable || index >= maxAttempts - 1) {
        throw error;
      }

      await new Promise((resolve) => setTimeout(resolve, delays[index]));
      return attempt(index + 1);
    }
  })();
}

function sha256File(filePath) {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(filePath));
  return hash.digest("hex");
}

function expectedDigest(checksumsText, assetName) {
  for (const line of checksumsText.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const parts = trimmed.split(/\s+/);
    const name = parts[parts.length - 1].replace(/^\*/, "");
    if (name === assetName) return parts[0].toLowerCase();
  }
  return null;
}

async function verifyChecksum(archivePath, assetName, checksumsUrl) {
  const checksumsText = await retryWithBackoff(() => fetchTextWithRedirects(checksumsUrl));
  const expected = expectedDigest(checksumsText, assetName);
  if (!expected) {
    throw new Error(`no checksum entry for ${assetName} in ${checksumsUrl}`);
  }

  const actual = sha256File(archivePath).toLowerCase();
  if (actual !== expected) {
    throw new Error(`checksum mismatch for ${assetName} (expected ${expected}, got ${actual})`);
  }
}

async function installBinary() {
  const { assetName, archiveUrl, checksumsUrl } = getReleaseAssets();
  const binDir = path.join(__dirname, "bin");
  const archivePath = path.join(binDir, assetName);
  const binaryName = os.type() === "Windows_NT" ? "sm.exe" : "sm";
  const binaryPath = path.join(binDir, binaryName);

  if (fs.existsSync(binaryPath)) {
    return;
  }

  fs.mkdirSync(binDir, { recursive: true });
  console.log(`Downloading sm ${version} from ${archiveUrl}`);
  await retryWithBackoff(() => downloadWithRedirects(archiveUrl, archivePath));
  await verifyChecksum(archivePath, assetName, checksumsUrl);

  if (archivePath.endsWith(".zip")) {
    const zip = new AdmZip(archivePath);
    zip.extractAllTo(binDir, true);
  } else {
    const { extract } = await import("tar");
    await extract({ file: archivePath, cwd: binDir });
  }

  fs.unlinkSync(archivePath);
  if (!fs.existsSync(binaryPath)) {
    throw new Error(`binary ${binaryName} not found after extracting ${assetName}`);
  }
  if (os.type() !== "Windows_NT") {
    fs.chmodSync(binaryPath, 0o755);
  }
}

installBinary().catch((error) => {
  console.error(`Error installing sm binary: ${error.message}`);
  process.exit(1);
});
