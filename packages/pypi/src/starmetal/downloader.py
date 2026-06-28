from __future__ import annotations

import hashlib
import os
import platform
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Optional, Tuple, Union
from urllib.error import URLError
from urllib.request import Request, urlopen

import certifi


def _is_apple_silicon(machine: str) -> bool:
    if machine in {"aarch64", "arm64"}:
        return True
    try:
        result = subprocess.run(
            ["sysctl", "-n", "hw.optional.arm64"],
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, ValueError):
        return False
    return result.stdout.strip() == "1"


def _platform_triple() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "windows":
        if machine in {"amd64", "x86_64"}:
            return "x86_64-pc-windows-msvc"
        raise RuntimeError(f"Unsupported Windows architecture: {machine}")

    if system == "linux":
        if machine in {"amd64", "x86_64"}:
            return "x86_64-unknown-linux-gnu"
        if machine in {"aarch64", "arm64"}:
            return "aarch64-unknown-linux-gnu"
        raise RuntimeError(f"Unsupported Linux architecture: {machine}")

    if system == "darwin":
        if _is_apple_silicon(machine):
            return "aarch64-apple-darwin"
        if machine in {"amd64", "x86_64"}:
            return "x86_64-apple-darwin"
        raise RuntimeError(f"Unsupported macOS architecture: {machine}")

    raise RuntimeError(f"Unsupported platform: {system} {machine}")


def _python_version_to_tag(version: str) -> str:
    if "rc" in version:
        core, suffix = version.split("rc", 1)
        return f"{core}-rc.{suffix}"
    return version


def _asset(version: str) -> Tuple[str, str, str, str]:
    tag = _python_version_to_tag(version)
    triple = _platform_triple()
    ext = "zip" if "windows" in triple else "tar.gz"
    asset_name = f"starmetal-{triple}.{ext}"
    base = f"https://github.com/Goldziher/starmetal/releases/download/v{tag}"
    return (
        f"{base}/{asset_name}",
        ext,
        asset_name,
        f"{base}/starmetal_{tag}_checksums.txt",
    )


def _is_retryable_error(error: Union[Exception, str]) -> bool:
    message = str(error).lower()
    return any(
        part in message
        for part in [
            "timeout",
            "connection",
            "refused",
            "reset",
            "unreachable",
            "http 5",
            "temporarily unavailable",
        ]
    )


def _retry_with_backoff(fn, max_attempts: int = 3) -> Optional[str]:
    delays = [1, 2, 4]
    for attempt in range(max_attempts):
        try:
            return fn()
        except Exception as error:
            if not _is_retryable_error(error) or attempt >= max_attempts - 1:
                raise
            delay = delays[attempt]
            print(
                f"Transient error (attempt {attempt + 1}/{max_attempts}): {error}; retrying in {delay}s...",
                file=sys.stderr,
            )
            time.sleep(delay)
    return None


def _download(url: str, destination: Path) -> None:
    def attempt() -> None:
        request = Request(url, headers={"User-Agent": "starmetal-python-wrapper"})
        context = ssl.create_default_context(cafile=certifi.where())
        try:
            with urlopen(request, timeout=30, context=context) as response:
                if response.status != 200:
                    raise RuntimeError(f"HTTP {response.status}: {response.reason}")
                destination.write_bytes(response.read())
        except URLError as exc:
            raise RuntimeError(f"Failed to download binary: {exc}") from exc

    _retry_with_backoff(attempt)


def _download_text(url: str) -> str:
    def attempt() -> str:
        request = Request(url, headers={"User-Agent": "starmetal-python-wrapper"})
        context = ssl.create_default_context(cafile=certifi.where())
        try:
            with urlopen(request, timeout=30, context=context) as response:
                if response.status != 200:
                    raise RuntimeError(f"HTTP {response.status}: {response.reason}")
                return response.read().decode("utf-8")
        except URLError as exc:
            raise RuntimeError(f"Failed to download checksums: {exc}") from exc

    text = _retry_with_backoff(attempt)
    if text is None:
        raise RuntimeError("Failed to download checksums")
    return text


def _expected_digest(checksums_text: str, asset_name: str) -> Optional[str]:
    for line in checksums_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        if parts[-1].lstrip("*") == asset_name:
            return parts[0].lower()
    return None


def _verify_checksum(archive: Path, asset_name: str, checksums_url: str) -> None:
    checksums_text = _download_text(checksums_url)
    expected = _expected_digest(checksums_text, asset_name)
    if expected is None:
        raise RuntimeError(f"no checksum entry for {asset_name} in {checksums_url}")

    actual = hashlib.sha256(archive.read_bytes()).hexdigest().lower()
    if actual != expected:
        raise RuntimeError(
            f"checksum mismatch for {asset_name} (expected {expected}, got {actual})"
        )


def _safe_extract_tar(archive: Path, destination: Path) -> None:
    destination_root = destination.resolve()
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            target = (destination / member.name).resolve()
            try:
                target.relative_to(destination_root)
            except ValueError as exc:
                raise RuntimeError(f"archive member escapes destination: {member.name}") from exc
        tar.extractall(destination)


def _safe_extract_zip(archive: Path, destination: Path) -> None:
    destination_root = destination.resolve()
    with zipfile.ZipFile(archive) as zip_file:
        for member in zip_file.infolist():
            target = (destination / member.filename).resolve()
            try:
                target.relative_to(destination_root)
            except ValueError as exc:
                raise RuntimeError(f"archive member escapes destination: {member.filename}") from exc
        zip_file.extractall(destination)


def _extract(archive: Path, ext: str, destination: Path) -> None:
    if ext == "zip":
        _safe_extract_zip(archive, destination)
    else:
        _safe_extract_tar(archive, destination)


def _binary_name() -> str:
    return "sm.exe" if platform.system().lower() == "windows" else "sm"


def _cache_dir(version: str) -> Path:
    path = Path.home() / ".cache" / "starmetal" / version
    path.mkdir(parents=True, exist_ok=True)
    return path


def ensure_binary() -> str:
    from starmetal import __version__

    override = os.getenv("STARMETAL_BINARY")
    if override:
        return override

    cache_dir = _cache_dir(__version__)
    binary_path = cache_dir / _binary_name()
    if binary_path.exists() and os.access(binary_path, os.X_OK):
        return str(binary_path)

    lock_path = cache_dir / ".lock"
    lock_acquired = False
    try:
        lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        os.close(lock_fd)
        lock_acquired = True
    except FileExistsError:
        for _ in range(300):
            time.sleep(0.1)
            if binary_path.exists() and os.access(binary_path, os.X_OK):
                return str(binary_path)
        raise RuntimeError(f"Timeout waiting for concurrent sm installation in {cache_dir}")

    try:
        if binary_path.exists() and os.access(binary_path, os.X_OK):
            return str(binary_path)

        archive_url, ext, asset_name, checksums_url = _asset(__version__)
        print(f"Downloading sm {__version__}...", file=sys.stderr)
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            archive_path = tmpdir / asset_name
            _download(archive_url, archive_path)
            _verify_checksum(archive_path, asset_name, checksums_url)

            staging = tmpdir / "staging"
            staging.mkdir()
            _extract(archive_path, ext, staging)

            if cache_dir.exists():
                shutil.rmtree(cache_dir)
            staging.replace(cache_dir)

        if not binary_path.exists():
            raise RuntimeError(f"binary {_binary_name()} not found after extracting {asset_name}")
        if platform.system().lower() != "windows":
            binary_path.chmod(0o755)
        return str(binary_path)
    finally:
        if lock_acquired:
            try:
                lock_path.unlink()
            except FileNotFoundError:
                pass


def run_sm(args: list[str]) -> None:
    binary = ensure_binary()
    result = subprocess.run([binary, *args], check=False)
    sys.exit(result.returncode)
