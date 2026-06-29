#!/usr/bin/env python3
"""Black-box HTTP assertions for the StarMetal Docker proxy E2E harness."""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


def request(
    base_url: str,
    path: str,
    token: str | None,
    *,
    method: str = "GET",
    body: bytes | None = None,
    extra_headers: dict[str, str] | None = None,
    expected: int | tuple[int, ...] = 200,
) -> Response:
    headers = dict(extra_headers or {})
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(f"{base_url}{path}", data=body, headers=headers, method=method)
    try:
        with urlopen(req, timeout=20) as response:
            status = response.status
            data = response.read()
            result = Response(status, {k.lower(): v for k, v in response.headers.items()}, data)
    except HTTPError as error:
        data = error.read()
        result = Response(error.code, {k.lower(): v for k, v in error.headers.items()}, data)
    except URLError as error:
        raise AssertionError(f"{method} {path} failed: {error}") from error

    expected_values = (expected,) if isinstance(expected, int) else expected
    if result.status not in expected_values:
        raise AssertionError(
            f"{method} {path} expected {expected_values}, got {result.status}: {result.text()[:500]}"
        )
    return result


def wait_for_health(base_url: str, token: str) -> None:
    last_error: Exception | None = None
    for _ in range(60):
        try:
            response = request(base_url, "/healthz", token, expected=200)
            if response.body == b"ok":
                return
        except Exception as error:  # noqa: BLE001 - test harness prints the final failure.
            last_error = error
        time.sleep(1)
    raise AssertionError(f"StarMetal did not become healthy: {last_error}")


def assert_contains(value: str, needle: str, label: str) -> None:
    if needle not in value:
        raise AssertionError(f"{label} missing {needle!r}: {value[:500]}")


def assert_body(response: Response, minimum_size: int, label: str) -> None:
    if len(response.body) < minimum_size:
        raise AssertionError(f"{label} unexpectedly small: {len(response.body)} bytes")


def exercise_pypi(base_url: str, token: str) -> None:
    project = request(
        base_url,
        "/pypi/simple/sample-project/",
        token,
        extra_headers={"Accept": "application/vnd.pypi.simple.v1+json"},
    ).json()
    assert project["name"] == "sample-project"
    file_url = project["files"][0]["url"]
    assert_contains(file_url, "/pypi/packages/sample-project/1.0.0/", "PyPI rewritten URL")
    wheel = request(
        base_url,
        "/pypi/packages/sample-project/1.0.0/sample_project-1.0.0-py3-none-any.whl",
        token,
    )
    assert_body(wheel, 200, "PyPI wheel")


def exercise_npm(base_url: str, token: str) -> None:
    packument = request(base_url, "/npm/sample-npm", token).json()
    assert packument["name"] == "sample-npm"
    tarball = packument["versions"]["1.0.0"]["dist"]["tarball"]
    assert tarball == "http://starmetal:8080/npm/sample-npm/-/sample-npm-1.0.0.tgz"
    data = request(base_url, "/npm/sample-npm/-/sample-npm-1.0.0.tgz", token)
    assert_body(data, 100, "npm tarball")


def exercise_cargo(base_url: str, token: str) -> None:
    config = request(base_url, "/cargo/config.json", token).json()
    assert config["dl"] == "http://starmetal:8080/cargo/crates/{crate}/{version}/download"
    index = request(base_url, "/cargo/sa/mp/sample-crate", token)
    lines = [json.loads(line) for line in index.text().splitlines() if line.strip()]
    assert lines[0]["name"] == "sample-crate"
    crate = request(base_url, "/cargo/crates/sample-crate/1.0.0/download", token)
    assert_body(crate, 100, "Cargo crate")


def exercise_hex(base_url: str, token: str) -> None:
    package = request(base_url, "/hex/api/packages/sample_hex", token).json()
    assert package["name"] == "sample_hex"
    assert package["releases"][0]["url"] == "/hex/tarballs/sample_hex-1.0.0.tar"
    registry_entry = request(base_url, "/hex/packages/sample_hex", token)
    assert_body(registry_entry, 10, "Hex registry entry")
    tarball = request(base_url, "/hex/tarballs/sample_hex-1.0.0.tar", token)
    assert_body(tarball, 100, "Hex tarball")


def exercise_maven(base_url: str, token: str) -> None:
    metadata = request(base_url, "/maven/com/example/sample-lib/maven-metadata.xml", token)
    assert_contains(metadata.text(), "<version>1.0.0</version>", "Maven metadata")
    pom = request(base_url, "/maven/com/example/sample-lib/1.0.0/sample-lib-1.0.0.pom", token)
    assert_contains(pom.text(), "<artifactId>sample-lib</artifactId>", "Maven POM")
    jar = request(base_url, "/maven/com/example/sample-lib/1.0.0/sample-lib-1.0.0.jar", token)
    assert_body(jar, 20, "Maven jar")
    sha1 = request(base_url, "/maven/com/example/sample-lib/1.0.0/sample-lib-1.0.0.jar.sha1", token)
    assert len(sha1.text().strip()) == 40


def exercise_rubygems(base_url: str, token: str) -> None:
    versions = request(base_url, "/rubygems/versions", token)
    assert_contains(versions.text(), "samplegem 1.0.0", "RubyGems versions")
    info = request(base_url, "/rubygems/info/samplegem", token)
    assert_contains(info.text(), "checksum:", "RubyGems info")
    gem = request(base_url, "/rubygems/gems/samplegem-1.0.0.gem", token)
    assert_body(gem, 10, "RubyGems gem")


def exercise_nuget(base_url: str, token: str) -> None:
    index = request(base_url, "/nuget/v3/index.json", token).json()
    resources = json.dumps(index["resources"])
    assert_contains(resources, "http://starmetal:8080/nuget/v3-flatcontainer/", "NuGet resource URL")
    versions = request(base_url, "/nuget/v3-flatcontainer/sample.nuget/index.json", token).json()
    assert versions["versions"] == ["1.0.0"]
    nupkg = request(
        base_url,
        "/nuget/v3-flatcontainer/sample.nuget/1.0.0/sample.nuget.1.0.0.nupkg",
        token,
    )
    assert_body(nupkg, 100, "NuGet nupkg")
    nuspec = request(base_url, "/nuget/v3-flatcontainer/sample.nuget/1.0.0/sample.nuget.nuspec", token)
    assert_contains(nuspec.text(), "<id>sample.nuget</id>", "NuGet nuspec")
    sha512 = request(
        base_url,
        "/nuget/v3-flatcontainer/sample.nuget/1.0.0/sample.nuget.1.0.0.nupkg.sha512",
        token,
    )
    if len(sha512.text().strip()) < 40:
        raise AssertionError("NuGet sha512 sidecar is too short")
    registration = request(base_url, "/nuget/v3/registration/sample.nuget/index.json", token).json()
    assert registration["items"][0]["items"][0]["catalogEntry"]["id"] == "sample.nuget"


def exercise_pub(base_url: str, token: str) -> None:
    package = request(base_url, "/pub/api/packages/sample_pub", token).json()
    assert package["name"] == "sample_pub"
    archive_url = package["versions"][0]["archive_url"]
    assert archive_url == "http://starmetal:8080/pub/api/archives/sample_pub-1.0.0.tar.gz"
    version = request(base_url, "/pub/api/packages/sample_pub/versions/1.0.0", token).json()
    assert version["version"] == "1.0.0"
    archive = request(base_url, "/pub/api/archives/sample_pub-1.0.0.tar.gz", token)
    assert_body(archive, 80, "pub archive")


def exercise_common(base_url: str, token: str, phase: str) -> None:
    wait_for_health(base_url, token)

    request(base_url, "/pypi/simple/sample-project/", None, expected=401)
    cors = request(
        base_url,
        "/healthz",
        token,
        extra_headers={"Origin": "http://client.local"},
        expected=200,
    )
    if cors.headers.get("access-control-allow-origin") != "http://client.local":
        raise AssertionError(f"CORS did not allow configured origin in {phase}: {cors.headers}")

    for exercise in [
        exercise_pypi,
        exercise_npm,
        exercise_cargo,
        exercise_hex,
        exercise_maven,
        exercise_rubygems,
        exercise_nuget,
        exercise_pub,
    ]:
        exercise(base_url, token)


def exercise_online(base_url: str, fixture_url: str, token: str) -> None:
    exercise_common(base_url, token, "online")
    too_large = request(base_url, "/npm/too-large", token, expected=502)
    assert too_large.text() == "upstream registry request failed"
    too_large_upload = request(
        base_url,
        "/pypi/legacy/",
        token,
        method="POST",
        body=b"x" * 8192,
        extra_headers={"Content-Type": "application/octet-stream"},
        expected=(413, 400),
    )
    if too_large_upload.status == 400:
        raise AssertionError("upload limit did not reject oversized body before adapter parsing")

    counts = request(fixture_url, "/__requests", None).json()
    required_upstream_paths = [
        "/pypi/simple/sample-project/",
        "/pypi/packages/sample_project-1.0.0-py3-none-any.whl",
        "/npm/sample-npm",
        "/npm/sample-npm/-/sample-npm-1.0.0.tgz",
        "/cargo-index/sa/mp/sample-crate",
        "/cargo-crates/sample-crate/sample-crate-1.0.0.crate",
        "/hex/api/packages/sample_hex",
        "/hex-repo/packages/sample_hex",
        "/hex-repo/tarballs/sample_hex-1.0.0.tar",
        "/maven/com/example/sample-lib/maven-metadata.xml",
        "/maven/com/example/sample-lib/1.0.0/sample-lib-1.0.0.jar",
        "/rubygems/info/samplegem",
        "/rubygems/gems/samplegem-1.0.0.gem",
        "/nuget/v3-flatcontainer/sample.nuget/index.json",
        "/nuget/v3-flatcontainer/sample.nuget/1.0.0/sample.nuget.1.0.0.nupkg",
        "/pub/api/packages/sample_pub",
        "/pub/api/archives/sample_pub-1.0.0.tar.gz",
    ]
    missing = [path for path in required_upstream_paths if counts.get(path, 0) < 1]
    if missing:
        raise AssertionError(f"fixture upstream was not hit for: {missing}; counts={counts}")


def exercise_cached(base_url: str, token: str) -> None:
    exercise_common(base_url, token, "cached")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--fixture-url")
    parser.add_argument("--token", required=True)
    parser.add_argument("--phase", choices=["online", "cached"], required=True)
    args = parser.parse_args()

    if args.phase == "online":
        if not args.fixture_url:
            parser.error("--fixture-url is required for online phase")
        exercise_online(args.base_url.rstrip("/"), args.fixture_url.rstrip("/"), args.token)
    else:
        exercise_cached(args.base_url.rstrip("/"), args.token)

    print(f"docker proxy HTTP assertions passed: {args.phase}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
