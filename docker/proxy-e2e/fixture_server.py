#!/usr/bin/env python3
"""Deterministic local upstream registry fixtures for Docker proxy E2E tests."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import tarfile
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

REQUEST_COUNTS: dict[str, int] = {}


def sha1_hex(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha512_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha512(data).digest()).decode("ascii")


def fixed_zip(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            info = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    return buffer.getvalue()


def fixed_tar_gz(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as gzipped:
        with tarfile.open(fileobj=gzipped, mode="w") as archive:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mtime = 0
                info.mode = 0o644
                archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def fixed_tar(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def pypi_wheel() -> bytes:
    dist_info = "sample_project-1.0.0.dist-info"
    files = {
        "sample_project/__init__.py": b'__version__ = "1.0.0"\n',
        f"{dist_info}/METADATA": (
            b"Metadata-Version: 2.1\n"
            b"Name: sample-project\n"
            b"Version: 1.0.0\n"
            b"Summary: StarMetal proxy E2E fixture\n"
        ),
        f"{dist_info}/WHEEL": (
            b"Wheel-Version: 1.0\n"
            b"Generator: starmetal-proxy-e2e\n"
            b"Root-Is-Purelib: true\n"
            b"Tag: py3-none-any\n"
        ),
        f"{dist_info}/RECORD": b"",
    }
    return fixed_zip(files)


def rubygem() -> bytes:
    metadata = b"""--- !ruby/object:Gem::Specification
name: samplegem
version: !ruby/object:Gem::Version
  version: 1.0.0
platform: ruby
authors:
- StarMetal
autorequire:
bindir: bin
cert_chain: []
date: 2024-01-01 00:00:00.000000000 Z
dependencies: []
description: StarMetal native proxy fixture
email: []
executables: []
extensions: []
extra_rdoc_files: []
files:
- lib/samplegem.rb
homepage:
licenses:
- MIT
metadata: {}
post_install_message:
rdoc_options: []
require_paths:
- lib
required_ruby_version: !ruby/object:Gem::Requirement
  requirements:
  - - ">="
    - !ruby/object:Gem::Version
      version: '0'
required_rubygems_version: !ruby/object:Gem::Requirement
  requirements:
  - - ">="
    - !ruby/object:Gem::Version
      version: '0'
requirements: []
rubygems_version: 3.5.0
signing_key:
specification_version: 4
summary: StarMetal fixture
test_files: []
"""
    data_tar = fixed_tar({"lib/samplegem.rb": b"module Samplegem\n  MARKER = 'starmetal'\nend\n"})
    metadata_gz = gzip.compress(metadata, mtime=0)
    data_gz = gzip.compress(data_tar, mtime=0)
    checksums = (
        b"---\n"
        + f"SHA256:\n  metadata.gz: {sha256_hex(metadata_gz)}\n".encode()
        + f"  data.tar.gz: {sha256_hex(data_gz)}\n".encode()
    )
    checksums_gz = gzip.compress(checksums, mtime=0)
    return fixed_tar(
        {
            "metadata.gz": metadata_gz,
            "data.tar.gz": data_gz,
            "checksums.yaml.gz": checksums_gz,
        }
    )


ARTIFACTS: dict[str, bytes] = {
    "pypi_wheel": pypi_wheel(),
    "npm_tgz": fixed_tar_gz(
        {
            "package/package.json": (
                b'{"name":"sample-npm","version":"1.0.0","main":"index.js","license":"MIT"}\n'
            ),
            "package/index.js": b"module.exports = 'starmetal-proxy-e2e';\n",
        }
    ),
    "cargo_crate": fixed_tar_gz(
        {
            "sample-crate-1.0.0/Cargo.toml": (
                b'[package]\nname = "sample-crate"\nversion = "1.0.0"\nedition = "2021"\n'
            ),
            "sample-crate-1.0.0/src/lib.rs": b"pub fn marker() -> &'static str { \"starmetal\" }\n",
        }
    ),
    "hex_tar": fixed_tar_gz(
        {
            "metadata.config": b'[{"name":"sample_hex"},{"version":"1.0.0"}].\n',
            "contents.tar.gz": fixed_tar_gz({"lib/sample_hex.ex": b"defmodule SampleHex do\nend\n"}),
        }
    ),
    "maven_jar": fixed_zip({"com/example/Sample.class": b"not-a-real-class"}),
    "maven_pom": (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        b"  <modelVersion>4.0.0</modelVersion>\n"
        b"  <groupId>com.example</groupId>\n"
        b"  <artifactId>sample-lib</artifactId>\n"
        b"  <version>1.0.0</version>\n"
        b"</project>\n"
    ),
    "rubygem": rubygem(),
    "nuget_nupkg": fixed_zip(
        {
            "sample.nuget.nuspec": (
                b'<?xml version="1.0" encoding="utf-8"?>\n'
                b"<package><metadata>"
                b"<id>sample.nuget</id><version>1.0.0</version>"
                b"<authors>StarMetal</authors><description>fixture</description>"
                b"</metadata></package>\n"
            ),
            "lib/net8.0/sample.nuget.dll": b"not-a-real-dll",
        }
    ),
    "pub_archive": fixed_tar_gz(
        {
            "pubspec.yaml": (
                b"name: sample_pub\n"
                b"version: 1.0.0\n"
                b"description: StarMetal fixture\n"
                b"environment:\n"
                b"  sdk: '>=3.0.0 <4.0.0'\n"
            ),
            "lib/sample_pub.dart": b"String marker() => 'starmetal';\n",
        }
    ),
}

ARTIFACTS["nuget_nuspec"] = (
    b'<?xml version="1.0" encoding="utf-8"?>\n'
    b"<package><metadata>"
    b"<id>sample.nuget</id><version>1.0.0</version>"
    b"<authors>StarMetal</authors><description>fixture</description>"
    b"</metadata></package>\n"
)


def protobuf_varint(value: int) -> bytes:
    output = bytearray()
    while value >= 0x80:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def protobuf_field(field: int, data: bytes) -> bytes:
    return protobuf_varint((field << 3) | 2) + protobuf_varint(len(data)) + data


def hex_registry_entry() -> bytes:
    checksum = hashlib.sha256(ARTIFACTS["hex_tar"]).digest()
    release = (
        protobuf_field(1, b"1.0.0")
        + protobuf_field(2, checksum)
        + protobuf_field(5, checksum)
    )
    package = (
        protobuf_field(1, release)
        + protobuf_field(2, b"sample_hex")
        + protobuf_field(3, b"hexpm")
    )
    signed = protobuf_field(1, package)
    return signed


def fixture_url(path: str) -> str:
    return f"http://fixture-upstream:8081{path}"


def pypi_project() -> dict[str, object]:
    filename = "sample_project-1.0.0-py3-none-any.whl"
    data = ARTIFACTS["pypi_wheel"]
    return {
        "meta": {"api-version": "1.0"},
        "name": "sample-project",
        "versions": ["1.0.0"],
        "files": [
            {
                "filename": filename,
                "url": fixture_url(f"/pypi/packages/{filename}"),
                "hashes": {"sha256": sha256_hex(data)},
                "requires-python": ">=3.10",
                "yanked": False,
                "size": len(data),
            }
        ],
    }


def npm_packument() -> dict[str, object]:
    data = ARTIFACTS["npm_tgz"]
    return {
        "name": "sample-npm",
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {
                "name": "sample-npm",
                "version": "1.0.0",
                "license": "MIT",
                "dist": {
                    "tarball": fixture_url("/npm/sample-npm/-/sample-npm-1.0.0.tgz"),
                    "shasum": sha1_hex(data),
                    "integrity": f"sha512-{sha512_b64(data)}",
                },
            }
        },
    }


def cargo_index() -> bytes:
    entry = {
        "name": "sample-crate",
        "vers": "1.0.0",
        "deps": [],
        "cksum": sha256_hex(ARTIFACTS["cargo_crate"]),
        "features": {},
        "yanked": False,
        "v": 2,
    }
    return (json.dumps(entry, separators=(",", ":")) + "\n").encode()


def hex_package() -> dict[str, object]:
    return {
        "name": "sample_hex",
        "url": fixture_url("/hex/api/packages/sample_hex"),
        "html_url": "https://example.invalid/sample_hex",
        "docs_html_url": "https://example.invalid/sample_hex/docs",
        "meta": {"description": "fixture", "licenses": ["MIT"], "maintainers": []},
        "releases": [
            {
                "version": "1.0.0",
                "url": fixture_url("/hex/api/packages/sample_hex/releases/1.0.0"),
                "has_docs": False,
                "inserted_at": "2024-01-01T00:00:00.000000Z",
                "updated_at": "2024-01-01T00:00:00.000000Z",
            }
        ],
        "inserted_at": "2024-01-01T00:00:00.000000Z",
        "updated_at": "2024-01-01T00:00:00.000000Z",
    }


def maven_metadata() -> bytes:
    return (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b"<metadata><groupId>com.example</groupId><artifactId>sample-lib</artifactId>"
        b"<versioning><latest>1.0.0</latest><release>1.0.0</release>"
        b"<versions><version>1.0.0</version></versions>"
        b"<lastUpdated>20240101000000</lastUpdated></versioning></metadata>\n"
    )


def rubygems_versions() -> bytes:
    checksum = sha256_hex(rubygems_info())
    return f"created_at: 2024-01-01T00:00:00Z\n---\nsamplegem 1.0.0 {checksum}\n".encode()


def rubygems_info() -> bytes:
    checksum = sha256_hex(ARTIFACTS["rubygem"])
    return f"---\n1.0.0 |checksum:{checksum}\n".encode()


def pub_package() -> dict[str, object]:
    checksum = sha256_hex(ARTIFACTS["pub_archive"])
    return {
        "name": "sample_pub",
        "latest": {
            "version": "1.0.0",
            "archive_url": fixture_url("/pub/api/archives/sample_pub-1.0.0.tar.gz"),
            "archive_sha256": checksum,
            "pubspec": {
                "name": "sample_pub",
                "version": "1.0.0",
                "environment": {"sdk": ">=3.0.0 <4.0.0"},
            },
        },
        "versions": [
            {
                "version": "1.0.0",
                "archive_url": fixture_url("/pub/api/archives/sample_pub-1.0.0.tar.gz"),
                "archive_sha256": checksum,
                "pubspec": {
                    "name": "sample_pub",
                    "version": "1.0.0",
                    "environment": {"sdk": ">=3.0.0 <4.0.0"},
                },
            }
        ],
    }


def route(path: str) -> tuple[int, str, bytes]:
    if path == "/__requests":
        return 200, "application/json", json.dumps(REQUEST_COUNTS, sort_keys=True).encode()
    if path == "/__health":
        return 200, "text/plain", b"ok"
    if path == "/npm/too-large":
        return 200, "application/json", json.dumps({"padding": "x" * 20000}).encode()

    routes: dict[str, tuple[str, bytes]] = {
        "/pypi/simple/sample-project/": ("application/vnd.pypi.simple.v1+json", json.dumps(pypi_project()).encode()),
        "/pypi/packages/sample_project-1.0.0-py3-none-any.whl": ("application/octet-stream", ARTIFACTS["pypi_wheel"]),
        "/npm/sample-npm": ("application/json", json.dumps(npm_packument()).encode()),
        "/npm/sample-npm/-/sample-npm-1.0.0.tgz": ("application/octet-stream", ARTIFACTS["npm_tgz"]),
        "/cargo-index/sa/mp/sample-crate": ("text/plain", cargo_index()),
        "/cargo-crates/sample-crate/sample-crate-1.0.0.crate": ("application/octet-stream", ARTIFACTS["cargo_crate"]),
        "/hex/api/packages/sample_hex": ("application/json", json.dumps(hex_package()).encode()),
        "/hex-repo/packages/sample_hex": ("application/octet-stream", hex_registry_entry()),
        "/hex-repo/tarballs/sample_hex-1.0.0.tar": ("application/octet-stream", ARTIFACTS["hex_tar"]),
        "/maven/com/example/sample-lib/maven-metadata.xml": ("application/xml", maven_metadata()),
        "/maven/com/example/sample-lib/1.0.0/sample-lib-1.0.0.pom": ("application/xml", ARTIFACTS["maven_pom"]),
        "/maven/com/example/sample-lib/1.0.0/sample-lib-1.0.0.jar": (
            "application/octet-stream",
            ARTIFACTS["maven_jar"],
        ),
        "/maven/com/example/sample-lib/1.0.0/sample-lib-1.0.0.pom.sha1": (
            "text/plain",
            sha1_hex(ARTIFACTS["maven_pom"]).encode(),
        ),
        "/maven/com/example/sample-lib/1.0.0/sample-lib-1.0.0.jar.sha1": (
            "text/plain",
            sha1_hex(ARTIFACTS["maven_jar"]).encode(),
        ),
        "/rubygems/versions": ("text/plain", rubygems_versions()),
        "/rubygems/info/samplegem": ("text/plain", rubygems_info()),
        "/rubygems/gems/samplegem-1.0.0.gem": ("application/octet-stream", ARTIFACTS["rubygem"]),
        "/nuget/v3/index.json": ("application/json", b'{"version":"3.0.0","resources":[]}'),
        "/nuget/v3-flatcontainer/sample.nuget/index.json": ("application/json", b'{"versions":["1.0.0"]}'),
        "/nuget/v3-flatcontainer/sample.nuget/1.0.0/sample.nuget.1.0.0.nupkg": (
            "application/octet-stream",
            ARTIFACTS["nuget_nupkg"],
        ),
        "/nuget/v3-flatcontainer/sample.nuget/1.0.0/sample.nuget.1.0.0.nupkg.sha512": (
            "text/plain",
            sha512_b64(ARTIFACTS["nuget_nupkg"]).encode(),
        ),
        "/nuget/v3-flatcontainer/sample.nuget/1.0.0/sample.nuget.nuspec": (
            "application/xml",
            ARTIFACTS["nuget_nuspec"],
        ),
        "/pub/api/packages/sample_pub": ("application/json", json.dumps(pub_package()).encode()),
        "/pub/api/archives/sample_pub-1.0.0.tar.gz": ("application/octet-stream", ARTIFACTS["pub_archive"]),
    }
    if path in routes:
        content_type, body = routes[path]
        return 200, content_type, body
    return 404, "text/plain", f"fixture route not found: {path}\n".encode()


class Handler(BaseHTTPRequestHandler):
    server_version = "starmetal-fixture-upstream/1"

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        REQUEST_COUNTS[path] = REQUEST_COUNTS.get(path, 0) + 1
        status, content_type, body = route(path)
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self) -> None:
        self.do_GET()

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"{self.log_date_time_string()} {self.address_string()} {fmt % args}", flush=True)


def wait_forever(host: str, port: int) -> None:
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"fixture upstream listening on {host}:{port}", flush=True)
    httpd.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args()
    wait_forever(args.host, args.port)


if __name__ == "__main__":
    main()
