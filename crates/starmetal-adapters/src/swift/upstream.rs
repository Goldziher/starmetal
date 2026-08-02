//! Registry-identifier -> git URL mapping and source-archive construction for the Swift Package
//! Registry proxy (ADR-0023, SE-0292).
//!
//! This is the seam between the route handlers in [`super`] and the
//! [`starmetal_git::GitMirror`] port: it never touches a git library directly, only the port
//! trait, so the concrete gitoxide backend stays confined to `starmetal-git`.
//!
//! # Registry identifier -> git URL mapping (scope)
//!
//! Unlike the Go module proxy and the Zig tarball proxy, a Swift registry identifier
//! (`{scope}.{name}`) carries no host component at all — there is nothing in the identifier itself
//! to derive a git remote from. So, unlike `go.module_overrides`/`zig.repo_overrides`, there is no
//! built-in well-known-host mapping here: every package this proxy serves must be listed in
//! `swift.package_overrides` (operator-trusted config; a `file://` URL is permitted, the seam for
//! offline testing).

use std::collections::HashMap;
use std::io::{Read as _, Write as _};

use bytes::Bytes;
use sha2::{Digest, Sha256};
use starmetal_core::error::{Result, StarmetalError};
use starmetal_git::GitMirror;

/// Resolve a `{scope}.{name}` registry identifier to the git remote URL it is mirrored from.
///
/// There is no default host mapping (see the module doc comment) — the identifier must be listed
/// verbatim in `overrides`.
pub fn resolve_package_url(identifier: &str, overrides: &HashMap<String, String>) -> Result<String> {
    overrides.get(identifier).cloned().ok_or_else(|| {
        StarmetalError::Adapter(format!(
            "unknown Swift package '{identifier}'; add an entry to swift.package_overrides -- a Swift \
             registry identifier carries no host to derive a git remote from automatically"
        ))
    })
}

/// Ensure `git_url` is mirrored and fresh, mapping the port's error at this crate's boundary.
pub async fn ensure_mirror(mirror: &dyn GitMirror, git_url: &str) -> Result<()> {
    mirror
        .ensure_mirror(git_url)
        .await
        .map_err(|err| StarmetalError::Upstream(err.to_string()))
}

/// List the mirror's tags/branches, mapping the port's error at this crate's boundary.
pub async fn list_refs(mirror: &dyn GitMirror, git_url: &str) -> Result<Vec<starmetal_git::GitRef>> {
    mirror
        .list_refs(git_url)
        .await
        .map_err(|err| StarmetalError::Upstream(err.to_string()))
}

/// Read a blob at `reference`, mapping the port's error at this crate's boundary.
pub async fn read_blob(mirror: &dyn GitMirror, git_url: &str, reference: &str, path: &str) -> Result<Option<Bytes>> {
    mirror
        .read_blob(git_url, reference, path)
        .await
        .map_err(|err| StarmetalError::Upstream(err.to_string()))
}

/// Produce a source-tree archive at `reference`, mapping the port's error at this crate's boundary.
pub async fn archive_zip(mirror: &dyn GitMirror, git_url: &str, reference: &str) -> Result<Bytes> {
    mirror
        .archive(git_url, reference, starmetal_git::ArchiveFormat::Zip)
        .await
        .map_err(|err| StarmetalError::Upstream(err.to_string()))
}

/// Re-prefix every entry of the tree archive `starmetal-git` produced (root-level, no top-level
/// directory) with `{name}/`, matching the layout `swift package archive-source` itself produces.
///
/// Confirmed empirically against the real Swift 6.3 toolchain: SwiftPM's registry download
/// extraction strips exactly one leading path component when the archive root contains exactly one
/// entry, and a root-level archive (whose root instead contains several entries, e.g. `Package.swift`
/// and `Sources/`) is extracted with **no** stripping at all — silently misplacing every entry one
/// level too shallow (`Sources/pkg/pkg.swift` lands at `pkg/pkg.swift`) and breaking the manifest's
/// declared target paths. Re-prefixing every entry under a single top-level directory first avoids
/// this; entry order is sorted by path for determinism, independent of the source archive's own
/// ordering (mirroring the Go module proxy's zip construction).
pub fn build_registry_zip(name: &str, source_zip: &[u8]) -> Result<Bytes> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(source_zip))
        .map_err(|err| StarmetalError::Upstream(format!("invalid source tree archive: {err}")))?;

    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|err| StarmetalError::Upstream(format!("invalid source tree archive entry: {err}")))?;
        if file.is_dir() {
            continue;
        }
        let entry_name = file.name().to_string();
        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|err| StarmetalError::Upstream(format!("failed to read tree archive entry: {err}")))?;
        entries.push((entry_name, data));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut output = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut output);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o644);
        for (entry_name, data) in entries {
            let prefixed = format!("{name}/{entry_name}");
            writer
                .start_file(prefixed, options)
                .map_err(|err| StarmetalError::Upstream(format!("failed to write registry zip entry: {err}")))?;
            writer
                .write_all(&data)
                .map_err(|err| StarmetalError::Upstream(format!("failed to write registry zip entry: {err}")))?;
        }
        writer
            .finish()
            .map_err(|err| StarmetalError::Upstream(format!("failed to finalize registry zip: {err}")))?;
    }
    Ok(Bytes::from(output.into_inner()))
}

/// Lowercase-hex SHA-256 digest of `bytes`, as required by SE-0292's release-metadata `checksum`
/// field. Deliberately SHA-256, not blake3: the registry protocol mandates it.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

/// Base64-encoded SHA-256 digest of `bytes`, for the `Digest: sha-256=<...>` response header
/// (RFC 3230 / draft-ietf-httpbis-digest-headers).
pub fn sha256_base64(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_only_via_package_overrides() {
        let mut overrides = HashMap::new();
        overrides.insert("test.fixture".to_string(), "file:///tmp/fixture.git".to_string());
        assert_eq!(
            resolve_package_url("test.fixture", &overrides).unwrap(),
            "file:///tmp/fixture.git"
        );
    }

    #[test]
    fn rejects_an_identifier_without_an_override() {
        let overrides = HashMap::new();
        let err = resolve_package_url("test.fixture", &overrides).unwrap_err();
        assert!(err.to_string().contains("package_overrides"));
    }

    fn read_source_zip(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut buffer = std::io::Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut buffer);
            let options = zip::write::SimpleFileOptions::default();
            for (name, contents) in entries {
                writer.start_file(*name, options).unwrap();
                writer.write_all(contents.as_bytes()).unwrap();
            }
            writer.finish().unwrap();
        }
        buffer.into_inner()
    }

    fn zip_entry_names(bytes: &[u8]) -> Vec<String> {
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec())).unwrap();
        (0..archive.len())
            .map(|index| archive.by_index(index).unwrap().name().to_string())
            .collect()
    }

    #[test]
    fn prefixes_every_entry_with_the_package_name() {
        let source = read_source_zip(&[
            ("Package.swift", "// swift-tools-version:5.9\n"),
            ("Sources/fixture/fixture.swift", "public struct Fixture {}\n"),
        ]);
        let registry_zip = build_registry_zip("fixture", &source).unwrap();
        let names = zip_entry_names(&registry_zip);
        assert_eq!(
            names,
            vec!["fixture/Package.swift", "fixture/Sources/fixture/fixture.swift"]
        );
    }

    #[test]
    fn registry_zip_construction_is_deterministic() {
        let source = read_source_zip(&[("b.swift", "// b\n"), ("a.swift", "// a\n")]);
        let first = build_registry_zip("fixture", &source).unwrap();
        let second = build_registry_zip("fixture", &source).unwrap();
        assert_eq!(first, second);
        assert_eq!(zip_entry_names(&first), vec!["fixture/a.swift", "fixture/b.swift"]);
    }

    #[test]
    fn sha256_hex_is_a_lowercase_64_char_digest() {
        let digest = sha256_hex(b"hello");
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        assert_eq!(
            digest,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn sha256_base64_round_trips_the_same_digest_as_hex() {
        let hex_digest = sha256_hex(b"hello");
        let base64_digest = sha256_base64(b"hello");
        let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &base64_digest).unwrap();
        assert_eq!(hex::encode(decoded), hex_digest);
    }
}
