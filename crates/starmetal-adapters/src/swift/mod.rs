//! Swift Package Registry (SE-0292) proxy (ADR-0023).
//!
//! `swift package resolve`/`swift build` speak the [Swift Package Registry HTTP
//! protocol](https://github.com/swiftlang/swift-package-manager/blob/main/Documentation/PackageRegistry/Registry.md)
//! against an upstream git repository's tagged refs, translating git refs and trees into the
//! registry's JSON/archive shapes through the [`starmetal_git::GitMirror`] port — never through
//! `PackageService` — mirroring `starmetal_adapters::go` and `starmetal_adapters::zig`'s
//! architecture.
//!
//! # Routes
//!
//! Mounted at the repository's own name (`/swift` by default), matching every other adapter:
//!
//! - `GET /{scope}/{name}` — list releases
//! - `GET /{scope}/{name}/{version}` — release metadata
//! - `GET /{scope}/{name}/{version}/Package.swift` — manifest
//! - `GET /{scope}/{name}/{version}.zip` — source archive
//!
//! Every response carries `Content-Version: 1`, per the protocol.
//!
//! # Registry identifier -> git URL mapping (scope)
//!
//! Unlike the Go module proxy and the Zig tarball proxy, a Swift registry identifier
//! (`{scope}.{name}`) carries no host component — there is nothing in the identifier to derive a
//! git remote from automatically. Every package must be listed in `swift.package_overrides` (see
//! [`upstream`]); this is an honest scope boundary, not an oversight.
//!
//! # Source-archive layout
//!
//! The archive `starmetal-git` produces has no top-level directory prefix (every entry sits at the
//! tree root). Unlike the Zig tarball proxy, this layout does **not** work as-is: empirical testing
//! against the real Swift 6.3 toolchain (building a fixture package, serving it, and running
//! `swift package resolve`/`swift build` against it) showed SwiftPM's registry download extraction
//! strips exactly one leading path component only when the archive root contains exactly one entry.
//! A root-level archive (whose root instead holds several entries — at minimum `Package.swift` and
//! `Sources/`) is extracted with **no** stripping, silently misplacing every entry one level too
//! shallow (`Sources/pkg/pkg.swift` lands at `pkg/pkg.swift`) and breaking the manifest's declared
//! target paths (`swift build` then fails with `invalid custom path 'Sources/pkg' for target
//! 'pkg'`). [`upstream::build_registry_zip`] re-prefixes every entry with `{name}/` — the same
//! layout `swift package archive-source` itself produces — which resolves and builds correctly.
//! This mirrors the Go module proxy's zip re-prefixing step, not the Zig tarball proxy's
//! serve-as-is.
//!
//! # Scope
//!
//! In scope: a tagged semver ref of a repository whose package sources live at that repository's
//! root, served through the registry's list/metadata/manifest/archive endpoints.
//!
//! Out of scope for this increment:
//!
//! - Version-specific manifests (`Package.swift?swift-version=`) — only the unqualified manifest is
//!   served.
//! - The `metadata` object in release metadata (author, description, repository links, ...) — always
//!   an empty object.
//! - Package signing (`signature` resources) — SwiftPM is configured to allow unsigned archives in
//!   the live e2e; a production deployment fronting this proxy with a signing requirement is out of
//!   scope.
//! - Pagination, publishing, and the identifiers/lookup-by-URL endpoints.
//! - Untagged refs (arbitrary branches or commits) and non-semver tags — only tags whose name is (or
//!   is `v`-prefixed) a valid semantic version are resolved.

pub mod models;
pub mod upstream;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{OriginalUri, Path, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use starmetal_core::config::Config;
use starmetal_core::error::StarmetalError;
use starmetal_git::{GitMirror, GitRefKind};

use self::models::{ReleaseLink, ReleaseMetadata, ReleaseResource, SwiftRequest, parse_swift_request};
use self::upstream::{
    SwiftArchiveCache, ensure_mirror, get_or_build_archive, list_refs, read_blob, resolve_package_url,
};

/// State a caller must expose to mount the Swift Package Registry proxy router.
pub trait HasSwiftState: Clone + Send + Sync + 'static {
    fn config(&self) -> &Arc<Config>;
    fn git_mirror(&self) -> &Arc<dyn GitMirror>;
    /// The per-`(git_url, commit_oid)` built-archive cache (see [`upstream::SwiftArchiveCache`]),
    /// shared by the release-metadata and archive endpoints so a `swift package resolve` builds and
    /// hashes the registry zip once, not twice.
    fn archive_cache(&self) -> &Arc<SwiftArchiveCache>;
}

/// `Content-Version`, required on every response by the registry protocol.
fn content_version_header() -> HeaderName {
    HeaderName::from_static("content-version")
}

/// `Digest`, carrying the served archive's checksum (RFC 3230 / draft-ietf-httpbis-digest-headers).
fn digest_header() -> HeaderName {
    HeaderName::from_static("digest")
}

/// Stamp `Content-Version: 1` onto every response this adapter produces, success or error alike.
fn with_content_version(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(content_version_header(), HeaderValue::from_static("1"));
    response
}

/// The absolute URL SwiftPM should use to fetch a release's metadata, derived from the list
/// request's own mount path (`request_path`, e.g. `/swift/{scope}/{name}`) rather than a hardcoded
/// `/swift/` prefix — so the emitted link stays correct when an operator mounts the Swift proxy
/// under a non-default repository name (`[[repositories]] name = "my-swift"`).
fn release_metadata_url(base_url: &str, request_path: &str, version: &str) -> String {
    let path = request_path.trim_end_matches('/');
    format!("{base_url}{path}/{version}")
}

/// Build the Swift Package Registry router. `{scope}` and `{name}` are always single path segments
/// per SE-0292, so (unlike the Go module proxy and the Zig tarball proxy) no catch-all is needed for
/// them; only the version-bearing tail is a wildcard, since it may be `{version}`, `{version}.zip`,
/// or `{version}/Package.swift`.
pub fn router<S: HasSwiftState>() -> Router<S> {
    Router::new()
        .route("/{scope}/{name}", get(list_releases::<S>))
        .route("/{scope}/{name}/{*tail}", get(dispatch_tail::<S>))
}

async fn list_releases<S: HasSwiftState>(
    State(state): State<S>,
    Path((scope, name)): Path<(String, String)>,
    OriginalUri(original_uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let response = list_releases_inner(&state, &scope, &name, original_uri.path(), &headers).await;
    with_content_version(response.unwrap_or_else(IntoResponse::into_response))
}

async fn list_releases_inner<S: HasSwiftState>(
    state: &S,
    scope: &str,
    name: &str,
    request_path: &str,
    headers: &HeaderMap,
) -> Result<Response, (StatusCode, String)> {
    let identifier = models::registry_identifier(scope, name);
    let git_url =
        resolve_package_url(&identifier, &state.config().swift.package_overrides).map_err(|err| map_error(&err))?;
    let mirror = state.git_mirror().as_ref();
    ensure_mirror(mirror, &git_url).await.map_err(|err| map_error(&err))?;

    let base_url = crate::public_base_url(state.config(), headers);
    let refs = list_refs(mirror, &git_url).await.map_err(|err| map_error(&err))?;
    let releases: std::collections::BTreeMap<String, ReleaseLink> = refs
        .into_iter()
        .filter(|reference| reference.kind == GitRefKind::Tag)
        .filter_map(|reference| models::normalize_version_tag(&reference.name))
        .map(|version| {
            let url = release_metadata_url(&base_url, request_path, &version);
            (version, ReleaseLink { url })
        })
        .collect();

    json_response(&models::ReleasesResponse { releases })
}

async fn dispatch_tail<S: HasSwiftState>(
    State(state): State<S>,
    Path((scope, name, tail)): Path<(String, String, String)>,
) -> Response {
    let response = dispatch_tail_inner(&state, &scope, &name, &tail).await;
    with_content_version(response.unwrap_or_else(IntoResponse::into_response))
}

async fn dispatch_tail_inner<S: HasSwiftState>(
    state: &S,
    scope: &str,
    name: &str,
    tail: &str,
) -> Result<Response, (StatusCode, String)> {
    let request = parse_swift_request(tail)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "unrecognized Swift registry path".to_string()))?;

    let identifier = models::registry_identifier(scope, name);
    let git_url =
        resolve_package_url(&identifier, &state.config().swift.package_overrides).map_err(|err| map_error(&err))?;
    let mirror = state.git_mirror().as_ref();
    ensure_mirror(mirror, &git_url).await.map_err(|err| map_error(&err))?;

    let max_archive_bytes = state.config().swift.max_archive_bytes;
    let cache = state.archive_cache().as_ref();
    match request {
        SwiftRequest::Metadata(version) => {
            release_metadata(mirror, cache, &identifier, &git_url, name, &version, max_archive_bytes).await
        }
        SwiftRequest::Manifest(version) => manifest(mirror, &identifier, &git_url, &version).await,
        SwiftRequest::Archive(version) => {
            archive(mirror, cache, &identifier, &git_url, name, &version, max_archive_bytes).await
        }
    }
}

/// Resolve `version` (the normalized, `v`-free semver the protocol always requests) to the tag name
/// that names it, rejecting anything that is not a real tagged release before doing further work.
async fn resolve_tag(
    mirror: &dyn GitMirror,
    identifier: &str,
    git_url: &str,
    version: &str,
) -> Result<String, (StatusCode, String)> {
    if models::normalize_version_tag(version).as_deref() != Some(version) {
        return Err(not_found(identifier, version));
    }
    let refs = list_refs(mirror, git_url).await.map_err(|err| map_error(&err))?;
    refs.into_iter()
        .filter(|reference| reference.kind == GitRefKind::Tag)
        .find_map(|reference| {
            (models::normalize_version_tag(&reference.name).as_deref() == Some(version)).then_some(reference.name)
        })
        .ok_or_else(|| not_found(identifier, version))
}

async fn release_metadata(
    mirror: &dyn GitMirror,
    cache: &SwiftArchiveCache,
    identifier: &str,
    git_url: &str,
    name: &str,
    version: &str,
    max_archive_bytes: u64,
) -> Result<Response, (StatusCode, String)> {
    let tag = resolve_tag(mirror, identifier, git_url, version).await?;
    let cached = get_or_build_archive(cache, mirror, git_url, &tag, name, max_archive_bytes)
        .await
        .map_err(|err| map_error(&err))?;

    json_response(&ReleaseMetadata {
        id: identifier.to_string(),
        version: version.to_string(),
        resources: vec![ReleaseResource {
            name: "source-archive".to_string(),
            kind: "application/zip".to_string(),
            checksum: cached.checksum_hex.clone(),
        }],
        metadata: serde_json::json!({}),
    })
}

async fn manifest(
    mirror: &dyn GitMirror,
    identifier: &str,
    git_url: &str,
    version: &str,
) -> Result<Response, (StatusCode, String)> {
    let tag = resolve_tag(mirror, identifier, git_url, version).await?;
    let contents = read_blob(mirror, git_url, &tag, "Package.swift")
        .await
        .map_err(|err| map_error(&err))?
        .ok_or_else(|| not_found(identifier, version))?;
    Ok(([(header::CONTENT_TYPE, "text/x-swift")], Body::from(contents)).into_response())
}

async fn archive(
    mirror: &dyn GitMirror,
    cache: &SwiftArchiveCache,
    identifier: &str,
    git_url: &str,
    name: &str,
    version: &str,
    max_archive_bytes: u64,
) -> Result<Response, (StatusCode, String)> {
    let tag = resolve_tag(mirror, identifier, git_url, version).await?;
    let cached = get_or_build_archive(cache, mirror, git_url, &tag, name, max_archive_bytes)
        .await
        .map_err(|err| map_error(&err))?;
    let digest_value = format!("sha-256={}", cached.checksum_base64);

    let disposition_value = format!("attachment; filename=\"{name}-{version}.zip\"");
    let headers = [
        (header::CONTENT_TYPE, HeaderValue::from_static("application/zip")),
        (
            header::CONTENT_DISPOSITION,
            HeaderValue::from_str(&disposition_value).unwrap_or_else(|_| HeaderValue::from_static("attachment")),
        ),
        (
            digest_header(),
            HeaderValue::from_str(&digest_value).unwrap_or_else(|_| HeaderValue::from_static("")),
        ),
    ];
    Ok((headers, Body::from(cached.registry_zip.clone())).into_response())
}

fn not_found(identifier: &str, version: &str) -> (StatusCode, String) {
    map_error(&StarmetalError::VersionNotFound {
        ecosystem: "swift".to_string(),
        name: identifier.to_string(),
        version: version.to_string(),
    })
}

fn json_response<T: serde::Serialize>(body: &T) -> Result<Response, (StatusCode, String)> {
    let bytes = serde_json::to_vec(body).map_err(|err| map_error(&StarmetalError::from(err)))?;
    Ok(([(header::CONTENT_TYPE, "application/json")], Body::from(bytes)).into_response())
}

fn map_error(err: &StarmetalError) -> (StatusCode, String) {
    tracing::warn!(error = %err, "Swift Package Registry proxy request failed");
    crate::map_public_error(err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_metadata_url_is_derived_from_the_default_mount_path() {
        assert_eq!(
            release_metadata_url("http://localhost:8080", "/swift/test/fixture", "1.0.0"),
            "http://localhost:8080/swift/test/fixture/1.0.0"
        );
    }

    #[test]
    fn release_metadata_url_honors_a_custom_mount_name() {
        // An operator mounting the Swift proxy as `[[repositories]] name = "my-swift"` must get
        // links under `/my-swift/`, not a hardcoded `/swift/`.
        assert_eq!(
            release_metadata_url("https://registry.example", "/my-swift/test/fixture", "2.3.4"),
            "https://registry.example/my-swift/test/fixture/2.3.4"
        );
    }
}
