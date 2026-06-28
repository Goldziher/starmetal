//! PEP 503 Simple Repository API types, conversions, and HTML rendering.

use ahash::AHashMap;
use starmetal_core::package::{ArtifactDigest, PackageName, VersionInfo, VersionMetadata};
use starmetal_core::registry::pypi::{
    PypiFile, PypiIndex, PypiIndexProject, PypiMeta, PypiProject, PypiYanked,
};

/// Determines whether the client wants JSON or HTML responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PypiFormat {
    Json,
    Html,
}

/// Content-negotiate based on the `Accept` header value.
///
/// Returns `Json` when the client explicitly requests the PEP 691 JSON format,
/// otherwise falls back to `Html` (PEP 503).
pub fn negotiate_format(accept: Option<&str>) -> PypiFormat {
    match accept {
        Some(a) if a.contains("application/vnd.pypi.simple.v1+json") => PypiFormat::Json,
        _ => PypiFormat::Html,
    }
}

/// Extract a version string from a PyPI filename.
///
/// Handles both sdist (`name-version.tar.gz`, `.zip`) and wheel
/// (`name-version-pytag-abitag-platform.whl`) naming conventions.
fn version_from_filename(filename: &str) -> Option<String> {
    // Strip known extensions to get the stem
    let stem = if let Some(s) = filename.strip_suffix(".tar.gz") {
        s
    } else if let Some(s) = filename.strip_suffix(".tar.bz2") {
        s
    } else if let Some(s) = filename.strip_suffix(".zip") {
        s
    } else if let Some(s) = filename.strip_suffix(".whl") {
        // Wheel: name-version-pytag-abitag-platform.whl
        // We need the second segment after first hyphen
        let parts: Vec<&str> = s.splitn(3, '-').collect();
        return if parts.len() >= 2 {
            Some(parts[1].to_string())
        } else {
            None
        };
    } else {
        filename.strip_suffix(".egg")?
    };

    // sdist: name-version — find the last hyphen that separates name from version
    // The version always starts with a digit
    let bytes = stem.as_bytes();
    for (idx, &byte) in bytes.iter().enumerate().rev() {
        if byte == b'-'
            && let Some(next) = bytes.get(idx + 1)
            && next.is_ascii_digit()
        {
            return Some(stem[idx + 1..].to_string());
        }
    }
    None
}

/// Extract version info list from a PyPI project response.
///
/// Prefers the explicit `versions` list when available, falling back to
/// deriving versions from filenames.
pub fn pypi_project_to_version_infos(project: &PypiProject) -> Vec<VersionInfo> {
    if !project.versions.is_empty() {
        return project
            .versions
            .iter()
            .map(|v| {
                let yanked = project
                    .files
                    .iter()
                    .filter(|f| version_from_filename(&f.filename).as_deref() == Some(v.as_str()))
                    .all(|f| f.yanked.is_yanked());
                VersionInfo {
                    version: v.clone(),
                    yanked,
                }
            })
            .collect();
    }

    // Derive versions from filenames
    let mut seen = AHashMap::new();
    for file in &project.files {
        if let Some(version) = version_from_filename(&file.filename) {
            let entry = seen.entry(version).or_insert((false, true));
            // Track if ALL files for this version are yanked
            if !file.yanked.is_yanked() {
                entry.1 = false;
            }
        }
    }

    let mut versions: Vec<VersionInfo> = seen
        .into_iter()
        .map(|(version, (_, all_yanked))| VersionInfo {
            version,
            yanked: all_yanked,
        })
        .collect();
    versions.sort_by(|a, b| a.version.cmp(&b.version));
    versions
}

/// Filter PyPI files for a specific version and build `VersionMetadata`.
///
/// Returns `None` when no files match the requested version.
pub fn pypi_files_to_metadata(
    name: &PackageName,
    version: &str,
    files: &[PypiFile],
) -> Option<VersionMetadata> {
    let matching: Vec<&PypiFile> = files
        .iter()
        .filter(|f| version_from_filename(&f.filename).as_deref() == Some(version))
        .collect();

    if matching.is_empty() {
        return None;
    }

    let yanked = matching.iter().all(|f| f.yanked.is_yanked());

    let artifacts = matching
        .iter()
        .map(|f| {
            let upstream_hashes: AHashMap<String, String> = f
                .hashes
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            ArtifactDigest {
                filename: f.filename.clone(),
                blake3: String::new(),
                size: f.size.unwrap_or(0),
                upstream_hashes,
            }
        })
        .collect();

    Some(VersionMetadata {
        name: name.clone(),
        version: version.to_string(),
        artifacts,
        license: None,
        yanked,
    })
}

/// Render PEP 503 simple index HTML listing all known packages.
pub fn render_index_html(packages: &[PackageName]) -> String {
    let mut html = String::from("<!DOCTYPE html><html><body>\n");
    for pkg in packages {
        let name = pkg.as_str();
        html.push_str(&format!("<a href=\"/pypi/simple/{name}/\">{name}</a>\n"));
    }
    html.push_str("</body></html>");
    html
}

/// Render PEP 503 project detail HTML listing all files across versions.
///
/// File URLs point to our local download endpoint rather than upstream,
/// with a `#sha256=...` fragment appended when the upstream hash is available.
pub fn render_project_html(name: &PackageName, metadata_list: &[VersionMetadata]) -> String {
    let mut html = String::from("<!DOCTYPE html><html><body>\n");
    for meta in metadata_list {
        for artifact in &meta.artifacts {
            let pkg_name = name.as_str();
            let version = &meta.version;
            let filename = &artifact.filename;
            let mut href = format!("/pypi/packages/{pkg_name}/{version}/{filename}");
            if let Some(sha256) = artifact.upstream_hashes.get("sha256") {
                href.push_str(&format!("#sha256={sha256}"));
            }
            html.push_str(&format!("<a href=\"{href}\">{filename}</a>\n"));
        }
    }
    html.push_str("</body></html>");
    html
}

/// Build a PEP 691 JSON index response from a list of package names.
pub fn build_json_index(packages: &[PackageName]) -> PypiIndex {
    PypiIndex {
        meta: PypiMeta {
            api_version: "1.0".to_string(),
        },
        projects: packages
            .iter()
            .map(|p| PypiIndexProject {
                name: p.as_str().to_string(),
            })
            .collect(),
    }
}

/// Build a PEP 691 JSON project response from version metadata.
pub fn build_json_project(name: &PackageName, metadata_list: &[VersionMetadata]) -> PypiProject {
    let versions: Vec<String> = metadata_list.iter().map(|m| m.version.clone()).collect();

    let files: Vec<PypiFile> = metadata_list
        .iter()
        .flat_map(|meta| {
            meta.artifacts.iter().map(move |artifact| {
                let hashes = artifact
                    .upstream_hashes
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                let pkg_name = name.as_str();
                let version = &meta.version;
                let filename = &artifact.filename;
                PypiFile {
                    filename: filename.clone(),
                    url: format!("/pypi/packages/{pkg_name}/{version}/{filename}"),
                    hashes,
                    requires_python: None,
                    yanked: if meta.yanked {
                        starmetal_core::registry::pypi::PypiYanked::Bool(true)
                    } else {
                        starmetal_core::registry::pypi::PypiYanked::Bool(false)
                    },
                    size: Some(artifact.size),
                    upload_time: None,
                    dist_info_metadata: None,
                    gpg_sig: None,
                }
            })
        })
        .collect();

    PypiProject {
        meta: PypiMeta {
            api_version: "1.0".to_string(),
        },
        name: name.as_str().to_string(),
        versions,
        files,
    }
}

/// Rewrite file URLs in a `PypiProject` to point through the local starmetal endpoint.
///
/// Replaces absolute upstream URLs with local `/pypi/packages/{name}/{version}/{filename}`
/// paths so clients download through starmetal rather than hitting upstream directly.
pub fn rewrite_project_file_urls(project: &mut PypiProject) {
    let name = &project.name;
    for file in &mut project.files {
        if let Some(version) = version_from_filename(&file.filename) {
            file.url = format!("/pypi/packages/{name}/{version}/{}", file.filename);
        }
    }
}

/// Render PEP 503 project detail HTML directly from an upstream `PypiProject`.
///
/// Preserves all PEP 503 attributes: `data-requires-python`, `data-yanked`,
/// and hash fragments. File URLs must already be rewritten before calling this.
pub fn render_project_html_from_upstream(project: &PypiProject) -> String {
    let mut html = String::from("<!DOCTYPE html><html><body>\n");
    for file in &project.files {
        let mut attrs = format!("href=\"{}\"", file.url);
        if let Some(sha256) = file.hashes.get("sha256") {
            // Append hash fragment for PEP 503 integrity checking
            attrs = format!("href=\"{}#sha256={sha256}\"", file.url);
        }
        if let Some(requires_python) = &file.requires_python {
            attrs.push_str(&format!(
                " data-requires-python=\"{}\"",
                html_escape(requires_python)
            ));
        }
        if file.yanked.is_yanked() {
            match &file.yanked {
                PypiYanked::Reason(reason) => {
                    attrs.push_str(&format!(" data-yanked=\"{}\"", html_escape(reason)));
                }
                _ => attrs.push_str(" data-yanked=\"\""),
            }
        }
        html.push_str(&format!("<a {attrs}>{}</a>\n", file.filename));
    }
    html.push_str("</body></html>");
    html
}

/// Escape special HTML characters in attribute values.
fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_from_filename_sdist() {
        assert_eq!(
            version_from_filename("requests-2.31.0.tar.gz"),
            Some("2.31.0".to_string())
        );
    }

    #[test]
    fn test_version_from_filename_wheel() {
        assert_eq!(
            version_from_filename("requests-2.31.0-py3-none-any.whl"),
            Some("2.31.0".to_string())
        );
    }

    #[test]
    fn test_version_from_filename_zip() {
        assert_eq!(
            version_from_filename("flask-3.0.0.zip"),
            Some("3.0.0".to_string())
        );
    }

    #[test]
    fn test_version_from_filename_unknown_extension() {
        assert_eq!(version_from_filename("something.txt"), None);
    }

    #[test]
    fn test_negotiate_format_json() {
        assert_eq!(
            negotiate_format(Some("application/vnd.pypi.simple.v1+json")),
            PypiFormat::Json
        );
    }

    #[test]
    fn test_negotiate_format_html_default() {
        assert_eq!(negotiate_format(None), PypiFormat::Html);
        assert_eq!(negotiate_format(Some("text/html")), PypiFormat::Html);
    }

    #[test]
    fn test_render_index_html() {
        let packages = vec![PackageName::new("requests"), PackageName::new("flask")];
        let html = render_index_html(&packages);
        assert!(html.contains("<a href=\"/pypi/simple/requests/\">requests</a>"));
        assert!(html.contains("<a href=\"/pypi/simple/flask/\">flask</a>"));
    }
}
