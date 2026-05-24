use std::io::{Cursor, Read};

use bytes::Bytes;
use depot_core::error::{DepotError, Result};
use flate2::read::GzDecoder;

const MAX_METADATA_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArchiveMetadata {
    pub name: String,
    pub version: String,
    pub license: Option<String>,
    pub nuspec: Option<Bytes>,
}

pub(crate) fn parse_rubygem(data: &[u8]) -> Result<ArchiveMetadata> {
    let mut archive = tar::Archive::new(Cursor::new(data));
    let metadata = read_tar_entry(&mut archive, "metadata.gz")?;
    let metadata = gunzip(&metadata)?;
    let text = String::from_utf8(metadata)
        .map_err(|err| DepotError::Adapter(format!("invalid RubyGems metadata: {err}")))?;
    Ok(ArchiveMetadata {
        name: yaml_scalar(&text, "name")
            .ok_or_else(|| DepotError::Adapter("RubyGems metadata missing name".to_string()))?,
        version: yaml_version(&text)
            .ok_or_else(|| DepotError::Adapter("RubyGems metadata missing version".to_string()))?,
        license: yaml_sequence_first(&text, "licenses").or_else(|| yaml_scalar(&text, "license")),
        nuspec: None,
    })
}

pub(crate) fn parse_nuget(data: &[u8]) -> Result<ArchiveMetadata> {
    let mut archive = zip::ZipArchive::new(Cursor::new(data))
        .map_err(|err| DepotError::Adapter(format!("invalid NuGet package: {err}")))?;
    for index in 0..archive.len() {
        let file = archive
            .by_index(index)
            .map_err(|err| DepotError::Adapter(format!("invalid NuGet package entry: {err}")))?;
        let name = file.name().to_string();
        reject_unsafe_path(&name)?;
        if !name.ends_with(".nuspec") {
            continue;
        }
        let mut buffer = Vec::new();
        file.take(MAX_METADATA_BYTES as u64)
            .read_to_end(&mut buffer)
            .map_err(|err| DepotError::Adapter(format!("failed to read nuspec: {err}")))?;
        let text = String::from_utf8(buffer.clone())
            .map_err(|err| DepotError::Adapter(format!("invalid nuspec utf-8: {err}")))?;
        return Ok(ArchiveMetadata {
            name: xml_text(&text, "id")
                .ok_or_else(|| DepotError::Adapter("NuGet nuspec missing id".to_string()))?
                .to_ascii_lowercase(),
            version: xml_text(&text, "version")
                .ok_or_else(|| DepotError::Adapter("NuGet nuspec missing version".to_string()))?,
            license: xml_text(&text, "license"),
            nuspec: Some(Bytes::from(buffer)),
        });
    }
    Err(DepotError::Adapter(
        "NuGet package missing .nuspec".to_string(),
    ))
}

pub(crate) fn parse_pub_archive(data: &[u8]) -> Result<ArchiveMetadata> {
    let decoded = gunzip(data)?;
    let mut archive = tar::Archive::new(Cursor::new(decoded));
    let pubspec = read_tar_entry(&mut archive, "pubspec.yaml")?;
    let text = String::from_utf8(pubspec)
        .map_err(|err| DepotError::Adapter(format!("invalid pubspec.yaml: {err}")))?;
    let value: serde_yaml::Value = serde_yaml::from_str(&text)
        .map_err(|err| DepotError::Adapter(format!("invalid pubspec.yaml: {err}")))?;
    Ok(ArchiveMetadata {
        name: yaml_value(&value, "name")
            .or_else(|| yaml_scalar(&text, "name"))
            .ok_or_else(|| DepotError::Adapter("pubspec.yaml missing name".to_string()))?,
        version: yaml_value(&value, "version")
            .or_else(|| yaml_scalar(&text, "version"))
            .ok_or_else(|| DepotError::Adapter("pubspec.yaml missing version".to_string()))?,
        license: None,
        nuspec: None,
    })
}

pub(crate) fn parse_hex_tarball(data: &[u8]) -> Result<ArchiveMetadata> {
    let mut archive = tar::Archive::new(Cursor::new(data));
    let metadata = read_tar_entry(&mut archive, "metadata.config")?;
    let text = String::from_utf8(metadata)
        .map_err(|err| DepotError::Adapter(format!("invalid Hex metadata.config: {err}")))?;
    Ok(ArchiveMetadata {
        name: yaml_scalar(&text, "name")
            .or_else(|| erlang_binary(&text, "name"))
            .ok_or_else(|| DepotError::Adapter("Hex metadata.config missing name".to_string()))?,
        version: yaml_scalar(&text, "version")
            .or_else(|| erlang_binary(&text, "version"))
            .ok_or_else(|| {
                DepotError::Adapter("Hex metadata.config missing version".to_string())
            })?,
        license: yaml_sequence_first(&text, "licenses"),
        nuspec: None,
    })
}

fn read_tar_entry<R: Read>(archive: &mut tar::Archive<R>, expected_name: &str) -> Result<Vec<u8>> {
    let entries = archive
        .entries()
        .map_err(|err| DepotError::Adapter(format!("invalid tar archive: {err}")))?;
    for entry in entries {
        let entry =
            entry.map_err(|err| DepotError::Adapter(format!("invalid tar entry: {err}")))?;
        let path = entry
            .path()
            .map_err(|err| DepotError::Adapter(format!("invalid tar path: {err}")))?;
        let path = path.to_string_lossy();
        reject_unsafe_path(&path)?;
        if path.rsplit('/').next() != Some(expected_name) {
            continue;
        }
        let mut buffer = Vec::new();
        entry
            .take(MAX_METADATA_BYTES as u64)
            .read_to_end(&mut buffer)
            .map_err(|err| DepotError::Adapter(format!("failed to read tar entry: {err}")))?;
        return Ok(buffer);
    }
    Err(DepotError::Adapter(format!(
        "archive missing {expected_name}"
    )))
}

fn gunzip(data: &[u8]) -> Result<Vec<u8>> {
    let decoder = GzDecoder::new(data);
    let mut buffer = Vec::new();
    decoder
        .take(MAX_METADATA_BYTES as u64)
        .read_to_end(&mut buffer)
        .map_err(|err| DepotError::Adapter(format!("invalid gzip data: {err}")))?;
    Ok(buffer)
}

fn reject_unsafe_path(path: &str) -> Result<()> {
    if path.starts_with('/') || path.split('/').any(|part| part == "..") {
        return Err(DepotError::Adapter(format!("unsafe archive path: {path}")));
    }
    Ok(())
}

fn yaml_scalar(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix(key) else {
            continue;
        };
        let Some(value) = rest.trim_start().strip_prefix(':') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() || value.starts_with('!') {
            continue;
        }
        return Some(unquote(value));
    }
    None
}

fn yaml_value(value: &serde_yaml::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_yaml::Value::as_str)
        .map(str::to_string)
}

fn yaml_version(text: &str) -> Option<String> {
    yaml_scalar(text, "version").or_else(|| {
        let mut in_version = false;
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed == "version:" || trimmed.starts_with("version: !") {
                in_version = true;
                continue;
            }
            if in_version {
                if let Some(value) = trimmed.strip_prefix("version:") {
                    return Some(unquote(value.trim()));
                }
                if !line.starts_with(' ') && !line.starts_with('\t') {
                    in_version = false;
                }
            }
        }
        None
    })
}

fn yaml_sequence_first(text: &str, key: &str) -> Option<String> {
    let mut in_key = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == format!("{key}:") {
            in_key = true;
            continue;
        }
        if in_key {
            if let Some(value) = trimmed.strip_prefix('-') {
                return Some(unquote(value.trim()));
            }
            if !line.starts_with(' ') && !line.starts_with('\t') {
                return None;
            }
        }
    }
    None
}

fn erlang_binary(text: &str, key: &str) -> Option<String> {
    let marker = format!("{{{key},<<\"");
    let start = text.find(&marker)? + marker.len();
    let end = text[start..].find("\">>")? + start;
    Some(text[start..end].to_string())
}

fn xml_text(text: &str, tag: &str) -> Option<String> {
    let open_start = text.find(&format!("<{tag}"))?;
    let open_end = text[open_start..].find('>')? + open_start + 1;
    let close = text[open_end..].find(&format!("</{tag}>"))? + open_end;
    Some(text[open_end..close].trim().to_string())
}

fn unquote(value: &str) -> String {
    value
        .trim_matches('"')
        .trim_matches('\'')
        .trim_end_matches(',')
        .to_string()
}
