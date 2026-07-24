//! Manager for Cargo's `Cargo.toml` manifest format.

use std::path::Path;

use starmetal_core::package::{Ecosystem, PackageName};
use starmetal_update_core::dependency::{DepType, Dependency};
use starmetal_update_core::error::{Result, UpdateError};
use starmetal_update_core::ports::Manager;
use toml::{Table, Value};

/// Stable manager identifier reported by [`CargoManager::name`].
const MANAGER_NAME: &str = "cargo";

/// File name this manager matches on, regardless of directory.
const CARGO_MANIFEST_FILENAME: &str = "Cargo.toml";

/// Name of the [`starmetal_update_core::ports::Versioning`] scheme Cargo manifests use.
const SEMVER_SCHEME: &str = "semver";

/// Key that holds a version constraint inside a table-form dependency entry.
const VERSION_FIELD: &str = "version";

/// Key that holds the upstream crate name inside a renamed dependency entry.
const PACKAGE_FIELD: &str = "package";

/// Key that, when present on an inline-table dependency, marks it as a git source.
const GIT_FIELD: &str = "git";

/// Key that, when present on an inline-table dependency, marks it as a path source.
const PATH_FIELD: &str = "path";

/// Top-level manifest tables this manager reads, in the order they are scanned.
const DEPENDENCY_SECTIONS: [(&str, DepType); 3] = [
    ("dependencies", DepType::Runtime),
    ("dev-dependencies", DepType::Dev),
    ("build-dependencies", DepType::Build),
];

/// The single section this manager reads under `[workspace]`. Always mapped to
/// [`DepType::Runtime`]: workspace-inherited dependencies have no dev/build distinction of
/// their own (that distinction is made where a member crate declares `dep.workspace = true`).
const WORKSPACE_SECTIONS: [(&str, DepType); 1] = [("dependencies", DepType::Runtime)];

/// Key of the top-level table holding per-target dependency sections
/// (`[target.'cfg(...)'.dependencies]`).
const TARGET_TABLE: &str = "target";

/// Key of the top-level table holding `[workspace.dependencies]`.
const WORKSPACE_TABLE: &str = "workspace";

/// Header prefix that introduces a per-target section, e.g. `target.'cfg(unix)'.dependencies`.
const TARGET_HEADER_PREFIX: &str = "target.";

/// Header prefix that introduces the workspace section, e.g. `workspace.dependencies`.
const WORKSPACE_HEADER_PREFIX: &str = "workspace.";

/// Manager for Cargo's `Cargo.toml` manifest format.
///
/// Parses the `[dependencies]`, `[dev-dependencies]`, and `[build-dependencies]` tables
/// (including per-dependency `[dependencies.name]` sub-tables), their per-target equivalents
/// under `[target.'cfg(...)'.dependencies]` (and the `-dev`/`-build` variants, and quoted or
/// bare target specs), `[workspace.dependencies]` (always treated as [`DepType::Runtime`]),
/// and the dotted-key shorthand written directly under a dependency section (`serde.version =
/// "1.2.3"` under `[dependencies]`, as an alternative to `[dependencies.serde]` or an inline
/// table). Performs surgical, formatting-preserving edits when applying an update.
/// Dependencies that cannot be resolved to a registry version (`path`/`git` sources — even
/// when a `version` key is also present, since bumping it would be a meaningless no-op —
/// `workspace = true`, or renamed dependencies whose `package` key differs from the manifest
/// key) are skipped.
///
/// # Examples
///
/// ```
/// use starmetal_managers::CargoManager;
/// use starmetal_update_core::ports::Manager;
///
/// let manager = CargoManager::new();
/// assert_eq!(manager.name(), "cargo");
/// assert!(manager.matches_file("Cargo.toml"));
/// assert!(manager.matches_file("crates/foo/Cargo.toml"));
/// assert!(!manager.matches_file("Cargo.lock"));
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct CargoManager;

impl CargoManager {
    /// Creates a new [`CargoManager`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Manager for CargoManager {
    fn name(&self) -> &'static str {
        MANAGER_NAME
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Cargo
    }

    fn matches_file(&self, path: &str) -> bool {
        Path::new(path).file_name().and_then(|name| name.to_str()) == Some(CARGO_MANIFEST_FILENAME)
    }

    fn extract(&self, path: &str, content: &str) -> Result<Vec<Dependency>> {
        extract_dependencies(path, content)
    }

    fn apply_update(&self, content: &str, dependency: &Dependency, new_value: &str) -> Result<String> {
        validate_new_value(new_value)?;

        let key = dependency.name.as_str();
        let mut lines: Vec<String> = content.split('\n').map(str::to_string).collect();

        let mut current_section: Option<DepType> = None;
        let mut current_sub_key: Option<String> = None;
        let mut updated = false;

        for line in &mut lines {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                let (section, sub_key) = classify_header(trimmed);
                current_section = section;
                current_sub_key = sub_key;
                continue;
            }

            if current_section != Some(dependency.dep_type) {
                continue;
            }

            let replacement = match &current_sub_key {
                Some(sub_key) if sub_key == key => replace_field_value(line, VERSION_FIELD, new_value),
                Some(_) => None,
                None => replace_top_level_dependency(line, key, new_value),
            };

            if let Some(new_line) = replacement {
                *line = new_line;
                updated = true;
                break;
            }
        }

        if !updated {
            return Err(UpdateError::manager(
                MANAGER_NAME,
                format!("dependency `{key}` not found in `{}` for update", dependency.file_path),
            ));
        }

        let result = lines.join("\n");
        verify_applied_update(&result, dependency, new_value)?;
        Ok(result)
    }
}

/// Returns the registry version constraint for a dependency table entry, or `None` when
/// the entry cannot be resolved to a registry version (`path`/`git` sources — even when a
/// `version` key is also present, since bumping it would be a meaningless no-op —
/// `workspace = true`, or a renamed dependency whose `package` key differs from `name`).
fn dependency_version(name: &str, value: &Value) -> Option<String> {
    match value {
        Value::String(version) => Some(version.clone()),
        Value::Table(inline) => {
            if inline.contains_key(GIT_FIELD) || inline.contains_key(PATH_FIELD) {
                return None;
            }
            if let Some(package) = inline.get(PACKAGE_FIELD).and_then(Value::as_str)
                && package != name
            {
                return None;
            }
            inline.get(VERSION_FIELD).and_then(Value::as_str).map(str::to_string)
        }
        _ => None,
    }
}

/// Core implementation of [`Manager::extract`], factored out so [`verify_applied_update`] can
/// reuse the exact same dependency-discovery logic as its post-edit safety net (rather than a
/// second, potentially-diverging implementation).
///
/// Scans the top-level `[dependencies]`/`[dev-dependencies]`/`[build-dependencies]` tables,
/// every per-target `[target.<spec>.dependencies]` (and `-dev`/`-build`) table, and
/// `[workspace.dependencies]`. Per-dependency sub-tables (`[dependencies.name]`) and the
/// dotted-key shorthand (`name.version = "..."`) are both discovered here for free: the real
/// TOML parser resolves both forms to the same nested table shape.
fn extract_dependencies(path: &str, content: &str) -> Result<Vec<Dependency>> {
    let document = content
        .parse::<Table>()
        .map_err(|error| UpdateError::manager(MANAGER_NAME, format!("failed to parse `{path}`: {error}")))?;

    let mut dependencies = Vec::new();

    for (section_name, dep_type) in DEPENDENCY_SECTIONS {
        if let Some(Value::Table(section)) = document.get(section_name) {
            collect_section(section, dep_type, path, &mut dependencies);
        }
    }

    if let Some(Value::Table(targets)) = document.get(TARGET_TABLE) {
        for target_value in targets.values() {
            let Value::Table(target_table) = target_value else {
                continue;
            };
            for (section_name, dep_type) in DEPENDENCY_SECTIONS {
                if let Some(Value::Table(section)) = target_table.get(section_name) {
                    collect_section(section, dep_type, path, &mut dependencies);
                }
            }
        }
    }

    if let Some(Value::Table(workspace)) = document.get(WORKSPACE_TABLE) {
        for (section_name, dep_type) in WORKSPACE_SECTIONS {
            if let Some(Value::Table(section)) = workspace.get(section_name) {
                collect_section(section, dep_type, path, &mut dependencies);
            }
        }
    }

    Ok(dependencies)
}

/// Pushes a [`Dependency`] for every entry in `section` that [`dependency_version`] can
/// resolve to a registry version constraint.
fn collect_section(section: &Table, dep_type: DepType, path: &str, dependencies: &mut Vec<Dependency>) {
    for (name, value) in section {
        let Some(current_value) = dependency_version(name, value) else {
            continue;
        };

        dependencies.push(Dependency {
            name: PackageName::new(name.clone()),
            ecosystem: Ecosystem::Cargo,
            current_value,
            dep_type,
            file_path: path.to_string(),
            versioning: SEMVER_SCHEME.to_string(),
        });
    }
}

/// Rejects `new_value` strings that could not legitimately appear as a Cargo version
/// constraint and that, if spliced verbatim between quotes by [`replace_quoted_value_at`],
/// would allow TOML injection (e.g. a compromised upstream response embedding a closing
/// quote followed by attacker-controlled keys).
fn validate_new_value(new_value: &str) -> Result<()> {
    let has_unsafe_character = new_value
        .chars()
        .any(|character| character == '"' || character == '\'' || character.is_ascii_control());

    if has_unsafe_character {
        return Err(UpdateError::manager(
            MANAGER_NAME,
            format!("refusing to apply update: new version value `{new_value}` contains a quote or control character"),
        ));
    }

    Ok(())
}

/// Safety net run after [`Manager::apply_update`] performs its text-surgery edit: re-parses
/// the edited manifest with [`extract_dependencies`] (the same dependency-discovery logic
/// [`Manager::extract`] relies on, so it also finds per-target and workspace sections and the
/// dotted-key shorthand) and confirms `dependency` now reports exactly `new_value`. Returns an
/// error instead of silently returning corrupted or incorrectly edited output.
fn verify_applied_update(edited_content: &str, dependency: &Dependency, new_value: &str) -> Result<()> {
    let key = dependency.name.as_str();

    let dependencies = extract_dependencies(&dependency.file_path, edited_content).map_err(|error| {
        UpdateError::manager(
            MANAGER_NAME,
            format!("post-update verification failed for `{key}`: edited manifest is not valid TOML: {error}"),
        )
    })?;

    let matches = dependencies.iter().any(|found| {
        found.name.as_str() == key && found.dep_type == dependency.dep_type && found.current_value == new_value
    });

    if matches {
        Ok(())
    } else {
        Err(UpdateError::manager(
            MANAGER_NAME,
            format!(
                "post-update verification failed: `{key}` does not report version `{new_value}` after edit in `{}`",
                dependency.file_path
            ),
        ))
    }
}

/// The dependency table (if any) and per-dependency sub-key (if any) a table header line
/// selects. Recognizes plain sections (`[dependencies]`), per-dependency sub-tables
/// (`[dependencies.name]`), per-target sections and their sub-tables
/// (`[target.'cfg(unix)'.dependencies]`, `[target.'cfg(unix)'.dependencies.name]`), and
/// `[workspace.dependencies]` (and `[workspace.dependencies.name]`). `Other` headers (and
/// array-of-tables headers) reset both to `None`.
fn classify_header(trimmed_line: &str) -> (Option<DepType>, Option<String>) {
    if trimmed_line.starts_with("[[") {
        return (None, None);
    }

    let Some(inner) = trimmed_line.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) else {
        return (None, None);
    };
    let inner = inner.trim();

    if let Some((dep_type, sub_key)) = match_dependency_section(inner, &DEPENDENCY_SECTIONS) {
        return (Some(dep_type), sub_key);
    }

    if let Some(after_target) = inner.strip_prefix(TARGET_HEADER_PREFIX)
        && let Some(after_spec) = strip_target_spec(after_target)
        && let Some((dep_type, sub_key)) = match_dependency_section(after_spec, &DEPENDENCY_SECTIONS)
    {
        return (Some(dep_type), sub_key);
    }

    if let Some(after_workspace) = inner.strip_prefix(WORKSPACE_HEADER_PREFIX)
        && let Some((dep_type, sub_key)) = match_dependency_section(after_workspace, &WORKSPACE_SECTIONS)
    {
        return (Some(dep_type), sub_key);
    }

    (None, None)
}

/// Matches `remainder` (the header text after any `target.<spec>.`/`workspace.` prefix has
/// already been stripped) against `sections`, returning the matching [`DepType`] and, for a
/// per-dependency sub-table header (`dependencies.name`), the unquoted dependency name.
fn match_dependency_section(remainder: &str, sections: &[(&str, DepType)]) -> Option<(DepType, Option<String>)> {
    for (section_name, dep_type) in sections {
        if remainder == *section_name {
            return Some((*dep_type, None));
        }
        if let Some(sub_key) = remainder
            .strip_prefix(section_name)
            .and_then(|rest| rest.strip_prefix('.'))
        {
            return Some((*dep_type, Some(unquote_key(sub_key.trim()))));
        }
    }
    None
}

/// Consumes the target-spec component at the start of `remainder` (the header text
/// immediately after `target.`, e.g. `'cfg(unix)'.dependencies` or
/// `"x86_64-pc-windows-gnu".dependencies.serde`) and returns what follows its trailing `.`.
/// Handles both quoted specs (which may contain `.`, e.g. `cfg(target_os = "linux")`) and
/// bare specs (target triples, which never contain `.`).
fn strip_target_spec(remainder: &str) -> Option<&str> {
    match remainder.chars().next()? {
        quote @ ('\'' | '"') => {
            let after_open = &remainder[quote.len_utf8()..];
            let closing_relative = after_open.find(quote)?;
            let after_close = &after_open[closing_relative + quote.len_utf8()..];
            after_close.strip_prefix('.')
        }
        _ => {
            let dot_index = remainder.find('.')?;
            remainder[dot_index..].strip_prefix('.')
        }
    }
}

/// Strips a single layer of matching `"`/`'` quotes from a TOML key, if present.
fn unquote_key(key: &str) -> String {
    for quote in ['"', '\''] {
        if key.len() >= 2 && key.starts_with(quote) && key.ends_with(quote) {
            return key[1..key.len() - 1].to_string();
        }
    }
    key.to_string()
}

/// Whether `character` may appear inside a bare TOML key.
fn is_key_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_' || character == '-'
}

/// Whether byte offset `index` in `line` falls inside a single- or double-quoted TOML
/// string value, determined by counting quote characters before `index`. Used to keep
/// [`find_key_equals`] from mistaking decoy `field = ...` text embedded inside an unrelated
/// string value (e.g. `note = 'version = "9.9.9"'`) for a real key.
fn is_inside_string_literal(line: &str, index: usize) -> bool {
    let mut in_double_quotes = false;
    let mut in_single_quotes = false;

    for character in line[..index].chars() {
        match character {
            '"' if !in_single_quotes => in_double_quotes = !in_double_quotes,
            '\'' if !in_double_quotes => in_single_quotes = !in_single_quotes,
            _ => {}
        }
    }

    in_double_quotes || in_single_quotes
}

/// Finds `field` used as a key on `line` (bare or quoted, at a key-name boundary)
/// immediately followed, after optional whitespace, by `=`, ignoring any occurrence that
/// falls inside a quoted string value. Returns the byte index of that `=` character.
fn find_key_equals(line: &str, field: &str) -> Option<usize> {
    let mut search_from = 0;
    while let Some(relative) = line[search_from..].find(field) {
        let start = search_from + relative;
        let end = start + field.len();

        if is_inside_string_literal(line, start) {
            search_from = start + 1;
            continue;
        }

        let before_is_boundary = line[..start].chars().next_back().is_none_or(|c| !is_key_char(c));
        let after_is_boundary = line[end..].chars().next().is_none_or(|c| !is_key_char(c));

        if before_is_boundary && after_is_boundary {
            let remainder = line[end..].trim_start();
            if remainder.starts_with('=') {
                return Some(line.len() - remainder.len());
            }
        }

        search_from = start + 1;
    }
    None
}

/// Replaces the quoted string value that follows the `=` at `equals_index` on `line` with
/// `new_value`, preserving the quote character and everything else on the line.
fn replace_quoted_value_at(line: &str, equals_index: usize, new_value: &str) -> Option<String> {
    let after_equals = &line[equals_index + 1..];
    let value_start = equals_index + 1 + (after_equals.len() - after_equals.trim_start().len());

    let quote_char = line[value_start..].chars().next()?;
    if quote_char != '"' && quote_char != '\'' {
        return None;
    }

    let after_quote = &line[value_start + quote_char.len_utf8()..];
    let closing_relative = find_closing_quote(after_quote, quote_char)?;
    let closing_index = value_start + quote_char.len_utf8() + closing_relative;

    let mut result = String::with_capacity(line.len() + new_value.len());
    result.push_str(&line[..value_start + quote_char.len_utf8()]);
    result.push_str(new_value);
    result.push_str(&line[closing_index..]);
    Some(result)
}

/// Finds the byte offset of the closing `quote_char` in `after_quote` (the text immediately
/// following a value's opening quote). For a TOML basic string (`quote_char == '"'`), a `"`
/// preceded by an odd number of consecutive backslashes is an escaped quote (`\"`) and does
/// not terminate the string; a preceding *even* number of backslashes means those backslashes
/// are themselves escaped (`\\`), so the quote is unescaped and does terminate it. TOML
/// literal strings (`quote_char == '\''`) support no escaping at all, so the first `'`
/// always terminates them.
fn find_closing_quote(after_quote: &str, quote_char: char) -> Option<usize> {
    if quote_char != '"' {
        return after_quote.find(quote_char);
    }

    let mut escaped = false;
    for (index, character) in after_quote.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            '"' => return Some(index),
            _ => {}
        }
    }
    None
}

/// Replaces the quoted value of the `field` key on `line`, or `None` if `field` is not a
/// key on this line or its value is not a quoted string.
fn replace_field_value(line: &str, field: &str, new_value: &str) -> Option<String> {
    replace_field_value_from(line, 0, field, new_value)
}

/// Like [`replace_field_value`], but only searches for `field` in the substring of `line`
/// starting at byte offset `search_from`. Used to constrain the `version =` search to the
/// portion of an inline-table dependency line that follows the dependency key's own `=`
/// sign, so that a decoy `version =` occurring inside an earlier string value on the same
/// line (e.g. `tokio = { note = 'version = "9.9.9"', version = "1.35" }`) cannot be matched
/// instead of the real `version` field.
fn replace_field_value_from(line: &str, search_from: usize, field: &str, new_value: &str) -> Option<String> {
    let remainder = &line[search_from..];
    let relative_equals_index = find_key_equals(remainder, field)?;
    let equals_index = search_from + relative_equals_index;
    replace_quoted_value_at(line, equals_index, new_value)
}

/// Replaces `key`'s value on a top-level `[dependencies]`-style line, handling the plain
/// string form (`name = "1.2.3"`), the single-line inline-table form (`name = { version =
/// "1.2.3", features = [...] }`), and the dotted-key shorthand (`name.version = "1.2.3"`).
fn replace_top_level_dependency(line: &str, key: &str, new_value: &str) -> Option<String> {
    if let Some(replaced) = replace_dotted_key_version(line, key, new_value) {
        return Some(replaced);
    }

    let equals_index = find_key_equals(line, key)?;
    let value_part = line[equals_index + 1..].trim_start();

    if value_part.starts_with('"') || value_part.starts_with('\'') {
        replace_quoted_value_at(line, equals_index, new_value)
    } else if value_part.starts_with('{') {
        replace_field_value_from(line, equals_index + 1, VERSION_FIELD, new_value)
    } else {
        None
    }
}

/// Replaces the value on a dotted-key shorthand line directly under a dependency section,
/// e.g. `serde.version = "1.2.3"` written under `[dependencies]` — an alternative to the
/// `[dependencies.serde]` sub-table header and the `serde = { version = "..." }` inline-table
/// form. Returns `None` if `line` is not a `<key>.version = ...` line for `key` (in
/// particular, a plain `key = "1.2.3"` or `key = { ... }` line is left for
/// [`replace_top_level_dependency`]'s other branches, since `key` is not immediately followed
/// by a `.`).
fn replace_dotted_key_version(line: &str, key: &str, new_value: &str) -> Option<String> {
    let trimmed_start = line.trim_start();
    let leading_whitespace_len = line.len() - trimmed_start.len();

    let after_key = trimmed_start.strip_prefix(key)?;
    let after_dot = after_key.strip_prefix('.')?;

    let relative_equals_index = find_key_equals(after_dot, VERSION_FIELD)?;
    let equals_index = leading_whitespace_len + (trimmed_start.len() - after_dot.len()) + relative_equals_index;
    replace_quoted_value_at(line, equals_index, new_value)
}

#[cfg(test)]
mod tests {
    use starmetal_update_core::error::UpdateError;

    use super::*;

    const SAMPLE_MANIFEST: &str = r#"[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = "1.2.3"
serde_json = "1.0"
tokio = { version = "1.35", features = ["rt", "macros"] }
local-crate = { path = "../local-crate" }
git-crate = { git = "https://example.com/repo.git" }
workspace-crate = { workspace = true }
renamed = { package = "actual-name", version = "2.0" }
same-name = { package = "same-name", version = "0.5" }

[dev-dependencies]
proptest = "1.4"

[build-dependencies]
cc = "1.0"
"#;

    fn dependency(name: &str, current_value: &str, dep_type: DepType) -> Dependency {
        Dependency {
            name: PackageName::new(name),
            ecosystem: Ecosystem::Cargo,
            current_value: current_value.to_string(),
            dep_type,
            file_path: "Cargo.toml".to_string(),
            versioning: SEMVER_SCHEME.to_string(),
        }
    }

    #[test]
    fn should_report_stable_identity() {
        let manager = CargoManager::new();
        assert_eq!(manager.name(), "cargo");
        assert_eq!(manager.ecosystem(), Ecosystem::Cargo);
    }

    #[test]
    fn matches_file_accepts_cargo_toml_at_any_depth() {
        let manager = CargoManager::new();
        assert!(manager.matches_file("Cargo.toml"));
        assert!(manager.matches_file("crates/foo/Cargo.toml"));
        assert!(manager.matches_file("./Cargo.toml"));
    }

    #[test]
    fn matches_file_rejects_unrelated_paths() {
        let manager = CargoManager::new();
        assert!(!manager.matches_file("cargo.toml"));
        assert!(!manager.matches_file("Cargo.lock"));
        assert!(!manager.matches_file("crates/foo/Cargo.toml.bak"));
        assert!(!manager.matches_file("package.json"));
    }

    #[test]
    fn extract_returns_exact_dependency_set_in_manifest_order() {
        let manager = CargoManager::new();

        let dependencies = manager
            .extract("Cargo.toml", SAMPLE_MANIFEST)
            .expect("sample manifest should parse");

        let expected = vec![
            dependency("serde", "1.2.3", DepType::Runtime),
            dependency("serde_json", "1.0", DepType::Runtime),
            dependency("tokio", "1.35", DepType::Runtime),
            dependency("same-name", "0.5", DepType::Runtime),
            dependency("proptest", "1.4", DepType::Dev),
            dependency("cc", "1.0", DepType::Build),
        ];

        assert_eq!(dependencies, expected);
    }

    #[test]
    fn extract_skips_path_git_workspace_and_renamed_dependencies() {
        let manager = CargoManager::new();

        let dependencies = manager
            .extract("Cargo.toml", SAMPLE_MANIFEST)
            .expect("sample manifest should parse");

        let names: Vec<&str> = dependencies.iter().map(|dependency| dependency.name.as_str()).collect();
        assert!(!names.contains(&"local-crate"));
        assert!(!names.contains(&"git-crate"));
        assert!(!names.contains(&"workspace-crate"));
        assert!(!names.contains(&"renamed"));
        assert!(!names.contains(&"actual-name"));
    }

    #[test]
    fn extract_returns_empty_vec_for_manifest_without_dependency_tables() {
        let manager = CargoManager::new();
        let content = "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n";

        let dependencies = manager.extract("Cargo.toml", content).expect("manifest should parse");

        assert_eq!(dependencies, Vec::new());
    }

    #[test]
    fn extract_returns_parse_error_for_invalid_toml() {
        let manager = CargoManager::new();

        let result = manager.extract("Cargo.toml", "not valid toml [[[");

        match result {
            Err(UpdateError::Manager { manager, .. }) => assert_eq!(manager, "cargo"),
            other => panic!("expected UpdateError::Manager, got {other:?}"),
        }
    }

    #[test]
    fn apply_update_replaces_plain_string_version_without_touching_prefix_matches() {
        let manager = CargoManager::new();
        let dependency = dependency("serde", "1.2.3", DepType::Runtime);

        let updated = manager
            .apply_update(SAMPLE_MANIFEST, &dependency, "1.5.0")
            .expect("serde is present in the sample manifest");

        let expected = SAMPLE_MANIFEST.replacen("serde = \"1.2.3\"", "serde = \"1.5.0\"", 1);
        assert_eq!(updated, expected);
        assert!(updated.contains("serde_json = \"1.0\""));
    }

    #[test]
    fn apply_update_replaces_inline_table_version_only() {
        let manager = CargoManager::new();
        let dependency = dependency("tokio", "1.35", DepType::Runtime);

        let updated = manager
            .apply_update(SAMPLE_MANIFEST, &dependency, "1.36")
            .expect("tokio is present in the sample manifest");

        let expected = SAMPLE_MANIFEST.replacen(
            r#"tokio = { version = "1.35", features = ["rt", "macros"] }"#,
            r#"tokio = { version = "1.36", features = ["rt", "macros"] }"#,
            1,
        );
        assert_eq!(updated, expected);
    }

    #[test]
    fn apply_update_replaces_version_under_dotted_dependency_section() {
        let manager = CargoManager::new();
        let content =
            "[dependencies.serde]\nversion = \"1.2.3\"\nfeatures = [\"derive\"]\n\n[dependencies]\nother = \"1.0\"\n";
        let dependency = dependency("serde", "1.2.3", DepType::Runtime);

        let updated = manager
            .apply_update(content, &dependency, "1.3.0")
            .expect("serde section exists");

        let expected =
            "[dependencies.serde]\nversion = \"1.3.0\"\nfeatures = [\"derive\"]\n\n[dependencies]\nother = \"1.0\"\n";
        assert_eq!(updated, expected);
    }

    #[test]
    fn apply_update_only_touches_matching_dep_type_section() {
        let manager = CargoManager::new();
        let dependency = dependency("proptest", "1.4", DepType::Dev);

        let updated = manager
            .apply_update(SAMPLE_MANIFEST, &dependency, "1.5.0")
            .expect("proptest is present in dev-dependencies");

        let expected = SAMPLE_MANIFEST.replacen("proptest = \"1.4\"", "proptest = \"1.5.0\"", 1);
        assert_eq!(updated, expected);
        assert!(updated.contains("cc = \"1.0\""));
        assert!(updated.contains("serde = \"1.2.3\""));
    }

    #[test]
    fn apply_update_errors_when_dependency_is_in_a_different_section() {
        let manager = CargoManager::new();
        // `cc` only appears under [build-dependencies] in the sample manifest.
        let dependency = dependency("cc", "1.0", DepType::Runtime);

        let result = manager.apply_update(SAMPLE_MANIFEST, &dependency, "2.0");

        assert!(result.is_err());
    }

    #[test]
    fn apply_update_errors_when_dependency_is_missing() {
        let manager = CargoManager::new();
        let dependency = dependency("does-not-exist", "1.0.0", DepType::Runtime);

        let result = manager.apply_update(SAMPLE_MANIFEST, &dependency, "2.0.0");

        match result {
            Err(UpdateError::Manager { manager, message }) => {
                assert_eq!(manager, "cargo");
                assert!(message.contains("does-not-exist"));
            }
            other => panic!("expected UpdateError::Manager, got {other:?}"),
        }
    }

    #[test]
    fn apply_update_does_not_match_a_dependency_name_prefix() {
        let manager = CargoManager::new();
        let dependency = dependency("serde", "1.2.3", DepType::Runtime);

        let updated = manager
            .apply_update(SAMPLE_MANIFEST, &dependency, "9.9.9")
            .expect("serde is present");

        // Only the exact `serde` line changed; `serde_json` is untouched.
        assert!(updated.contains("serde_json = \"1.0\""));
        assert!(updated.contains("serde = \"9.9.9\""));
        assert!(!updated.contains("serde = \"1.2.3\""));
    }

    #[test]
    fn apply_update_rewrites_real_version_field_and_ignores_decoy_inside_a_string_value() {
        let manager = CargoManager::new();
        let content = "[dependencies]\ntokio = { note = 'version = \"9.9.9\"', version = \"1.35\" }\n";
        let dependency = dependency("tokio", "1.35", DepType::Runtime);

        let updated = manager
            .apply_update(content, &dependency, "1.40")
            .expect("tokio is present");

        let expected = "[dependencies]\ntokio = { note = 'version = \"9.9.9\"', version = \"1.40\" }\n";
        assert_eq!(updated, expected);
    }

    #[test]
    fn apply_update_rejects_new_value_containing_a_double_quote() {
        let manager = CargoManager::new();
        let dependency = dependency("serde", "1.2.3", DepType::Runtime);

        let result = manager.apply_update(SAMPLE_MANIFEST, &dependency, "1.0\", evil = \"1");

        match result {
            Err(UpdateError::Manager { manager, message }) => {
                assert_eq!(manager, "cargo");
                assert!(message.contains("quote or control character"));
            }
            other => panic!("expected UpdateError::Manager, got {other:?}"),
        }
    }

    #[test]
    fn apply_update_rejects_new_value_containing_a_newline() {
        let manager = CargoManager::new();
        let dependency = dependency("serde", "1.2.3", DepType::Runtime);

        let result = manager.apply_update(SAMPLE_MANIFEST, &dependency, "1.0\n[malicious]\nx = 1");

        match result {
            Err(UpdateError::Manager { manager, message }) => {
                assert_eq!(manager, "cargo");
                assert!(message.contains("quote or control character"));
            }
            other => panic!("expected UpdateError::Manager, got {other:?}"),
        }
    }

    #[test]
    fn extract_skips_git_and_path_dependencies_that_also_carry_a_version_key() {
        let manager = CargoManager::new();
        let content = "[dependencies]\n\
             foo = { git = \"https://example.com/foo.git\", version = \"1.0\" }\n\
             bar = { path = \"../bar\", version = \"1.0\" }\n\
             baz = \"1.0\"\n";

        let dependencies = manager.extract("Cargo.toml", content).expect("manifest should parse");

        let names: Vec<&str> = dependencies.iter().map(|dependency| dependency.name.as_str()).collect();
        assert_eq!(names, vec!["baz"]);
    }

    #[test]
    fn apply_update_errors_instead_of_returning_corrupted_output_when_verification_fails() {
        let manager = CargoManager::new();
        // Invalid TOML: a duplicate `[dependencies]` table. The line-based scanner only
        // looks at the first `[dependencies]` block and reports success, but the edited
        // manifest as a whole is not valid TOML, so the post-edit safety net must reject it
        // rather than return the apparently-successful-but-corrupt result.
        let content = "[dependencies]\nserde = \"1.0\"\n\n[dependencies]\nserde = \"2.0\"\n";
        let dependency = dependency("serde", "1.0", DepType::Runtime);

        let result = manager.apply_update(content, &dependency, "1.1.0");

        match result {
            Err(UpdateError::Manager { manager, message }) => {
                assert_eq!(manager, "cargo");
                assert!(message.contains("post-update verification failed"));
            }
            other => panic!("expected UpdateError::Manager, got {other:?}"),
        }
    }

    const TARGET_MANIFEST: &str = "[dependencies]\nserde = \"1.0\"\n\n[target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n\n[target.'cfg(windows)'.dev-dependencies]\nwinapi = \"0.3\"\n";

    #[test]
    fn extract_discovers_dependencies_under_per_target_sections() {
        let manager = CargoManager::new();

        let dependencies = manager
            .extract("Cargo.toml", TARGET_MANIFEST)
            .expect("target manifest should parse");

        let expected = vec![
            dependency("serde", "1.0", DepType::Runtime),
            dependency("libc", "0.2", DepType::Runtime),
            dependency("winapi", "0.3", DepType::Dev),
        ];
        assert_eq!(dependencies, expected);
    }

    #[test]
    fn apply_update_patches_a_dependency_under_a_per_target_section() {
        let manager = CargoManager::new();
        let libc = dependency("libc", "0.2", DepType::Runtime);

        let updated = manager
            .apply_update(TARGET_MANIFEST, &libc, "0.3.0")
            .expect("libc is present under target.'cfg(unix)'.dependencies");

        let expected = TARGET_MANIFEST.replacen("libc = \"0.2\"", "libc = \"0.3.0\"", 1);
        assert_eq!(updated, expected);
        assert!(updated.contains("winapi = \"0.3\""));
    }

    const WORKSPACE_MANIFEST: &str =
        "[workspace.dependencies]\nserde = \"1.0\"\ntokio = { version = \"1.35\", features = [\"rt\"] }\n";

    #[test]
    fn extract_discovers_workspace_dependencies_as_runtime() {
        let manager = CargoManager::new();

        let dependencies = manager
            .extract("Cargo.toml", WORKSPACE_MANIFEST)
            .expect("workspace manifest should parse");

        let expected = vec![
            dependency("serde", "1.0", DepType::Runtime),
            dependency("tokio", "1.35", DepType::Runtime),
        ];
        assert_eq!(dependencies, expected);
    }

    #[test]
    fn apply_update_patches_a_workspace_dependency() {
        let manager = CargoManager::new();
        let serde = dependency("serde", "1.0", DepType::Runtime);

        let updated = manager
            .apply_update(WORKSPACE_MANIFEST, &serde, "1.1.0")
            .expect("serde is present under [workspace.dependencies]");

        let expected = WORKSPACE_MANIFEST.replacen("serde = \"1.0\"", "serde = \"1.1.0\"", 1);
        assert_eq!(updated, expected);
        assert!(updated.contains(r#"tokio = { version = "1.35", features = ["rt"] }"#));
    }

    const DOTTED_KEY_MANIFEST: &str =
        "[dependencies]\nserde.version = \"1.2.3\"\nserde.features = [\"derive\"]\n\nother = \"1.0\"\n";

    #[test]
    fn extract_discovers_dotted_key_shorthand_dependencies() {
        let manager = CargoManager::new();

        let dependencies = manager
            .extract("Cargo.toml", DOTTED_KEY_MANIFEST)
            .expect("dotted-key manifest should parse");

        let expected = vec![
            dependency("serde", "1.2.3", DepType::Runtime),
            dependency("other", "1.0", DepType::Runtime),
        ];
        assert_eq!(dependencies, expected);
    }

    #[test]
    fn apply_update_patches_a_dotted_key_shorthand_dependency() {
        let manager = CargoManager::new();
        let serde = dependency("serde", "1.2.3", DepType::Runtime);

        let updated = manager
            .apply_update(DOTTED_KEY_MANIFEST, &serde, "1.3.0")
            .expect("serde.version is present under [dependencies]");

        let expected = "[dependencies]\nserde.version = \"1.3.0\"\nserde.features = [\"derive\"]\n\nother = \"1.0\"\n";
        assert_eq!(updated, expected);
    }

    #[test]
    fn apply_update_replaces_a_value_containing_an_escaped_quote_without_truncating() {
        let manager = CargoManager::new();
        let content = "[dependencies]\nserde = \"1.0\\\"weird\"\n";
        let dependency = dependency("serde", "1.0\"weird", DepType::Runtime);

        let updated = manager
            .apply_update(content, &dependency, "2.0.0")
            .expect("serde is present");

        let expected = "[dependencies]\nserde = \"2.0.0\"\n";
        assert_eq!(updated, expected);
    }
}
