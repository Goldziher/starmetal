use starmetal_core::registry::{
    cargo::CargoIndexEntry, hex::HexPackage, npm::NpmPackument, pypi::PypiProject,
};

const PYPI_FIXTURE: &str = r#"{
    "meta": { "api-version": "1.0" },
    "name": "requests",
    "versions": ["2.31.0", "2.32.0"],
    "files": [
        {
            "filename": "requests-2.32.0-py3-none-any.whl",
            "url": "https://files.pythonhosted.org/packages/requests-2.32.0-py3-none-any.whl",
            "hashes": {
                "sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
            },
            "requires-python": ">=3.8",
            "yanked": false,
            "size": 63721,
            "upload-time": "2024-05-20T12:00:00Z"
        },
        {
            "filename": "requests-2.32.0.tar.gz",
            "url": "https://files.pythonhosted.org/packages/requests-2.32.0.tar.gz",
            "hashes": {
                "sha256": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3"
            },
            "requires-python": ">=3.8",
            "yanked": false,
            "size": 131200
        }
    ]
}"#;

const NPM_FIXTURE: &str = r##"{
    "name": "express",
    "description": "Fast, unopinionated, minimalist web framework",
    "dist-tags": {
        "latest": "4.21.0",
        "next": "5.0.0-beta.3"
    },
    "versions": {
        "4.21.0": {
            "name": "express",
            "version": "4.21.0",
            "description": "Fast, unopinionated, minimalist web framework",
            "license": "MIT",
            "dependencies": {
                "body-parser": "1.20.3",
                "cookie": "0.6.0",
                "debug": "2.6.9",
                "finalhandler": "1.3.1",
                "path-to-regexp": "0.1.10"
            },
            "devDependencies": {
                "mocha": "10.4.0",
                "supertest": "7.0.0"
            },
            "dist": {
                "tarball": "https://registry.npmjs.org/express/-/express-4.21.0.tgz",
                "shasum": "d57cb706d49623d4ac27833f1cbc466b668eb915",
                "integrity": "sha512-VqcNGcj/Id5ZT1LZ/cfihi3ttTn+NJmkli2eZADigjq29qTlWi/hAQ43t/VLPq8+UX06FCEx3ByOYet6ZFblA==",
                "fileCount": 214,
                "unpackedSize": 220012
            }
        }
    },
    "time": {
        "created": "2010-12-29T19:38:25.450Z",
        "4.21.0": "2024-09-11T15:00:00.000Z"
    },
    "readme": "# Express - Fast web framework for Node.js"
}"##;

const CARGO_FIXTURE: &str = r#"{
    "name": "serde",
    "vers": "1.0.210",
    "deps": [
        {
            "name": "serde_derive",
            "req": "=1.0.210",
            "features": [],
            "optional": true,
            "default_features": true,
            "target": null,
            "kind": "normal",
            "registry": null,
            "package": null
        },
        {
            "name": "serde_test",
            "req": "^1.0",
            "features": [],
            "optional": false,
            "default_features": true,
            "target": null,
            "kind": "dev"
        }
    ],
    "cksum": "a]b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "features": {
        "default": ["std"],
        "std": [],
        "derive": ["serde_derive"],
        "alloc": [],
        "rc": [],
        "unstable": []
    },
    "features2": {},
    "yanked": false,
    "links": null,
    "v": 2,
    "rust_version": "1.31"
}"#;

const HEX_FIXTURE: &str = r#"{
    "name": "phoenix",
    "url": "https://hex.pm/api/packages/phoenix",
    "html_url": "https://hex.pm/packages/phoenix",
    "meta": {
        "description": "Peace of mind from prototype to production",
        "licenses": ["MIT"],
        "links": {
            "GitHub": "https://github.com/phoenixframework/phoenix"
        },
        "maintainers": ["Chris McCord", "Jose Valim"]
    },
    "releases": [
        {
            "version": "1.7.14",
            "url": "https://hex.pm/api/packages/phoenix/releases/1.7.14",
            "has_docs": true,
            "inserted_at": "2024-06-10T10:00:00Z",
            "updated_at": "2024-06-10T10:00:00Z"
        },
        {
            "version": "1.7.12",
            "url": "https://hex.pm/api/packages/phoenix/releases/1.7.12",
            "has_docs": true,
            "inserted_at": "2024-03-15T08:00:00Z",
            "retirement": {
                "reason": "security",
                "message": "CVE-2024-XXXX fixed in 1.7.14"
            }
        }
    ],
    "inserted_at": "2014-08-05T12:00:00Z",
    "updated_at": "2024-06-10T10:00:00Z"
}"#;

#[test]
fn should_deserialize_pypi_pep691_response() {
    let project: PypiProject =
        serde_json::from_str(PYPI_FIXTURE).expect("failed to deserialize PyPI fixture");

    assert_eq!(project.name, "requests");
    assert_eq!(project.meta.api_version, "1.0");
    assert_eq!(project.versions, vec!["2.31.0", "2.32.0"]);
    assert_eq!(project.files.len(), 2);

    let whl = &project.files[0];
    assert_eq!(whl.filename, "requests-2.32.0-py3-none-any.whl");
    assert_eq!(whl.requires_python.as_deref(), Some(">=3.8"));
    assert!(!whl.yanked.is_yanked());
    assert_eq!(whl.size, Some(63721));
    assert!(whl.hashes.contains_key("sha256"));

    let sdist = &project.files[1];
    assert_eq!(sdist.filename, "requests-2.32.0.tar.gz");
    assert!(sdist.upload_time.is_none());
}

#[test]
fn should_deserialize_npm_packument() {
    let packument: NpmPackument =
        serde_json::from_str(NPM_FIXTURE).expect("failed to deserialize npm fixture");

    assert_eq!(packument.name, "express");
    assert_eq!(
        packument.description.as_deref(),
        Some("Fast, unopinionated, minimalist web framework")
    );
    assert_eq!(
        packument.dist_tags.get("latest").map(String::as_str),
        Some("4.21.0")
    );
    assert!(packument.versions.contains_key("4.21.0"));

    let v = &packument.versions["4.21.0"];
    assert_eq!(v.license.as_deref(), Some("MIT"));
    assert_eq!(
        v.dependencies.get("debug").map(String::as_str),
        Some("2.6.9")
    );
    assert_eq!(v.dist.shasum, "d57cb706d49623d4ac27833f1cbc466b668eb915");
    assert!(v.dist.integrity.is_some());
    assert_eq!(v.dist.file_count, Some(214));

    assert!(packument.readme.is_some());
    assert_eq!(
        packument.time.get("created").map(String::as_str),
        Some("2010-12-29T19:38:25.450Z")
    );
}

#[test]
fn should_deserialize_cargo_sparse_index_entry() {
    let entry: CargoIndexEntry =
        serde_json::from_str(CARGO_FIXTURE).expect("failed to deserialize Cargo fixture");

    assert_eq!(entry.name, "serde");
    assert_eq!(entry.vers, "1.0.210");
    assert!(!entry.yanked);
    assert_eq!(entry.v, Some(2));
    assert_eq!(entry.rust_version.as_deref(), Some("1.31"));
    assert_eq!(entry.deps.len(), 2);

    let derive_dep = &entry.deps[0];
    assert_eq!(derive_dep.name, "serde_derive");
    assert_eq!(derive_dep.req, "=1.0.210");
    assert!(derive_dep.optional);

    let features = &entry.features;
    assert!(features.contains_key("default"));
    assert_eq!(features["default"], vec!["std"]);
    assert!(features.contains_key("derive"));
}

#[test]
fn should_deserialize_hex_package_response() {
    let package: HexPackage =
        serde_json::from_str(HEX_FIXTURE).expect("failed to deserialize Hex fixture");

    assert_eq!(package.name, "phoenix");
    assert_eq!(
        package.url.as_deref(),
        Some("https://hex.pm/api/packages/phoenix")
    );
    assert_eq!(package.releases.len(), 2);

    let meta = package.meta.as_ref().expect("meta should be present");
    assert_eq!(
        meta.description.as_deref(),
        Some("Peace of mind from prototype to production")
    );
    assert_eq!(meta.licenses, vec!["MIT"]);
    assert_eq!(meta.maintainers.len(), 2);

    let latest = &package.releases[0];
    assert_eq!(latest.version, "1.7.14");
    assert!(latest.has_docs);
    assert!(!latest.is_retired());

    let retired = &package.releases[1];
    assert_eq!(retired.version, "1.7.12");
    assert!(retired.is_retired());
    let retirement = retired
        .retirement
        .as_ref()
        .expect("should have retirement info");
    assert_eq!(retirement.reason, "security");
    assert!(
        retirement
            .message
            .as_ref()
            .is_some_and(|m| m.contains("CVE"))
    );
}

#[test]
fn should_roundtrip_pypi_through_serialize_deserialize() {
    let project: PypiProject = serde_json::from_str(PYPI_FIXTURE).unwrap();
    let json = serde_json::to_string(&project).unwrap();
    let roundtripped: PypiProject = serde_json::from_str(&json).unwrap();
    assert_eq!(project.name, roundtripped.name);
    assert_eq!(project.files.len(), roundtripped.files.len());
}

#[test]
fn should_handle_yanked_pypi_variants() {
    let with_reason = r#"{
        "meta": { "api-version": "1.0" },
        "name": "broken-pkg",
        "files": [{
            "filename": "broken-1.0.tar.gz",
            "url": "https://example.com/broken-1.0.tar.gz",
            "hashes": { "sha256": "abc123" },
            "yanked": "security vulnerability"
        }]
    }"#;

    let project: PypiProject = serde_json::from_str(with_reason).unwrap();
    assert!(project.files[0].yanked.is_yanked());
}
