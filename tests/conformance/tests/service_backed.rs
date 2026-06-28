use std::sync::Arc;

use ahash::AHashMap;
use async_trait::async_trait;
use bytes::Bytes;
use starmetal_core::error::{Result, StarmetalError};
use starmetal_core::package::{
    ArtifactDigest, ArtifactId, Ecosystem, PackageName, VersionInfo, VersionMetadata,
};
use starmetal_core::policy::PolicyConfig;
use starmetal_core::ports::{PackageService, UpstreamClient};
use starmetal_service::CachingPackageService;
use starmetal_storage::OpenDalStorage;

const ARTIFACT_BYTES: &[u8] = b"artifact bytes";
const SHA1: &str = "1f80eeacf4808e99293f1d55132f34cd5c5a46a5";
const SHA256: &str = "4659fc0570122b0e0aa14f4ff7c261b1fe51795a01ba79963f462ebf40d7520d";
const SHA512_BASE64: &str =
    "2+ZxEOA7dhjT/g95Er8TdnGPbdnMm0EDQR0/IrDlIEoMHM9tOZFql9d40U7tTF5fSAx7PFIIUTHjWNoPb/bs1Q==";
const SRI: &str = "sha512-2+ZxEOA7dhjT/g95Er8TdnGPbdnMm0EDQR0/IrDlIEoMHM9tOZFql9d40U7tTF5fSAx7PFIIUTHjWNoPb/bs1Q==";

struct StaticUpstream {
    ecosystem: Ecosystem,
    metadata: VersionMetadata,
    artifact_bytes: Bytes,
}

#[async_trait]
impl UpstreamClient for StaticUpstream {
    fn ecosystem(&self) -> Ecosystem {
        self.ecosystem
    }

    async fn fetch_versions(&self, _name: &PackageName) -> Result<Vec<VersionInfo>> {
        Ok(vec![VersionInfo {
            version: self.metadata.version.clone(),
            yanked: self.metadata.yanked,
        }])
    }

    async fn fetch_metadata(&self, _name: &PackageName, _version: &str) -> Result<VersionMetadata> {
        Ok(self.metadata.clone())
    }

    async fn fetch_artifact(&self, _artifact_id: &ArtifactId) -> Result<Bytes> {
        Ok(self.artifact_bytes.clone())
    }
}

fn metadata(
    _ecosystem: Ecosystem,
    name: &str,
    version: &str,
    filename: &str,
    hashes: &[(&str, &str)],
) -> VersionMetadata {
    VersionMetadata {
        name: PackageName::new(name),
        version: version.to_string(),
        artifacts: vec![ArtifactDigest {
            filename: filename.to_string(),
            blake3: String::new(),
            size: 0,
            upstream_hashes: hashes
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
        }],
        license: Some("MIT".to_string()),
        yanked: false,
    }
}

fn service_for(
    ecosystem: Ecosystem,
    metadata: VersionMetadata,
    artifact_bytes: Bytes,
    policy: PolicyConfig,
) -> CachingPackageService {
    let upstream = StaticUpstream {
        ecosystem,
        metadata,
        artifact_bytes,
    };
    let mut upstreams: AHashMap<Ecosystem, Arc<dyn UpstreamClient>> = AHashMap::new();
    upstreams.insert(ecosystem, Arc::new(upstream));
    CachingPackageService::new(
        Arc::new(OpenDalStorage::memory().expect("memory storage")),
        upstreams,
        policy,
    )
}

#[tokio::test]
async fn service_backed_cache_fetches_and_reuses_artifacts_for_each_registry() {
    for (ecosystem, name, version, filename, hashes) in [
        (
            Ecosystem::PyPI,
            "six",
            "1.16.0",
            "six-1.16.0.tar.gz",
            vec![("sha256", SHA256)],
        ),
        (
            Ecosystem::Npm,
            "is-odd",
            "3.0.1",
            "is-odd-3.0.1.tgz",
            vec![("integrity", SRI)],
        ),
        (
            Ecosystem::Cargo,
            "once_cell",
            "1.19.0",
            "once_cell-1.19.0.crate",
            vec![("sha256", SHA256)],
        ),
        (
            Ecosystem::Hex,
            "jason",
            "1.4.1",
            "jason-1.4.1.tar",
            vec![("sha256", SHA256)],
        ),
        (
            Ecosystem::Maven,
            "junit:junit",
            "4.13.2",
            "junit-4.13.2.jar",
            vec![("sha1", SHA1)],
        ),
        (
            Ecosystem::RubyGems,
            "rack",
            "2.2.8",
            "rack-2.2.8.gem",
            vec![("sha256", SHA256)],
        ),
        (
            Ecosystem::NuGet,
            "newtonsoft.json",
            "13.0.3",
            "newtonsoft.json.13.0.3.nupkg",
            vec![("sha512", SHA512_BASE64)],
        ),
        (
            Ecosystem::Pub,
            "collection",
            "1.18.0",
            "collection-1.18.0.tar.gz",
            vec![("sha256", SHA256)],
        ),
    ] {
        let metadata = metadata(ecosystem, name, version, filename, &hashes);
        let service = service_for(
            ecosystem,
            metadata,
            Bytes::from_static(ARTIFACT_BYTES),
            PolicyConfig::default(),
        );
        let artifact = ArtifactId {
            ecosystem,
            name: PackageName::new(name),
            version: version.to_string(),
            filename: filename.to_string(),
        };

        let first = service
            .get_artifact(&artifact)
            .await
            .unwrap_or_else(|err| panic!("{ecosystem} first artifact fetch failed: {err}"));
        let second = service
            .get_artifact(&artifact)
            .await
            .unwrap_or_else(|err| panic!("{ecosystem} cached artifact fetch failed: {err}"));

        assert_eq!(first, Bytes::from_static(ARTIFACT_BYTES));
        assert_eq!(second, Bytes::from_static(ARTIFACT_BYTES));
    }
}

#[tokio::test]
async fn service_backed_conformance_rejects_policy_violations() {
    let metadata = metadata(
        Ecosystem::PyPI,
        "blocked-package",
        "1.0.0",
        "blocked-package-1.0.0.tar.gz",
        &[("sha256", SHA256)],
    );
    let policy = PolicyConfig {
        blocked_packages: vec!["blocked-package".to_string()],
        ..PolicyConfig::default()
    };
    let service = service_for(
        Ecosystem::PyPI,
        metadata,
        Bytes::from_static(ARTIFACT_BYTES),
        policy,
    );
    let artifact = ArtifactId {
        ecosystem: Ecosystem::PyPI,
        name: PackageName::new("blocked-package"),
        version: "1.0.0".to_string(),
        filename: "blocked-package-1.0.0.tar.gz".to_string(),
    };

    let err = service
        .get_artifact(&artifact)
        .await
        .expect_err("blocked package should not be served");
    assert!(matches!(err, StarmetalError::PolicyViolation(_)));
}

#[tokio::test]
async fn service_backed_conformance_rejects_bad_upstream_hashes() {
    for (algorithm, bad_hash) in [
        ("sha256", "bad-sha256"),
        ("sha1", "bad-sha1"),
        ("sha512", "bad-sha512"),
        ("integrity", "sha512-bad-sri"),
    ] {
        let metadata = metadata(
            Ecosystem::Npm,
            "hash-test",
            "1.0.0",
            "hash-test-1.0.0.tgz",
            &[(algorithm, bad_hash)],
        );
        let service = service_for(
            Ecosystem::Npm,
            metadata,
            Bytes::from_static(ARTIFACT_BYTES),
            PolicyConfig::default(),
        );
        let artifact = ArtifactId {
            ecosystem: Ecosystem::Npm,
            name: PackageName::new("hash-test"),
            version: "1.0.0".to_string(),
            filename: "hash-test-1.0.0.tgz".to_string(),
        };

        let err = service
            .get_artifact(&artifact)
            .await
            .expect_err(&format!("{algorithm} mismatch should be rejected"));
        assert!(
            matches!(err, StarmetalError::IntegrityError { .. }),
            "expected integrity error for {algorithm}, got {err:?}"
        );
    }
}
