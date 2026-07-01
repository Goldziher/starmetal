use std::collections::BTreeMap;
#[cfg(not(unix))]
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(unix)]
use std::{fs, os::unix::fs::PermissionsExt};

use ahash::AHashMap;
use async_trait::async_trait;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use bytes::Bytes;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use pkcs8::DecodePrivateKey;
use sha2::Digest;
use starmetal_core::error::{Result, StarmetalError};
use starmetal_core::integrity;
use starmetal_core::package::{
    ArtifactDigest, ArtifactId, Ecosystem, PackageName, StorageKey, VersionInfo, VersionMetadata,
    decode_storage_segment, validate_storage_segment,
};
use starmetal_core::policy::PolicyConfig;
use starmetal_core::ports::{
    PackageService, PublishingService, StatisticsService, StoragePort, UpstreamClient,
};
use starmetal_core::publishing::{
    ProtocolMetadata, PublishMode, PublishRecord, PublishRequest, PublishResult, PublishSource,
    YankRequest,
};
use starmetal_core::signing::{
    DsseEnvelope, DsseSignature, STARMETAL_DSSE_PAYLOAD_TYPE, SignatureSource, SignatureStatement,
    SigningAlgorithm, SigningConfig, SigningKeyStatus, SigningMode,
};
use starmetal_core::statistics::{EcosystemStatistics, StatisticsSnapshot};
use zeroize::Zeroizing;

const DSSE_PAE_PREFIX: &str = "DSSEv1";

pub struct SigningService {
    mode: SigningMode,
    verify_on_read: bool,
    sign_cached_upstream: bool,
    keys: Vec<SigningKeyMaterial>,
}

struct SigningKeyMaterial {
    id: String,
    algorithm: SigningAlgorithm,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    certificate_fingerprint_sha256: Option<String>,
    certificate_chain_pem: Vec<String>,
    ecosystems: Vec<Ecosystem>,
    packages: Vec<String>,
}

struct StatementInput {
    ecosystem: Ecosystem,
    package: PackageName,
    version: String,
    filename: Option<String>,
    storage_key: String,
    size: u64,
    blake3: String,
    upstream_hashes: AHashMap<String, String>,
    source: SignatureSource,
}

impl SigningService {
    pub fn from_config(config: &SigningConfig) -> Result<Option<Self>> {
        if !config.enabled {
            return Ok(None);
        }

        let mut keys = Vec::new();
        for key in &config.keys {
            if key.status == SigningKeyStatus::Disabled {
                continue;
            }
            let Some(private_key_file) = &key.private_key_file else {
                continue;
            };
            if key.private_key_password_env.is_some() {
                return Err(StarmetalError::Config(format!(
                    "signing key {} uses encrypted private keys, which are not implemented yet",
                    key.id
                )));
            }
            validate_private_key_permissions(private_key_file)?;
            let private_key_pem = Zeroizing::new(fs::read_to_string(private_key_file)?);
            let signing_key =
                SigningKey::from_pkcs8_pem(private_key_pem.as_str()).map_err(|err| {
                    StarmetalError::Config(format!("invalid signing key {}: {err}", key.id))
                })?;
            let verifying_key = signing_key.verifying_key();
            let certificate_fingerprint_sha256 =
                optional_file_sha256(key.certificate_file.as_deref())?;
            let certificate_chain_pem = optional_pem_chain(key.certificate_chain_file.as_deref())?;
            keys.push(SigningKeyMaterial {
                id: key.id.clone(),
                algorithm: key.algorithm,
                signing_key,
                verifying_key,
                certificate_fingerprint_sha256,
                certificate_chain_pem,
                ecosystems: key.ecosystems.clone(),
                packages: key.packages.clone(),
            });
        }

        if matches!(
            config.mode,
            SigningMode::SignOnly | SigningMode::SignAndVerify
        ) && !keys
            .iter()
            .any(|key| key.algorithm == SigningAlgorithm::Ed25519)
        {
            return Err(StarmetalError::Config(
                "signing requires a loadable active ed25519 key".to_string(),
            ));
        }

        Ok(Some(Self {
            mode: config.mode,
            verify_on_read: config.verify_on_read,
            sign_cached_upstream: config.sign_cached_upstream,
            keys,
        }))
    }

    fn verify_on_read(&self) -> bool {
        self.verify_on_read
            && matches!(
                self.mode,
                SigningMode::SignAndVerify | SigningMode::VerifyOnly
            )
    }

    fn sign_cached_upstream(&self) -> bool {
        self.sign_cached_upstream
            && matches!(
                self.mode,
                SigningMode::SignOnly | SigningMode::SignAndVerify
            )
    }

    fn select_key(
        &self,
        ecosystem: Ecosystem,
        package: &PackageName,
    ) -> Result<&SigningKeyMaterial> {
        self.keys
            .iter()
            .find(|key| {
                let ecosystem_allowed =
                    key.ecosystems.is_empty() || key.ecosystems.contains(&ecosystem);
                let package_allowed = key.packages.is_empty()
                    || key.packages.iter().any(|name| name == package.as_str());
                ecosystem_allowed && package_allowed
            })
            .ok_or_else(|| {
                StarmetalError::Config(format!(
                    "no signing key is scoped for {ecosystem}/{package}"
                ))
            })
    }

    fn statement(&self, input: StatementInput) -> Result<SignatureStatement> {
        let key = self.select_key(input.ecosystem, &input.package)?;
        Ok(SignatureStatement {
            ecosystem: input.ecosystem,
            package: input.package,
            version: input.version,
            filename: input.filename,
            storage_key: input.storage_key,
            size: input.size,
            blake3: input.blake3,
            upstream_hashes: input
                .upstream_hashes
                .into_iter()
                .collect::<BTreeMap<_, _>>(),
            source: input.source,
            issued_at_unix_seconds: unix_now(),
            key_id: key.id.clone(),
            certificate_fingerprint_sha256: key.certificate_fingerprint_sha256.clone(),
        })
    }

    fn sign_statement(&self, statement: SignatureStatement) -> Result<DsseEnvelope> {
        if !matches!(
            self.mode,
            SigningMode::SignOnly | SigningMode::SignAndVerify
        ) {
            return Err(StarmetalError::Config(
                "signing service is not configured for signing".to_string(),
            ));
        }
        let key = self.select_key(statement.ecosystem, &statement.package)?;
        let payload = serde_json::to_vec(&statement)?;
        let pae = dsse_pae(STARMETAL_DSSE_PAYLOAD_TYPE.as_bytes(), &payload);
        let signature = key.signing_key.sign(&pae);
        Ok(DsseEnvelope {
            payload_type: STARMETAL_DSSE_PAYLOAD_TYPE.to_string(),
            payload: BASE64_STANDARD.encode(payload),
            signatures: vec![DsseSignature {
                key_id: key.id.clone(),
                algorithm: key.algorithm,
                signature: BASE64_STANDARD.encode(signature.to_bytes()),
                certificate_fingerprint_sha256: key.certificate_fingerprint_sha256.clone(),
                certificate_chain_pem: key.certificate_chain_pem.clone(),
            }],
        })
    }

    fn verify_envelope(&self, envelope_bytes: &[u8]) -> Result<SignatureStatement> {
        let envelope: DsseEnvelope = serde_json::from_slice(envelope_bytes)?;
        if envelope.payload_type != STARMETAL_DSSE_PAYLOAD_TYPE {
            return Err(StarmetalError::IntegrityError {
                expected: STARMETAL_DSSE_PAYLOAD_TYPE.to_string(),
                actual: envelope.payload_type,
            });
        }
        let payload = BASE64_STANDARD.decode(&envelope.payload).map_err(|err| {
            StarmetalError::IntegrityError {
                expected: "base64 DSSE payload".to_string(),
                actual: err.to_string(),
            }
        })?;
        let pae = dsse_pae(envelope.payload_type.as_bytes(), &payload);
        for signature in &envelope.signatures {
            let Some(key) = self.keys.iter().find(|key| key.id == signature.key_id) else {
                continue;
            };
            if signature.algorithm != key.algorithm {
                continue;
            }
            if signature.certificate_fingerprint_sha256 != key.certificate_fingerprint_sha256 {
                continue;
            }
            let signature_bytes = BASE64_STANDARD
                .decode(&signature.signature)
                .map_err(|err| StarmetalError::IntegrityError {
                    expected: "base64 DSSE signature".to_string(),
                    actual: err.to_string(),
                })?;
            let signature =
                ed25519_dalek::Signature::from_slice(&signature_bytes).map_err(|err| {
                    StarmetalError::IntegrityError {
                        expected: "ed25519 signature".to_string(),
                        actual: err.to_string(),
                    }
                })?;
            if key.verifying_key.verify(&pae, &signature).is_ok() {
                return Ok(serde_json::from_slice(&payload)?);
            }
        }
        Err(StarmetalError::IntegrityError {
            expected: "valid DSSE signature".to_string(),
            actual: "no configured key verified the envelope".to_string(),
        })
    }
}

/// Pull-through caching implementation of `PackageService`.
///
/// Sits between protocol adapters (inbound) and storage/upstream (outbound),
/// applying policy checks and integrity verification on cache misses.
pub struct CachingPackageService {
    storage: Arc<dyn StoragePort>,
    upstream_clients: AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
    policy: PolicyConfig,
    signing: Option<Arc<SigningService>>,
    statistics: Mutex<StatisticsSnapshot>,
}

struct StoredObjectSignatureCheck<'a> {
    ecosystem: Ecosystem,
    name: &'a PackageName,
    version: &'a str,
    filename: Option<&'a str>,
    storage_key: &'a str,
    data: &'a Bytes,
    source: SignatureSource,
}

impl CachingPackageService {
    pub fn new(
        storage: Arc<dyn StoragePort>,
        upstream_clients: AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
        policy: PolicyConfig,
    ) -> Self {
        Self {
            storage,
            upstream_clients,
            policy,
            signing: None,
            statistics: Mutex::new(StatisticsSnapshot::default()),
        }
    }

    pub fn new_with_signing(
        storage: Arc<dyn StoragePort>,
        upstream_clients: AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
        policy: PolicyConfig,
        signing: Option<SigningService>,
    ) -> Self {
        Self {
            storage,
            upstream_clients,
            policy,
            signing: signing.map(Arc::new),
            statistics: Mutex::new(StatisticsSnapshot::default()),
        }
    }

    fn upstream(&self, ecosystem: Ecosystem) -> Result<&Arc<dyn UpstreamClient>> {
        self.upstream_clients.get(&ecosystem).ok_or_else(|| {
            StarmetalError::Config(format!("no upstream configured for {ecosystem}"))
        })
    }

    fn check_package_allowed(&self, name: &PackageName) -> Result<()> {
        if self
            .policy
            .blocked_packages
            .iter()
            .any(|b| b == name.as_str())
        {
            return Err(StarmetalError::PolicyViolation(format!(
                "package {name} is blocked"
            )));
        }
        Ok(())
    }

    fn verify_upstream_hash(data: &Bytes, digest: &ArtifactDigest) -> Result<()> {
        if let Some(integrity) = digest.upstream_hashes.get("integrity") {
            return verify_subresource_integrity(data, integrity);
        }

        if let Some(expected) = digest.upstream_hashes.get("sha256") {
            let actual = hex::encode(sha2::Sha256::digest(data));
            return verify_hex_digest("sha256", expected, &actual);
        }

        if let Some(expected) = digest.upstream_hashes.get("sha1") {
            let actual = hex::encode(sha1::Sha1::digest(data));
            return verify_hex_digest("sha1", expected, &actual);
        }

        if let Some(expected) = digest.upstream_hashes.get("sha512") {
            let actual = base64::Engine::encode(&BASE64_STANDARD, sha2::Sha512::digest(data));
            return verify_hex_digest("sha512", expected, &actual);
        }

        Ok(())
    }

    fn versions_key(ecosystem: Ecosystem, name: &PackageName) -> Result<String> {
        let name = name.storage_segment()?;
        let ecosystem = ecosystem.to_string();
        Ok(StorageKey::from_segments(&[&ecosystem, &name, "_versions.json"])?.into_string())
    }

    fn metadata_key(ecosystem: Ecosystem, name: &PackageName, version: &str) -> Result<String> {
        let name = name.storage_segment()?;
        validate_storage_segment("version", version)?;
        let ecosystem = ecosystem.to_string();
        Ok(
            StorageKey::from_segments(&[&ecosystem, &name, version, "_metadata.json"])?
                .into_string(),
        )
    }

    fn raw_upstream_key(ecosystem: Ecosystem, name: &PackageName) -> Result<String> {
        let name = name.storage_segment()?;
        let ecosystem = ecosystem.to_string();
        Ok(StorageKey::from_segments(&[&ecosystem, &name, "_raw_upstream"])?.into_string())
    }

    fn published_record_key(
        ecosystem: Ecosystem,
        name: &PackageName,
        version: &str,
    ) -> Result<String> {
        let name = name.storage_segment()?;
        validate_storage_segment("version", version)?;
        let ecosystem = ecosystem.to_string();
        Ok(StorageKey::from_segments(&[
            "_starmetal",
            "published",
            &ecosystem,
            &name,
            version,
            "record.json",
        ])?
        .into_string())
    }

    fn published_legacy_manifest_key(
        ecosystem: Ecosystem,
        name: &PackageName,
        version: &str,
    ) -> Result<String> {
        let name = name.storage_segment()?;
        validate_storage_segment("version", version)?;
        let ecosystem = ecosystem.to_string();
        let manifest = format!("{version}.json");
        validate_storage_segment("published manifest filename", &manifest)?;
        Ok(
            StorageKey::from_segments(&["_starmetal", "published", &ecosystem, &name, &manifest])?
                .into_string(),
        )
    }

    fn signature_sidecar_key(storage_key: &str) -> String {
        format!("{storage_key}.starmetal.sig.json")
    }

    fn signature_bundle_key(
        ecosystem: Ecosystem,
        name: &PackageName,
        version: &str,
        filename: &str,
    ) -> Result<String> {
        let name = name.storage_segment()?;
        validate_storage_segment("version", version)?;
        let filename = crate_safe_signature_filename(filename)?;
        let ecosystem = ecosystem.to_string();
        Ok(StorageKey::from_segments(&[
            "_starmetal",
            "signatures",
            &ecosystem,
            &name,
            version,
            &filename,
        ])?
        .into_string())
    }

    async fn put_and_track(
        &self,
        key: &str,
        data: Bytes,
        staged_keys: &mut Vec<String>,
    ) -> Result<()> {
        self.storage.put(key, data).await?;
        staged_keys.push(key.to_string());
        Ok(())
    }

    async fn rollback_staged_keys(&self, keys: &[String]) {
        for key in keys.iter().rev() {
            if let Err(err) = self.storage.delete(key).await {
                tracing::warn!(key, error = %err, "failed to roll back staged publish key");
            }
        }
    }

    async fn sign_and_store_statement(
        &self,
        statement: SignatureStatement,
        sidecar_key: &str,
        bundle_key: &str,
        staged_keys: &mut Vec<String>,
    ) -> Result<()> {
        let Some(signing) = &self.signing else {
            return Ok(());
        };
        let envelope = signing.sign_statement(statement)?;
        let bytes = Bytes::from(serde_json::to_vec(&envelope)?);
        self.put_and_track(sidecar_key, bytes.clone(), staged_keys)
            .await?;
        self.put_and_track(bundle_key, bytes, staged_keys).await
    }

    fn verify_on_read(&self) -> bool {
        self.signing
            .as_ref()
            .is_some_and(|signing| signing.verify_on_read())
    }

    async fn verify_storage_signature(&self, check: StoredObjectSignatureCheck<'_>) -> Result<()> {
        let Some(signing) = &self.signing else {
            return Ok(());
        };
        let sidecar_key = Self::signature_sidecar_key(check.storage_key);
        let envelope_bytes = self.storage.get(&sidecar_key).await?.ok_or_else(|| {
            StarmetalError::IntegrityError {
                expected: format!("signature sidecar {sidecar_key}"),
                actual: "missing signature sidecar".to_string(),
            }
        })?;
        let statement = signing.verify_envelope(&envelope_bytes)?;
        let actual = integrity::blake3_hex(check.data);
        if statement.storage_key != check.storage_key
            || statement.ecosystem != check.ecosystem
            || statement.package != *check.name
            || statement.version != check.version
            || statement.filename.as_deref() != check.filename
            || statement.blake3 != actual
            || statement.size != check.data.len() as u64
            || statement.source != check.source
        {
            return Err(StarmetalError::IntegrityError {
                expected: "signature statement matching stored object".to_string(),
                actual: "signature statement mismatch".to_string(),
            });
        }
        Ok(())
    }

    async fn verify_artifact_signature(
        &self,
        artifact_id: &ArtifactId,
        storage_key: &str,
        data: &Bytes,
    ) -> Result<()> {
        let local_result = self
            .verify_storage_signature(StoredObjectSignatureCheck {
                ecosystem: artifact_id.ecosystem,
                name: &artifact_id.name,
                version: &artifact_id.version,
                filename: Some(artifact_id.filename.as_str()),
                storage_key,
                data,
                source: SignatureSource::Local,
            })
            .await;
        match local_result {
            Ok(()) => Ok(()),
            Err(local_err) => self
                .verify_storage_signature(StoredObjectSignatureCheck {
                    ecosystem: artifact_id.ecosystem,
                    name: &artifact_id.name,
                    version: &artifact_id.version,
                    filename: Some(artifact_id.filename.as_str()),
                    storage_key,
                    data,
                    source: SignatureSource::UpstreamCache,
                })
                .await
                .map_err(|_| local_err),
        }
    }

    async fn verify_metadata_signature(
        &self,
        ecosystem: Ecosystem,
        name: &PackageName,
        version: &str,
        storage_key: &str,
        data: &Bytes,
    ) -> Result<()> {
        self.verify_storage_signature(StoredObjectSignatureCheck {
            ecosystem,
            name,
            version,
            filename: None,
            storage_key,
            data,
            source: SignatureSource::Metadata,
        })
        .await
    }

    async fn load_versions_for_publish(
        &self,
        ecosystem: Ecosystem,
        name: &PackageName,
    ) -> Result<Vec<VersionInfo>> {
        let key = Self::versions_key(ecosystem, name)?;
        if let Some(cached) = self.storage.get(&key).await? {
            return Ok(serde_json::from_slice(&cached)?);
        }

        if let Some(upstream) = self.upstream_clients.get(&ecosystem) {
            return match upstream.fetch_versions(name).await {
                Ok(versions) => Ok(versions),
                Err(StarmetalError::PackageNotFound { .. }) => Ok(Vec::new()),
                Err(err) => Err(err),
            };
        }

        Ok(Vec::new())
    }

    async fn store_versions(
        &self,
        ecosystem: Ecosystem,
        name: &PackageName,
        versions: &[VersionInfo],
    ) -> Result<()> {
        let key = Self::versions_key(ecosystem, name)?;
        self.storage
            .put(&key, Bytes::from(serde_json::to_vec(versions)?))
            .await
    }

    fn record_statistics(
        &self,
        ecosystem: Ecosystem,
        update: impl FnOnce(&mut EcosystemStatistics),
    ) {
        let Ok(mut snapshot) = self.statistics.lock() else {
            tracing::warn!("statistics lock is poisoned; skipping statistics update");
            return;
        };
        let stats = snapshot
            .ecosystems
            .entry(ecosystem.to_string())
            .or_insert_with(EcosystemStatistics::default);
        update(stats);
        stats.last_activity_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_secs());
    }

    fn record_upstream_error(&self, ecosystem: Ecosystem) {
        self.record_statistics(ecosystem, |stats| {
            stats.upstream_errors = stats.upstream_errors.saturating_add(1);
        });
    }

    fn record_integrity_failure(&self, ecosystem: Ecosystem) {
        self.record_statistics(ecosystem, |stats| {
            stats.integrity_failures = stats.integrity_failures.saturating_add(1);
        });
    }
}

#[async_trait]
impl PackageService for CachingPackageService {
    async fn list_versions(
        &self,
        ecosystem: Ecosystem,
        name: &PackageName,
    ) -> Result<Vec<VersionInfo>> {
        self.check_package_allowed(name)?;

        let key = Self::versions_key(ecosystem, name)?;

        if let Some(cached) = self.storage.get(&key).await? {
            tracing::debug!(ecosystem = %ecosystem, name = %name, "cache hit for versions");
            self.record_statistics(ecosystem, |stats| {
                stats.versions_cache_hits = stats.versions_cache_hits.saturating_add(1);
            });
            let versions: Vec<VersionInfo> = serde_json::from_slice(&cached)?;
            return Ok(versions);
        }

        self.record_statistics(ecosystem, |stats| {
            stats.versions_cache_misses = stats.versions_cache_misses.saturating_add(1);
        });
        tracing::info!(ecosystem = %ecosystem, name = %name, "fetching versions from upstream");
        let upstream = self.upstream(ecosystem)?;
        let versions = upstream.fetch_versions(name).await.inspect_err(|_err| {
            self.record_upstream_error(ecosystem);
        })?;

        let serialized = serde_json::to_vec(&versions)?;
        self.storage.put(&key, Bytes::from(serialized)).await?;

        Ok(versions)
    }

    async fn get_version_metadata(
        &self,
        ecosystem: Ecosystem,
        name: &PackageName,
        version: &str,
    ) -> Result<VersionMetadata> {
        self.check_package_allowed(name)?;

        let key = Self::metadata_key(ecosystem, name, version)?;

        if let Some(cached) = self.storage.get(&key).await? {
            tracing::debug!(ecosystem = %ecosystem, name = %name, version, "cache hit for metadata");
            self.record_statistics(ecosystem, |stats| {
                stats.metadata_cache_hits = stats.metadata_cache_hits.saturating_add(1);
            });
            if self.verify_on_read() {
                self.verify_metadata_signature(ecosystem, name, version, &key, &cached)
                    .await?;
            }
            let metadata: VersionMetadata = serde_json::from_slice(&cached)?;
            self.policy.check(&metadata)?;
            return Ok(metadata);
        }

        self.record_statistics(ecosystem, |stats| {
            stats.metadata_cache_misses = stats.metadata_cache_misses.saturating_add(1);
        });
        tracing::info!(ecosystem = %ecosystem, name = %name, version, "fetching metadata from upstream");
        let upstream = self.upstream(ecosystem)?;
        let metadata = upstream
            .fetch_metadata(name, version)
            .await
            .inspect_err(|_err| {
                self.record_upstream_error(ecosystem);
            })?;

        self.policy.check(&metadata)?;

        let serialized = serde_json::to_vec(&metadata)?;
        self.storage.put(&key, Bytes::from(serialized)).await?;

        Ok(metadata)
    }

    async fn validate_metadata(&self, metadata: &VersionMetadata) -> Result<()> {
        self.check_package_allowed(&metadata.name)?;
        self.policy.check(metadata)
    }

    async fn get_artifact(&self, artifact_id: &ArtifactId) -> Result<Bytes> {
        self.check_package_allowed(&artifact_id.name)?;
        let metadata = self
            .get_version_metadata(
                artifact_id.ecosystem,
                &artifact_id.name,
                &artifact_id.version,
            )
            .await?;
        let artifact_digest = metadata
            .artifacts
            .iter()
            .find(|artifact| artifact.filename == artifact_id.filename)
            .ok_or_else(|| StarmetalError::ArtifactNotFound(artifact_id.storage_key()))?;

        let key = artifact_id.validated_storage_key()?.into_string();
        let hash_key = format!("{key}.blake3");

        if let Some(cached) = self.storage.get(&key).await? {
            let expected_hash = self.storage.get(&hash_key).await?.ok_or_else(|| {
                self.record_integrity_failure(artifact_id.ecosystem);
                StarmetalError::IntegrityError {
                    expected: format!("missing sidecar {hash_key}"),
                    actual: "unverified cached artifact".to_string(),
                }
            })?;
            let expected = std::str::from_utf8(&expected_hash)
                .map_err(|e| StarmetalError::Storage(e.to_string()))?;
            if let Err(err) = integrity::verify_or_err(&cached, expected) {
                self.record_integrity_failure(artifact_id.ecosystem);
                return Err(err);
            }
            self.record_statistics(artifact_id.ecosystem, |stats| {
                stats.artifact_cache_hits = stats.artifact_cache_hits.saturating_add(1);
                stats.bytes_served = stats.bytes_served.saturating_add(cached.len() as u64);
            });
            if self.verify_on_read() {
                self.verify_artifact_signature(artifact_id, &key, &cached)
                    .await?;
            }
            return Ok(cached);
        }

        self.record_statistics(artifact_id.ecosystem, |stats| {
            stats.artifact_cache_misses = stats.artifact_cache_misses.saturating_add(1);
        });
        tracing::info!(key, "fetching artifact from upstream");
        let upstream = self.upstream(artifact_id.ecosystem)?;
        let data = upstream
            .fetch_artifact(artifact_id)
            .await
            .inspect_err(|_err| {
                self.record_upstream_error(artifact_id.ecosystem);
            })?;
        if let Err(err) = Self::verify_upstream_hash(&data, artifact_digest) {
            self.record_integrity_failure(artifact_id.ecosystem);
            return Err(err);
        }

        let hash = integrity::blake3_hex(&data);
        self.storage.put(&hash_key, Bytes::from(hash)).await?;
        self.storage.put(&key, data.clone()).await?;
        if let Some(signing) = &self.signing
            && signing.sign_cached_upstream()
        {
            let statement = signing.statement(StatementInput {
                ecosystem: artifact_id.ecosystem,
                package: artifact_id.name.clone(),
                version: artifact_id.version.clone(),
                filename: Some(artifact_id.filename.clone()),
                storage_key: key.clone(),
                size: data.len() as u64,
                blake3: integrity::blake3_hex(&data),
                upstream_hashes: artifact_digest.upstream_hashes.clone(),
                source: SignatureSource::UpstreamCache,
            })?;
            let sidecar_key = Self::signature_sidecar_key(&key);
            let bundle_key = Self::signature_bundle_key(
                artifact_id.ecosystem,
                &artifact_id.name,
                &artifact_id.version,
                &format!("{}.sig.json", artifact_id.filename),
            )?;
            let mut staged_keys = Vec::new();
            self.sign_and_store_statement(statement, &sidecar_key, &bundle_key, &mut staged_keys)
                .await?;
        }
        self.record_statistics(artifact_id.ecosystem, |stats| {
            stats.bytes_served = stats.bytes_served.saturating_add(data.len() as u64);
        });

        Ok(data)
    }

    async fn list_packages(&self, ecosystem: Ecosystem) -> Result<Vec<PackageName>> {
        let prefix = format!("{ecosystem}/");
        let keys = self.storage.list_prefix(&prefix).await?;

        let mut seen = ahash::AHashSet::new();
        let mut packages = Vec::new();

        for key in &keys {
            // Keys are "<ecosystem>/<name>/..." — extract second component
            let rest = key.strip_prefix(&prefix).unwrap_or(key);
            if let Some(name) = rest.split('/').next()
                && !name.is_empty()
                && seen.insert(name.to_string())
            {
                packages.push(PackageName::new(decode_storage_segment(name)));
            }
        }

        Ok(packages)
    }

    async fn get_raw_upstream(
        &self,
        ecosystem: Ecosystem,
        name: &PackageName,
    ) -> Result<Option<Bytes>> {
        self.check_package_allowed(name)?;
        let key = Self::raw_upstream_key(ecosystem, name)?;
        self.storage.get(&key).await
    }

    async fn put_raw_upstream(
        &self,
        ecosystem: Ecosystem,
        name: &PackageName,
        data: Bytes,
    ) -> Result<()> {
        self.check_package_allowed(name)?;
        let key = Self::raw_upstream_key(ecosystem, name)?;
        self.storage.put(&key, data).await
    }
}

#[async_trait]
impl PublishingService for CachingPackageService {
    async fn publish_package(&self, request: PublishRequest) -> Result<PublishResult> {
        self.check_package_allowed(&request.name)?;
        if request.artifacts.is_empty() {
            return Err(StarmetalError::Publish(
                "publish requires at least one artifact".to_string(),
            ));
        }

        let metadata_key = Self::metadata_key(request.ecosystem, &request.name, &request.version)?;
        if !request.allow_overwrite && self.storage.exists(&metadata_key).await? {
            return Err(StarmetalError::Publish(format!(
                "version already exists: {}/{}@{}",
                request.ecosystem, request.name, request.version
            )));
        }

        if !request.allow_shadowing
            && let Some(upstream) = self.upstream_clients.get(&request.ecosystem)
            && upstream
                .fetch_metadata(&request.name, &request.version)
                .await
                .is_ok()
        {
            return Err(StarmetalError::Publish(format!(
                "refusing to shadow upstream version: {}/{}@{}",
                request.ecosystem, request.name, request.version
            )));
        }

        let mut staged_keys = Vec::new();
        let mut digests = Vec::with_capacity(request.artifacts.len());
        for artifact in &request.artifacts {
            if artifact.filename.trim().is_empty() {
                return Err(StarmetalError::Publish(
                    "artifact filename must not be empty".to_string(),
                ));
            }
            let artifact_id = ArtifactId {
                ecosystem: request.ecosystem,
                name: request.name.clone(),
                version: request.version.clone(),
                filename: artifact.filename.clone(),
            };
            let _ = artifact_id.validated_storage_key()?;
            let blake3 = integrity::blake3_hex(&artifact.data);
            digests.push(artifact.digest(blake3));
        }

        let mut metadata = request.metadata(digests.clone());
        if request.allow_overwrite
            && let Some(existing) = self.storage.get(&metadata_key).await?
        {
            let mut existing_metadata: VersionMetadata = serde_json::from_slice(&existing)?;
            for digest in digests {
                existing_metadata
                    .artifacts
                    .retain(|artifact| artifact.filename != digest.filename);
                existing_metadata.artifacts.push(digest);
            }
            existing_metadata.license = metadata.license.clone().or(existing_metadata.license);
            existing_metadata.yanked = metadata.yanked;
            existing_metadata.listed = Some(request.listed);
            if !matches!(request.protocol_metadata, ProtocolMetadata::Generic) {
                existing_metadata.protocol_metadata = Some(request.protocol_metadata.clone());
            }
            metadata = existing_metadata;
        }
        self.policy.check(&metadata)?;

        let result = async {
            for artifact in &request.artifacts {
                let artifact_id = ArtifactId {
                    ecosystem: request.ecosystem,
                    name: request.name.clone(),
                    version: request.version.clone(),
                    filename: artifact.filename.clone(),
                };
                let key = artifact_id.validated_storage_key()?.into_string();
                let blake3 = integrity::blake3_hex(&artifact.data);
                self.put_and_track(
                    &format!("{key}.blake3"),
                    Bytes::from(blake3.clone()),
                    &mut staged_keys,
                )
                .await?;
                self.put_and_track(&key, artifact.data.clone(), &mut staged_keys)
                    .await?;

                let statement = self
                    .signing
                    .as_ref()
                    .map(|signing| {
                        signing.statement(StatementInput {
                            ecosystem: request.ecosystem,
                            package: request.name.clone(),
                            version: request.version.clone(),
                            filename: Some(artifact.filename.clone()),
                            storage_key: key.clone(),
                            size: artifact.data.len() as u64,
                            blake3,
                            upstream_hashes: artifact.upstream_hashes.clone(),
                            source: SignatureSource::Local,
                        })
                    })
                    .transpose()?;
                if let Some(statement) = statement {
                    let sidecar_key = Self::signature_sidecar_key(&key);
                    let bundle_key = Self::signature_bundle_key(
                        request.ecosystem,
                        &request.name,
                        &request.version,
                        &format!("{}.sig.json", artifact.filename),
                    )?;
                    self.sign_and_store_statement(
                        statement,
                        &sidecar_key,
                        &bundle_key,
                        &mut staged_keys,
                    )
                    .await?;
                }
            }

            let metadata_bytes = Bytes::from(serde_json::to_vec(&metadata)?);
            self.put_and_track(&metadata_key, metadata_bytes.clone(), &mut staged_keys)
                .await?;
            let metadata_statement = self
                .signing
                .as_ref()
                .map(|signing| {
                    signing.statement(StatementInput {
                        ecosystem: request.ecosystem,
                        package: request.name.clone(),
                        version: request.version.clone(),
                        filename: None,
                        storage_key: metadata_key.clone(),
                        size: metadata_bytes.len() as u64,
                        blake3: integrity::blake3_hex(&metadata_bytes),
                        upstream_hashes: AHashMap::new(),
                        source: SignatureSource::Metadata,
                    })
                })
                .transpose()?;
            if let Some(statement) = metadata_statement {
                let sidecar_key = Self::signature_sidecar_key(&metadata_key);
                let bundle_key = Self::signature_bundle_key(
                    request.ecosystem,
                    &request.name,
                    &request.version,
                    "metadata.sig.json",
                )?;
                self.sign_and_store_statement(
                    statement,
                    &sidecar_key,
                    &bundle_key,
                    &mut staged_keys,
                )
                .await?;
            }

            let published_manifest_key = Self::published_legacy_manifest_key(
                request.ecosystem,
                &request.name,
                &request.version,
            )?;
            self.put_and_track(&published_manifest_key, metadata_bytes, &mut staged_keys)
                .await?;

            let record = PublishRecord {
                ecosystem: request.ecosystem,
                name: request.name.clone(),
                version: request.version.clone(),
                artifacts: metadata.artifacts.clone(),
                source: PublishSource::Local,
                protocol_metadata: request.protocol_metadata.clone(),
                published_at_unix_seconds: unix_now(),
                yanked: metadata.yanked,
                listed: request.listed,
            };
            let record_key =
                Self::published_record_key(request.ecosystem, &request.name, &request.version)?;
            self.put_and_track(
                &record_key,
                Bytes::from(serde_json::to_vec(&record)?),
                &mut staged_keys,
            )
            .await?;

            let mut versions = self
                .load_versions_for_publish(request.ecosystem, &request.name)
                .await?;
            if let Some(version) = versions
                .iter_mut()
                .find(|version| version.version == request.version)
            {
                version.yanked = request.yanked;
            } else {
                versions.push(VersionInfo {
                    version: request.version.clone(),
                    yanked: request.yanked,
                });
            }
            let versions_key = Self::versions_key(request.ecosystem, &request.name)?;
            self.put_and_track(
                &versions_key,
                Bytes::from(serde_json::to_vec(&versions)?),
                &mut staged_keys,
            )
            .await?;

            Ok(PublishResult {
                ecosystem: request.ecosystem,
                name: request.name.clone(),
                version: request.version.clone(),
                artifacts: metadata.artifacts.clone(),
                mode: PublishMode::Local,
            })
        }
        .await;

        let result = match result {
            Ok(result) => result,
            Err(err) => {
                self.rollback_staged_keys(&staged_keys).await;
                return Err(err);
            }
        };

        self.record_statistics(request.ecosystem, |stats| {
            stats.publishes = stats.publishes.saturating_add(1);
        });

        Ok(result)
    }

    async fn set_yanked(&self, request: YankRequest) -> Result<VersionMetadata> {
        self.check_package_allowed(&request.name)?;
        let metadata_key = Self::metadata_key(request.ecosystem, &request.name, &request.version)?;
        let cached = self.storage.get(&metadata_key).await?.ok_or_else(|| {
            StarmetalError::VersionNotFound {
                ecosystem: request.ecosystem.to_string(),
                name: request.name.to_string(),
                version: request.version.clone(),
            }
        })?;
        let mut metadata: VersionMetadata = serde_json::from_slice(&cached)?;
        metadata.yanked = request.yanked;
        self.policy.check(&metadata)?;

        let metadata_bytes = Bytes::from(serde_json::to_vec(&metadata)?);
        self.storage
            .put(&metadata_key, metadata_bytes.clone())
            .await?;
        let metadata_statement = self
            .signing
            .as_ref()
            .map(|signing| {
                signing.statement(StatementInput {
                    ecosystem: request.ecosystem,
                    package: request.name.clone(),
                    version: request.version.clone(),
                    filename: None,
                    storage_key: metadata_key.clone(),
                    size: metadata_bytes.len() as u64,
                    blake3: integrity::blake3_hex(&metadata_bytes),
                    upstream_hashes: AHashMap::new(),
                    source: SignatureSource::Metadata,
                })
            })
            .transpose()?;
        if let Some(statement) = metadata_statement {
            let sidecar_key = Self::signature_sidecar_key(&metadata_key);
            let bundle_key = Self::signature_bundle_key(
                request.ecosystem,
                &request.name,
                &request.version,
                "metadata.sig.json",
            )?;
            let mut staged_keys = Vec::new();
            self.sign_and_store_statement(statement, &sidecar_key, &bundle_key, &mut staged_keys)
                .await?;
        }
        let published_manifest_key = Self::published_legacy_manifest_key(
            request.ecosystem,
            &request.name,
            &request.version,
        )?;
        self.storage
            .put(&published_manifest_key, metadata_bytes)
            .await?;
        let record_key =
            Self::published_record_key(request.ecosystem, &request.name, &request.version)?;
        if let Some(record_bytes) = self.storage.get(&record_key).await? {
            let mut record: PublishRecord = serde_json::from_slice(&record_bytes)?;
            record.yanked = request.yanked;
            self.storage
                .put(&record_key, Bytes::from(serde_json::to_vec(&record)?))
                .await?;
        }

        let mut versions = self
            .load_versions_for_publish(request.ecosystem, &request.name)
            .await?;
        if let Some(version) = versions
            .iter_mut()
            .find(|version| version.version == request.version)
        {
            version.yanked = request.yanked;
        } else {
            versions.push(VersionInfo {
                version: request.version.clone(),
                yanked: request.yanked,
            });
        }
        self.store_versions(request.ecosystem, &request.name, &versions)
            .await?;
        self.record_statistics(request.ecosystem, |stats| {
            stats.yanks = stats.yanks.saturating_add(1);
        });

        Ok(metadata)
    }
}

impl StatisticsService for CachingPackageService {
    fn statistics(&self) -> StatisticsSnapshot {
        match self.statistics.lock() {
            Ok(snapshot) => snapshot.clone(),
            Err(_) => {
                tracing::warn!("statistics lock is poisoned; returning empty statistics snapshot");
                StatisticsSnapshot::default()
            }
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map_or(0, |duration| duration.as_secs())
}

fn dsse_pae(payload_type: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(DSSE_PAE_PREFIX.as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(payload_type.len().to_string().as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(payload_type);
    encoded.push(b' ');
    encoded.extend_from_slice(payload.len().to_string().as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(payload);
    encoded
}

fn crate_safe_signature_filename(filename: &str) -> Result<String> {
    let encoded = filename
        .bytes()
        .map(|byte| match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'_' => {
                char::from(byte).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect::<String>();
    validate_storage_segment("signature filename", &encoded)?;
    Ok(encoded)
}

fn optional_file_sha256(path: Option<&Path>) -> Result<Option<String>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes = fs::read(path)?;
    Ok(Some(hex::encode(sha2::Sha256::digest(bytes))))
}

fn optional_pem_chain(path: Option<&Path>) -> Result<Vec<String>> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let pem = fs::read_to_string(path)?;
    Ok(vec![pem])
}

fn validate_private_key_permissions(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path)?;
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(StarmetalError::Config(format!(
                "signing private key {} must not be group/world-readable or writable",
                path.display()
            )));
        }
    }
    Ok(())
}

fn verify_hex_digest(algorithm: &str, expected: &str, actual: &str) -> Result<()> {
    if expected.trim().eq_ignore_ascii_case(actual.trim()) {
        Ok(())
    } else {
        Err(StarmetalError::IntegrityError {
            expected: format!("{algorithm}:{expected}"),
            actual: format!("{algorithm}:{actual}"),
        })
    }
}

fn verify_subresource_integrity(data: &Bytes, integrity_value: &str) -> Result<()> {
    for token in integrity_value.split_ascii_whitespace() {
        let Some((algorithm, encoded)) = token.split_once('-') else {
            continue;
        };

        let actual = match algorithm {
            "sha512" => sha2::Sha512::digest(data).to_vec(),
            "sha384" => sha2::Sha384::digest(data).to_vec(),
            "sha256" => sha2::Sha256::digest(data).to_vec(),
            _ => continue,
        };

        let expected =
            BASE64_STANDARD
                .decode(encoded)
                .map_err(|e| StarmetalError::IntegrityError {
                    expected: format!("{algorithm}:{encoded}"),
                    actual: format!("invalid SRI digest: {e}"),
                })?;

        if expected == actual {
            return Ok(());
        }

        return Err(StarmetalError::IntegrityError {
            expected: format!("{algorithm}:{encoded}"),
            actual: format!("{algorithm}:mismatch"),
        });
    }

    Err(StarmetalError::IntegrityError {
        expected: integrity_value.to_string(),
        actual: "no supported SRI digest".to_string(),
    })
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use super::*;
    #[cfg(unix)]
    use pkcs8::{EncodePrivateKey, LineEnding};
    use starmetal_core::package::ArtifactDigest;
    use starmetal_core::publishing::PublishedArtifact;
    #[cfg(unix)]
    use starmetal_core::signing::{SigningKeyConfig, SigningMode};

    struct MockStorage {
        data: Mutex<AHashMap<String, Bytes>>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                data: Mutex::new(AHashMap::new()),
            }
        }

        fn with_data(entries: Vec<(&str, Bytes)>) -> Self {
            let mut map = AHashMap::new();
            for (k, v) in entries {
                map.insert(k.to_string(), v);
            }
            Self {
                data: Mutex::new(map),
            }
        }
    }

    #[async_trait]
    impl StoragePort for MockStorage {
        async fn get(&self, key: &str) -> Result<Option<Bytes>> {
            Ok(self.data.lock().unwrap().get(key).cloned())
        }

        async fn put(&self, key: &str, data: Bytes) -> Result<()> {
            self.data.lock().unwrap().insert(key.to_string(), data);
            Ok(())
        }

        async fn exists(&self, key: &str) -> Result<bool> {
            Ok(self.data.lock().unwrap().contains_key(key))
        }

        async fn delete(&self, key: &str) -> Result<()> {
            self.data.lock().unwrap().remove(key);
            Ok(())
        }

        async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>> {
            Ok(self
                .data
                .lock()
                .unwrap()
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    struct MockUpstream {
        eco: Ecosystem,
        versions: Vec<VersionInfo>,
        metadata: AHashMap<String, VersionMetadata>,
        artifacts: AHashMap<String, Bytes>,
    }

    #[async_trait]
    impl UpstreamClient for MockUpstream {
        fn ecosystem(&self) -> Ecosystem {
            self.eco
        }

        async fn fetch_versions(&self, _name: &PackageName) -> Result<Vec<VersionInfo>> {
            Ok(self.versions.clone())
        }

        async fn fetch_metadata(
            &self,
            _name: &PackageName,
            version: &str,
        ) -> Result<VersionMetadata> {
            self.metadata
                .get(version)
                .cloned()
                .ok_or_else(|| StarmetalError::VersionNotFound {
                    ecosystem: self.eco.to_string(),
                    name: "test".to_string(),
                    version: version.to_string(),
                })
        }

        async fn fetch_artifact(&self, artifact_id: &ArtifactId) -> Result<Bytes> {
            self.artifacts
                .get(&artifact_id.filename)
                .cloned()
                .ok_or_else(|| StarmetalError::ArtifactNotFound(artifact_id.storage_key()))
        }
    }

    fn test_metadata(name: &str, version: &str) -> VersionMetadata {
        VersionMetadata {
            name: PackageName::new(name),
            version: version.to_string(),
            artifacts: vec![ArtifactDigest {
                filename: format!("{name}-{version}.tar.gz"),
                blake3: "0".repeat(64),
                size: 1024,
                upstream_hashes: AHashMap::new(),
            }],
            license: Some("MIT".to_string()),
            yanked: false,
            listed: None,
            protocol_metadata: None,
        }
    }

    fn test_metadata_with_artifact(
        name: &str,
        version: &str,
        filename: &str,
        upstream_hashes: AHashMap<String, String>,
    ) -> VersionMetadata {
        VersionMetadata {
            name: PackageName::new(name),
            version: version.to_string(),
            artifacts: vec![ArtifactDigest {
                filename: filename.to_string(),
                blake3: String::new(),
                size: 1024,
                upstream_hashes,
            }],
            license: Some("MIT".to_string()),
            yanked: false,
            listed: None,
            protocol_metadata: None,
        }
    }

    fn build_service(
        storage: Arc<MockStorage>,
        upstream: MockUpstream,
        policy: PolicyConfig,
    ) -> CachingPackageService {
        let eco = upstream.ecosystem();
        let mut clients: AHashMap<Ecosystem, Arc<dyn UpstreamClient>> = AHashMap::new();
        clients.insert(eco, Arc::new(upstream));
        CachingPackageService::new(storage, clients, policy)
    }

    struct MissingPackageUpstream {
        eco: Ecosystem,
    }

    #[async_trait]
    impl UpstreamClient for MissingPackageUpstream {
        fn ecosystem(&self) -> Ecosystem {
            self.eco
        }

        async fn fetch_versions(&self, name: &PackageName) -> Result<Vec<VersionInfo>> {
            Err(StarmetalError::PackageNotFound {
                ecosystem: self.eco.to_string(),
                name: name.as_str().to_string(),
            })
        }

        async fn fetch_metadata(
            &self,
            name: &PackageName,
            version: &str,
        ) -> Result<VersionMetadata> {
            Err(StarmetalError::VersionNotFound {
                ecosystem: self.eco.to_string(),
                name: name.as_str().to_string(),
                version: version.to_string(),
            })
        }

        async fn fetch_artifact(&self, artifact_id: &ArtifactId) -> Result<Bytes> {
            Err(StarmetalError::ArtifactNotFound(artifact_id.storage_key()))
        }
    }

    fn build_service_with_missing_package_upstream(
        storage: Arc<MockStorage>,
        ecosystem: Ecosystem,
    ) -> CachingPackageService {
        let mut clients: AHashMap<Ecosystem, Arc<dyn UpstreamClient>> = AHashMap::new();
        clients.insert(
            ecosystem,
            Arc::new(MissingPackageUpstream { eco: ecosystem }),
        );
        CachingPackageService::new(storage, clients, PolicyConfig::default())
    }

    #[cfg(unix)]
    fn write_test_signing_key(path: &Path, mode: u32) {
        let secret = [7_u8; 32];
        let signing_key = SigningKey::from_bytes(&secret);
        let pem = signing_key.to_pkcs8_pem(LineEnding::LF).unwrap();
        fs::write(path, pem.as_bytes()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    fn signing_config(private_key_file: PathBuf) -> SigningConfig {
        SigningConfig {
            enabled: true,
            mode: SigningMode::SignAndVerify,
            verify_on_read: true,
            sign_cached_upstream: false,
            keys: vec![SigningKeyConfig {
                id: "test-key".to_string(),
                algorithm: SigningAlgorithm::Ed25519,
                private_key_file: Some(private_key_file),
                private_key_password_env: None,
                certificate_file: None,
                certificate_chain_file: None,
                ecosystems: vec![Ecosystem::PyPI],
                packages: Vec::new(),
                status: SigningKeyStatus::Active,
            }],
            trust_roots: Vec::new(),
        }
    }

    #[tokio::test]
    async fn cache_hit_returns_stored_artifact() {
        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("requests"),
            version: "2.31.0".to_string(),
            filename: "requests-2.31.0.tar.gz".to_string(),
        };
        let artifact_data = Bytes::from_static(b"fake tarball content");
        let hash = integrity::blake3_hex(&artifact_data);
        let storage = Arc::new(MockStorage::with_data(vec![
            (&artifact_id.storage_key(), artifact_data.clone()),
            (
                &format!("{}.blake3", artifact_id.storage_key()),
                Bytes::from(hash),
            ),
        ]));
        let mut metadata = AHashMap::new();
        metadata.insert(
            "2.31.0".to_string(),
            test_metadata_with_artifact(
                "requests",
                "2.31.0",
                "requests-2.31.0.tar.gz",
                AHashMap::new(),
            ),
        );

        let upstream = MockUpstream {
            eco: Ecosystem::PyPI,
            versions: vec![],
            metadata,
            artifacts: AHashMap::new(), // Empty: should never be called
        };

        let service = build_service(storage, upstream, PolicyConfig::default());
        let result = service.get_artifact(&artifact_id).await.unwrap();
        assert_eq!(result, artifact_data, "should return cached artifact data");
    }

    #[tokio::test]
    async fn cache_miss_fetches_and_stores() {
        let storage = Arc::new(MockStorage::new());
        let artifact_data = Bytes::from_static(b"fetched from upstream");
        let mut artifacts = AHashMap::new();
        artifacts.insert("serde-1.0.0.tar.gz".to_string(), artifact_data.clone());
        let mut metadata = AHashMap::new();
        metadata.insert(
            "1.0.0".to_string(),
            test_metadata_with_artifact("serde", "1.0.0", "serde-1.0.0.tar.gz", AHashMap::new()),
        );

        let upstream = MockUpstream {
            eco: Ecosystem::Cargo,
            versions: vec![],
            metadata,
            artifacts,
        };

        let service = build_service(storage.clone(), upstream, PolicyConfig::default());

        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::Cargo,
            name: PackageName::new("serde"),
            version: "1.0.0".to_string(),
            filename: "serde-1.0.0.tar.gz".to_string(),
        };

        let result = service.get_artifact(&artifact_id).await.unwrap();
        assert_eq!(result, artifact_data, "should return upstream data");

        // Verify it was stored
        let stored = storage
            .get(&artifact_id.storage_key())
            .await
            .unwrap()
            .expect("artifact should be cached after fetch");
        assert_eq!(
            stored, artifact_data,
            "stored data should match fetched data"
        );
    }

    #[tokio::test]
    async fn policy_blocks_forbidden_package() {
        let storage = Arc::new(MockStorage::new());
        let meta = test_metadata("evil-pkg", "1.0.0");
        let mut metadata_map = AHashMap::new();
        metadata_map.insert("1.0.0".to_string(), meta);

        let upstream = MockUpstream {
            eco: Ecosystem::PyPI,
            versions: vec![],
            metadata: metadata_map,
            artifacts: AHashMap::new(),
        };

        let policy = PolicyConfig {
            blocked_packages: vec!["evil-pkg".to_string()],
            ..Default::default()
        };

        let service = build_service(storage, upstream, policy);
        let name = PackageName::new("evil-pkg");
        let result = service
            .get_version_metadata(Ecosystem::PyPI, &name, "1.0.0")
            .await;

        assert!(result.is_err(), "should reject blocked package");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("policy violation"),
            "error should be a policy violation, got: {err}"
        );
    }

    #[tokio::test]
    async fn blocked_metadata_never_cached() {
        let storage = Arc::new(MockStorage::new());
        let meta = test_metadata("blocked-pkg", "2.0.0");
        let mut metadata_map = AHashMap::new();
        metadata_map.insert("2.0.0".to_string(), meta);

        let upstream = MockUpstream {
            eco: Ecosystem::Npm,
            versions: vec![],
            metadata: metadata_map,
            artifacts: AHashMap::new(),
        };

        let policy = PolicyConfig {
            blocked_packages: vec!["blocked-pkg".to_string()],
            ..Default::default()
        };

        let service = build_service(storage.clone(), upstream, policy);
        let name = PackageName::new("blocked-pkg");
        let _ = service
            .get_version_metadata(Ecosystem::Npm, &name, "2.0.0")
            .await;

        let key = CachingPackageService::metadata_key(Ecosystem::Npm, &name, "2.0.0").unwrap();
        let cached = storage.get(&key).await.unwrap();
        assert!(
            cached.is_none(),
            "blocked metadata must not be stored in cache"
        );
    }

    #[tokio::test]
    async fn list_packages_extracts_names() {
        let storage = Arc::new(MockStorage::with_data(vec![
            ("pypi/requests/2.31.0/_metadata.json", Bytes::new()),
            ("pypi/requests/2.30.0/_metadata.json", Bytes::new()),
            ("pypi/flask/3.0.0/_metadata.json", Bytes::new()),
            ("pypi/django/4.2.0/_metadata.json", Bytes::new()),
        ]));

        let service =
            CachingPackageService::new(storage.clone(), AHashMap::new(), PolicyConfig::default());
        let packages = service.list_packages(Ecosystem::PyPI).await.unwrap();

        let mut names: Vec<String> = packages.iter().map(|p| p.as_str().to_string()).collect();
        names.sort();
        assert_eq!(names, vec!["django", "flask", "requests"]);
    }

    #[tokio::test]
    async fn missing_upstream_returns_error() {
        let storage = Arc::new(MockStorage::new());
        let service = CachingPackageService::new(storage, AHashMap::new(), PolicyConfig::default());

        let name = PackageName::new("anything");
        let result = service.list_versions(Ecosystem::Hex, &name).await;

        assert!(
            result.is_err(),
            "should error when no upstream is configured"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("no upstream configured for hex"),
            "error should mention missing upstream, got: {err}"
        );
    }

    #[tokio::test]
    async fn publish_package_stores_metadata_artifact_and_versions() {
        let storage = Arc::new(MockStorage::new());
        let service =
            CachingPackageService::new(storage.clone(), AHashMap::new(), PolicyConfig::default());
        let artifact_data = Bytes::from_static(b"published artifact");
        let request = PublishRequest {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("sample"),
            version: "1.0.0".to_string(),
            license: Some("MIT".to_string()),
            yanked: false,
            listed: true,
            artifacts: vec![PublishedArtifact {
                filename: "sample-1.0.0.tar.gz".to_string(),
                data: artifact_data.clone(),
                upstream_hashes: AHashMap::new(),
            }],
            protocol_metadata: ProtocolMetadata::default_for(Ecosystem::PyPI),
            allow_overwrite: false,
            allow_shadowing: false,
        };

        let result = service.publish_package(request).await.unwrap();

        assert_eq!(result.version, "1.0.0");
        assert_eq!(
            result.artifacts[0].blake3,
            integrity::blake3_hex(&artifact_data)
        );

        let name = PackageName::new("sample");
        let metadata = service
            .get_version_metadata(Ecosystem::PyPI, &name, "1.0.0")
            .await
            .unwrap();
        assert_eq!(metadata.license.as_deref(), Some("MIT"));

        let artifact = service
            .get_artifact(&ArtifactId {
                ecosystem: Ecosystem::PyPI,
                name: name.clone(),
                version: "1.0.0".to_string(),
                filename: "sample-1.0.0.tar.gz".to_string(),
            })
            .await
            .unwrap();
        assert_eq!(artifact, artifact_data);

        let versions = service.list_versions(Ecosystem::PyPI, &name).await.unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, "1.0.0");

        let manifest = storage
            .get("_starmetal/published/pypi/sample/1.0.0.json")
            .await
            .unwrap();
        assert!(manifest.is_some(), "published manifest should be stored");

        let record_key =
            CachingPackageService::published_record_key(Ecosystem::PyPI, &name, "1.0.0").unwrap();
        let record = storage
            .get(&record_key)
            .await
            .unwrap()
            .expect("publish record should be stored");
        let record: PublishRecord = serde_json::from_slice(&record).unwrap();
        assert_eq!(record.source, PublishSource::Local);
        assert!(!record.yanked);
        assert!(record.listed);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn publish_package_signs_artifacts_and_rejects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("signing.pk8");
        write_test_signing_key(&key_path, 0o600);
        let signing = SigningService::from_config(&signing_config(key_path))
            .unwrap()
            .unwrap();
        let storage = Arc::new(MockStorage::new());
        let service = CachingPackageService::new_with_signing(
            storage.clone(),
            AHashMap::new(),
            PolicyConfig::default(),
            Some(signing),
        );
        let name = PackageName::new("signed");
        let artifact_data = Bytes::from_static(b"signed artifact");

        service
            .publish_package(PublishRequest {
                ecosystem: Ecosystem::PyPI,
                name: name.clone(),
                version: "1.0.0".to_string(),
                license: Some("MIT".to_string()),
                yanked: false,
                listed: true,
                artifacts: vec![PublishedArtifact {
                    filename: "signed-1.0.0.tar.gz".to_string(),
                    data: artifact_data,
                    upstream_hashes: AHashMap::new(),
                }],
                protocol_metadata: ProtocolMetadata::default_for(Ecosystem::PyPI),
                allow_overwrite: false,
                allow_shadowing: false,
            })
            .await
            .unwrap();

        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::PyPI,
            name: name.clone(),
            version: "1.0.0".to_string(),
            filename: "signed-1.0.0.tar.gz".to_string(),
        };
        let storage_key = artifact_id.storage_key();
        let sidecar_key = CachingPackageService::signature_sidecar_key(&storage_key);
        assert!(
            storage.get(&sidecar_key).await.unwrap().is_some(),
            "artifact signature sidecar should be stored"
        );
        let bundle_key = CachingPackageService::signature_bundle_key(
            Ecosystem::PyPI,
            &name,
            "1.0.0",
            "signed-1.0.0.tar.gz.sig.json",
        )
        .unwrap();
        assert!(
            storage.get(&bundle_key).await.unwrap().is_some(),
            "signature bundle should be stored"
        );

        let tampered = Bytes::from_static(b"tampered artifact");
        storage.put(&storage_key, tampered.clone()).await.unwrap();
        storage
            .put(
                &format!("{storage_key}.blake3"),
                Bytes::from(integrity::blake3_hex(&tampered)),
            )
            .await
            .unwrap();
        let err = service.get_artifact(&artifact_id).await.unwrap_err();
        assert!(matches!(err, StarmetalError::IntegrityError { .. }));
        assert!(err.to_string().contains("signature statement mismatch"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn signed_artifact_read_does_not_depend_on_publish_record() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("signing.pk8");
        write_test_signing_key(&key_path, 0o600);
        let signing = SigningService::from_config(&signing_config(key_path))
            .unwrap()
            .unwrap();
        let storage = Arc::new(MockStorage::new());
        let service = CachingPackageService::new_with_signing(
            storage.clone(),
            AHashMap::new(),
            PolicyConfig::default(),
            Some(signing),
        );
        let name = PackageName::new("recordless");

        service
            .publish_package(PublishRequest {
                ecosystem: Ecosystem::PyPI,
                name: name.clone(),
                version: "1.0.0".to_string(),
                license: Some("MIT".to_string()),
                yanked: false,
                listed: true,
                artifacts: vec![PublishedArtifact {
                    filename: "recordless-1.0.0.tar.gz".to_string(),
                    data: Bytes::from_static(b"signed artifact"),
                    upstream_hashes: AHashMap::new(),
                }],
                protocol_metadata: ProtocolMetadata::default_for(Ecosystem::PyPI),
                allow_overwrite: false,
                allow_shadowing: false,
            })
            .await
            .unwrap();

        let record_key =
            CachingPackageService::published_record_key(Ecosystem::PyPI, &name, "1.0.0").unwrap();
        storage.delete(&record_key).await.unwrap();
        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::PyPI,
            name,
            version: "1.0.0".to_string(),
            filename: "recordless-1.0.0.tar.gz".to_string(),
        };
        let storage_key = artifact_id.storage_key();
        let tampered = Bytes::from_static(b"tampered artifact");
        storage.put(&storage_key, tampered.clone()).await.unwrap();
        storage
            .put(
                &format!("{storage_key}.blake3"),
                Bytes::from(integrity::blake3_hex(&tampered)),
            )
            .await
            .unwrap();

        let err = service.get_artifact(&artifact_id).await.unwrap_err();

        assert!(matches!(err, StarmetalError::IntegrityError { .. }));
        assert!(err.to_string().contains("signature statement mismatch"));
    }

    #[cfg(unix)]
    #[test]
    fn signing_service_rejects_group_accessible_private_key() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("signing.pk8");
        write_test_signing_key(&key_path, 0o640);

        let err = match SigningService::from_config(&signing_config(key_path)) {
            Ok(_) => panic!("group-readable private key should be rejected"),
            Err(err) => err.to_string(),
        };

        assert!(err.contains("must not be group/world-readable or writable"));
    }

    #[tokio::test]
    async fn publish_package_allows_new_local_package_when_upstream_package_not_found() {
        let storage = Arc::new(MockStorage::new());
        let service = build_service_with_missing_package_upstream(storage, Ecosystem::Npm);
        let name = PackageName::new("local-pnpm");

        service
            .publish_package(PublishRequest {
                ecosystem: Ecosystem::Npm,
                name: name.clone(),
                version: "1.0.0".to_string(),
                license: Some("MIT".to_string()),
                yanked: false,
                listed: true,
                artifacts: vec![PublishedArtifact {
                    filename: "local-pnpm-1.0.0.tgz".to_string(),
                    data: Bytes::from_static(b"published artifact"),
                    upstream_hashes: AHashMap::new(),
                }],
                protocol_metadata: ProtocolMetadata::default_for(Ecosystem::Npm),
                allow_overwrite: false,
                allow_shadowing: false,
            })
            .await
            .unwrap();

        let versions = service.list_versions(Ecosystem::Npm, &name).await.unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, "1.0.0");
        assert!(!versions[0].yanked);
    }

    #[tokio::test]
    async fn publish_package_rejects_duplicate_version_by_default() {
        let storage = Arc::new(MockStorage::new());
        let service =
            CachingPackageService::new(storage.clone(), AHashMap::new(), PolicyConfig::default());
        let request = PublishRequest {
            ecosystem: Ecosystem::Npm,
            name: PackageName::new("sample"),
            version: "1.0.0".to_string(),
            license: Some("MIT".to_string()),
            yanked: false,
            listed: true,
            artifacts: vec![PublishedArtifact {
                filename: "sample-1.0.0.tgz".to_string(),
                data: Bytes::from_static(b"published artifact"),
                upstream_hashes: AHashMap::new(),
            }],
            protocol_metadata: ProtocolMetadata::default_for(Ecosystem::Npm),
            allow_overwrite: false,
            allow_shadowing: false,
        };

        service.publish_package(request.clone()).await.unwrap();
        let err = service.publish_package(request).await.unwrap_err();

        assert!(matches!(err, StarmetalError::Publish(_)));
        assert!(err.to_string().contains("version already exists"));
    }

    #[tokio::test]
    async fn publish_package_overwrite_merges_artifacts_for_existing_version() {
        let storage = Arc::new(MockStorage::new());
        let service = CachingPackageService::new(storage, AHashMap::new(), PolicyConfig::default());
        let base = PublishRequest {
            ecosystem: Ecosystem::Maven,
            name: PackageName::new("com.example:sample"),
            version: "1.0.0".to_string(),
            license: Some("MIT".to_string()),
            yanked: false,
            listed: true,
            artifacts: vec![PublishedArtifact {
                filename: "sample-1.0.0.pom".to_string(),
                data: Bytes::from_static(b"pom"),
                upstream_hashes: AHashMap::new(),
            }],
            protocol_metadata: ProtocolMetadata::default_for(Ecosystem::Maven),
            allow_overwrite: false,
            allow_shadowing: false,
        };
        service.publish_package(base).await.unwrap();

        service
            .publish_package(PublishRequest {
                artifacts: vec![PublishedArtifact {
                    filename: "sample-1.0.0.jar".to_string(),
                    data: Bytes::from_static(b"jar"),
                    upstream_hashes: AHashMap::new(),
                }],
                allow_overwrite: true,
                allow_shadowing: false,
                ecosystem: Ecosystem::Maven,
                name: PackageName::new("com.example:sample"),
                version: "1.0.0".to_string(),
                license: None,
                yanked: false,
                listed: true,
                protocol_metadata: ProtocolMetadata::default_for(Ecosystem::Maven),
            })
            .await
            .unwrap();

        let metadata = service
            .get_version_metadata(
                Ecosystem::Maven,
                &PackageName::new("com.example:sample"),
                "1.0.0",
            )
            .await
            .unwrap();
        let filenames = metadata
            .artifacts
            .iter()
            .map(|artifact| artifact.filename.as_str())
            .collect::<Vec<_>>();
        assert_eq!(filenames, vec!["sample-1.0.0.pom", "sample-1.0.0.jar"]);
        assert_eq!(metadata.license.as_deref(), Some("MIT"));
    }

    #[tokio::test]
    async fn publish_package_rejects_upstream_shadowing_by_default() {
        let storage = Arc::new(MockStorage::new());
        let mut metadata = AHashMap::new();
        metadata.insert("1.0.0".to_string(), test_metadata("sample", "1.0.0"));
        let upstream = MockUpstream {
            eco: Ecosystem::Cargo,
            versions: vec![],
            metadata,
            artifacts: AHashMap::new(),
        };
        let service = build_service(storage, upstream, PolicyConfig::default());
        let request = PublishRequest {
            ecosystem: Ecosystem::Cargo,
            name: PackageName::new("sample"),
            version: "1.0.0".to_string(),
            license: Some("MIT".to_string()),
            yanked: false,
            listed: true,
            artifacts: vec![PublishedArtifact {
                filename: "sample-1.0.0.crate".to_string(),
                data: Bytes::from_static(b"published artifact"),
                upstream_hashes: AHashMap::new(),
            }],
            protocol_metadata: ProtocolMetadata::default_for(Ecosystem::Cargo),
            allow_overwrite: false,
            allow_shadowing: false,
        };

        let err = service.publish_package(request).await.unwrap_err();

        assert!(matches!(err, StarmetalError::Publish(_)));
        assert!(err.to_string().contains("refusing to shadow upstream"));
    }

    #[tokio::test]
    async fn set_yanked_updates_metadata_and_version_listing() {
        let storage = Arc::new(MockStorage::new());
        let service =
            CachingPackageService::new(storage.clone(), AHashMap::new(), PolicyConfig::default());
        let name = PackageName::new("sample");
        service
            .publish_package(PublishRequest {
                ecosystem: Ecosystem::RubyGems,
                name: name.clone(),
                version: "1.0.0".to_string(),
                license: Some("MIT".to_string()),
                yanked: false,
                listed: true,
                artifacts: vec![PublishedArtifact {
                    filename: "sample-1.0.0.gem".to_string(),
                    data: Bytes::from_static(b"published artifact"),
                    upstream_hashes: AHashMap::new(),
                }],
                protocol_metadata: ProtocolMetadata::default_for(Ecosystem::RubyGems),
                allow_overwrite: false,
                allow_shadowing: false,
            })
            .await
            .unwrap();

        let metadata = service
            .set_yanked(YankRequest {
                ecosystem: Ecosystem::RubyGems,
                name: name.clone(),
                version: "1.0.0".to_string(),
                yanked: true,
            })
            .await
            .unwrap();

        assert!(metadata.yanked);
        let versions = service
            .list_versions(Ecosystem::RubyGems, &name)
            .await
            .unwrap();
        assert!(versions[0].yanked);

        let record_key =
            CachingPackageService::published_record_key(Ecosystem::RubyGems, &name, "1.0.0")
                .unwrap();
        let record = storage
            .get(&record_key)
            .await
            .unwrap()
            .expect("publish record should be stored");
        let record: PublishRecord = serde_json::from_slice(&record).unwrap();
        assert!(record.yanked);
    }

    #[tokio::test]
    async fn cached_metadata_is_rechecked_against_current_policy() {
        let name = PackageName::new("cached-pkg");
        let cached_metadata = VersionMetadata {
            license: Some("GPL-3.0".to_string()),
            ..test_metadata("cached-pkg", "1.0.0")
        };
        let key = CachingPackageService::metadata_key(Ecosystem::Npm, &name, "1.0.0").unwrap();
        let storage = Arc::new(MockStorage::with_data(vec![(
            &key,
            Bytes::from(serde_json::to_vec(&cached_metadata).unwrap()),
        )]));
        let upstream = MockUpstream {
            eco: Ecosystem::Npm,
            versions: vec![],
            metadata: AHashMap::new(),
            artifacts: AHashMap::new(),
        };
        let policy = PolicyConfig {
            allowed_licenses: vec!["MIT".to_string()],
            ..Default::default()
        };
        let service = build_service(storage, upstream, policy);

        let result = service
            .get_version_metadata(Ecosystem::Npm, &name, "1.0.0")
            .await;

        assert!(matches!(result, Err(StarmetalError::PolicyViolation(_))));
    }

    #[tokio::test]
    async fn integrity_verified_on_cache_hit() {
        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("requests"),
            version: "2.31.0".to_string(),
            filename: "requests-2.31.0.tar.gz".to_string(),
        };
        let artifact_data = Bytes::from_static(b"fake tarball content");
        let hash = integrity::blake3_hex(&artifact_data);
        let mut metadata = AHashMap::new();
        metadata.insert(
            "2.31.0".to_string(),
            test_metadata_with_artifact(
                "requests",
                "2.31.0",
                "requests-2.31.0.tar.gz",
                AHashMap::new(),
            ),
        );

        let storage = Arc::new(MockStorage::with_data(vec![
            (&artifact_id.storage_key(), artifact_data.clone()),
            (
                &format!("{}.blake3", artifact_id.storage_key()),
                Bytes::from(hash),
            ),
        ]));

        let upstream = MockUpstream {
            eco: Ecosystem::PyPI,
            versions: vec![],
            metadata,
            artifacts: AHashMap::new(),
        };

        let service = build_service(storage, upstream, PolicyConfig::default());
        let result = service.get_artifact(&artifact_id).await.unwrap();
        assert_eq!(
            result, artifact_data,
            "should return verified cached artifact"
        );
    }

    #[tokio::test]
    async fn integrity_rejects_corrupted_artifact() {
        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("requests"),
            version: "2.31.0".to_string(),
            filename: "requests-2.31.0.tar.gz".to_string(),
        };
        let artifact_data = Bytes::from_static(b"corrupted data");
        let wrong_hash = "0".repeat(64);
        let mut metadata = AHashMap::new();
        metadata.insert(
            "2.31.0".to_string(),
            test_metadata_with_artifact(
                "requests",
                "2.31.0",
                "requests-2.31.0.tar.gz",
                AHashMap::new(),
            ),
        );

        let storage = Arc::new(MockStorage::with_data(vec![
            (&artifact_id.storage_key(), artifact_data),
            (
                &format!("{}.blake3", artifact_id.storage_key()),
                Bytes::from(wrong_hash),
            ),
        ]));

        let upstream = MockUpstream {
            eco: Ecosystem::PyPI,
            versions: vec![],
            metadata,
            artifacts: AHashMap::new(),
        };

        let service = build_service(storage, upstream, PolicyConfig::default());
        let result = service.get_artifact(&artifact_id).await;
        assert!(result.is_err(), "should reject corrupted artifact");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("integrity check failed"),
            "error should be integrity failure, got: {err}"
        );
    }

    #[tokio::test]
    async fn integrity_rejects_cached_artifact_without_sidecar() {
        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("requests"),
            version: "2.31.0".to_string(),
            filename: "requests-2.31.0.tar.gz".to_string(),
        };
        let artifact_data = Bytes::from_static(b"unverified data");
        let mut metadata = AHashMap::new();
        metadata.insert(
            "2.31.0".to_string(),
            test_metadata_with_artifact(
                "requests",
                "2.31.0",
                "requests-2.31.0.tar.gz",
                AHashMap::new(),
            ),
        );

        let storage = Arc::new(MockStorage::with_data(vec![(
            &artifact_id.storage_key(),
            artifact_data,
        )]));

        let upstream = MockUpstream {
            eco: Ecosystem::PyPI,
            versions: vec![],
            metadata,
            artifacts: AHashMap::new(),
        };

        let service = build_service(storage, upstream, PolicyConfig::default());
        let result = service.get_artifact(&artifact_id).await;
        assert!(result.is_err(), "should reject unverified cached artifact");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("missing sidecar"),
            "error should mention missing sidecar, got: {err}"
        );
    }

    #[tokio::test]
    async fn policy_blocks_artifact_download() {
        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("evil-pkg"),
            version: "1.0.0".to_string(),
            filename: "evil-pkg-1.0.0.tar.gz".to_string(),
        };
        let artifact_data = Bytes::from_static(b"evil content");

        let storage = Arc::new(MockStorage::with_data(vec![(
            &artifact_id.storage_key(),
            artifact_data,
        )]));

        let upstream = MockUpstream {
            eco: Ecosystem::PyPI,
            versions: vec![],
            metadata: AHashMap::new(),
            artifacts: AHashMap::new(),
        };

        let policy = PolicyConfig {
            blocked_packages: vec!["evil-pkg".to_string()],
            ..Default::default()
        };

        let service = build_service(storage, upstream, policy);
        let result = service.get_artifact(&artifact_id).await;
        assert!(
            result.is_err(),
            "should block artifact download for blocked package"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("policy violation"),
            "error should be a policy violation, got: {err}"
        );
    }

    #[tokio::test]
    async fn hash_sidecar_stored_on_fetch() {
        let storage = Arc::new(MockStorage::new());
        let artifact_data = Bytes::from_static(b"upstream content");
        let expected_hash = integrity::blake3_hex(&artifact_data);
        let mut artifacts = AHashMap::new();
        artifacts.insert("pkg-1.0.0.tar.gz".to_string(), artifact_data.clone());
        let mut metadata = AHashMap::new();
        metadata.insert(
            "1.0.0".to_string(),
            test_metadata_with_artifact("pkg", "1.0.0", "pkg-1.0.0.tar.gz", AHashMap::new()),
        );

        let upstream = MockUpstream {
            eco: Ecosystem::Cargo,
            versions: vec![],
            metadata,
            artifacts,
        };

        let service = build_service(storage.clone(), upstream, PolicyConfig::default());

        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::Cargo,
            name: PackageName::new("pkg"),
            version: "1.0.0".to_string(),
            filename: "pkg-1.0.0.tar.gz".to_string(),
        };

        let result = service.get_artifact(&artifact_id).await.unwrap();
        assert_eq!(result, artifact_data);

        let hash_key = format!("{}.blake3", artifact_id.storage_key());
        let stored_hash = storage
            .get(&hash_key)
            .await
            .unwrap()
            .expect("blake3 sidecar should be stored after fetch");
        assert_eq!(
            std::str::from_utf8(&stored_hash).unwrap(),
            expected_hash,
            "stored hash should match computed blake3"
        );
    }

    #[tokio::test]
    async fn records_cache_statistics_for_artifact_fetches() {
        let storage = Arc::new(MockStorage::new());
        let artifact_data = Bytes::from_static(b"upstream content");
        let mut artifacts = AHashMap::new();
        artifacts.insert("pkg-1.0.0.tgz".to_string(), artifact_data.clone());
        let mut metadata = AHashMap::new();
        metadata.insert(
            "1.0.0".to_string(),
            test_metadata_with_artifact("pkg", "1.0.0", "pkg-1.0.0.tgz", AHashMap::new()),
        );
        let upstream = MockUpstream {
            eco: Ecosystem::Npm,
            versions: vec![],
            metadata,
            artifacts,
        };
        let service = build_service(storage, upstream, PolicyConfig::default());
        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::Npm,
            name: PackageName::new("pkg"),
            version: "1.0.0".to_string(),
            filename: "pkg-1.0.0.tgz".to_string(),
        };

        let first = service.get_artifact(&artifact_id).await.unwrap();
        let second = service.get_artifact(&artifact_id).await.unwrap();

        assert_eq!(first, artifact_data);
        assert_eq!(second, artifact_data);
        let snapshot = service.statistics();
        let npm = snapshot
            .ecosystems
            .get("npm")
            .expect("npm statistics should be present");
        assert_eq!(npm.metadata_cache_misses, 1);
        assert_eq!(npm.metadata_cache_hits, 1);
        assert_eq!(npm.artifact_cache_misses, 1);
        assert_eq!(npm.artifact_cache_hits, 1);
        assert_eq!(npm.bytes_served, (artifact_data.len() * 2) as u64);
        assert!(npm.last_activity_unix_seconds.is_some());
    }

    #[tokio::test]
    async fn upstream_sha256_verified_before_cache_store() {
        let storage = Arc::new(MockStorage::new());
        let artifact_data = Bytes::from_static(b"upstream content");
        let sha256 = hex::encode(sha2::Sha256::digest(&artifact_data));
        let mut upstream_hashes = AHashMap::new();
        upstream_hashes.insert("sha256".to_string(), sha256);

        let mut artifacts = AHashMap::new();
        artifacts.insert("pkg-1.0.0.tar.gz".to_string(), artifact_data.clone());
        let mut metadata = AHashMap::new();
        metadata.insert(
            "1.0.0".to_string(),
            test_metadata_with_artifact("pkg", "1.0.0", "pkg-1.0.0.tar.gz", upstream_hashes),
        );

        let upstream = MockUpstream {
            eco: Ecosystem::PyPI,
            versions: vec![],
            metadata,
            artifacts,
        };

        let service = build_service(storage, upstream, PolicyConfig::default());
        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("pkg"),
            version: "1.0.0".to_string(),
            filename: "pkg-1.0.0.tar.gz".to_string(),
        };

        let result = service.get_artifact(&artifact_id).await.unwrap();
        assert_eq!(result, artifact_data);
    }

    #[tokio::test]
    async fn upstream_sha256_mismatch_rejected() {
        let storage = Arc::new(MockStorage::new());
        let artifact_data = Bytes::from_static(b"upstream content");
        let mut upstream_hashes = AHashMap::new();
        upstream_hashes.insert("sha256".to_string(), "0".repeat(64));

        let mut artifacts = AHashMap::new();
        artifacts.insert("pkg-1.0.0.tar.gz".to_string(), artifact_data);
        let mut metadata = AHashMap::new();
        metadata.insert(
            "1.0.0".to_string(),
            test_metadata_with_artifact("pkg", "1.0.0", "pkg-1.0.0.tar.gz", upstream_hashes),
        );

        let upstream = MockUpstream {
            eco: Ecosystem::Cargo,
            versions: vec![],
            metadata,
            artifacts,
        };

        let service = build_service(storage.clone(), upstream, PolicyConfig::default());
        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::Cargo,
            name: PackageName::new("pkg"),
            version: "1.0.0".to_string(),
            filename: "pkg-1.0.0.tar.gz".to_string(),
        };

        let result = service.get_artifact(&artifact_id).await;
        assert!(result.is_err(), "should reject upstream hash mismatch");
        assert!(
            storage
                .get(&artifact_id.storage_key())
                .await
                .unwrap()
                .is_none(),
            "mismatched artifact must not be cached"
        );
    }

    #[tokio::test]
    async fn upstream_npm_sri_verified_before_cache_store() {
        let storage = Arc::new(MockStorage::new());
        let artifact_data = Bytes::from_static(b"npm tarball");
        let sri = format!(
            "sha512-{}",
            BASE64_STANDARD.encode(sha2::Sha512::digest(&artifact_data))
        );
        let mut upstream_hashes = AHashMap::new();
        upstream_hashes.insert("integrity".to_string(), sri);

        let mut artifacts = AHashMap::new();
        artifacts.insert("pkg-1.0.0.tgz".to_string(), artifact_data.clone());
        let mut metadata = AHashMap::new();
        metadata.insert(
            "1.0.0".to_string(),
            test_metadata_with_artifact("pkg", "1.0.0", "pkg-1.0.0.tgz", upstream_hashes),
        );

        let upstream = MockUpstream {
            eco: Ecosystem::Npm,
            versions: vec![],
            metadata,
            artifacts,
        };

        let service = build_service(storage, upstream, PolicyConfig::default());
        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::Npm,
            name: PackageName::new("pkg"),
            version: "1.0.0".to_string(),
            filename: "pkg-1.0.0.tgz".to_string(),
        };

        let result = service.get_artifact(&artifact_id).await.unwrap();
        assert_eq!(result, artifact_data);
    }

    #[tokio::test]
    async fn license_policy_blocks_artifact_download() {
        let storage = Arc::new(MockStorage::new());
        let artifact_data = Bytes::from_static(b"package");
        let mut artifacts = AHashMap::new();
        artifacts.insert("pkg-1.0.0.tar.gz".to_string(), artifact_data);

        let mut metadata = AHashMap::new();
        metadata.insert(
            "1.0.0".to_string(),
            VersionMetadata {
                name: PackageName::new("pkg"),
                version: "1.0.0".to_string(),
                artifacts: vec![ArtifactDigest {
                    filename: "pkg-1.0.0.tar.gz".to_string(),
                    blake3: String::new(),
                    size: 0,
                    upstream_hashes: AHashMap::new(),
                }],
                license: None,
                yanked: false,
                listed: None,
                protocol_metadata: None,
            },
        );

        let upstream = MockUpstream {
            eco: Ecosystem::PyPI,
            versions: vec![],
            metadata,
            artifacts,
        };
        let policy = PolicyConfig {
            block_unlicensed: true,
            ..Default::default()
        };
        let service = build_service(storage, upstream, policy);
        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("pkg"),
            version: "1.0.0".to_string(),
            filename: "pkg-1.0.0.tar.gz".to_string(),
        };

        let result = service.get_artifact(&artifact_id).await;
        assert!(result.is_err(), "license policy should block artifact");
        assert!(result.unwrap_err().to_string().contains("has no license"));
    }
}
