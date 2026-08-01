//! DSSE signing and verification (ADR-0004 / ADR-0024).
//!
//! Houses [`SigningService`] — artifact/metadata signature and provenance-attestation signing and
//! verification — plus the ed25519/PKCS#8 key-loading helpers it is built from. The `CachingPackageService`
//! gate and publish paths drive it through the `pub(in crate::service)` surface exposed here.

use std::collections::BTreeMap;
#[cfg(not(unix))]
use std::fs;
use std::path::Path;
#[cfg(unix)]
use std::{fs, os::unix::fs::PermissionsExt};

use ahash::AHashMap;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use ed25519_dalek::{Signer, SigningKey, Verifier as Ed25519Verifier, VerifyingKey};
use pkcs8::{
    DecodePrivateKey, ObjectIdentifier, PrivateKeyInfoOwned,
    der::{Decode, DecodePem, asn1::OctetStringRef},
    spki::SubjectPublicKeyInfoOwned,
};
use sha2::Digest;
use starmetal_core::attestation::INTOTO_PAYLOAD_TYPE;
use starmetal_core::error::{Result, StarmetalError};
use starmetal_core::package::{Ecosystem, PackageName};
use starmetal_core::signing::{
    DsseEnvelope, DsseSignature, STARMETAL_DSSE_PAYLOAD_TYPE, SignatureSource, SignatureStatement, SigningAlgorithm,
    SigningConfig, SigningKeyStatus, SigningMode,
};
use zeroize::Zeroizing;

use super::unix_now;

const DSSE_PAE_PREFIX: &str = "DSSEv1";
const ED25519_OID: &str = "1.3.101.112";
pub(in crate::service) const ED25519_KEY_BYTES: usize = 32;

pub struct SigningService {
    mode: SigningMode,
    verify_on_read: bool,
    sign_cached_upstream: bool,
    keys: Vec<SigningKeyMaterial>,
}

struct SigningKeyMaterial {
    id: String,
    algorithm: SigningAlgorithm,
    status: SigningKeyStatus,
    signing_key: Option<SigningKey>,
    verifying_key: VerifyingKey,
    certificate_fingerprint_sha256: Option<String>,
    certificate_chain_pem: Vec<String>,
    ecosystems: Vec<Ecosystem>,
    packages: Vec<String>,
}

pub(in crate::service) struct StatementInput {
    pub(in crate::service) ecosystem: Ecosystem,
    pub(in crate::service) package: PackageName,
    pub(in crate::service) version: String,
    pub(in crate::service) filename: Option<String>,
    pub(in crate::service) storage_key: String,
    pub(in crate::service) size: u64,
    pub(in crate::service) blake3: String,
    pub(in crate::service) upstream_hashes: AHashMap<String, String>,
    pub(in crate::service) source: SignatureSource,
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
            if key.status == SigningKeyStatus::VerifyOnly && key.private_key_file.is_some() {
                return Err(StarmetalError::Config(format!(
                    "verify-only signing key {} must use public_key_file instead of private_key_file",
                    key.id
                )));
            }
            let signing_key = if let Some(private_key_file) = &key.private_key_file {
                if key.private_key_password_env.is_some() {
                    return Err(StarmetalError::Config(format!(
                        "signing key {} uses encrypted private keys, which are not implemented yet",
                        key.id
                    )));
                }
                validate_private_key_permissions(private_key_file)?;
                let private_key_pem = Zeroizing::new(fs::read_to_string(private_key_file)?);
                Some(load_ed25519_signing_key(private_key_pem.as_str(), &key.id)?)
            } else {
                None
            };
            let verifying_key = if let Some(public_key_file) = &key.public_key_file {
                let public_key_pem = fs::read_to_string(public_key_file)?;
                let verifying_key = load_ed25519_verifying_key(&public_key_pem, &key.id)?;
                if let Some(signing_key) = &signing_key
                    && signing_key.verifying_key().to_bytes() != verifying_key.to_bytes()
                {
                    return Err(StarmetalError::Config(format!(
                        "signing key {} private_key_file does not match public_key_file",
                        key.id
                    )));
                }
                verifying_key
            } else if let Some(signing_key) = &signing_key {
                signing_key.verifying_key()
            } else {
                return Err(StarmetalError::Config(format!(
                    "signing key {} requires private_key_file or public_key_file",
                    key.id
                )));
            };
            let certificate_fingerprint_sha256 = optional_file_sha256(key.certificate_file.as_deref())?;
            let certificate_chain_pem = optional_pem_chain(key.certificate_chain_file.as_deref())?;
            keys.push(SigningKeyMaterial {
                id: key.id.clone(),
                algorithm: key.algorithm,
                status: key.status,
                signing_key,
                verifying_key,
                certificate_fingerprint_sha256,
                certificate_chain_pem,
                ecosystems: key.ecosystems.clone(),
                packages: key.packages.clone(),
            });
        }

        if matches!(config.mode, SigningMode::SignOnly | SigningMode::SignAndVerify)
            && !keys.iter().any(|key| {
                key.status == SigningKeyStatus::Active
                    && key.algorithm == SigningAlgorithm::Ed25519
                    && key.signing_key.is_some()
            })
        {
            return Err(StarmetalError::Config(
                "signing requires a loadable active ed25519 key".to_string(),
            ));
        }
        if matches!(config.mode, SigningMode::SignAndVerify | SigningMode::VerifyOnly) && keys.is_empty() {
            return Err(StarmetalError::Config(
                "signature verification requires at least one verification key".to_string(),
            ));
        }

        Ok(Some(Self {
            mode: config.mode,
            verify_on_read: config.verify_on_read
                || matches!(config.mode, SigningMode::SignAndVerify | SigningMode::VerifyOnly),
            sign_cached_upstream: config.sign_cached_upstream,
            keys,
        }))
    }

    pub(in crate::service) fn verify_on_read(&self) -> bool {
        self.verify_on_read && matches!(self.mode, SigningMode::SignAndVerify | SigningMode::VerifyOnly)
    }

    pub(in crate::service) fn sign_cached_upstream(&self) -> bool {
        self.sign_cached_upstream && matches!(self.mode, SigningMode::SignOnly | SigningMode::SignAndVerify)
    }

    fn select_signing_key(&self, ecosystem: Ecosystem, package: &PackageName) -> Result<&SigningKeyMaterial> {
        self.keys
            .iter()
            .find(|key| {
                if key.status != SigningKeyStatus::Active || key.signing_key.is_none() {
                    return false;
                }
                let ecosystem_allowed = key.ecosystems.is_empty() || key.ecosystems.contains(&ecosystem);
                let package_allowed =
                    key.packages.is_empty() || key.packages.iter().any(|name| name == package.as_str());
                ecosystem_allowed && package_allowed
            })
            .ok_or_else(|| StarmetalError::Config(format!("no signing key is scoped for {ecosystem}/{package}")))
    }

    pub(in crate::service) fn statement(&self, input: StatementInput) -> Result<SignatureStatement> {
        let key = self.select_signing_key(input.ecosystem, &input.package)?;
        Ok(SignatureStatement {
            ecosystem: input.ecosystem,
            package: input.package,
            version: input.version,
            filename: input.filename,
            storage_key: input.storage_key,
            size: input.size,
            blake3: input.blake3,
            upstream_hashes: input.upstream_hashes.into_iter().collect::<BTreeMap<_, _>>(),
            source: input.source,
            issued_at_unix_seconds: unix_now(),
            key_id: key.id.clone(),
            certificate_fingerprint_sha256: key.certificate_fingerprint_sha256.clone(),
        })
    }

    /// DSSE-sign an arbitrary payload under `payload_type`, using the key scoped to the coordinate.
    /// The shared substance behind `sign_statement` (artifact signatures, ADR-0004) and
    /// `sign_attestation` (in-toto/SLSA provenance, ADR-0024).
    fn sign_payload(
        &self,
        ecosystem: Ecosystem,
        package: &PackageName,
        payload_type: &str,
        payload: &[u8],
    ) -> Result<DsseEnvelope> {
        if !matches!(self.mode, SigningMode::SignOnly | SigningMode::SignAndVerify) {
            return Err(StarmetalError::Config(
                "signing service is not configured for signing".to_string(),
            ));
        }
        let key = self.select_signing_key(ecosystem, package)?;
        let signing_key = key
            .signing_key
            .as_ref()
            .ok_or_else(|| StarmetalError::Config(format!("signing key {} has no private key material", key.id)))?;
        let pae = dsse_pae(payload_type.as_bytes(), payload);
        let signature = signing_key.sign(&pae);
        Ok(DsseEnvelope {
            payload_type: payload_type.to_string(),
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

    pub(in crate::service) fn sign_statement(&self, statement: SignatureStatement) -> Result<DsseEnvelope> {
        let ecosystem = statement.ecosystem;
        let package = statement.package.clone();
        let payload = serde_json::to_vec(&statement)?;
        self.sign_payload(ecosystem, &package, STARMETAL_DSSE_PAYLOAD_TYPE, &payload)
    }

    /// DSSE-sign an in-toto provenance statement payload with the coordinate's key (ADR-0024).
    pub(in crate::service) fn sign_attestation(
        &self,
        ecosystem: Ecosystem,
        package: &PackageName,
        payload: &[u8],
    ) -> Result<DsseEnvelope> {
        self.sign_payload(ecosystem, package, INTOTO_PAYLOAD_TYPE, payload)
    }

    pub(in crate::service) fn verify_envelope(&self, envelope_bytes: &[u8]) -> Result<SignatureStatement> {
        let envelope: DsseEnvelope = serde_json::from_slice(envelope_bytes)?;
        if envelope.payload_type != STARMETAL_DSSE_PAYLOAD_TYPE {
            return Err(StarmetalError::IntegrityError {
                expected: STARMETAL_DSSE_PAYLOAD_TYPE.to_string(),
                actual: envelope.payload_type,
            });
        }
        let payload = BASE64_STANDARD
            .decode(&envelope.payload)
            .map_err(|err| StarmetalError::IntegrityError {
                expected: "base64 DSSE payload".to_string(),
                actual: err.to_string(),
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
            let signature_bytes =
                BASE64_STANDARD
                    .decode(&signature.signature)
                    .map_err(|err| StarmetalError::IntegrityError {
                        expected: "base64 DSSE signature".to_string(),
                        actual: err.to_string(),
                    })?;
            let signature = ed25519_dalek::Signature::from_slice(&signature_bytes).map_err(|err| {
                StarmetalError::IntegrityError {
                    expected: "ed25519 signature".to_string(),
                    actual: err.to_string(),
                }
            })?;
            if key.verifying_key.verify(&pae, &signature).is_ok() {
                let statement: SignatureStatement = serde_json::from_slice(&payload)?;
                if statement.key_id != key.id
                    || statement.certificate_fingerprint_sha256 != key.certificate_fingerprint_sha256
                {
                    continue;
                }
                return Ok(statement);
            }
        }
        Err(StarmetalError::IntegrityError {
            expected: "valid DSSE signature".to_string(),
            actual: "no configured key verified the envelope".to_string(),
        })
    }

    /// Verify a DSSE envelope of `expected_payload_type` against the configured keys, returning the
    /// decoded payload of the first signature that verifies. Used to check provenance attestations,
    /// whose payload is opaque in-toto JSON (unlike the typed `SignatureStatement` of
    /// `verify_envelope`).
    fn verify_dsse_payload(&self, envelope_bytes: &[u8], expected_payload_type: &str) -> Result<Vec<u8>> {
        let envelope: DsseEnvelope = serde_json::from_slice(envelope_bytes)?;
        if envelope.payload_type != expected_payload_type {
            return Err(StarmetalError::IntegrityError {
                expected: expected_payload_type.to_string(),
                actual: envelope.payload_type,
            });
        }
        let payload = BASE64_STANDARD
            .decode(&envelope.payload)
            .map_err(|err| StarmetalError::IntegrityError {
                expected: "base64 DSSE payload".to_string(),
                actual: err.to_string(),
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
            let signature_bytes =
                BASE64_STANDARD
                    .decode(&signature.signature)
                    .map_err(|err| StarmetalError::IntegrityError {
                        expected: "base64 DSSE signature".to_string(),
                        actual: err.to_string(),
                    })?;
            let signature = ed25519_dalek::Signature::from_slice(&signature_bytes).map_err(|err| {
                StarmetalError::IntegrityError {
                    expected: "ed25519 signature".to_string(),
                    actual: err.to_string(),
                }
            })?;
            if key.verifying_key.verify(&pae, &signature).is_ok() {
                return Ok(payload);
            }
        }
        Err(StarmetalError::IntegrityError {
            expected: "valid DSSE signature".to_string(),
            actual: "no configured key verified the envelope".to_string(),
        })
    }

    /// Verify a provenance attestation DSSE envelope, returning its verified in-toto payload bytes.
    pub(in crate::service) fn verify_attestation(&self, envelope_bytes: &[u8]) -> Result<Vec<u8>> {
        self.verify_dsse_payload(envelope_bytes, INTOTO_PAYLOAD_TYPE)
    }
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

fn load_ed25519_signing_key(pem: &str, key_id: &str) -> Result<SigningKey> {
    let info = PrivateKeyInfoOwned::from_pkcs8_pem(pem)
        .map_err(|err| StarmetalError::Config(format!("invalid signing key {key_id}: {err}")))?;
    validate_ed25519_oid(info.algorithm.oid, key_id)?;
    let private_key = extract_ed25519_private_key(info.private_key.as_bytes(), key_id)?;
    Ok(SigningKey::from_bytes(&private_key))
}

fn load_ed25519_verifying_key(pem: &str, key_id: &str) -> Result<VerifyingKey> {
    let info = SubjectPublicKeyInfoOwned::from_pem(pem)
        .map_err(|err| StarmetalError::Config(format!("invalid verification key {key_id}: {err}")))?;
    validate_ed25519_oid(info.algorithm.oid, key_id)?;
    let bytes = info.subject_public_key.as_bytes().ok_or_else(|| {
        StarmetalError::Config(format!(
            "invalid verification key {key_id}: public key must be byte-aligned"
        ))
    })?;
    let public_key = bytes.try_into().map_err(|_| {
        StarmetalError::Config(format!(
            "invalid verification key {key_id}: public key must be {ED25519_KEY_BYTES} bytes"
        ))
    })?;
    VerifyingKey::from_bytes(public_key)
        .map_err(|err| StarmetalError::Config(format!("invalid verification key {key_id}: {err}")))
}

fn validate_ed25519_oid(oid: ObjectIdentifier, key_id: &str) -> Result<()> {
    if oid.to_string() == ED25519_OID {
        return Ok(());
    }
    Err(StarmetalError::Config(format!(
        "invalid signing key {key_id}: expected ed25519 key algorithm"
    )))
}

fn extract_ed25519_private_key(bytes: &[u8], key_id: &str) -> Result<[u8; ED25519_KEY_BYTES]> {
    if let Ok(key) = bytes.try_into() {
        return Ok(key);
    }
    if let Ok(inner) = <&OctetStringRef>::from_der(bytes)
        && let Ok(key) = inner.as_bytes().try_into()
    {
        return Ok(key);
    }
    Err(StarmetalError::Config(format!(
        "invalid signing key {key_id}: private key must be {ED25519_KEY_BYTES} bytes"
    )))
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
