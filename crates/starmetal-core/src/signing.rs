use std::{collections::BTreeMap, path::PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::package::{Ecosystem, PackageName};

pub const STARMETAL_DSSE_PAYLOAD_TYPE: &str = "application/vnd.starmetal.package-signing.v1+json";

#[cfg(feature = "signing-x509")]
pub fn validate_certificate_der(certificate_der: &[u8]) -> std::result::Result<(), String> {
    use x509_parser::prelude::{FromDer, X509Certificate};

    X509Certificate::from_der(certificate_der)
        .map(|_| ())
        .map_err(|err| format!("invalid X.509 certificate: {err}"))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SigningMode {
    SignOnly,
    #[default]
    SignAndVerify,
    VerifyOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SigningAlgorithm {
    Ed25519,
    EcdsaP256Sha256,
    MlDsa65,
}

impl SigningAlgorithm {
    pub fn is_classical(self) -> bool {
        matches!(self, Self::Ed25519 | Self::EcdsaP256Sha256)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SigningKeyStatus {
    #[default]
    Active,
    VerifyOnly,
    Disabled,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct SigningConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: SigningMode,
    #[serde(default)]
    pub verify_on_read: bool,
    #[serde(default)]
    pub sign_cached_upstream: bool,
    #[serde(default)]
    pub keys: Vec<SigningKeyConfig>,
    #[serde(default)]
    pub trust_roots: Vec<SigningTrustRootConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SigningKeyConfig {
    pub id: String,
    pub algorithm: SigningAlgorithm,
    pub private_key_file: Option<PathBuf>,
    pub public_key_file: Option<PathBuf>,
    pub private_key_password_env: Option<String>,
    pub certificate_file: Option<PathBuf>,
    pub certificate_chain_file: Option<PathBuf>,
    #[serde(default)]
    pub ecosystems: Vec<Ecosystem>,
    #[serde(default)]
    pub packages: Vec<String>,
    #[serde(default)]
    pub status: SigningKeyStatus,
}

impl SigningKeyConfig {
    pub fn allows(&self, ecosystem: Ecosystem, package: &PackageName) -> bool {
        let ecosystem_allowed = self.ecosystems.is_empty() || self.ecosystems.contains(&ecosystem);
        let package_allowed =
            self.packages.is_empty() || self.packages.iter().any(|name| name == package.as_str());
        ecosystem_allowed && package_allowed
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SigningTrustRootConfig {
    pub id: String,
    pub certificate_file: PathBuf,
    #[serde(default)]
    pub allowed_algorithms: Vec<SigningAlgorithm>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DsseEnvelope {
    pub payload_type: String,
    pub payload: String,
    pub signatures: Vec<DsseSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DsseSignature {
    pub key_id: String,
    pub algorithm: SigningAlgorithm,
    pub signature: String,
    #[serde(default)]
    pub certificate_fingerprint_sha256: Option<String>,
    #[serde(default)]
    pub certificate_chain_pem: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SignatureStatement {
    pub ecosystem: Ecosystem,
    pub package: PackageName,
    pub version: String,
    pub filename: Option<String>,
    pub storage_key: String,
    pub size: u64,
    pub blake3: String,
    pub upstream_hashes: BTreeMap<String, String>,
    pub source: SignatureSource,
    pub issued_at_unix_seconds: u64,
    pub key_id: String,
    #[serde(default)]
    pub certificate_fingerprint_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureSource {
    Local,
    UpstreamCache,
    Metadata,
}
