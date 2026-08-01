//! In-toto / SLSA provenance statement generation (ADR-0024).
//!
//! Pure, framework-free builder for the provenance attestation Starmetal produces for an artifact it
//! publishes or caches. The statement is a plain [`serde_json::Value`] (an in-toto Statement v1 with
//! an SLSA provenance v1 predicate); the service layer signs it into a DSSE envelope with Starmetal's
//! own key and stores it as a sidecar, and the [`Verifier`](crate::supply_chain::Verifier) gate
//! checks that signed attestation on serve/ingest.
//!
//! The caller injects the RFC 3339 build timestamp so generation stays deterministic and testable
//! (no clock dependency here).

use serde_json::{Value, json};

/// The in-toto Statement type URI (the `_type` field).
pub const INTOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// The SLSA provenance predicate type URI.
pub const SLSA_PROVENANCE_PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";

/// The DSSE `payloadType` for an in-toto statement envelope.
pub const INTOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// Starmetal's SLSA `buildType` URI, identifying a publish/cache-fill as the "build".
pub const STARMETAL_BUILD_TYPE: &str = "https://starmetal.dev/provenance/publish/v1";

/// Build an in-toto v1 provenance statement for a subject artifact.
///
/// `subject_name` is the artifact's coordinate-scoped name (e.g. its storage key), `subject_blake3`
/// its BLAKE3 content digest, `builder_id` the SLSA builder identity, and `built_at` an RFC 3339
/// timestamp. The result is the DSSE *payload* the service signs; it is not itself signed here.
pub fn provenance_statement(subject_name: &str, subject_blake3: &str, builder_id: &str, built_at: &str) -> Value {
    json!({
        "_type": INTOTO_STATEMENT_TYPE,
        "subject": [{
            "name": subject_name,
            "digest": { "blake3": subject_blake3 },
        }],
        "predicateType": SLSA_PROVENANCE_PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": STARMETAL_BUILD_TYPE,
                "externalParameters": {},
                "internalParameters": {},
                "resolvedDependencies": [],
            },
            "runDetails": {
                "builder": { "id": builder_id },
                "metadata": {
                    "invocationId": subject_blake3,
                    "startedOn": built_at,
                    "finishedOn": built_at,
                },
            },
        },
    })
}

/// The single subject a provenance statement attests to — its `name` and BLAKE3 `digest` — if the
/// statement is well-formed and names exactly one subject. Used by the verifier to confirm an
/// attestation covers the artifact in hand (both its coordinate name and its bytes).
pub fn statement_subject(statement: &Value) -> Option<(&str, &str)> {
    let subjects = statement.get("subject")?.as_array()?;
    let [subject] = subjects.as_slice() else {
        return None;
    };
    let name = subject.get("name")?.as_str()?;
    let blake3 = subject.get("digest")?.get("blake3")?.as_str()?;
    Some((name, blake3))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_statement_has_the_intoto_and_slsa_shape() {
        let statement = provenance_statement(
            "npm/left-pad/1.3.0/left-pad.tgz",
            "abc123",
            "https://starmetal.dev",
            "2026-08-01T00:00:00Z",
        );
        assert_eq!(statement["_type"], INTOTO_STATEMENT_TYPE);
        assert_eq!(statement["predicateType"], SLSA_PROVENANCE_PREDICATE_TYPE);
        assert_eq!(statement["subject"][0]["name"], "npm/left-pad/1.3.0/left-pad.tgz");
        assert_eq!(statement["subject"][0]["digest"]["blake3"], "abc123");
        assert_eq!(
            statement["predicate"]["buildDefinition"]["buildType"],
            STARMETAL_BUILD_TYPE
        );
        assert_eq!(
            statement["predicate"]["runDetails"]["builder"]["id"],
            "https://starmetal.dev"
        );
        assert_eq!(
            statement["predicate"]["runDetails"]["metadata"]["startedOn"],
            "2026-08-01T00:00:00Z"
        );
    }

    #[test]
    fn statement_subject_extracts_the_single_subject_name_and_digest() {
        let statement = provenance_statement("pypi/x/1.0.0/x.tgz", "deadbeef", "b", "t");
        assert_eq!(statement_subject(&statement), Some(("pypi/x/1.0.0/x.tgz", "deadbeef")));
    }

    #[test]
    fn statement_subject_rejects_zero_or_multiple_subjects() {
        assert_eq!(statement_subject(&json!({})), None);
        assert_eq!(statement_subject(&json!({ "subject": [] })), None);
        let two = json!({
            "subject": [
                { "name": "a", "digest": { "blake3": "a" } },
                { "name": "b", "digest": { "blake3": "b" } },
            ]
        });
        assert_eq!(statement_subject(&two), None);
    }
}
