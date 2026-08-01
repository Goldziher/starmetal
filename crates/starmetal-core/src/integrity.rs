use bytes::Bytes;

use crate::error::{Result, StarmetalError};

/// Compute blake3 hash of data, returning hex-encoded string.
pub fn blake3_hex(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// Compute blake3 hash incrementally from multiple chunks.
pub fn blake3_streaming(chunks: &[&[u8]]) -> String {
    let mut hasher = blake3::Hasher::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    hasher.finalize().to_hex().to_string()
}

/// Verify data against an expected blake3 hex digest.
pub fn verify_blake3(data: &Bytes, expected: &str) -> bool {
    blake3_hex(data) == expected
}

/// The length of a blake3 digest rendered as lowercase hex.
pub const BLAKE3_HEX_LEN: usize = 64;

/// Returns `true` when `value` is a well-formed blake3 digest: exactly [`BLAKE3_HEX_LEN`] lowercase
/// hex characters, matching what [`blake3_hex`] produces.
///
/// Use this to validate an externally supplied digest (for example an admin quarantine
/// promote/reject path parameter) before interpolating it into a storage key, so a crafted value
/// such as `../../config` can never escape its intended key prefix (path-traversal / key injection).
pub fn is_blake3_hex(value: &str) -> bool {
    value.len() == BLAKE3_HEX_LEN && value.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Verify data and return a `Result`, producing `StarmetalError::IntegrityError` on mismatch.
pub fn verify_or_err(data: &Bytes, expected: &str) -> Result<()> {
    let actual = blake3_hex(data);
    if actual == expected {
        Ok(())
    } else {
        Err(StarmetalError::IntegrityError {
            expected: expected.to_string(),
            actual,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_known_hash() {
        let hash = blake3_hex(b"");
        assert_eq!(hash, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
    }

    #[test]
    fn hash_and_verify_roundtrip() {
        let data = Bytes::from_static(b"hello starmetal");
        let hash = blake3_hex(&data);
        assert!(verify_blake3(&data, &hash));
        assert!(!verify_blake3(
            &data,
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn verify_or_err_success() {
        let data = Bytes::from_static(b"test data");
        let hash = blake3_hex(&data);
        assert!(verify_or_err(&data, &hash).is_ok());
    }

    #[test]
    fn verify_or_err_failure() {
        let data = Bytes::from_static(b"test data");
        let err = verify_or_err(&data, "bad_hash").unwrap_err();
        assert!(err.to_string().contains("integrity check failed"));
    }

    #[test]
    fn is_blake3_hex_accepts_a_well_formed_digest() {
        let digest = blake3_hex(b"hello starmetal");
        assert!(is_blake3_hex(&digest));
        assert!(is_blake3_hex(&"a".repeat(BLAKE3_HEX_LEN)));
    }

    #[test]
    fn is_blake3_hex_rejects_malformed_input() {
        assert!(!is_blake3_hex(""), "empty string is not a digest");
        assert!(!is_blake3_hex(&"a".repeat(63)), "too short");
        assert!(!is_blake3_hex(&"a".repeat(65)), "too long");
        assert!(!is_blake3_hex(&"A".repeat(64)), "uppercase hex is not accepted");
        assert!(!is_blake3_hex(&format!("{}g", "a".repeat(63))), "non-hex character");
        assert!(!is_blake3_hex("../../config"), "path traversal is not a digest");
        assert!(
            !is_blake3_hex(&format!("..%2f..%2f{}", "a".repeat(54))),
            "percent-encoded traversal"
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        let part1 = b"hello ";
        let part2 = b"starmetal";
        let full = b"hello starmetal";
        let oneshot = blake3_hex(full);
        let streamed = blake3_streaming(&[part1, part2]);
        assert_eq!(oneshot, streamed);
    }

    #[test]
    fn fixture_driven_vectors() {
        let path =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testing_data/integrity/01_blake3_vectors.json");
        let content = std::fs::read_to_string(&path).unwrap();
        let fixtures: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();

        for fix in &fixtures {
            let input = fix["input"]["data"].as_str().unwrap();
            let hash = blake3_hex(input.as_bytes());

            if let Some(expected) = fix["expected"]["blake3"].as_str() {
                assert_eq!(hash, expected, "fixture '{}'", fix["name"].as_str().unwrap_or("?"));
            }
            let data = Bytes::from(input.to_string());
            assert!(verify_blake3(&data, &hash));
        }
    }
}
