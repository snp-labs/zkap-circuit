//! Witness-generator sidecar schema and validation.
//!
//! `witness_gen.wasm` ships as a plain, unsigned file outside the signed
//! CRS manifest (see [`crate::manifest`] — the `witness_gen` artifact was
//! removed from the manifest trust path). This module defines the
//! independent sidecar document, `witness_gen.json`, that travels with the
//! wasm in its own release channel.
//!
//! # Integrity, not circuit trust
//!
//! [`WitnessGenSidecar::sha256`] is a **distribution-integrity** guard: it
//! lets a consumer confirm the wasm bytes were not corrupted in transit or
//! swapped by accident. It is **not** a circuit-trust claim. Whether a
//! witness generator produces witnesses that satisfy the R1CS is enforced
//! by Groth16 soundness plus the on-chain public-input pins — a wrong or
//! malicious generator simply yields proofs that fail verification, with
//! no loss of soundness. So the sha256 guards bytes, not correctness.
//!
//! # Compatibility, not provenance
//!
//! [`WitnessGenSidecar::compatible_ar1cs_blake3`] **gates** which CRS
//! shapes the wasm may pair with: a CRS whose `ar1cs_blake3`
//! ([`crate::manifest::Manifest::ar1cs_blake3`]) is absent from this list
//! is rejected before proving. The wasm is shape-agnostic — a single file
//! covers multiple shapes — so the list carries one entry per supported
//! shape. The optional [`WitnessGenSidecar::circuit_commit`] /
//! [`WitnessGenSidecar::circuit_id`] fields are **informational
//! provenance only** and MUST NOT gate: pinning them would forbid the
//! deliberate independent-version pairings this design enables.

use serde::{Deserialize, Serialize};

/// Independent sidecar for an independently-distributed `witness_gen.wasm`.
///
/// Serialised as `witness_gen.json` and published alongside the wasm in
/// its own release channel, decoupled from the per-shape CRS bundle. Field
/// order is significant for serde; see the module docs for the integrity
/// (`sha256`) vs. compatibility (`compatible_ar1cs_blake3`) vs. provenance
/// (`circuit_commit` / `circuit_id`) distinction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessGenSidecar {
    /// Independent witness-generator version (e.g. `"v0.1.1-rc.4"`). Free
    /// text; not parsed, not gating.
    pub version: String,
    /// SHA-256 of `witness_gen.wasm` as 64-char lowercase hex (no `0x`
    /// prefix). Distribution-integrity guard only — see the module docs.
    pub sha256: String,
    /// CRS `ar1cs_blake3` values this wasm is compatible with, each
    /// 64-char lowercase hex. MUST be non-empty. Gates which CRS shapes
    /// the wasm may pair with.
    pub compatible_ar1cs_blake3: Vec<String>,
    /// Optional source commit that built the wasm. Informational
    /// provenance — MUST NOT gate compatibility.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub circuit_commit: Option<String>,
    /// Optional circuit identifier. Informational provenance — MUST NOT
    /// gate compatibility.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub circuit_id: Option<String>,
}

/// Errors surfaced when parsing or enforcing a [`WitnessGenSidecar`].
///
/// The sidecar contract is fail-closed: a missing, empty, or malformed
/// field — or a sha / compatibility mismatch — is always a hard error,
/// never a silent pass.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SidecarError {
    /// JSON parse of the sidecar document failed.
    #[error("witness_gen sidecar parse error: {0}")]
    Parse(String),
    /// `sha256` was not exactly 64 lowercase-hex characters.
    #[error("witness_gen sidecar sha256 malformed (expected 64 lowercase-hex chars): {0}")]
    MalformedSha256(String),
    /// `compatible_ar1cs_blake3` was empty.
    #[error("witness_gen sidecar compatible_ar1cs_blake3 must be non-empty")]
    EmptyCompatibleList,
    /// A `compatible_ar1cs_blake3` entry was not 64 lowercase-hex characters.
    #[error(
        "witness_gen sidecar compatible_ar1cs_blake3 entry malformed \
         (expected 64 lowercase-hex chars): {0}"
    )]
    MalformedCompatibleEntry(String),
    /// The computed sha256 of the wasm did not match the sidecar's claim.
    #[error("witness_gen sidecar sha256 mismatch: expected {expected}, computed {actual}")]
    ShaMismatch {
        /// The `sha256` the sidecar claimed.
        expected: String,
        /// The sha256 actually computed over the wasm bytes.
        actual: String,
    },
    /// A CRS `ar1cs_blake3` was not present in `compatible_ar1cs_blake3`.
    #[error("witness_gen sidecar is not compatible with CRS ar1cs_blake3 {0}")]
    Incompatible(String),
}

impl WitnessGenSidecar {
    /// Parse a `witness_gen.json` byte buffer and [`validate`](Self::validate) it.
    ///
    /// JSON parse failures map to [`SidecarError::Parse`]; schema problems
    /// surface as the corresponding `Malformed*` / `EmptyCompatibleList`
    /// variants.
    pub fn from_json(bytes: &[u8]) -> Result<Self, SidecarError> {
        let sidecar: Self =
            serde_json::from_slice(bytes).map_err(|e| SidecarError::Parse(format!("{e}")))?;
        sidecar.validate()?;
        Ok(sidecar)
    }

    /// Validate the static shape of the sidecar.
    ///
    /// Checks that `sha256` is 64 lowercase-hex chars and that
    /// `compatible_ar1cs_blake3` is non-empty with every entry 64
    /// lowercase-hex chars. The provenance fields (`circuit_commit`,
    /// `circuit_id`) are intentionally unchecked.
    pub fn validate(&self) -> Result<(), SidecarError> {
        if !is_64_lc_hex(&self.sha256) {
            return Err(SidecarError::MalformedSha256(self.sha256.clone()));
        }
        if self.compatible_ar1cs_blake3.is_empty() {
            return Err(SidecarError::EmptyCompatibleList);
        }
        for entry in &self.compatible_ar1cs_blake3 {
            if !is_64_lc_hex(entry) {
                return Err(SidecarError::MalformedCompatibleEntry(entry.clone()));
            }
        }
        Ok(())
    }

    /// Verify that `wasm_bytes` hashes to the sidecar's claimed `sha256`.
    ///
    /// Computes `sha256(wasm_bytes)` and compares it to [`Self::sha256`];
    /// a mismatch yields [`SidecarError::ShaMismatch`]. Assumes
    /// [`validate`](Self::validate) has already run; call it first if the
    /// sidecar's static shape has not yet been checked.
    pub fn verify_wasm_sha(&self, wasm_bytes: &[u8]) -> Result<(), SidecarError> {
        use sha2::{Digest, Sha256};
        let actual = hex::encode(Sha256::digest(wasm_bytes));
        if actual != self.sha256 {
            return Err(SidecarError::ShaMismatch {
                expected: self.sha256.clone(),
                actual,
            });
        }
        Ok(())
    }

    /// Enforce that `crs_ar1cs_blake3` is in `compatible_ar1cs_blake3`.
    ///
    /// Runs [`validate`](Self::validate) first, then returns
    /// [`SidecarError::Incompatible`] if the CRS shape is not listed.
    pub fn require_compatible(&self, crs_ar1cs_blake3: &str) -> Result<(), SidecarError> {
        self.validate()?;
        if !self.is_compatible(crs_ar1cs_blake3) {
            return Err(SidecarError::Incompatible(crs_ar1cs_blake3.to_string()));
        }
        Ok(())
    }

    /// Convenience membership check against `compatible_ar1cs_blake3`.
    ///
    /// Does not validate the sidecar; use
    /// [`require_compatible`](Self::require_compatible) for the gating
    /// path that also rejects malformed sidecars.
    pub fn is_compatible(&self, crs_ar1cs_blake3: &str) -> bool {
        self.compatible_ar1cs_blake3
            .iter()
            .any(|e| e == crs_ar1cs_blake3)
    }
}

/// `true` iff `s` is exactly 64 characters, each a lowercase hex digit.
fn is_64_lc_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_SHA: &str = "aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff00112233";
    const BLAKE3_A: &str = "f928dbaef3750a67a85f1ab0bc317fb5616cd1626affb2ecc2aa847f64fdd962";
    const BLAKE3_B: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn sample() -> WitnessGenSidecar {
        WitnessGenSidecar {
            version: "v0.1.1-rc.4".into(),
            sha256: VALID_SHA.into(),
            compatible_ar1cs_blake3: vec![BLAKE3_A.into(), BLAKE3_B.into()],
            circuit_commit: None,
            circuit_id: None,
        }
    }

    /// Acceptance: `WitnessGenSidecar → serde_json → WitnessGenSidecar`
    /// preserves every field.
    #[test]
    fn sidecar_round_trip_via_serde() {
        let original = WitnessGenSidecar {
            circuit_commit: Some("deadbeef".into()),
            circuit_id: Some("zkap-main-v1".into()),
            ..sample()
        };
        let bytes = serde_json::to_vec(&original).expect("serialize");
        let back = WitnessGenSidecar::from_json(&bytes).expect("deserialize + validate");
        assert_eq!(original, back);
    }

    /// Acceptance: `from_json` parses + validates a well-formed document.
    #[test]
    fn from_json_accepts_valid_document() {
        let bytes = serde_json::to_vec(&sample()).expect("serialize");
        let parsed = WitnessGenSidecar::from_json(&bytes).expect("parse valid sidecar");
        assert_eq!(parsed, sample());
    }

    /// Acceptance: `verify_wasm_sha` accepts the matching wasm and rejects
    /// a mismatch with [`SidecarError::ShaMismatch`].
    #[test]
    fn verify_wasm_sha_pass_and_mismatch() {
        use sha2::{Digest, Sha256};
        let wasm = b"the witness generator wasm bytes";
        let sha = hex::encode(Sha256::digest(wasm));
        let sidecar = WitnessGenSidecar {
            sha256: sha,
            ..sample()
        };
        sidecar
            .verify_wasm_sha(wasm)
            .expect("matching sha must pass");

        let err = sidecar
            .verify_wasm_sha(b"different bytes")
            .expect_err("mismatched sha must fail");
        assert!(matches!(err, SidecarError::ShaMismatch { .. }));
    }

    /// Acceptance: `require_compatible` passes for a listed CRS shape and
    /// rejects an unlisted one with [`SidecarError::Incompatible`].
    #[test]
    fn require_compatible_pass_and_incompatible() {
        let sidecar = sample();
        sidecar
            .require_compatible(BLAKE3_A)
            .expect("listed shape must be compatible");

        let unlisted = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let err = sidecar
            .require_compatible(unlisted)
            .expect_err("unlisted shape must be rejected");
        assert!(matches!(err, SidecarError::Incompatible(_)));
    }

    /// Acceptance: an empty `compatible_ar1cs_blake3` is rejected.
    #[test]
    fn empty_compatible_list_rejected() {
        let sidecar = WitnessGenSidecar {
            compatible_ar1cs_blake3: vec![],
            ..sample()
        };
        let err = sidecar.validate().expect_err("empty list must fail");
        assert!(matches!(err, SidecarError::EmptyCompatibleList));
    }

    /// Acceptance: a malformed `sha256` (wrong length / uppercase / non-hex)
    /// is rejected.
    #[test]
    fn malformed_sha256_rejected() {
        for bad in ["", "deadbeef", &"A".repeat(64), &"g".repeat(64)] {
            let sidecar = WitnessGenSidecar {
                sha256: bad.to_string(),
                ..sample()
            };
            let err = sidecar.validate().expect_err("malformed sha must fail");
            assert!(matches!(err, SidecarError::MalformedSha256(_)));
        }
    }

    /// Acceptance: a malformed `compatible_ar1cs_blake3` entry is rejected.
    #[test]
    fn malformed_compatible_entry_rejected() {
        let sidecar = WitnessGenSidecar {
            compatible_ar1cs_blake3: vec![BLAKE3_A.into(), "not-hex".into()],
            ..sample()
        };
        let err = sidecar
            .validate()
            .expect_err("malformed compatible entry must fail");
        assert!(matches!(err, SidecarError::MalformedCompatibleEntry(_)));
    }

    /// Acceptance: `None` provenance fields are skipped on serialize.
    #[test]
    fn provenance_none_fields_skipped_on_serialize() {
        let v = serde_json::to_value(sample()).expect("serialize");
        let obj = v.as_object().expect("sidecar object");
        assert!(
            !obj.contains_key("circuit_commit"),
            "circuit_commit must be skipped when None"
        );
        assert!(
            !obj.contains_key("circuit_id"),
            "circuit_id must be skipped when None"
        );
    }
}
