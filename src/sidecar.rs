// SPDX-License-Identifier: LGPL-3.0-or-later

//! The proof sidecar: a JSON file (`<proof>.json`) carrying the request
//! metadata, versions, and stream digest of a proof file. Metadata only — the
//! proof file itself stays the raw device-identical byte stream, and
//! verification never trusts the sidecar for soundness (the verifier re-derives
//! everything from the stream and the parameters).
//!
//! Secrecy rule: for statements whose public output is itself key material
//! (master key, children, BIP-39 seed) the sidecar stores only
//! `output_keccak256`; the verifier supplies the expected output out of band and
//! the commitment cross-checks it. The genuinely public outputs (public key,
//! Ethereum address) are stored plainly in `output`.

use serde::{Deserialize, Serialize};

pub const FORMAT: &str = "proofofseed-sidecar/1";

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Versions {
    pub cli: String,
    pub deterministic_entropy_version: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Sidecar {
    pub format: String,
    pub statement: String,
    pub family: String,
    pub num_iters: usize,
    pub rounds: usize,
    /// The request's derivation path (parent path for child statements, full
    /// path for key statements), `None` for the seed-level statements.
    pub path: Option<String>,
    /// The asserted child index (child statements only), e.g. `0'`.
    pub index: Option<String>,
    /// The derived parent chain code the request anchors (child statements only).
    pub chain_code: Option<String>,
    pub binding: String,
    /// The half-open response range this file carries; `None` = the full
    /// sequence proved in one TRNG-entropy run.
    pub range: Option<(u16, u16)>,
    pub entropy_mode: EntropyMode,
    /// The plain public output — only for statements whose output is public.
    pub output: Option<String>,
    /// Keccak-256 of the expected public output (always present).
    pub output_keccak256: String,
    pub stream_bytes: u64,
    pub stream_keccak256: String,
    pub versions: Versions,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum EntropyMode {
    Trng,
    Deterministic,
}

impl Sidecar {
    pub fn path_for(proof: &std::path::Path) -> std::path::PathBuf {
        let mut os = proof.as_os_str().to_owned();
        os.push(".json");
        std::path::PathBuf::from(os)
    }

    pub fn write(&self, proof: &std::path::Path) -> Result<(), String> {
        let path = Self::path_for(proof);
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, json + "\n")
            .map_err(|e| format!("cannot write sidecar {}: {e}", path.display()))
    }

    pub fn read(proof: &std::path::Path) -> Result<Self, String> {
        let path = Self::path_for(proof);
        let json = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read sidecar {}: {e}", path.display()))?;
        let sidecar: Sidecar = serde_json::from_str(&json)
            .map_err(|e| format!("malformed sidecar {}: {e}", path.display()))?;
        if sidecar.format != FORMAT {
            return Err(format!(
                "sidecar {} has format {:?}, expected {FORMAT:?}",
                path.display(),
                sidecar.format
            ));
        }
        Ok(sidecar)
    }

    /// The fields that must agree across the ranges of one proof (everything
    /// except the range and the per-file stream data).
    pub fn assembly_key(&self) -> impl PartialEq + std::fmt::Debug + use<> {
        (
            self.statement.clone(),
            self.family.clone(),
            self.num_iters,
            self.rounds,
            self.path.clone(),
            self.index.clone(),
            self.chain_code.clone(),
            self.binding.clone(),
            self.output_keccak256.clone(),
            self.versions.clone(),
        )
    }
}
