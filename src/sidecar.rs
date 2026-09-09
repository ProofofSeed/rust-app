// SPDX-License-Identifier: LGPL-3.0-or-later

//! The JSON metadata record written alongside a proof file.

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
    /// The request's derivation path.
    pub path: Option<String>,
    /// The asserted child index.
    pub index: Option<String>,
    /// The derived parent chain code the request anchors.
    pub chain_code: Option<String>,
    pub binding: String,
    /// The half-open response range this file carries.
    pub range: Option<(u16, u16)>,
    pub entropy_mode: EntropyMode,
    /// The plain public output, for the statements whose output is public.
    pub output: Option<String>,
    /// Keccak-256 of the expected public output.
    pub output_keccak256: String,
    /// The witness byte length, for the statements whose circuit allocates one input
    /// per witness byte.
    #[serde(default)]
    pub witness_len: Option<usize>,
    /// The byte length of the BIP-39 PBKDF2 salt.
    #[serde(default)]
    pub salt_len: Option<usize>,
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
        use std::io::Write as _;
        let path = Self::path_for(proof);
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        // The sidecar carries the anchored parent chain code (an extended-key
        // component — see the security note in the README), so it is created 0600
        // and refuses to overwrite or follow a symlink, like the proof file
        // (the proof is always created fresh, so the sidecar never overwrites).
        let mut file = crate::fsutil::create_new_0600(&path)?;
        file.write_all(json.as_bytes())
            .and_then(|_| file.write_all(b"\n"))
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
        // The wire format caps the response count; a sidecar claiming more is
        // malformed (and the range, if any, must lie within it).
        if sidecar.num_iters == 0 || sidecar.num_iters > crate::MAX_RESPONSES {
            return Err(format!(
                "sidecar {} declares {} responses, outside 1..={}",
                path.display(),
                sidecar.num_iters,
                crate::MAX_RESPONSES
            ));
        }
        if let Some((start, end)) = sidecar.range
            && (start >= end || end as usize > sidecar.num_iters)
        {
            return Err(format!(
                "sidecar {} has range {start}..{end} outside its {} responses",
                path.display(),
                sidecar.num_iters
            ));
        }
        Ok(sidecar)
    }

    /// The fields that must agree across the ranges of one proof.
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
            self.witness_len,
            self.salt_len,
            self.versions.deterministic_entropy_version,
        )
    }
}
