// SPDX-License-Identifier: LGPL-3.0-or-later

//! Small hex helpers (kept in-tree rather than pulling a dependency).

pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    if !s.len().is_multiple_of(2) {
        return Err(format!("odd-length hex string ({} chars)", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| format!("invalid hex at position {i}"))
        })
        .collect()
}

/// Keccak-256 of `data`, hex-encoded (the digest used throughout the proof
/// suite's sidecars and fixtures).
pub fn keccak_hex(data: &[u8]) -> String {
    use zkboo::crypto::Hasher;
    let mut h = zkboo::crypto::Keccak256Hasher::new();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_into(&mut out);
    encode(&out)
}
