// SPDX-License-Identifier: LGPL-3.0-or-later

//! Hex encoding and decoding helpers.

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

/// Keccak-256 of the given bytes, hex-encoded.
pub fn keccak_hex(data: &[u8]) -> String {
    use zkboo::crypto::Hasher;
    let mut h = proofofseed_circuits::hasher::Keccak256Hasher::new();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_into(&mut out);
    encode(&out)
}

/// A writer that Keccak-256-hashes everything written through it.
pub struct HashingWriter<W: std::io::Write> {
    inner: W,
    hasher: proofofseed_circuits::hasher::Keccak256Hasher,
}

impl<W: std::io::Write> HashingWriter<W> {
    pub fn new(inner: W) -> Self {
        use zkboo::crypto::Hasher;
        Self { inner, hasher: proofofseed_circuits::hasher::Keccak256Hasher::new() }
    }

    /// Flushes the inner writer and returns the hex digest of everything written.
    pub fn finish(mut self) -> std::io::Result<String> {
        use zkboo::crypto::Hasher;
        self.inner.flush()?;
        let mut out = [0u8; 32];
        self.hasher.finalize_into(&mut out);
        Ok(encode(&out))
    }
}

impl<W: std::io::Write> std::io::Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        use zkboo::crypto::Hasher;
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
