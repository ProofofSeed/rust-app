// SPDX-License-Identifier: LGPL-3.0-or-later

//! Mnemonic input and BIP-39 validation.

use std::io::{IsTerminal, Read};

use crate::wordlist::WORDLIST;
use zeroize::{Zeroize, Zeroizing};
use zkboo::backend::{Backend, Frontend};
use zkboo::circuit::Circuit;

/// Where the mnemonic comes from.
pub struct SeedSource {
    pub seed_file: Option<std::path::PathBuf>,
    pub stdin: bool,
}

/// Reads the mnemonic from the selected channel and normalises it.
pub fn read_mnemonic(source: &SeedSource) -> Result<Zeroizing<String>, String> {
    let raw: Zeroizing<String> = match (&source.seed_file, source.stdin) {
        (Some(_), true) => return Err("choose one of --seed-file and --stdin".into()),
        (Some(path), false) => Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read seed file {}: {e}", path.display()))?,
        ),
        (None, true) => {
            if std::io::stdin().is_terminal() {
                return Err(
                    "--stdin requires piped input (a terminal would echo the mnemonic; \
                     use the interactive prompt instead)"
                        .into(),
                );
            }
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| format!("cannot read stdin: {e}"))?;
            Zeroizing::new(buf)
        }
        (None, false) => {
            if let Ok(path) = std::env::var("PROOFOFSEED_SEED_FILE") {
                Zeroizing::new(
                    std::fs::read_to_string(&path)
                        .map_err(|e| format!("cannot read PROOFOFSEED_SEED_FILE {path}: {e}"))?,
                )
            } else {
                Zeroizing::new(
                    rpassword::prompt_password("mnemonic (hidden): ")
                        .map_err(|e| format!("cannot read prompt: {e}"))?,
                )
            }
        }
    };
    // Built character by character, and at exact capacity: see knowledge/security.md.
    let mut normalized = String::with_capacity(raw.len());
    for word in raw.split_whitespace() {
        if !normalized.is_empty() {
            normalized.push(' ');
        }
        normalized.extend(word.chars().map(|c| c.to_ascii_lowercase()));
    }
    if normalized.is_empty() {
        return Err("empty mnemonic".into());
    }
    Ok(Zeroizing::new(normalized))
}

/// Prompts for the BIP-39 passphrase.
pub fn read_passphrase() -> Result<Zeroizing<String>, String> {
    rpassword::prompt_password("BIP-39 passphrase (hidden, empty for none): ")
        .map(Zeroizing::new)
        .map_err(|e| format!("cannot read prompt: {e}"))
}

/// SHA-256 of a message, computed by executing the `zkboo-sha2` circuit natively.
struct Sha256Of {
    msg: Vec<u8>,
}

impl Drop for Sha256Of {
    fn drop(&mut self) {
        self.msg.zeroize();
    }
}

impl Circuit for Sha256Of {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let msg = self.msg.iter().map(|&b| frontend.input(b)).collect();
        zkboo_sha2::sha256bytes(frontend.allocator(), msg)
            .into_iter()
            .for_each(|w| frontend.output(w));
        proofofseed_circuits::assert_nothing(frontend);
    }
}

/// Validates a mnemonic against the BIP-39 word count, wordlist and checksum.
pub fn validate_bip39(mnemonic: &str) -> Result<(), String> {
    let words: Vec<&str> = mnemonic.split(' ').collect();
    let count = words.len();
    if ![12, 15, 18, 21, 24].contains(&count) {
        return Err(format!(
            "{count} words is not a BIP-39 length (12/15/18/21/24)"
        ));
    }
    // A word is referred to by position, never by itself: see knowledge/security.md.
    let mut indices: Zeroizing<Vec<u32>> = Zeroizing::new(Vec::with_capacity(count));
    for (position, word) in words.iter().enumerate() {
        match WORDLIST.binary_search(word) {
            Ok(i) => indices.push(i as u32),
            Err(_) => {
                return Err(format!(
                    "word {} of {count} is not a BIP-39 English word",
                    position + 1
                ));
            }
        }
    }
    // Repack the 11-bit indices: ENT entropy bits then CS = ENT/32 checksum bits.
    let total_bits = count * 11;
    let checksum_bits = total_bits / 33;
    let entropy_bits = total_bits - checksum_bits;
    let mut bits: Zeroizing<Vec<bool>> = Zeroizing::new(Vec::with_capacity(total_bits));
    for index in indices.iter() {
        for shift in (0..11).rev() {
            bits.push((index >> shift) & 1 != 0);
        }
    }
    let mut entropy = Zeroizing::new(vec![0u8; entropy_bits / 8]);
    for (i, bit) in bits[..entropy_bits].iter().enumerate() {
        if *bit {
            entropy[i / 8] |= 1 << (7 - i % 8);
        }
    }
    let digest = proofofseed_circuits::checked_payload(
        proofofseed_host::harness::exec_words(&Sha256Of { msg: entropy.to_vec() }),
    )
    .expect("the SHA-256 circuit makes no assertion that can fail");
    for (i, bit) in bits[entropy_bits..].iter().enumerate() {
        let digest_bit = (digest.u8[i / 8] >> (7 - i % 8)) & 1 != 0;
        if *bit != digest_bit {
            return Err("BIP-39 checksum mismatch (typo in the mnemonic?)".into());
        }
    }
    Ok(())
}
