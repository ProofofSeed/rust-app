// SPDX-License-Identifier: LGPL-3.0-or-later

//! Refuses to build when a zkboo or proofofseed crate resolves from anywhere but crates.io.
//!
//! A `[patch]` entry, in a manifest or in a cargo configuration file, would build the code against
//! a local tree that the lockfile's checksums do not cover. The lockfile is the one record of what
//! was resolved, so it is read here rather than the manifest.

use std::path::Path;

/// Whether a crate must resolve from crates.io: every zkboo and proofofseed crate but this one.
fn guarded(name: &str) -> bool {
    (name.starts_with("zkboo") || name.starts_with("proofofseed-"))
        && name != env!("CARGO_PKG_NAME")
}

/// The lockfile's source for crates.io.
const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// Lists the guarded packages the lockfile resolves from anywhere but crates.io.
fn off_registry(lock: &str) -> Vec<String> {
    let mut found = Vec::new();
    for block in lock.split("[[package]]").skip(1) {
        let field = |key: &str| {
            block.lines().find_map(|line| {
                let (k, v) = line.split_once('=')?;
                (k.trim() == key).then(|| v.trim().trim_matches('"').to_string())
            })
        };
        let Some(name) = field("name") else { continue };
        if !guarded(&name) {
            continue;
        }
        let source = field("source");
        if source.as_deref() != Some(CRATES_IO) {
            found.push(format!(
                "{name} {} from {}",
                field("version").unwrap_or_default(),
                source.as_deref().unwrap_or("a path")
            ));
        }
    }
    found
}

fn main() {
    let lock_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock");
    println!("cargo::rerun-if-changed={}", lock_path.display());
    println!("cargo::rerun-if-changed=build.rs");
    let lock = std::fs::read_to_string(&lock_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", lock_path.display()));
    if !lock.contains("\nname = \"zkboo\"\n") {
        panic!("{} resolves no zkboo crate", lock_path.display());
    }
    let found = off_registry(&lock);
    if !found.is_empty() {
        panic!(
            "these crates resolve from somewhere other than crates.io, so a [patch] is in \
             force:\n  {}",
            found.join("\n  ")
        );
    }
}
