// SPDX-License-Identifier: LGPL-3.0-or-later

//! Refuses to build when a zkboo or proofofseed crate resolves from a registry.
//!
//! A `[patch.crates-io]` entry whose local version stops satisfying the requirement is ignored
//! by cargo without a warning, and the published crate is resolved in its place. The lockfile is
//! the one record of what was resolved, so it is read here rather than the manifest.

use std::path::Path;

/// Whether a crate must resolve from a path.
fn guarded(name: &str) -> bool {
    name.starts_with("zkboo") || name.starts_with("proofofseed-")
}

/// Lists the guarded packages the lockfile resolves from anywhere but a path.
fn unpatched(lock: &str) -> Vec<String> {
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
        if let Some(source) = field("source") {
            found.push(format!(
                "{name} {} from {source}",
                field("version").unwrap_or_default()
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
    let found = unpatched(&lock);
    if !found.is_empty() {
        panic!(
            "these crates resolve from a registry, so the [patch.crates-io] table has \
             disengaged (a local version no longer satisfies the requirement):\n  {}",
            found.join("\n  ")
        );
    }
}
