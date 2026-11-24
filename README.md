# proofofseed

A standalone command-line prover and verifier for proofs of seed: zero-knowledge (ZKBoo) proofs that a BIP-39/BIP-32/SLIP-10-derived key was derived from a held seed, bound to a verifier-chosen context.
It is the software-wallet counterpart of the ProofofSeed Ledger app, and consumes the same `proofofseed-core` library, so the statements, the wire-level request semantics and the proof bytes are identical on both.

## Status

A research prototype: it has not been audited and is not for production use.
The 438-response default gives a soundness error of `(2/3)^438 <= 2^-256` only under the Fiat-Shamir transform and the security of the Keccak-256 hash, assumptions that have not been independently reviewed.
It holds a raw seed in host memory, with no guarantee against swap or core dumps.
The `zkboo` crates and `proofofseed-core` are not yet published, so it cannot be built from a clean checkout until they are; see Building.

## Usage

```sh
proofofseed prove --statement hardened-child --path "m/84'/0'" --index "0'" \
    --binding <hex> -o proof.pos                    # prompts for the mnemonic
proofofseed prove ... --range 0..100                # resumable or parallel ranges
proofofseed verify --proof proof.pos --expected-output-file output.hex
proofofseed assemble part1.pos part2.pos -o full.pos --expected-output-file output.hex
proofofseed derive --statement ethereum-address --path "m/44'/60'/0'/0/0"
proofofseed profile --statement hardened-child      # sizes and memory, no witness
proofofseed prove --statement ... --dry-run --calibrate   # plan and local timing
```

Statements are `master-key`, `hardened-child`, `bip39-seed`, `public-key`, `normal-child` and `ethereum-address`; families are `bip32` (default) and `slip10`, the latter for the recovery statements only.
The default response count is 438, a soundness error of `(2/3)^438 <= 2^-256` and 128-bit post-quantum.

The mnemonic is read from a hidden prompt, from `--seed-file` (or the file named by `PROOFOFSEED_SEED_FILE`), or from piped stdin, never from the command line or an environment variable.
BIP-39 checksums are validated, overridable with `--allow-invalid-mnemonic`.
A proof file is the raw device-identical stream; a JSON sidecar at `<file>.json` carries request metadata, versions and digests, and for the statements whose output is itself key material it carries only a commitment to that output.

## Security

The tool holds the raw seed in host memory while it runs, so run it only on a machine you trust, ideally air-gapped.
`verify` and `assemble` refuse a proof carrying fewer than `--min-responses` responses regardless of what a relayed sidecar claims.
The sidecar carries the parent chain code for a child statement, which is an extended-key component and should be treated as sensitive.
The full posture is in [`knowledge/security.md`](knowledge/security.md).

## Building

The `proofofseed-circuits`, `proofofseed-host` and `zkboo` crates resolve from crates.io.
`build.rs` refuses to build if the lockfile resolves any of them from anywhere else, so that a `[patch]` in force cannot pass for the published code.
`rust-toolchain.toml` pins the compiler to Rust 1.95.0.

```sh
cargo build --release
cargo test --release
```

## Structure

- `src/` — `main.rs` (the clap entry point), `statements.rs` (statement and family arguments), `seed.rs` (mnemonic input and BIP-39 validation), `prove.rs`, `verify.rs` and `assemble.rs` (the commands), `sidecar.rs`, `paths.rs`, `hexutil.rs`, `fsutil.rs`, and `wordlist.rs` (the canonical BIP-39 English wordlist, data only).
- `tests/cli.rs` — round trips with named refusals, byte-equality against the library, dry-run agreement with the profiler, witness hygiene on the failure paths, and the input channels.
- `knowledge/` — design records.

Dependencies beyond the proofofseed and zkboo stack are `clap`, `rpassword`, `serde`, `serde_json`, `getrandom` and `zeroize`, each with its reason stated in `Cargo.toml`.

Licensed LGPL-3.0-or-later; every source file carries an SPDX header.

## Licence

Copyright © 2026 Stefano Gogioso.
The code is LGPL-3.0-or-later (see `LICENSE`); vendored third-party code keeps its own licence.
