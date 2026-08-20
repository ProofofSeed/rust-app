# proofofseed

A standalone command-line prover and verifier for **proofs of seed**: zero-knowledge (ZKBoo) proofs that a BIP-39/BIP-32/SLIP-10-derived key was derived from the seed you hold, bound to a verifier-chosen context — for software wallets, on any host.

This is the software-wallet counterpart of the ProofofSeed Ledger app: both consume the same `proofofseed-core` library (`../proofofseed-core`), so the statements, the wire-level request semantics, and the proof bytes are identical. For the statements a stock device can actually prove against its own seed — the **derived-key** statements (`hardened-child`, `normal-child`, `public-key`, `ethereum-address`) — a device and this CLI holding the same seed produce byte-identical ranged proofs and can split one proof between them, provided the co-proving request carries the derivation **path, index, and parent chain code explicitly** (the CLI always does; a device request that instead relies on compiled-in defaults absorbs those fields differently and will not assemble). `master-key` and `bip39-seed` are proved here against the real seed but the device proves them only on a public test vector, so those two are not co-provable — only the CLI reaches them against a real seed.

## Usage

```sh
proofofseed prove --statement hardened-child --path "m/84'/0'" --index "0'" \
    --binding <hex> -o proof.pos                    # prompts for the mnemonic
proofofseed prove ... --range 0..219                # resumable/parallel ranges
proofofseed verify --proof proof.pos --expected-output-file output.hex
proofofseed assemble part1.pos part2.pos -o full.pos --expected-output-file output.hex
proofofseed derive --statement ethereum-address --path "m/44'/60'/0'/0/0"
proofofseed profile --statement hardened-child     # sizes/memory, no witness
proofofseed prove --statement ... --dry-run --calibrate   # plan + local timing
```

Statements: `master-key`, `hardened-child`, `bip39-seed`, `public-key`, `normal-child`, `ethereum-address`; families `bip32` (default) and `slip10` (recovery statements only). The default response count is **438** (soundness error `(2/3)^438 ≤ 2^-256`, 128-bit post-quantum).

The mnemonic is read from a hidden prompt, `--seed-file` (or the file named by `PROOFOFSEED_SEED_FILE`), or piped stdin — never from the command line or an environment variable. BIP-39 checksums are validated (override with `--allow-invalid-mnemonic`). Proof files are the raw device-identical stream; a JSON sidecar (`<file>.json`) carries request metadata, versions and digests — for the statements whose output is itself key material, only a *commitment* to the expected output.

## Security posture

This tool holds your **raw seed** in host memory while it runs — a categorically higher-stakes witness than a hardware wallet's derived keys. Run it only on a machine you trust, ideally air-gapped; key material is volatile-zeroed after use, but no swap or core-dump guarantees are claimed. Ranged (deterministic-entropy) proving must use one build across all runs of a proof — see `../proofofseed-core/knowledge/plan.md` and the ledger-app's `docs/range-proving.md` for the entropy design and its caveats.

**The sidecar carries the parent chain code.** For a child-statement proof the verifier must anchor the parent chain code, so it is stored in the JSON sidecar (created mode 0600). A chain code is an extended-key component: combined with the parent public key it forms an xpub (all non-hardened descendant addresses become linkable), and for a `normal-child` proof, chain code plus the revealed child private key reconstructs the parent private key. Treat the sidecar as sensitive, hand it only to the intended verifier, and prefer hardened statements where the verifier already independently holds the anchor.

**Soundness is the verifier's to demand.** The sidecar is metadata that travels with a relayed proof; `verify` and `assemble` therefore refuse any proof carrying fewer than `--min-responses` (default 438) responses rather than trusting the count the sidecar asserts, and the stream verifier rejects a proof with unread trailing responses — so a 438-response proof cannot be passed off as a weaker one.

## Structure and dependencies

`src/`: `main.rs` (clap entry), `statements.rs` (circuit/request plumbing), `seed.rs` (input channels + BIP-39 checksum via the zkboo-sha2 circuit), `prove.rs`/`verify.rs`/`assemble.rs` (commands), `sidecar.rs`, `paths.rs`, `hexutil.rs`, `wordlist.rs` (the canonical BIP-39 English wordlist, data only). Tests: `tests/cli.rs` — the milestone-2 acceptance suite (round trips with named refusals, CLI ≡ library byte-equality, dry-run ≡ profiler, witness hygiene on failure paths, checksum, channels).

Deliberate dependencies beyond the proofofseed/zkboo stack, each with a one-line reason in `Cargo.toml`: `clap` (parsing, off the secret dataflow), `rpassword` (hidden prompts), `serde`/`serde_json` (sidecars), `getrandom` (fresh prover entropy), `zeroize`. Until the zkboo crates are published, building requires the local working trees (`[patch.crates-io]` paths).
