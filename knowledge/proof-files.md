# Proof files, sidecars and assembly

## The proof file

The proof file is the raw byte stream, identical to what a device emits for the same request.
It carries no header of its own, which is what makes it interoperable with the device and with the `proofofseed` Python package.
Proofs stream to disk at constant memory, so a proof larger than RAM is not a special case.

## The sidecar

Metadata is written alongside the proof as `<proof>.json`, in the format `proofofseed-sidecar/1`.
Verification never trusts it for soundness: the verifier re-derives everything from the stream under the parameters it chooses to trust, each of which is overridable on the command line.

Secrecy rule: for statements whose public output is itself key material (master key, hardened child, normal child, BIP-39 seed) the sidecar stores only `output_keccak256`.
The verifier supplies the expected output out of band and the commitment cross-checks it.
The genuinely public outputs (public key, Ethereum address) are stored plainly in `output`.

## Witness shape

The seed statements allocate one circuit input per witness byte, so the witness length is a public parameter of the circuit rather than an internal detail.
A verifier that does not receive it rebuilds the canonical test-vector circuit and rejects every real proof.
`witness_len` therefore travels in the sidecar.

For BIP-39 the salt is `"mnemonic"` followed by the passphrase, and its bytes are witness.
Only `salt_len` travels.
A verifier rebuilds the circuit from the two lengths and never receives the passphrase; what it can infer is how long one is (`salt_len - 8`), or that there is none (`salt_len == 8`).

## Entropy modes and assembly

A rangeless proof draws fresh prover entropy from the OS.
A ranged proof switches to the deterministic entropy derived from the request transcript, which is what lets slices produced by separate runs, or by separate devices holding the same seed, assemble into one proof.

`assemble` gathers range files given explicitly or found in a directory, checks through their sidecars that they belong to one proof, that their ranges exactly partition the response sequence, and that each file matches its recorded digest.
The assembled proof is verified before anything is written; gaps and overlaps refuse.

The version component of the assembly key is `deterministic_entropy_version`, the only version that governs whether two ranges share prover entropy — not the tool's own version string, which is informational and differs between the CLI and the Python package.
Ranged proving nonetheless requires one build across all runs of a proof.
