# Interoperability with the device

The CLI and the ProofofSeed Ledger app consume the same `proofofseed-core` library, so the statements, the wire-level request semantics and the proof bytes are identical.

## Co-proving

For the derived-key statements — `hardened-child`, `normal-child`, `public-key`, `ethereum-address` — a device and the CLI holding the same seed produce byte-identical ranged proofs, and one proof can be split between them.
That holds only when both requests carry the same derivation fields:

- For the child statements: the parent path, the child index and the parent chain code.
  The CLI always sets all three.
  A co-proving device request must set them explicitly rather than falling back to compiled-in defaults, which absorb differently into the entropy transcript.
- For `public-key` and `ethereum-address`: the full path, with no index and no chain code on either side.

## What is not co-provable

`master-key` and `bip39-seed` are proved here against the real seed, but a stock device proves them only on a public test vector, because the path they need is not exposed by the operating system.
Only the CLI reaches those two against a real seed.
