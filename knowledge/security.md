# Security posture

## The witness is the raw seed

The CLI holds the mnemonic, and every key derived from it, in host memory for the duration of a run.
That is a categorically higher-stakes witness than a hardware wallet's, which never exposes anything above the derived key the statement is about.
Run it on a machine you trust, ideally air-gapped.
Key material is volatile-zeroed after use; no swap or core-dump guarantee is claimed, because none is implemented.

## Mnemonic input channels

The mnemonic is never accepted on the command line or in an environment variable.
The channels are an interactive hidden prompt (the default), a file named by `--seed-file` or by `PROOFOFSEED_SEED_FILE`, and piped stdin.
Piped stdin is refused when stdin is a terminal, so a mnemonic is never typed with echo on.
The environment variable names a file; it never carries the secret itself.

Normalisation builds the phrase character by character into a buffer of exact capacity, rather than through `to_ascii_lowercase`, which would allocate a throwaway `String` per word — each holding a mnemonic word verbatim and dropped unwiped.

BIP-39 validation refers to a word by its position in the phrase and never by the word itself, so no mnemonic word can reach an error string.
The checksum SHA-256 is computed by executing the `zkboo-sha2` circuit natively, so no second hash implementation enters the trust path.
`--allow-invalid-mnemonic` overrides validation for non-BIP-39 phrases.

## Panic behaviour

The stream verifier in `proofofseed-host` turns a malformed or truncated proof into a `false` return through `catch_unwind`.
That requires unwinding, so both profiles pin `panic = "unwind"`: under `panic = "abort"` a crafted proof would abort the process.

The default panic hook still prints a trace, including the binary's build path, on the way.
`fsutil::quietly` swaps the process-global hook for the duration of one verification; the CLI is single-threaded, so this is race-free here.

## What the sidecar discloses

For a child-statement proof the verifier must anchor the parent chain code, so the sidecar carries it.
A chain code is an extended-key component: combined with the parent public key it forms an xpub, which makes every non-hardened descendant address linkable, and for a `normal-child` proof the chain code together with the revealed child private key reconstructs the parent private key.
Sidecars are created mode 0600. Hand one only to the intended verifier, and prefer hardened statements where the verifier already holds the anchor independently.

## Soundness is the verifier's to demand

A sidecar travels with a relayed proof, so the response count it states is not evidence.
`verify` and `assemble` refuse any proof carrying fewer than `--min-responses` responses, default 438, rather than trusting the count the sidecar asserts.
The stream verifier also rejects a proof with unread trailing responses, so a 438-response proof cannot be passed off as a weaker one.

## File creation

Proof files, sidecars and the `--output-secret-to` file are created with `O_CREAT | O_EXCL` and mode 0600 set at open time.
`O_EXCL` refuses to overwrite an existing file and refuses to follow a symlink planted at the path, so an output cannot be redirected into a shared directory; setting the mode at open time leaves no window in which the file exists world-readable.
