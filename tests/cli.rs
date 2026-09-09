// SPDX-License-Identifier: LGPL-3.0-or-later

//! Acceptance tests for the `proofofseed` command-line tool.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use proofofseed_circuits::ranged::{
    WitnessMaterial, deterministic_seed_entropy, ranged_request_digest,
};
use proofofseed_circuits::request::{Family, ProofRequest};
use proofofseed_circuits::{HARDENED_CHILD, HardenedChildCircuit};
use proofofseed_host::derive;
use proofofseed_host::harness::gen_stream_range;
use zkboo_profiling::profile;

const H: u32 = 0x8000_0000;
const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_proofofseed"))
}

fn run(args: &[&str]) -> Output {
    bin().args(args).output().expect("binary runs")
}

fn seed_file(dir: &Path) -> PathBuf {
    let path = dir.join("mnemonic.txt");
    std::fs::write(&path, MNEMONIC).expect("write mnemonic");
    path
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn assert_ok(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} failed:\nstdout: {}\nstderr: {}",
        stdout(out),
        stderr(out)
    );
}

fn assert_err(out: &Output, needle: &str, what: &str) {
    assert!(!out.status.success(), "{what} unexpectedly succeeded: {}", stdout(out));
    assert!(
        stderr(out).contains(needle),
        "{what}: stderr does not name the refuser {needle:?}:\n{}",
        stderr(out)
    );
}

#[test]
fn ranged_proofs_assemble_verify_and_refuse_the_negatives() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dir = dir.path();
    let seed = seed_file(dir);
    let seed = seed.to_str().unwrap();
    let base: Vec<String> = [
        "prove", "--statement", "hardened-child", "--path", "m/84'/0'", "--index", "0'",
        "--binding", "aabbcc", "-n", "6", "--seed-file", seed,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let part = |range: &str, out: &str| {
        let mut args = base.clone();
        args.extend(["--range".into(), range.into(), "-o".into(), dir.join(out).display().to_string()]);
        args
    };
    assert_ok(&bin().args(part("0..3", "a.pos")).output().unwrap(), "prove 0..3");
    assert_ok(&bin().args(part("3..6", "b.pos")).output().unwrap(), "prove 3..6");
    let out_hex = dir.join("output.hex");
    let derived = run(&[
        "derive", "--statement", "hardened-child", "--path", "m/84'/0'", "--index", "0'",
        "--seed-file", seed, "--reveal",
    ]);
    assert_ok(&derived, "derive --reveal");
    std::fs::write(&out_hex, stdout(&derived)).unwrap();
    let out_hex = out_hex.to_str().unwrap();
    let full = dir.join("full.pos");
    let assembled = run(&[
        "assemble", dir.join("a.pos").to_str().unwrap(), dir.join("b.pos").to_str().unwrap(),
        "-o", full.to_str().unwrap(), "--expected-output-file", out_hex, "--min-responses", "6",
    ]);
    assert_ok(&assembled, "assemble");
    let verified = run(&[
        "verify", "--proof", full.to_str().unwrap(), "--expected-output-file", out_hex,
        "--min-responses", "6",
    ]);
    assert_ok(&verified, "verify assembled");
    // Negatives, each with the passing twin above: a lone range is not a proof; a
    // wrong binding refuses; a gap refuses assembly.
    let lone = run(&["verify", "--proof", dir.join("a.pos").to_str().unwrap(), "--expected-output-file", out_hex]);
    assert_err(&lone, "a range, not a complete proof", "lone range");
    let wrong_binding = run(&[
        "verify", "--proof", full.to_str().unwrap(), "--expected-output-file", out_hex,
        "--binding", "deadbeef", "--min-responses", "6",
    ]);
    assert_err(&wrong_binding, "does not verify", "wrong binding");
    // The soundness floor: the same complete proof is refused when the verifier
    // demands more responses than it carries (a relayer cannot downgrade it).
    let downgraded = run(&[
        "verify", "--proof", full.to_str().unwrap(), "--expected-output-file", out_hex,
    ]);
    assert_err(&downgraded, "demands at least 438", "soundness floor");
    assert_ok(&bin().args(part("4..6", "c.pos")).output().unwrap(), "prove 4..6");
    let gap = run(&[
        "assemble", dir.join("a.pos").to_str().unwrap(), dir.join("c.pos").to_str().unwrap(),
        "-o", dir.join("gap.pos").to_str().unwrap(), "--expected-output-file", out_hex,
    ]);
    assert_err(&gap, "gap in coverage", "assembly with a gap");
    // A range proved under a different binding must not join the set.
    let mut foreign = base.clone();
    for a in foreign.iter_mut() {
        if a == "aabbcc" {
            *a = "deadbeef".into();
        }
    }
    foreign.extend(["--range".into(), "3..6".into(), "-o".into(), dir.join("f.pos").display().to_string()]);
    assert_ok(&bin().args(&foreign).output().unwrap(), "prove foreign binding");
    let mixed = run(&[
        "assemble", dir.join("a.pos").to_str().unwrap(), dir.join("f.pos").to_str().unwrap(),
        "-o", dir.join("mixed.pos").to_str().unwrap(), "--expected-output-file", out_hex,
    ]);
    assert_err(&mixed, "not ranges of the same proof", "assembly across bindings");
}

#[test]
fn cli_ranged_stream_is_byte_identical_to_the_library() {
    // The acceptance's interop pin: the CLI's deterministic ranged stream must
    // equal the shared library's for the identical request — the same equality a
    // Ledger holding this seed must meet.
    let dir = tempfile::tempdir().expect("tempdir");
    let dir = dir.path();
    let seed_path = seed_file(dir);
    let proof = dir.join("seg.pos");
    let out = run(&[
        "prove", "--statement", "hardened-child", "--path", "m/84'/0'", "--index", "0'",
        "--binding", "aabbcc", "-n", "6", "--range", "1..3",
        "--seed-file", seed_path.to_str().unwrap(), "-o", proof.to_str().unwrap(),
    ]);
    assert_ok(&out, "prove 1..3");
    let cli_bytes = std::fs::read(&proof).expect("proof file");
    // Reconstruct the identical request through the shared crates.
    let seed = derive::bip39_seed(MNEMONIC.as_bytes(), b"");
    let parent = derive::bip32_node(&seed, &[H | 84, H]);
    let request = ProofRequest {
        num_iters: 6,
        rounds: 2048,
        family: Family::Bip32Secp256k1,
        path: Some(vec![H | 84, H]),
        index: Some(H),
        chain_code: Some(parent.chain_code),
        binding: vec![0xaa, 0xbb, 0xcc],
        range: Some((1, 3)),
    };
    let digest = ranged_request_digest(
        HARDENED_CHILD,
        &request,
        &[H | 84, H],
        WitnessMaterial::Child {
            parent_priv: &*parent.private_key,
            chain_code: &parent.chain_code,
            index: H,
        },
    );
    let circuit = HardenedChildCircuit {
        chain_code: parent.chain_code.to_vec(),
        parent_priv: parent.private_key.to_vec(),
        index: H,
    };
    let entropy = deterministic_seed_entropy(&circuit, &digest);
    let library_bytes = gen_stream_range(&circuit, 6, (1, 3), &*entropy, &request.binding);
    assert_eq!(cli_bytes, library_bytes, "CLI stream vs library stream");
}

#[test]
fn dry_run_matches_the_profiler_defaults_to_438_and_reads_no_seed() {
    // No --seed-file, no stdin, no PROOFOFSEED_SEED_FILE, stdin left as the test
    // harness's (non-piped): a dry run that tried to read a seed would either
    // prompt (blocking/failing) or error — success proves it touched no witness.
    let out = bin()
        .args(["prove", "--statement", "hardened-child", "--dry-run"])
        .env_remove("PROOFOFSEED_SEED_FILE")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("runs");
    assert_ok(&out, "dry run without any seed source");
    let text = stdout(&out);
    let expected = profile(&proofofseed_circuits::hardened_child_circuit())
        .response_size::<[u8; 32], [u8; 32]>();
    assert!(
        text.contains(&format!("bytes/response   : {expected} ")),
        "dry-run response size must match zkboo-profiling:\n{text}"
    );
    assert!(text.contains("438 total"), "the default response count must be 438:\n{text}");
}

#[test]
fn failure_paths_never_echo_the_mnemonic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dir = dir.path();
    let seed = seed_file(dir);
    // Wrong index hardness: fails after the seed was read; the mnemonic must
    // appear in no output stream.
    let out = run(&[
        "prove", "--statement", "hardened-child", "--path", "m/84'/0'", "--index", "0",
        "-n", "2", "--seed-file", seed.to_str().unwrap(), "-o",
        dir.join("x.pos").to_str().unwrap(),
    ]);
    assert_err(&out, "hardened", "wrong index hardness");
    for stream in [stdout(&out), stderr(&out)] {
        assert!(!stream.contains("abandon"), "mnemonic leaked into output:\n{stream}");
    }
    // The checksum-validation failure path must not echo the offending word
    // either (a real word of the user's phrase). Use a real word so a naive
    // implementation would be tempted to print it.
    let typo = dir.join("typo.txt");
    std::fs::write(&typo, MNEMONIC.replace("about", "zzzzz")).unwrap();
    let out = run(&[
        "derive", "--statement", "ethereum-address", "--path", "m/44'/60'/0'/0/0",
        "--seed-file", typo.to_str().unwrap(),
    ]);
    assert_err(&out, "not a BIP-39 English word", "invalid word");
    for stream in [stdout(&out), stderr(&out)] {
        assert!(!stream.contains("zzzzz"), "an invalid word leaked into output:\n{stream}");
    }
}

#[test]
fn mnemonic_checksum_is_validated_with_an_override() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dir = dir.path();
    let bad = dir.join("bad.txt");
    // Last word swapped: valid words, broken checksum.
    std::fs::write(&bad, MNEMONIC.replace(" about", " abandon")).unwrap();
    let refused = run(&[
        "derive", "--statement", "ethereum-address", "--path", "m/44'/60'/0'/0/0",
        "--seed-file", bad.to_str().unwrap(),
    ]);
    assert_err(&refused, "checksum", "broken checksum");
    let allowed = run(&[
        "derive", "--statement", "ethereum-address", "--path", "m/44'/60'/0'/0/0",
        "--seed-file", bad.to_str().unwrap(), "--allow-invalid-mnemonic",
    ]);
    assert_ok(&allowed, "checksum override");
    let not_a_word = dir.join("notword.txt");
    std::fs::write(&not_a_word, "zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz").unwrap();
    let refused = run(&[
        "derive", "--statement", "ethereum-address", "--path", "m/44'/60'/0'/0/0",
        "--seed-file", not_a_word.to_str().unwrap(),
    ]);
    assert_err(&refused, "not a BIP-39 English word", "unknown word");
}

#[test]
fn derive_guards_secret_outputs_and_prints_public_ones() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dir = dir.path();
    let seed = seed_file(dir);
    let seed = seed.to_str().unwrap();
    let guarded = run(&[
        "derive", "--statement", "master-key", "--seed-file", seed,
    ]);
    assert_err(&guarded, "--reveal", "secret output without --reveal");
    let revealed = run(&[
        "derive", "--statement", "master-key", "--seed-file", seed, "--reveal",
    ]);
    assert_ok(&revealed, "secret output with --reveal");
    let public = run(&[
        "derive", "--statement", "ethereum-address", "--path", "m/44'/60'/0'/0/0",
        "--seed-file", seed,
    ]);
    assert_ok(&public, "public output without --reveal");
    // The serialised output embeds the test mnemonic's well-known first Ethereum
    // address, 0x9858EfFD232B4033E47d90003D41EC34EcaEda94.
    assert!(
        stdout(&public).contains("9858effd232b4033e47d90003d41ec34ecaeda94"),
        "derive must produce the published address: {}",
        stdout(&public)
    );
}

#[test]
fn stdin_channel_accepts_a_piped_mnemonic() {
    use std::io::Write as _;
    use std::process::Stdio;
    let mut child = bin()
        .args([
            "derive", "--statement", "ethereum-address", "--path", "m/44'/60'/0'/0/0", "--stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child.stdin.as_mut().unwrap().write_all(MNEMONIC.as_bytes()).unwrap();
    let out = child.wait_with_output().expect("wait");
    assert_ok(&out, "stdin derive");
}

#[test]
fn a_truncated_proof_is_refused_cleanly_without_a_panic_trace() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dir = dir.path();
    let seed = seed_file(dir);
    let seed = seed.to_str().unwrap();
    let proof = dir.join("p.pos");
    let out_hex = dir.join("o.hex");
    let derived = run(&[
        "derive", "--statement", "ethereum-address", "--path", "m/44'/60'/0'/0/0",
        "--seed-file", seed,
    ]);
    std::fs::write(&out_hex, stdout(&derived)).unwrap();
    assert_ok(&bin().args([
        "prove", "--statement", "ethereum-address", "--path", "m/44'/60'/0'/0/0",
        "-n", "2", "--seed-file", seed, "-o", proof.to_str().unwrap(),
    ]).output().unwrap(), "prove for truncation");
    // Lop a byte off the middle of a response, leaving the sidecar untouched.
    let bytes = std::fs::read(&proof).unwrap();
    std::fs::remove_file(&proof).unwrap();
    std::fs::write(&proof, &bytes[..bytes.len() - 1]).unwrap();
    let out = run(&[
        "verify", "--proof", proof.to_str().unwrap(), "--expected-output-file",
        out_hex.to_str().unwrap(), "--min-responses", "2",
    ]);
    assert_err(&out, "does not verify", "truncated proof");
    assert!(!stderr(&out).contains("panicked"), "no panic trace leaks:\n{}", stderr(&out));
    assert!(!stderr(&out).contains(".rs:"), "no source path leaks:\n{}", stderr(&out));
}

#[test]
fn key_statements_reject_a_stray_index() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dir = dir.path();
    let seed = seed_file(dir);
    let out = run(&[
        "derive", "--statement", "ethereum-address", "--path", "m/44'/60'/0'/0/0",
        "--index", "0'", "--seed-file", seed.to_str().unwrap(),
    ]);
    assert_err(&out, "no index", "stray index on a key statement");
}

#[test]
fn trng_full_proof_round_trips_and_differs_between_runs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dir = dir.path();
    let seed = seed_file(dir);
    let seed = seed.to_str().unwrap();
    let prove = |name: &str| {
        let out = run(&[
            "prove", "--statement", "ethereum-address", "--path", "m/44'/60'/0'/0/0",
            "--binding", "0011", "-n", "1", "--seed-file", seed, "-o",
            dir.join(name).to_str().unwrap(),
        ]);
        assert_ok(&out, "TRNG prove");
    };
    prove("t1.pos");
    prove("t2.pos");
    let verified = run(&[
        "verify", "--proof", dir.join("t1.pos").to_str().unwrap(), "--min-responses", "1",
    ]);
    assert_ok(&verified, "verify TRNG proof from its sidecar (public output)");
    let a = std::fs::read(dir.join("t1.pos")).unwrap();
    let b = std::fs::read(dir.join("t2.pos")).unwrap();
    assert_ne!(a, b, "two TRNG runs must not share prover entropy");
}
