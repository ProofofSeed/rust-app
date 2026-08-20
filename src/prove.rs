// SPDX-License-Identifier: LGPL-3.0-or-later

//! The `prove`, `derive` and `profile` commands.

use std::io::Write as _;
use std::time::Instant;

use clap::Args;
use zeroize::Zeroizing;

use crate::hexutil;
use crate::paths;
use crate::seed::{self, SeedSource};
use crate::sidecar::{EntropyMode, Sidecar, Versions};
use crate::statements::{
    FamilyArg, Resolved, ResolveParams, StatementArg, dummy_circuit, fresh_entropy, resolve,
};
use crate::{DEFAULT_RESPONSES, MAX_RESPONSES};

#[derive(Args)]
pub struct StatementSelector {
    /// The statement to prove
    #[arg(long, value_enum)]
    pub statement: StatementArg,
    /// The derivation family
    #[arg(long, value_enum, default_value = "bip32")]
    pub family: FamilyArg,
    /// Derivation path: the PARENT path for the child statements (e.g. "m/84'/0'"),
    /// the full key path for public-key/ethereum-address
    #[arg(long)]
    pub path: Option<String>,
    /// The child index for the child statements (e.g. "0'" — hardened marked with ' or h)
    #[arg(long)]
    pub index: Option<String>,
    /// BIP-39 PBKDF2 rounds (bip39-seed only)
    #[arg(long, default_value_t = 2048)]
    pub rounds: usize,
}

#[derive(Args)]
pub struct SeedArgs {
    /// Read the mnemonic from this file (default: interactive hidden prompt,
    /// or the file named by PROOFOFSEED_SEED_FILE)
    #[arg(long)]
    pub seed_file: Option<std::path::PathBuf>,
    /// Read the mnemonic from piped stdin (refused on a terminal)
    #[arg(long)]
    pub stdin: bool,
    /// Prompt for a BIP-39 passphrase (default: empty passphrase)
    #[arg(long)]
    pub passphrase: bool,
    /// Skip the BIP-39 wordlist/checksum validation (for non-BIP-39 phrases)
    #[arg(long)]
    pub allow_invalid_mnemonic: bool,
}

#[derive(Args)]
pub struct ProveArgs {
    #[command(flatten)]
    pub selector: StatementSelector,
    /// Total number of responses N (the soundness parameter; the challenge is
    /// computed over all N even when a range is proved)
    #[arg(short = 'n', long, default_value_t = DEFAULT_RESPONSES)]
    pub responses: usize,
    /// Prove only the response range START..END (half-open) of the N-response
    /// sequence; switches to deterministic prover entropy so ranges from
    /// separate runs assemble into one proof
    #[arg(long, value_parser = parse_range)]
    pub range: Option<(u16, u16)>,
    /// The binding (authorisation context, e.g. a transaction hash) as hex
    #[arg(long)]
    pub binding: Option<String>,
    /// Read the binding from a file (raw bytes)
    #[arg(long, conflicts_with = "binding")]
    pub binding_file: Option<std::path::PathBuf>,
    /// Output proof file (sidecar written alongside as FILE.json)
    #[arg(short = 'o', long)]
    pub output: Option<std::path::PathBuf>,
    /// Also write the expected public output to this file, mode 0600 (for
    /// handing to the verifier when the output is secret material)
    #[arg(long)]
    pub output_secret_to: Option<std::path::PathBuf>,
    /// Plan only: print proof size and memory numbers, touch no witness
    #[arg(long)]
    pub dry_run: bool,
    /// With --dry-run: time one single-response proof on this machine and
    /// extrapolate (uses the canonical test-vector witness, not your seed)
    #[arg(long, requires = "dry_run")]
    pub calibrate: bool,
    #[command(flatten)]
    pub seed: SeedArgs,
}

#[derive(Args)]
pub struct DeriveArgs {
    #[command(flatten)]
    pub selector: StatementSelector,
    /// Print the output even when it is secret key material
    #[arg(long)]
    pub reveal: bool,
    #[command(flatten)]
    pub seed: SeedArgs,
}

#[derive(Args)]
pub struct ProfileArgs {
    #[command(flatten)]
    pub selector: StatementSelector,
    /// Total number of responses N for the size projection
    #[arg(short = 'n', long, default_value_t = DEFAULT_RESPONSES)]
    pub responses: usize,
    /// Project the size of this response range only
    #[arg(long, value_parser = parse_range)]
    pub range: Option<(u16, u16)>,
}

fn parse_range(s: &str) -> Result<(u16, u16), String> {
    let (a, b) = s
        .split_once("..")
        .ok_or_else(|| format!("range {s:?} must be START..END (half-open)"))?;
    let start: u16 = a.trim().parse().map_err(|_| format!("invalid range start {a:?}"))?;
    let end: u16 = b.trim().parse().map_err(|_| format!("invalid range end {b:?}"))?;
    if start >= end {
        return Err(format!("empty range {start}..{end}"));
    }
    Ok((start, end))
}

fn check_responses(responses: usize, range: Option<(u16, u16)>) -> Result<(), String> {
    if !(1..=MAX_RESPONSES).contains(&responses) {
        return Err(format!(
            "--responses must be in 1..={MAX_RESPONSES} (the wire format's bound; \
             {DEFAULT_RESPONSES} is the deployment soundness parameter)"
        ));
    }
    if let Some((_, end)) = range
        && end as usize > responses
    {
        return Err(format!("range end {end} exceeds the response count {responses}"));
    }
    Ok(())
}

fn read_binding(
    binding: &Option<String>,
    binding_file: &Option<std::path::PathBuf>,
) -> Result<Vec<u8>, String> {
    let bytes = match (binding, binding_file) {
        (Some(hex), None) => hexutil::decode(hex)?,
        (None, Some(path)) => std::fs::read(path)
            .map_err(|e| format!("cannot read binding file {}: {e}", path.display()))?,
        (None, None) => Vec::new(),
        (Some(_), Some(_)) => unreachable!("clap conflicts_with"),
    };
    if bytes.len() > 255 {
        return Err(format!("binding is {} bytes; the wire format caps it at 255", bytes.len()));
    }
    Ok(bytes)
}

fn parse_selector_paths(
    selector: &StatementSelector,
) -> Result<(Option<Vec<u32>>, Option<u32>), String> {
    let path = selector.path.as_deref().map(paths::parse_path).transpose()?;
    let index = selector.index.as_deref().map(paths::parse_component).transpose()?;
    Ok((path, index))
}

/// Reads and validates the mnemonic (and optional passphrase) from the chosen
/// channel.
fn read_seed_material(
    args: &SeedArgs,
) -> Result<(Zeroizing<String>, Zeroizing<String>), String> {
    let mnemonic = seed::read_mnemonic(&SeedSource {
        seed_file: args.seed_file.clone(),
        stdin: args.stdin,
    })?;
    if !args.allow_invalid_mnemonic {
        seed::validate_bip39(&mnemonic)
            .map_err(|e| format!("{e} (pass --allow-invalid-mnemonic to proceed anyway)"))?;
    }
    let passphrase = if args.passphrase {
        seed::read_passphrase()?
    } else {
        Zeroizing::new(String::new())
    };
    Ok((mnemonic, passphrase))
}

fn resolve_from(
    selector: &StatementSelector,
    responses: usize,
    binding: Vec<u8>,
    range: Option<(u16, u16)>,
    seed_args: &SeedArgs,
) -> Result<Resolved, String> {
    let (path, index) = parse_selector_paths(selector)?;
    let (mnemonic, passphrase) = read_seed_material(seed_args)?;
    resolve(ResolveParams {
        statement: selector.statement,
        family: selector.family,
        path,
        index,
        num_iters: responses,
        rounds: selector.rounds,
        binding,
        range,
        mnemonic: mnemonic.as_bytes(),
        passphrase: passphrase.as_bytes(),
    })
}

fn human_bytes(n: u64) -> String {
    match n {
        n if n >= 1 << 30 => format!("{:.2} GiB", n as f64 / (1u64 << 30) as f64),
        n if n >= 1 << 20 => format!("{:.2} MiB", n as f64 / (1u64 << 20) as f64),
        n if n >= 1 << 10 => format!("{:.2} KiB", n as f64 / 1024.0),
        n => format!("{n} B"),
    }
}

fn dry_run(args: &ProveArgs) -> Result<(), String> {
    let selector = &args.selector;
    let circuit = dummy_circuit(selector.statement, selector.family, selector.rounds)?;
    let prof = circuit.profile();
    let response = prof.response_size::<[u8; 32], [u8; 32]>() as u64;
    let (start, end) = args.range.map_or((0, args.responses), |(a, b)| (a as usize, b as usize));
    let emitted = (end - start) as u64;
    println!("statement        : {} ({})", selector.statement.name(), selector.family.name());
    println!("responses        : {} total, emitting {start}..{end} ({emitted})", args.responses);
    println!("bytes/response   : {} ({})", response, human_bytes(response));
    println!("proof bytes      : {} ({})", response * emitted, human_bytes(response * emitted));
    println!(
        "full proof @{}  : {}",
        args.responses,
        human_bytes(response * args.responses as u64)
    );
    println!("prover memory    : {} B (per pass)", prof.prover_mem_usage::<usize>().total());
    if args.calibrate {
        let t0 = Instant::now();
        let _ = circuit.gen_stream(1, b"calibration-entropy", b"");
        let per_iter = t0.elapsed();
        // One n=1 proof = one challenge pass + one response pass, which is also
        // exactly the per-response cost of a full n=N proof (N of each).
        let full = per_iter * args.responses as u32;
        println!("calibration      : {per_iter:.2?} per response on this machine");
        println!(
            "est. full proof  : {full:.2?} @{} responses (ranged runs add one challenge pass per \
             response of the full sequence)",
            args.responses
        );
    }
    Ok(())
}

pub fn run(args: ProveArgs) -> Result<(), String> {
    check_responses(args.responses, args.range)?;
    if args.dry_run {
        return dry_run(&args);
    }
    if args.responses < DEFAULT_RESPONSES {
        eprintln!(
            "warning: proving {} responses; a verifier demanding the default {} will reject this \
             proof (they must pass --min-responses {})",
            args.responses, DEFAULT_RESPONSES, args.responses
        );
    }
    let binding = read_binding(&args.binding, &args.binding_file)?;
    let resolved = resolve_from(&args.selector, args.responses, binding, args.range, &args.seed)?;
    let statement = args.selector.statement;
    let output = resolved.circuit.output();
    let entropy = match &resolved.digest {
        Some(digest) => resolved.circuit.entropy_for(digest),
        None => fresh_entropy()?,
    };
    let (start, end) = args.range.map_or((0, args.responses), |(a, b)| (a as usize, b as usize));
    let default_name = match args.range {
        Some((a, b)) => format!("proofofseed-{}-{a}-{b}.pos", statement.name()),
        None => format!("proofofseed-{}.pos", statement.name()),
    };
    let proof_path = args.output.unwrap_or_else(|| default_name.into());
    let file = crate::fsutil::create_new_0600(&proof_path)?;
    let mut writer = std::io::BufWriter::new(file);
    let written = resolved
        .circuit
        .prove_to(args.responses, (start, end), &*entropy, &resolved.request.binding, &mut writer)
        .map_err(|e| format!("proof streaming failed: {e}"))?;
    writer.flush().map_err(|e| format!("proof streaming failed: {e}"))?;
    drop(writer);
    let stream = std::fs::read(&proof_path)
        .map_err(|e| format!("cannot re-read {}: {e}", proof_path.display()))?;
    let sidecar = Sidecar {
        format: crate::sidecar::FORMAT.into(),
        statement: statement.name().into(),
        family: args.selector.family.name().into(),
        num_iters: args.responses,
        rounds: args.selector.rounds,
        path: resolved.request.path.as_deref().map(paths::format_path),
        index: resolved.request.index.map(paths::format_component),
        chain_code: resolved.request.chain_code.map(|cc| hexutil::encode(&cc)),
        binding: hexutil::encode(&resolved.request.binding),
        range: args.range,
        entropy_mode: if args.range.is_some() {
            EntropyMode::Deterministic
        } else {
            EntropyMode::Trng
        },
        output: (!statement.output_is_secret()).then(|| hexutil::encode(&output)),
        output_keccak256: hexutil::keccak_hex(&output),
        stream_bytes: written,
        stream_keccak256: hexutil::keccak_hex(&stream),
        versions: Versions {
            cli: env!("CARGO_PKG_VERSION").into(),
            deterministic_entropy_version:
                proofofseed_circuits::ranged::DETERMINISTIC_ENTROPY_VERSION,
        },
    };
    sidecar.write(&proof_path)?;
    if let Some(out_path) = &args.output_secret_to {
        write_secret(out_path, hexutil::encode(&output).as_bytes())?;
        println!("expected output  : written to {} (mode 0600)", out_path.display());
    }
    println!("proof            : {} ({})", proof_path.display(), human_bytes(written));
    println!("responses        : {start}..{end} of {}", args.responses);
    println!("stream keccak256 : {}", sidecar.stream_keccak256);
    if statement.output_is_secret() {
        println!(
            "expected output  : SECRET (commitment {}); hand it to the verifier out of band",
            sidecar.output_keccak256
        );
    } else {
        println!("expected output  : {}", hexutil::encode(&output));
    }
    Ok(())
}

pub fn run_derive(args: DeriveArgs) -> Result<(), String> {
    let resolved = resolve_from(&args.selector, 1, Vec::new(), None, &args.seed)?;
    let statement = args.selector.statement;
    let output = resolved.circuit.output();
    if statement.output_is_secret() && !args.reveal {
        return Err(format!(
            "the {} output is secret key material; pass --reveal to print it \
             (commitment: {})",
            statement.name(),
            hexutil::keccak_hex(&output)
        ));
    }
    println!("{}", hexutil::encode(&output));
    Ok(())
}

pub fn run_profile(args: ProfileArgs) -> Result<(), String> {
    check_responses(args.responses, args.range)?;
    let selector = &args.selector;
    let circuit = dummy_circuit(selector.statement, selector.family, selector.rounds)?;
    let prof = circuit.profile();
    let response = prof.response_size::<[u8; 32], [u8; 32]>() as u64;
    let emitted = args.range.map_or(args.responses as u64, |(a, b)| (b - a) as u64);
    println!("statement          : {} ({})", selector.statement.name(), selector.family.name());
    println!("bytes/response     : {response} ({})", human_bytes(response));
    println!(
        "proof @{:<4}       : {} ({})",
        args.responses,
        response * args.responses as u64,
        human_bytes(response * args.responses as u64)
    );
    if args.range.is_some() {
        println!("range bytes        : {} ({})", response * emitted, human_bytes(response * emitted));
    }
    println!("prover memory      : {} B", prof.prover_mem_usage::<usize>().total());
    println!("executor memory    : {} B", prof.executor_mem_usage::<usize>().total());
    println!("max refcount       : {:?}", prof.max_refcount());
    Ok(())
}

fn write_secret(path: &std::path::Path, data: &[u8]) -> Result<(), String> {
    let mut file = crate::fsutil::create_new_0600(path)?;
    file.write_all(data)
        .and_then(|_| file.write_all(b"\n"))
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}
