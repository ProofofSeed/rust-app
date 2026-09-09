// SPDX-License-Identifier: LGPL-3.0-or-later

//! The `assemble` command.

use std::io::Write as _;

use clap::Args;

use crate::hexutil;
use crate::sidecar::{EntropyMode, Sidecar};
use crate::verify::{VerifyArgs, expected_output};

#[derive(Args)]
pub struct AssembleArgs {
    /// Range-proof files, or a single directory to scan for *.pos files
    #[arg(required = true)]
    pub inputs: Vec<std::path::PathBuf>,
    /// The assembled output proof file
    #[arg(short = 'o', long)]
    pub output: std::path::PathBuf,
    /// The expected public output, hex (required when it is secret material)
    #[arg(long)]
    pub expected_output: Option<String>,
    /// Read the expected output from a file (hex)
    #[arg(long, conflicts_with = "expected_output")]
    pub expected_output_file: Option<std::path::PathBuf>,
    /// Reject unless the assembled proof carries at least this many responses
    #[arg(long, default_value_t = crate::DEFAULT_RESPONSES)]
    pub min_responses: usize,
}

fn collect_inputs(inputs: &[std::path::PathBuf]) -> Result<Vec<std::path::PathBuf>, String> {
    if inputs.len() == 1 && inputs[0].is_dir() {
        let dir = &inputs[0];
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .map_err(|e| format!("cannot read directory {}: {e}", dir.display()))?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|ext| ext == "pos"))
            .collect();
        files.sort();
        if files.is_empty() {
            return Err(format!("no .pos files in {}", dir.display()));
        }
        Ok(files)
    } else {
        Ok(inputs.to_vec())
    }
}

pub fn run(args: AssembleArgs) -> Result<(), String> {
    let files = collect_inputs(&args.inputs)?;
    let mut parts: Vec<(std::path::PathBuf, Sidecar)> = Vec::with_capacity(files.len());
    for file in files {
        let sidecar = Sidecar::read(&file)?;
        if sidecar.entropy_mode != EntropyMode::Deterministic {
            return Err(format!(
                "{}: not a ranged (deterministic-entropy) proof — TRNG proofs cannot be assembled",
                file.display()
            ));
        }
        if sidecar.range.is_none() {
            return Err(format!("{}: sidecar carries no range", file.display()));
        }
        parts.push((file, sidecar));
    }
    let first_path = parts[0].0.clone();
    let reference = parts[0].1.clone();
    let key = reference.assembly_key();
    for (file, sidecar) in &parts[1..] {
        if sidecar.assembly_key() != key {
            return Err(format!(
                "{} and {} are not ranges of the same proof (request, output, or versions differ)",
                first_path.display(),
                file.display()
            ));
        }
    }
    parts.sort_by_key(|(_, s)| s.range.expect("checked present").0);
    // The ranges must exactly partition [0, num_iters).
    let mut expected_start: u16 = 0;
    for (file, sidecar) in &parts {
        let (start, end) = sidecar.range.expect("checked present");
        if start != expected_start {
            return Err(if start > expected_start {
                format!(
                    "gap in coverage: responses {expected_start}..{start} are missing \
                     (next file {})",
                    file.display()
                )
            } else {
                format!(
                    "overlapping coverage at response {start} (file {})",
                    file.display()
                )
            });
        }
        expected_start = end;
    }
    let total = reference.num_iters;
    if expected_start as usize != total {
        return Err(format!(
            "coverage ends at response {expected_start} of {total}: the tail is missing"
        ));
    }
    if total < args.min_responses {
        return Err(format!(
            "assembled proof would carry {total} responses; demanded at least {} \
             (pass --min-responses to accept less)",
            args.min_responses
        ));
    }
    // Concatenate, checking each file against its recorded digest.
    let mut assembled: Vec<u8> = Vec::new();
    for (file, sidecar) in &parts {
        let bytes =
            std::fs::read(file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
        if bytes.len() as u64 != sidecar.stream_bytes
            || hexutil::keccak_hex(&bytes) != sidecar.stream_keccak256
        {
            return Err(format!(
                "{} does not match its sidecar's stream digest (corrupted or replaced?)",
                file.display()
            ));
        }
        assembled.extend_from_slice(&bytes);
    }
    // Verify the assembled proof before writing anything.
    let reference = &reference;
    let statement = crate::verify::statement_by_name(&reference.statement)?;
    let probe = VerifyArgs {
        proof: args.output.clone(),
        expected_output: args.expected_output.clone(),
        expected_output_file: args.expected_output_file.clone(),
        binding: None,
        min_responses: args.min_responses,
    };
    let output = expected_output(&probe, reference, statement)?;
    let binding = hexutil::decode(&reference.binding)?;
    let chain_code = reference.chain_code.as_deref().map(hexutil::decode).transpose()?;
    let index = reference.index.as_deref().map(crate::paths::parse_component).transpose()?;
    let family = crate::verify::family_by_name(&reference.family)?;
    let ok = crate::fsutil::quietly(|| {
        proofofseed_host::verify(
            statement.id(),
            &output,
            &assembled,
            total,
            &binding,
            reference.rounds,
            chain_code.as_deref(),
            index,
            family.wire() as u8,
        )
    });
    if !ok {
        return Err("the assembled proof does not verify — nothing written".into());
    }
    let mut file = crate::fsutil::create_new_0600(&args.output)?;
    file.write_all(&assembled)
        .map_err(|e| format!("cannot write {}: {e}", args.output.display()))?;
    let sidecar = Sidecar {
        range: None,
        entropy_mode: EntropyMode::Deterministic,
        stream_bytes: assembled.len() as u64,
        stream_keccak256: hexutil::keccak_hex(&assembled),
        ..reference.clone()
    };
    sidecar.write(&args.output)?;
    println!(
        "PASS: assembled {} ranges into {} ({} responses, {} bytes) — verified",
        parts.len(),
        args.output.display(),
        total,
        assembled.len()
    );
    Ok(())
}
