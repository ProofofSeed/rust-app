// SPDX-License-Identifier: LGPL-3.0-or-later

//! The `verify` command: checks a proof file against its sidecar's parameters
//! (each overridable on the command line) and the expected public output. The
//! sidecar is metadata, not authority: the statement's soundness comes from the
//! stream itself under the parameters the verifier chooses to trust, and for
//! secret-output statements the expected output must be supplied out of band
//! (cross-checked against the sidecar's commitment).

use clap::Args;

use crate::hexutil;
use crate::paths;
use crate::sidecar::Sidecar;
use crate::statements::{FamilyArg, StatementArg};

#[derive(Args)]
pub struct VerifyArgs {
    /// The proof file (raw stream; sidecar expected at FILE.json)
    #[arg(long)]
    pub proof: std::path::PathBuf,
    /// The expected public output, hex (required when it is secret material and
    /// therefore absent from the sidecar)
    #[arg(long)]
    pub expected_output: Option<String>,
    /// Read the expected output from a file (hex, as written by
    /// `prove --output-secret-to`)
    #[arg(long, conflicts_with = "expected_output")]
    pub expected_output_file: Option<std::path::PathBuf>,
    /// Override the sidecar's binding (hex)
    #[arg(long)]
    pub binding: Option<String>,
    /// Reject the proof unless it carries at least this many responses — the
    /// soundness the verifier demands, not a number the (relayable) sidecar can
    /// lower. Defaults to the deployment parameter (438, 128-bit post-quantum);
    /// pass a smaller value only if you deliberately accept weaker soundness.
    #[arg(long, default_value_t = crate::DEFAULT_RESPONSES)]
    pub min_responses: usize,
}

pub fn statement_by_name(name: &str) -> Result<StatementArg, String> {
    [
        StatementArg::MasterKey,
        StatementArg::HardenedChild,
        StatementArg::Bip39Seed,
        StatementArg::PublicKey,
        StatementArg::NormalChild,
        StatementArg::EthereumAddress,
    ]
    .into_iter()
    .find(|s| s.name() == name)
    .ok_or_else(|| format!("unknown statement {name:?} in sidecar"))
}

pub fn family_by_name(name: &str) -> Result<FamilyArg, String> {
    match name {
        "bip32-secp256k1" => Ok(FamilyArg::Bip32),
        "slip10-ed25519" => Ok(FamilyArg::Slip10),
        _ => Err(format!("unknown family {name:?} in sidecar")),
    }
}

pub fn run(args: VerifyArgs) -> Result<(), String> {
    let sidecar = Sidecar::read(&args.proof)?;
    let stream = std::fs::read(&args.proof)
        .map_err(|e| format!("cannot read proof {}: {e}", args.proof.display()))?;
    if let Some((start, end)) = sidecar.range {
        let carried = end
            .checked_sub(start)
            .ok_or_else(|| format!("malformed sidecar range {start}..{end}"))?;
        if carried as usize != sidecar.num_iters {
            return Err(format!(
                "this file carries responses {start}..{end} of {} — a range, not a complete \
                 proof; assemble the full range set first (proofofseed assemble)",
                sidecar.num_iters
            ));
        }
    }
    // The soundness parameter is the verifier's to demand, not the sidecar's to
    // assert: a relayer cannot pass off a downgraded proof by lowering num_iters.
    if sidecar.num_iters < args.min_responses {
        return Err(format!(
            "proof carries {} responses; verifier demands at least {} \
             (soundness (2/3)^{} vs the required (2/3)^{}). Pass --min-responses to accept less.",
            sidecar.num_iters, args.min_responses, sidecar.num_iters, args.min_responses
        ));
    }
    let statement = statement_by_name(&sidecar.statement)?;
    let family = family_by_name(&sidecar.family)?;
    let output = expected_output(&args, &sidecar, statement)?;
    let binding = match &args.binding {
        Some(hex) => hexutil::decode(hex)?,
        None => hexutil::decode(&sidecar.binding)?,
    };
    let chain_code = sidecar.chain_code.as_deref().map(hexutil::decode).transpose()?;
    let index = sidecar.index.as_deref().map(paths::parse_component).transpose()?;
    let ok = crate::fsutil::quietly(|| {
        proofofseed_host::verify_with_shape(
            statement.id(),
            &output,
            &stream,
            sidecar.num_iters,
            &binding,
            sidecar.rounds,
            chain_code.as_deref(),
            index,
            family.wire() as u8,
            sidecar.witness_len,
            sidecar.salt_len,
        )
    });
    if ok {
        println!(
            "PASS: {} ({}) verifies with {} responses under the given binding and output",
            sidecar.statement, sidecar.family, sidecar.num_iters
        );
        Ok(())
    } else {
        Err(format!(
            "FAIL: {} proof does not verify under the given parameters",
            sidecar.statement
        ))
    }
}

/// Resolves the expected output from the arguments and/or sidecar, enforcing the
/// secrecy rule and cross-checking the sidecar's commitment when both exist.
pub fn expected_output(
    args: &VerifyArgs,
    sidecar: &Sidecar,
    statement: StatementArg,
) -> Result<Vec<u8>, String> {
    let supplied = match (&args.expected_output, &args.expected_output_file) {
        (Some(hex), None) => Some(hexutil::decode(hex)?),
        (None, Some(path)) => {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            Some(hexutil::decode(text.trim())?)
        }
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("clap conflicts_with"),
    };
    let output = match (supplied, &sidecar.output) {
        (Some(bytes), _) => bytes,
        (None, Some(hex)) => hexutil::decode(hex)?,
        (None, None) => {
            return Err(format!(
                "the {} output is secret material and absent from the sidecar; supply it with \
                 --expected-output or --expected-output-file (commitment: {})",
                statement.name(),
                sidecar.output_keccak256
            ));
        }
    };
    if hexutil::keccak_hex(&output) != sidecar.output_keccak256 {
        return Err(
            "the supplied expected output does not match the sidecar's output commitment".into(),
        );
    }
    Ok(output)
}
