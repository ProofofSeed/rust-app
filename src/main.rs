// SPDX-License-Identifier: LGPL-3.0-or-later

//! A standalone proof-of-seed prover and verifier for software wallets.

mod assemble;
mod fsutil;
mod hexutil;
mod paths;
mod prove;
mod seed;
mod sidecar;
mod statements;
mod verify;
mod wordlist;

use clap::{Parser, Subcommand};

/// The default soundness parameter: 438 responses, a soundness error of
/// (2/3)^438 <= 2^-256.
pub const DEFAULT_RESPONSES: usize = 438;

/// The wire format's response-count bound.
pub const MAX_RESPONSES: usize = 512;

#[derive(Parser)]
#[command(
    name = "proofofseed",
    version,
    about = "Create and verify zero-knowledge proofs of seed for software wallets",
    long_about = "Create and verify zero-knowledge proofs of seed: ZKBoo proofs that a \
BIP-39/BIP-32/SLIP-10-derived key was derived from the seed you hold, bound to a \
verifier-chosen context. Proofs stream to disk at constant memory; ranges of one \
proof can be produced by separate runs or devices and assembled afterwards."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a proof (streams the raw proof bytes to a file, plus a JSON sidecar)
    Prove(prove::ProveArgs),
    /// Verify a proof file against its sidecar and/or explicit parameters
    Verify(verify::VerifyArgs),
    /// Derive and print a statement's public output (for verifier-side pinning)
    Derive(prove::DeriveArgs),
    /// Assemble range-proof files into one complete proof, checking coverage
    Assemble(assemble::AssembleArgs),
    /// Print proof-size and memory numbers for a statement (no witness needed)
    Profile(prove::ProfileArgs),
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Prove(args) => prove::run(args),
        Command::Verify(args) => verify::run(args),
        Command::Derive(args) => prove::run_derive(args),
        Command::Assemble(args) => assemble::run(args),
        Command::Profile(args) => prove::run_profile(args),
    };
    match result {
        Ok(()) => {}
        Err(message) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
    }
}
