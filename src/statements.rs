// SPDX-License-Identifier: LGPL-3.0-or-later

//! Thin CLI adapter over the shared statement plumbing in
//! `proofofseed_host::statement`: clap value-enums for the statement and family
//! arguments, converting to the shared `Statement`/`Family` types. The resolve
//! logic, circuit dispatch, witness assembly and entropy live in the library so
//! the CLI and the Python package cannot drift.

use clap::ValueEnum;
use proofofseed_circuits::request::Family;
use proofofseed_host::statement::Statement;

pub use proofofseed_host::statement::{
    AnyCircuit, Resolved, ResolveParams, dummy_circuit, fresh_entropy, resolve,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum)]
pub enum StatementArg {
    /// Seed -> BIP-32 master key + chain code (output is secret material)
    MasterKey,
    /// Parent key -> hardened child key + chain code (output is secret material)
    HardenedChild,
    /// Mnemonic -> BIP-39 seed via PBKDF2 (output is secret material)
    Bip39Seed,
    /// Private key -> secp256k1 public key (public output)
    PublicKey,
    /// Parent key -> normal (non-hardened) child (output is secret material)
    NormalChild,
    /// Private key -> Ethereum address (public output)
    EthereumAddress,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum)]
pub enum FamilyArg {
    /// BIP-32 over secp256k1 (Bitcoin, Ethereum, the BIP-44 ecosystem)
    Bip32,
    /// SLIP-10 over ed25519 (Solana, TON, NEAR, ...) — recovery statements only
    Slip10,
}

impl StatementArg {
    pub fn to_statement(self) -> Statement {
        match self {
            StatementArg::MasterKey => Statement::MasterKey,
            StatementArg::HardenedChild => Statement::HardenedChild,
            StatementArg::Bip39Seed => Statement::Bip39Seed,
            StatementArg::PublicKey => Statement::PublicKey,
            StatementArg::NormalChild => Statement::NormalChild,
            StatementArg::EthereumAddress => Statement::EthereumAddress,
        }
    }

    pub fn id(self) -> u8 {
        self.to_statement().id()
    }

    pub fn name(self) -> &'static str {
        self.to_statement().name()
    }

    pub fn output_is_secret(self) -> bool {
        self.to_statement().output_is_secret()
    }
}

impl FamilyArg {
    pub fn wire(self) -> Family {
        match self {
            FamilyArg::Bip32 => Family::Bip32Secp256k1,
            FamilyArg::Slip10 => Family::Slip10Ed25519,
        }
    }

    pub fn name(self) -> &'static str {
        proofofseed_host::statement::family_name(self.wire())
    }
}
