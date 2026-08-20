// SPDX-License-Identifier: LGPL-3.0-or-later

//! Statement plumbing: mapping the CLI's statement/family arguments onto the
//! shared circuits, requests, witness material, and entropy — mirroring exactly
//! what the device app does for the same request, so a device and this CLI
//! holding the same seed produce byte-identical ranged proofs.

use clap::ValueEnum;
use proofofseed_circuits::ranged::{
    WitnessMaterial, deterministic_seed_entropy, ranged_request_digest,
};
use proofofseed_circuits::request::{Family, ProofRequest};
use proofofseed_circuits::{
    AddressCircuit, BIP39_SEED, ETH_ADDRESS, HARDENED_CHILD, HardenedChildCircuit, MASTER_KEY,
    MasterKeyCircuit, NORMAL_CHILD, NormalChildCircuit, PUBLIC_KEY, PubKeyCircuit, SeedCircuit,
    Slip10ChildCircuit, Slip10MasterCircuit, bip39_seed_circuit, ethereum_address_circuit,
    hardened_child_circuit, master_key_circuit, normal_child_circuit, public_key_circuit,
    slip10_child_circuit, slip10_master_circuit,
};
use proofofseed_host::{derive, harness};
use zeroize::Zeroizing;
use zkboo_profiling::{ProfilingData, profile};

use crate::paths::HARDENED;

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
    pub fn id(self) -> u8 {
        match self {
            StatementArg::MasterKey => MASTER_KEY,
            StatementArg::HardenedChild => HARDENED_CHILD,
            StatementArg::Bip39Seed => BIP39_SEED,
            StatementArg::PublicKey => PUBLIC_KEY,
            StatementArg::NormalChild => NORMAL_CHILD,
            StatementArg::EthereumAddress => ETH_ADDRESS,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            StatementArg::MasterKey => "master-key",
            StatementArg::HardenedChild => "hardened-child",
            StatementArg::Bip39Seed => "bip39-seed",
            StatementArg::PublicKey => "public-key",
            StatementArg::NormalChild => "normal-child",
            StatementArg::EthereumAddress => "ethereum-address",
        }
    }

    /// Whether the statement's public output is itself secret key material (the
    /// sidecar then stores only a commitment to it).
    pub fn output_is_secret(self) -> bool {
        !matches!(self, StatementArg::PublicKey | StatementArg::EthereumAddress)
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
        match self {
            FamilyArg::Bip32 => "bip32-secp256k1",
            FamilyArg::Slip10 => "slip10-ed25519",
        }
    }
}

pub fn check_family(statement: StatementArg, family: FamilyArg) -> Result<(), String> {
    if family == FamilyArg::Slip10
        && !matches!(statement, StatementArg::MasterKey | StatementArg::HardenedChild)
    {
        return Err(format!(
            "family slip10 carries only the recovery statements (master-key, hardened-child), \
             not {}",
            statement.name()
        ));
    }
    Ok(())
}

/// A statement circuit with its real witness inside, dispatchable without
/// generics at the call sites.
pub enum AnyCircuit {
    Master(MasterKeyCircuit),
    Seed(SeedCircuit),
    HardenedChild(HardenedChildCircuit),
    NormalChild(NormalChildCircuit),
    PubKey(PubKeyCircuit),
    Address(AddressCircuit),
    Slip10Master(Slip10MasterCircuit),
    Slip10Child(Slip10ChildCircuit),
}

macro_rules! with_circuit {
    ($self:expr, $c:ident => $body:expr) => {
        match $self {
            AnyCircuit::Master($c) => $body,
            AnyCircuit::Seed($c) => $body,
            AnyCircuit::HardenedChild($c) => $body,
            AnyCircuit::NormalChild($c) => $body,
            AnyCircuit::PubKey($c) => $body,
            AnyCircuit::Address($c) => $body,
            AnyCircuit::Slip10Master($c) => $body,
            AnyCircuit::Slip10Child($c) => $body,
        }
    };
}

impl AnyCircuit {
    pub fn output(&self) -> Vec<u8> {
        with_circuit!(self, c => harness::output_of(c))
    }

    pub fn profile(&self) -> ProfilingData {
        with_circuit!(self, c => profile(c))
    }

    pub fn entropy_for(&self, digest: &Zeroizing<[u8; 32]>) -> Zeroizing<[u8; 32]> {
        with_circuit!(self, c => deterministic_seed_entropy(c, digest))
    }

    pub fn prove_to<W: std::io::Write>(
        &self,
        n: usize,
        range: (usize, usize),
        seed_entropy: &[u8],
        binding: &[u8],
        writer: W,
    ) -> std::io::Result<u64> {
        with_circuit!(self, c => harness::gen_stream_range_to(c, n, range, seed_entropy, binding, writer))
    }

    pub fn gen_stream(&self, n: usize, seed_entropy: &[u8], binding: &[u8]) -> Vec<u8> {
        with_circuit!(self, c => harness::gen_stream(c, n, seed_entropy, binding))
    }
}

/// The dummy-witness circuit for a statement (the canonical test-vector
/// constructors): sizes and memory are data-oblivious, so `profile` and
/// `--dry-run` never need a witness.
pub fn dummy_circuit(
    statement: StatementArg,
    family: FamilyArg,
    rounds: usize,
) -> Result<AnyCircuit, String> {
    check_family(statement, family)?;
    Ok(match (family, statement) {
        (FamilyArg::Bip32, StatementArg::MasterKey) => AnyCircuit::Master(master_key_circuit()),
        (FamilyArg::Slip10, StatementArg::MasterKey) => {
            AnyCircuit::Slip10Master(slip10_master_circuit())
        }
        (FamilyArg::Bip32, StatementArg::Bip39Seed) => {
            AnyCircuit::Seed(bip39_seed_circuit(rounds))
        }
        (FamilyArg::Bip32, StatementArg::HardenedChild) => {
            AnyCircuit::HardenedChild(hardened_child_circuit())
        }
        (FamilyArg::Slip10, StatementArg::HardenedChild) => {
            AnyCircuit::Slip10Child(slip10_child_circuit())
        }
        (FamilyArg::Bip32, StatementArg::NormalChild) => {
            AnyCircuit::NormalChild(normal_child_circuit())
        }
        (FamilyArg::Bip32, StatementArg::PublicKey) => AnyCircuit::PubKey(public_key_circuit()),
        (FamilyArg::Bip32, StatementArg::EthereumAddress) => {
            AnyCircuit::Address(ethereum_address_circuit())
        }
        _ => unreachable!("family checked above"),
    })
}

/// Everything a prove/derive run needs, resolved from the seed: the circuit with
/// its witness, the device-compatible request, and the witness-derived data the
/// deterministic entropy absorbs.
pub struct Resolved {
    pub circuit: AnyCircuit,
    pub request: ProofRequest,
    pub digest: Option<Zeroizing<[u8; 32]>>,
}

pub struct ResolveParams<'a> {
    pub statement: StatementArg,
    pub family: FamilyArg,
    pub path: Option<Vec<u32>>,
    pub index: Option<u32>,
    pub num_iters: usize,
    pub rounds: usize,
    pub binding: Vec<u8>,
    pub range: Option<(u16, u16)>,
    pub mnemonic: &'a [u8],
    pub passphrase: &'a [u8],
}

/// Derives the witness from the mnemonic and builds the circuit + request,
/// mirroring the device's resolution rules (chain-code anchoring included: the
/// request carries the derived parent chain code, so the verifier checks it).
pub fn resolve(p: ResolveParams<'_>) -> Result<Resolved, String> {
    check_family(p.statement, p.family)?;
    let mut salt = Zeroizing::new(b"mnemonic".to_vec());
    salt.extend_from_slice(p.passphrase);
    let seed = derive::bip39_seed(p.mnemonic, p.passphrase);
    let statement = p.statement;
    let needs_path = !matches!(statement, StatementArg::MasterKey | StatementArg::Bip39Seed);
    if !needs_path && (p.path.is_some() || p.index.is_some()) {
        return Err(format!("{} takes no --path/--index", statement.name()));
    }
    let mut request = ProofRequest {
        num_iters: p.num_iters,
        rounds: p.rounds,
        family: p.family.wire(),
        path: p.path.clone(),
        index: p.index,
        chain_code: None,
        binding: p.binding,
        range: p.range,
    };
    let (circuit, resolved_path, material_owner): (AnyCircuit, Vec<u32>, MaterialOwner) =
        match statement {
            StatementArg::MasterKey => {
                let circuit = match p.family {
                    FamilyArg::Bip32 => AnyCircuit::Master(MasterKeyCircuit { seed: seed.to_vec() }),
                    FamilyArg::Slip10 => {
                        AnyCircuit::Slip10Master(Slip10MasterCircuit { seed: seed.to_vec() })
                    }
                };
                (circuit, Vec::new(), MaterialOwner::Seed { seed: seed.to_vec().into() })
            }
            StatementArg::Bip39Seed => {
                let circuit = AnyCircuit::Seed(SeedCircuit {
                    mnemonic: p.mnemonic.to_vec(),
                    salt: salt.to_vec(),
                    rounds: p.rounds,
                });
                (
                    circuit,
                    Vec::new(),
                    MaterialOwner::Mnemonic {
                        mnemonic: Zeroizing::new(p.mnemonic.to_vec()),
                        salt: salt.clone(),
                    },
                )
            }
            StatementArg::HardenedChild | StatementArg::NormalChild => {
                let parent_path = p.path.clone().ok_or("--path (the PARENT path) is required")?;
                let index = p.index.ok_or("--index (the child index) is required")?;
                let hardened_stmt = statement == StatementArg::HardenedChild;
                if (index & HARDENED != 0) != hardened_stmt {
                    return Err(format!(
                        "{} requires a {} child index",
                        statement.name(),
                        if hardened_stmt { "hardened" } else { "non-hardened" }
                    ));
                }
                let node = match p.family {
                    FamilyArg::Bip32 => derive::bip32_node(&seed, &parent_path),
                    FamilyArg::Slip10 => derive::slip10_node(&seed, &parent_path)
                        .ok_or("slip10 paths must be fully hardened")?,
                };
                request.chain_code = Some(node.chain_code);
                let circuit = match (p.family, hardened_stmt) {
                    (FamilyArg::Bip32, true) => AnyCircuit::HardenedChild(HardenedChildCircuit {
                        chain_code: node.chain_code.to_vec(),
                        parent_priv: node.private_key.to_vec(),
                        index,
                    }),
                    (FamilyArg::Bip32, false) => AnyCircuit::NormalChild(NormalChildCircuit {
                        chain_code: node.chain_code.to_vec(),
                        parent_priv: node.private_key.to_vec(),
                        index,
                    }),
                    (FamilyArg::Slip10, true) => AnyCircuit::Slip10Child(Slip10ChildCircuit {
                        chain_code: node.chain_code.to_vec(),
                        parent_priv: node.private_key.to_vec(),
                        index,
                    }),
                    (FamilyArg::Slip10, false) => unreachable!("hardness checked above"),
                };
                (
                    circuit,
                    parent_path,
                    MaterialOwner::Child {
                        parent_priv: node.private_key.to_vec().into(),
                        chain_code: node.chain_code,
                        index,
                    },
                )
            }
            StatementArg::PublicKey | StatementArg::EthereumAddress => {
                let full_path = p.path.clone().ok_or("--path (the full key path) is required")?;
                let node = derive::bip32_node(&seed, &full_path);
                let circuit = if statement == StatementArg::PublicKey {
                    AnyCircuit::PubKey(PubKeyCircuit { private_key: node.private_key.to_vec() })
                } else {
                    AnyCircuit::Address(AddressCircuit { private_key: node.private_key.to_vec() })
                };
                (
                    circuit,
                    full_path,
                    MaterialOwner::Priv { private_key: node.private_key.to_vec().into() },
                )
            }
        };
    let digest = request.range.map(|_| {
        let material = material_owner.borrow();
        ranged_request_digest(statement.id(), &request, &resolved_path, material)
    });
    Ok(Resolved { circuit, request, digest })
}

/// Owned witness material (the shared [WitnessMaterial] borrows), zeroized on drop.
enum MaterialOwner {
    Seed { seed: Zeroizing<Vec<u8>> },
    Mnemonic { mnemonic: Zeroizing<Vec<u8>>, salt: Zeroizing<Vec<u8>> },
    Child { parent_priv: Zeroizing<Vec<u8>>, chain_code: [u8; 32], index: u32 },
    Priv { private_key: Zeroizing<Vec<u8>> },
}

impl MaterialOwner {
    fn borrow(&self) -> WitnessMaterial<'_> {
        match self {
            MaterialOwner::Seed { seed } => WitnessMaterial::Seed { seed },
            MaterialOwner::Mnemonic { mnemonic, salt } => {
                WitnessMaterial::Mnemonic { mnemonic, salt }
            }
            MaterialOwner::Child { parent_priv, chain_code, index } => WitnessMaterial::Child {
                parent_priv,
                chain_code,
                index: *index,
            },
            MaterialOwner::Priv { private_key } => WitnessMaterial::Priv { private_key },
        }
    }
}

/// Fresh 32-byte prover entropy from the OS (the rangeless mode; the software
/// analog of the device TRNG draw).
pub fn fresh_entropy() -> Result<Zeroizing<[u8; 32]>, String> {
    let mut entropy = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut *entropy).map_err(|e| format!("OS randomness failed: {e}"))?;
    Ok(entropy)
}
