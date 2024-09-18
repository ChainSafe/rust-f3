// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

//! GPBFT consensus protocol implementation.
//!
//! This module provides the core structures and logic for the GPBFT consensus protocol, including:
//! - Chain and tipset structures for blockchain state representation
//! - Power table management for validator voting power tracking
//! - Consensus phases and payload structures
//! - Justification and verification mechanisms
//! - Network types such as `ActorId`, `StoragePower`, and `PubKey`
//!
//! Key components:
//! - [`ECChain`]: Represents a chain of tipsets
//! - [`PowerTable`]: Manages validator voting power
//! - [`Payload`]: Contains consensus round information
//! - [`Justification`]: Holds votes and signatures for consensus decisions
//!
//! This module enables:
//! - Building and validating blockchain structures
//! - Managing validator power and keys
//! - Progressing through consensus phases
//! - Creating and verifying consensus decisions
//!
//! It provides the foundational types and logic for implementing GPBFT consensus in a blockchain network.

pub mod api;
pub mod chain;
mod powertable;
mod types;

pub use powertable::{PowerEntries, PowerEntry, PowerTable};

// re-exports
pub use fvm_ipld_bitfield::BitField;
pub use num_bigint::{BigInt, Sign};
pub use num_traits::Zero;

pub use crate::chain::{Cid, ECChain};
pub use types::{ActorId, NetworkName, PubKey, StoragePower};

/// Additional data signed by participants in a GPBFT instance
#[derive(PartialEq, Eq, Clone)]
pub struct SupplementalData {
    /// Merkle-tree root of instance-specific commitments
    ///
    /// Currently empty, but will eventually include things like
    /// snark-friendly power-table commitments.
    pub commitments: keccak_hash::H256,
    /// The DagCBOR-blake2b256 CID of the power table used to validate the next instance
    ///
    /// This takes look-back into account and represents a `[]PowerEntry`.
    /// The CID is limited to a maximum length of 38 bytes.
    pub power_table: Cid,
}

/// Represents the different phases of the GPBFT consensus protocol
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// This phase marks the beginning of a new consensus round. During this phase,
    /// participants typically initialize their local state and prepare for the
    /// subsequent phases of the protocol.
    Initial,
    /// Initial phase for quality assessment
    Quality,
    /// Phase for convergence of opinions
    Converge,
    /// Preparation phase before commitment
    Prepare,
    /// Commitment phase of the consensus
    Commit,
    /// Decision-making phase
    Decide,
    /// Final phase indicating termination of the consensus round
    Terminated,
}

/// Fields of the message that make up the signature payload in the GPBFT consensus protocol
#[derive(PartialEq, Eq)]
pub struct Payload {
    /// GPBFT instance number
    pub instance: u64,
    /// GPBFT round number
    pub round: u64,
    /// Current phase of the GPBFT protocol
    pub step: Phase,
    /// Additional data related to this consensus instance
    pub supplemental_data: SupplementalData,
    /// The agreed-upon value for this instance
    pub value: ECChain,
}

impl Payload {
    /// Creates a new Payload instance
    ///
    /// # Arguments
    ///
    /// * `instance` - The GPBFT instance number
    /// * `round` - The current round number
    /// * `step` - The current phase of the protocol
    /// * `supplemental_data` - Additional data for this instance
    /// * `value` - The agreed-upon ECChain
    pub fn new(
        instance: u64,
        round: u64,
        step: Phase,
        supplemental_data: SupplementalData,
        value: ECChain,
    ) -> Self {
        Payload {
            instance,
            round,
            step,
            supplemental_data,
            value,
        }
    }
}

/// Represents a justification for a decision in the GPBFT consensus protocol
pub struct Justification {
    /// The payload that is signed by the signature
    pub vote: Payload,
    /// Indexes in the base power table of the signers (`bitset`)
    pub signers: BitField,
    /// BLS aggregate signature of signers
    pub signature: Vec<u8>,
}
