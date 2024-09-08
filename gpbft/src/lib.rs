// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

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

#[derive(PartialEq, Eq, Clone)]
pub struct SupplementalData {
    pub commitments: [u32; 32],
    pub power_table: Cid,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Initial,
    Quality,
    Converge,
    Prepare,
    Commit,
    Decide,
    Terminated,
}

#[derive(PartialEq, Eq)]
pub struct Payload {
    pub instance: u64,
    pub round: u64,
    pub step: Phase,
    pub supplemental_data: SupplementalData,
    pub value: ECChain,
}

impl Payload {
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

pub struct Justification {
    pub vote: Payload,
    pub signers: BitField,
    pub signature: Vec<u8>,
}
