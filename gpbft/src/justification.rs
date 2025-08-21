// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use crate::payload::Payload;
use fvm_ipld_bitfield::BitField;

/// Represents a justification for a decision in the GPBFT consensus protocol
pub struct Justification {
    /// The payload that is signed by the signature
    pub vote: Payload,
    /// Indexes in the base power table of the signers (`bitset`)
    pub signers: BitField,
    /// BLS aggregate signature of signers
    pub signature: Vec<u8>,
}
