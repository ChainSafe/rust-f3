// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use serde::{Deserialize, Serialize};

/// `ActorId` represents the unique identifier for an actor in the Filecoin network.
pub type ActorId = u64;
/// `StoragePower` represents the amount of storage power an actor has in the network.
pub type StoragePower = num_bigint::BigInt;

/// `MAX_PUBKEY_LEN` represents the maximum length of a public key in bytes.
pub const MAX_PUBKEY_LEN: usize = 48;

/// `PubKey` represents a public key used for cryptographic operations in the network.
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone, Default)]
#[serde(transparent)]
pub struct PubKey(pub Vec<u8>);

impl PubKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns true if the public key does not exceed the maximum length.
    pub fn is_valid(&self) -> bool {
        self.0.len() <= MAX_PUBKEY_LEN
    }
}

/// `NetworkName` represents the name of the Filecoin network.
///
/// It is used to distinguish between different Filecoin networks,
/// e.g. mainnet or calibnet.
pub type NetworkName = String;
