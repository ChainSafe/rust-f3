// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT
use derive_quickcheck_arbitrary::Arbitrary;

/// `ActorId` represents the unique identifier for an actor in the Filecoin network.
pub type ActorId = u64;
/// `StoragePower` represents the amount of storage power an actor has in the network.
pub type StoragePower = num_bigint::BigInt;
/// `PubKey` represents a public key used for cryptographic operations in the network.
#[derive(Debug, PartialEq, Eq, Clone, Default, Arbitrary)]
pub struct PubKey(Vec<u8>);

impl PubKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// `NetworkName` represents the name of the Filecoin network.
///
/// It is used to distinguish between different Filecoin networks,
/// e.g. mainnet or calibnet.
pub type NetworkName = String;
