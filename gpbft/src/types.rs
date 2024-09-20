// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

/// `ActorId` represents the unique identifier for an actor in the Filecoin network.
pub type ActorId = u64;
/// `StoragePower` represents the amount of storage power an actor has in the network.
pub type StoragePower = num_bigint::BigInt;
/// `PubKey` represents a public key used for cryptographic operations in the network.
pub type PubKey = Vec<u8>;

/// `NetworkName` represents the name of the Filecoin network.
///
/// It is used to distinguish between different Filecoin networks,
/// e.g. mainnet or calibnet.
pub type NetworkName = String;
