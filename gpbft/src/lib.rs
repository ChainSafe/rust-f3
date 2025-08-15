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
mod error;
pub mod justification;
pub mod payload;
pub mod powertable;
pub mod test_utils;
mod types;

// re-exports
pub use fvm_ipld_bitfield::BitField;
pub use fvm_ipld_encoding::{Error as CborError, to_vec as to_vec_cbor};
pub use num_bigint::{BigInt, Sign};
pub use num_traits::Zero;

pub use crate::chain::{cid_from_bytes, Cid, ECChain, Tipset};
pub use crate::justification::Justification;
pub use crate::payload::{Payload, Phase, SupplementalData};
pub use error::GPBFTError;
pub use powertable::{is_strong_quorum, PowerEntries, PowerEntry, PowerTable};
pub use types::{ActorId, NetworkName, PubKey, StoragePower};

type Result<T> = std::result::Result<T, GPBFTError>;
