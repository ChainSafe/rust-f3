// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

//! BLS signature implementation using BDN aggregation scheme.
//!
//! This module implements the BLS signature scheme used in the Filecoin F3 protocol.
//! It uses the BLS12_381 curve with G1 for public keys and G2 for signatures.
//! The BDN (Boneh-Drijvers-Neven) scheme is used for signature and public key aggregation
//! to prevent rogue public-key attacks.

mod bdn;
mod verifier;

pub use verifier::{BLSError, BLSVerifier};
