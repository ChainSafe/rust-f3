// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

//! BDN (Boneh-Drijvers-Neven) signature aggregation scheme, for preventing rogue public-key attacks.
//!
//! NOTE: currently uses standard BLS aggregation without coefficient weighting, hence returns incorrect values compared to go-f3.
//!
use crate::verifier::BLSError;
use bls_signatures::{PublicKey, Signature};
use bls12_381::{G1Projective, G2Affine, G2Projective};

/// BDN aggregation context for managing signature and public key aggregation
pub struct BDNAggregation {
    pub_keys: Vec<PublicKey>,
}

impl BDNAggregation {
    pub fn new(pub_keys: Vec<PublicKey>) -> Result<Self, BLSError> {
        if pub_keys.is_empty() {
            return Err(BLSError::EmptyPublicKeys);
        }

        Ok(Self { pub_keys })
    }

    /// Aggregates signatures using standard BLS aggregation
    /// TODO: Implement BDN aggregation scheme: https://github.com/ChainSafe/rust-f3/issues/29
    pub fn aggregate_sigs(&self, sigs: Vec<Signature>) -> Result<Signature, BLSError> {
        if sigs.len() != self.pub_keys.len() {
            return Err(BLSError::LengthMismatch {
                pub_keys: self.pub_keys.len(),
                sigs: sigs.len(),
            });
        }

        // Standard BLS aggregation
        let mut agg_point = G2Projective::identity();
        for sig in sigs {
            let sig: G2Affine = sig.into();
            agg_point += sig;
        }

        // Convert back to Signature
        let agg_sig: Signature = agg_point.into();
        Ok(agg_sig)
    }

    /// Aggregates public keys using standard BLS aggregation
    /// TODO: Implement BDN aggregation scheme: https://github.com/ChainSafe/rust-f3/issues/29
    pub fn aggregate_pub_keys(&self) -> Result<PublicKey, BLSError> {
        // Standard BLS aggregation
        let mut agg_point = G1Projective::identity();
        for pub_key in &self.pub_keys {
            let pub_key_point: G1Projective = (*pub_key).into();
            agg_point += pub_key_point;
        }

        // Convert back to PublicKey
        let agg_pub_key: PublicKey = agg_point.into();
        Ok(agg_pub_key)
    }
}
