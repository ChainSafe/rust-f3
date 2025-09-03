// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

//! BDN (Boneh-Drijvers-Neven) signature aggregation scheme, for preventing rogue public-key attacks.
//!
//! NOTE: currently uses standard BLS aggregation without coefficient weighting, hence returns incorrect values compared to go-f3.
//!
use crate::verifier::BLSError;
use bls_signatures::{PublicKey, Serialize, Signature};
use bls12_381::{G1Projective, G2Projective};
use filecoin_f3_gpbft::PubKey;

/// BDN aggregation context for managing signature and public key aggregation
pub struct BDNAggregation {
    pub_keys: Vec<PubKey>,
}

impl BDNAggregation {
    pub fn new(pub_keys: &[PubKey]) -> Result<Self, BLSError> {
        if pub_keys.is_empty() {
            return Err(BLSError::EmptyPublicKeys);
        }

        Ok(Self {
            pub_keys: pub_keys.to_vec(),
        })
    }

    /// Aggregates signatures using standard BLS aggregation
    /// TODO: Implement BDN aggregation scheme: https://github.com/ChainSafe/rust-f3/issues/29
    pub fn aggregate_sigs(&self, sigs: &[Vec<u8>]) -> Result<Vec<u8>, BLSError> {
        if sigs.len() != self.pub_keys.len() {
            return Err(BLSError::LengthMismatch {
                pub_keys: self.pub_keys.len(),
                sigs: sigs.len(),
            });
        }

        let mut aggregated_point = G2Projective::identity();

        for sig_bytes in sigs.iter() {
            // Deserialize signature to G2 point
            let signature =
                Signature::from_bytes(sig_bytes).map_err(|_| BLSError::SignatureDeserialization)?;
            let sig_point: G2Projective = signature.into();

            // Standard BLS aggregation
            aggregated_point += sig_point;
        }

        // Convert back to signature
        let aggregated_sig: Signature = aggregated_point.into();
        Ok(aggregated_sig.as_bytes().to_vec())
    }

    /// Aggregates public keys using standard BLS aggregation
    /// TODO: Implement BDN aggregation scheme: https://github.com/ChainSafe/rust-f3/issues/29
    pub fn aggregate_pub_keys(&self) -> Result<PublicKey, BLSError> {
        let mut aggregated_point = G1Projective::identity();

        for pub_key_bytes in &self.pub_keys {
            let public_key = PublicKey::from_bytes(&pub_key_bytes.0)
                .map_err(|_| BLSError::PublicKeyDeserialization)?;

            // Convert public key to G1Projective for curve operations
            let pub_key_point: G1Projective = public_key.into();

            // Standard BLS aggregation
            aggregated_point += pub_key_point;
        }

        // Convert back to PublicKey
        Ok(aggregated_point.into())
    }
}
