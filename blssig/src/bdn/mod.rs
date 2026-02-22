// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

//! BDN (Boneh-Drijvers-Neven) signature aggregation scheme, for preventing rogue public-key attacks.
//! Those attacks could allow an attacker to forge a public-key and then make a verifiable
//! signature for an aggregation of signatures. It fixes the situation by adding coefficients to the aggregate.
//!
//! See the papers:
//! - <https://eprint.iacr.org/2018/483.pdf>
//! - <https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html>
//!
use crate::verifier::BLSError;
use blake2::Blake2xs;
use blake2::digest::{ExtendableOutput, Update, XofReader};
use bls_signatures::{PublicKey, Serialize, Signature};
use bls12_381::{G1Projective, G2Projective, Scalar};
use rayon::prelude::*;

/// BDN aggregation context for managing signature and public key aggregation
pub struct BDNAggregation {
    pub(crate) coefficients: Vec<Scalar>,
    pub(crate) terms: Vec<PublicKey>,
}

impl BDNAggregation {
    pub fn new(pub_keys: Vec<PublicKey>) -> Result<Self, BLSError> {
        if pub_keys.is_empty() {
            return Err(BLSError::EmptyPublicKeys);
        }

        let coefficients = Self::calc_coefficients(&pub_keys)?;
        let terms = Self::calc_terms(&pub_keys, &coefficients);

        Ok(Self {
            coefficients,
            terms,
        })
    }

    /// Aggregates signatures using BDN aggregation with coefficients.
    /// Computes: `sum((coef_i + 1) * sig_i)` for signatures at the given indices
    pub fn aggregate_sigs(
        &self,
        indices: &[u64],
        sigs: &[Signature],
    ) -> Result<Signature, BLSError> {
        if sigs.len() != indices.len() {
            return Err(BLSError::LengthMismatch {
                pub_keys: indices.len(),
                sigs: sigs.len(),
            });
        }

        for &idx in indices {
            if idx as usize >= self.coefficients.len() {
                return Err(BLSError::SignerIndexOutOfRange(idx as usize));
            }
        }

        let mut agg_point = G2Projective::identity();
        for (sig, &idx) in sigs.iter().zip(indices.iter()) {
            let coef = self.coefficients[idx as usize];
            let sig_point: G2Projective = (*sig).into();
            let sig_c = sig_point * coef;
            let sig_c = sig_c + sig_point;

            agg_point += sig_c;
        }

        // Convert back to Signature
        let agg_sig: Signature = agg_point.into();
        Ok(agg_sig)
    }

    /// Aggregates public keys indices using BDN aggregation with coefficients.
    /// Computes: `sum((coef_i + 1) * pub_key_i)`
    pub fn aggregate_pub_keys(&self, indices: &[u64]) -> Result<PublicKey, BLSError> {
        for &idx in indices {
            if idx as usize >= self.terms.len() {
                return Err(BLSError::SignerIndexOutOfRange(idx as usize));
            }
        }

        // Sum of pre-computed terms (which are already (coef_i + 1) * pub_key_i)
        let mut agg_point = G1Projective::identity();
        for &idx in indices {
            let term_point: G1Projective = self.terms[idx as usize].into();
            agg_point += term_point;
        }

        // Convert back to PublicKey
        let agg_pub_key: PublicKey = agg_point.into();
        Ok(agg_pub_key)
    }

    pub fn calc_coefficients(pub_keys: &[PublicKey]) -> Result<Vec<Scalar>, BLSError> {
        let mut hasher = Blake2xs::new(0xFFFF);

        // Hash all public keys
        for pub_key in pub_keys {
            let bytes = pub_key.as_bytes();
            hasher.update(&bytes);
        }

        // Read 16 bytes per public key
        let mut reader = hasher.finalize_xof();
        let mut output = vec![0u8; pub_keys.len() * 16];
        reader.read(&mut output);

        // Convert every consecutive 16 bytes chunk to a scalar
        let mut coefficients = Vec::with_capacity(pub_keys.len());
        for i in 0..pub_keys.len() {
            let chunk = &output[i * 16..(i + 1) * 16];

            // Convert 16 bytes to 32 bytes, for scalar (pad with zeros)
            let mut bytes_32 = [0u8; 32];
            bytes_32[..16].copy_from_slice(chunk);

            // BLS12-381 scalars expects little-endian byte representation
            let scalar = Scalar::from_bytes(&bytes_32);
            if scalar.is_some().into() {
                coefficients.push(scalar.unwrap());
            } else {
                return Err(BLSError::InvalidScalar);
            }
        }

        Ok(coefficients)
    }

    pub fn calc_terms(pub_keys: &[PublicKey], coefficients: &[Scalar]) -> Vec<PublicKey> {
        pub_keys
            .par_iter()
            .enumerate()
            .map(|(i, pub_key)| {
                let pub_key_point: G1Projective = (*pub_key).into();
                let pub_c = pub_key_point * coefficients[i];
                let term = pub_c + pub_key_point;
                term.into()
            })
            .collect()
    }
}
