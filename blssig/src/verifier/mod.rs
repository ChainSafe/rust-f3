// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use bls_signatures::{PublicKey, Serialize, Signature, verify_messages};
use filecoin_f3_gpbft::PubKey;
use filecoin_f3_gpbft::api::Verifier;
use hashlink::LruCache;
use parking_lot::RwLock;
use std::sync::Arc;
use thiserror::Error;

use crate::bdn::BDNAggregation;

#[cfg(test)]
mod tests;

#[derive(Error, Debug)]
pub enum BLSError {
    #[error("empty public keys provided")]
    EmptyPublicKeys,
    #[error("empty signers provided")]
    EmptySigners,
    #[error("empty signatures provided")]
    EmptySignatures,
    #[error("invalid public key length: expected {BLS_PUBLIC_KEY_LENGTH} bytes, got {0}")]
    InvalidPublicKeyLength(usize),
    #[error("failed to deserialize public key: {0}")]
    PublicKeyDeserialization(bls_signatures::Error),
    #[error("invalid signature length: expected {BLS_SIGNATURE_LENGTH} bytes, got {0}")]
    InvalidSignatureLength(usize),
    #[error("failed to deserialize signature: {0}")]
    SignatureDeserialization(bls_signatures::Error),
    #[error("BLS signature verification failed")]
    SignatureVerificationFailed,
    #[error("mismatched number of public keys and signatures: {pub_keys} != {sigs}")]
    LengthMismatch { pub_keys: usize, sigs: usize },
    #[error("invalid scalar value")]
    InvalidScalar,
    #[error("signer index {0} is out of range")]
    SignerIndexOutOfRange(usize),
}

/// BLS signature verifier using BDN aggregation scheme
///
/// This verifier implements the same scheme used by `go-f3/blssig`, with:
/// - BLS12_381 curve
/// - G1 for public keys, G2 for signatures
/// - BDN aggregation for rogue-key attack prevention
pub struct BLSVerifier {
    /// Cache for deserialized public key points to avoid expensive repeated operations
    point_cache: RwLock<LruCache<Vec<u8>, PublicKey>>,
    /// Cache for current power table's BDN aggregation
    /// Only caches the current since power tables don't tend to repeat after rotation
    bdn_cache: RwLock<Option<(Vec<PubKey>, Arc<BDNAggregation>)>>,
}

impl Default for BLSVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// BLS12-381 public key length in bytes
const BLS_PUBLIC_KEY_LENGTH: usize = 48;

/// BLS12-381 signature length in bytes
const BLS_SIGNATURE_LENGTH: usize = 96;

/// Maximum number of cached public key points to prevent excessive memory usage
const MAX_POINT_CACHE_SIZE: usize = 10_000;

impl BLSVerifier {
    pub fn new() -> Self {
        Self {
            // key size: 48, value size: 196, total estimated: 1.83 MiB
            point_cache: RwLock::new(LruCache::new(MAX_POINT_CACHE_SIZE)),
            bdn_cache: RwLock::new(None),
        }
    }

    /// Verifies a single BLS signature
    fn verify_single(&self, pub_key: &PubKey, msg: &[u8], sig: &[u8]) -> Result<(), BLSError> {
        // Validate input lengths
        if pub_key.0.len() != BLS_PUBLIC_KEY_LENGTH {
            return Err(BLSError::InvalidPublicKeyLength(pub_key.0.len()));
        }
        if sig.len() != BLS_SIGNATURE_LENGTH {
            return Err(BLSError::InvalidSignatureLength(sig.len()));
        }

        // Get cached public key
        let pub_key = self.get_or_cache_public_key(&pub_key.0)?;

        // Deserialize signature
        let signature = self.deserialize_signature(sig)?;

        // Verify using bls-signatures
        let msgs = [msg];
        let pub_keys = [pub_key];
        match verify_messages(&signature, &msgs, &pub_keys) {
            true => Ok(()),
            false => Err(BLSError::SignatureVerificationFailed),
        }
    }

    /// Gets a cached public key or deserialize and caches it
    fn get_or_cache_public_key(&self, pub_key: &[u8]) -> Result<PublicKey, BLSError> {
        // Check cache first
        if let Some(cached) = self.point_cache.write().get(pub_key) {
            return Ok(*cached);
        }

        // Deserialize and cache
        let typed_pub_key = self.deserialize_public_key(pub_key)?;
        self.point_cache
            .write()
            .insert(pub_key.to_vec(), typed_pub_key);
        Ok(typed_pub_key)
    }

    fn deserialize_public_key(&self, pub_key: &[u8]) -> Result<PublicKey, BLSError> {
        PublicKey::from_bytes(pub_key).map_err(BLSError::PublicKeyDeserialization)
    }

    fn deserialize_signature(&self, sig: &[u8]) -> Result<Signature, BLSError> {
        Signature::from_bytes(sig).map_err(BLSError::SignatureDeserialization)
    }

    /// Gets a cached BDN aggregation or creates and caches it
    fn get_or_cache_bdn(&self, power_table: &[PubKey]) -> Result<Arc<BDNAggregation>, BLSError> {
        // Check cache first
        if let Some((cached_power_table, cached_bdn)) = self.bdn_cache.read().as_ref() {
            if cached_power_table == power_table {
                return Ok(cached_bdn.clone());
            }
        }

        // Deserialize and create new BDN aggregation
        let mut typed_pub_keys = vec![];
        for pub_key in power_table {
            if pub_key.0.len() != BLS_PUBLIC_KEY_LENGTH {
                return Err(BLSError::InvalidPublicKeyLength(pub_key.0.len()));
            }
            typed_pub_keys.push(self.get_or_cache_public_key(&pub_key.0)?);
        }

        let bdn = Arc::new(BDNAggregation::new(typed_pub_keys)?);

        // Cache it
        self.bdn_cache
            .write()
            .replace((power_table.to_vec(), bdn.clone()));

        Ok(bdn)
    }
}

impl Verifier for BLSVerifier {
    type Error = BLSError;

    fn verify(&self, pub_key: &PubKey, msg: &[u8], sig: &[u8]) -> Result<(), Self::Error> {
        self.verify_single(pub_key, msg, sig)
    }

    fn aggregate(&self, pub_keys: &[PubKey], sigs: &[Vec<u8>]) -> Result<Vec<u8>, Self::Error> {
        if pub_keys.is_empty() {
            return Err(BLSError::EmptyPublicKeys);
        }
        if sigs.is_empty() {
            return Err(BLSError::EmptySignatures);
        }

        if pub_keys.len() != sigs.len() {
            return Err(BLSError::LengthMismatch {
                pub_keys: pub_keys.len(),
                sigs: sigs.len(),
            });
        }

        // Validate all input lengths
        let mut typed_pub_keys = vec![];
        let mut typed_sigs = vec![];
        for (i, pub_key) in pub_keys.iter().enumerate() {
            if pub_key.0.len() != BLS_PUBLIC_KEY_LENGTH {
                return Err(BLSError::InvalidPublicKeyLength(pub_key.0.len()));
            }
            if sigs[i].len() != BLS_SIGNATURE_LENGTH {
                return Err(BLSError::InvalidSignatureLength(sigs[i].len()));
            }

            typed_pub_keys.push(self.get_or_cache_public_key(&pub_key.0)?);
            typed_sigs.push(self.deserialize_signature(&sigs[i])?);
        }

        let bdn = BDNAggregation::new(typed_pub_keys)?;
        let agg_sig = bdn.aggregate_sigs(typed_sigs)?;
        Ok(agg_sig.as_bytes())
    }

    fn verify_aggregate(
        &self,
        payload: &[u8],
        agg_sig: &[u8],
        power_table: &[PubKey],
        signer_indices: &[u64],
    ) -> Result<(), Self::Error> {
        if power_table.is_empty() {
            return Err(BLSError::EmptyPublicKeys);
        }
        if signer_indices.is_empty() {
            return Err(BLSError::EmptySigners);
        }

        let bdn = self.get_or_cache_bdn(power_table)?;
        let agg_pub_key = bdn.aggregate_pub_keys(signer_indices)?;
        let agg_pub_key_bytes = PubKey(agg_pub_key.as_bytes().to_vec());
        self.verify_single(&agg_pub_key_bytes, payload, agg_sig)
    }
}
