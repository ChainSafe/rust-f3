// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use bls_signatures::{PublicKey, Serialize, Signature, verify_messages};
use filecoin_f3_gpbft::PubKey;
use filecoin_f3_gpbft::api::Verifier;
use hashlink::LruCache;
use parking_lot::RwLock;
use thiserror::Error;

use crate::bdn::BDNAggregation;

#[cfg(test)]
mod tests;

#[derive(Error, Debug, PartialEq)]
pub enum BLSError {
    #[error("empty public keys provided")]
    EmptyPublicKeys,
    #[error("invalid public key length: expected {BLS_PUBLIC_KEY_LENGTH} bytes, got {0}")]
    InvalidPublicKeyLength(usize),
    #[error("failed to deserialize public key")]
    PublicKeyDeserialization,
    #[error("invalid signature length: expected {BLS_SIGNATURE_LENGTH} bytes, got {0}")]
    InvalidSignatureLength(usize),
    #[error("failed to deserialize signature")]
    SignatureDeserialization,
    #[error("BLS signature verification failed")]
    SignatureVerificationFailed,
    #[error("mismatched number of public keys and signatures: {pub_keys} != {sigs}")]
    LengthMismatch { pub_keys: usize, sigs: usize },
}

/// BLS signature verifier using BDN aggregation scheme
///
/// This verifier implements the same scheme used by `go-f3/blssig`, with:
/// - BLS12_381 curve
/// - G1 for public keys, G2 for signatures  
/// - BDN aggregation for rogue-key attack prevention
/// - Point cache for performance optimization
pub struct BLSVerifier {
    /// Cache for deserialized public key points to avoid expensive repeated operations
    point_cache: RwLock<LruCache<Vec<u8>, PublicKey>>,
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
            point_cache: RwLock::new(LruCache::new(MAX_POINT_CACHE_SIZE)),
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
        let signature =
            Signature::from_bytes(sig).map_err(|_| BLSError::SignatureDeserialization)?;

        // Verify using bls-signatures
        let messages = vec![msg];
        let public_keys = vec![pub_key];
        match verify_messages(&signature, &messages, &public_keys) {
            true => Ok(()),
            false => Err(BLSError::SignatureVerificationFailed),
        }
    }

    /// Gets a cached public key or deserialize and caches it
    fn get_or_cache_public_key(&self, pub_key_bytes: &[u8]) -> Result<PublicKey, BLSError> {
        // Check cache first
        let mut cache = self.point_cache.write();
        if let Some(cached_key) = cache.get(pub_key_bytes) {
            return Ok(*cached_key);
        }
        drop(cache);

        // Deserialize the public key
        let pub_key =
            PublicKey::from_bytes(pub_key_bytes).map_err(|_| BLSError::PublicKeyDeserialization)?;

        // Cache it
        let mut cache = self.point_cache.write();
        cache.insert(pub_key_bytes.to_vec(), pub_key);
        drop(cache);

        Ok(pub_key)
    }
}

impl Verifier for BLSVerifier {
    type Error = BLSError;

    fn verify(&self, pub_key: &PubKey, msg: &[u8], sig: &[u8]) -> Result<(), Self::Error> {
        self.verify_single(pub_key, msg, sig)
    }

    fn aggregate(&self, pub_keys: &[PubKey], sigs: &[Vec<u8>]) -> Result<Vec<u8>, Self::Error> {
        if pub_keys.is_empty() || sigs.is_empty() {
            return Err(BLSError::EmptyPublicKeys);
        }
        if pub_keys.len() != sigs.len() {
            return Err(BLSError::LengthMismatch {
                pub_keys: pub_keys.len(),
                sigs: sigs.len(),
            });
        }

        // Validate all input lengths
        for (i, pub_key) in pub_keys.iter().enumerate() {
            if pub_key.0.len() != BLS_PUBLIC_KEY_LENGTH {
                return Err(BLSError::InvalidPublicKeyLength(pub_key.0.len()));
            }
            if sigs[i].len() != BLS_SIGNATURE_LENGTH {
                return Err(BLSError::InvalidSignatureLength(sigs[i].len()));
            }
        }

        let bdn = BDNAggregation::new(pub_keys)?;
        bdn.aggregate_sigs(sigs)
    }

    fn verify_aggregate(
        &self,
        payload: &[u8],
        agg_sig: &[u8],
        signers: &[PubKey],
    ) -> Result<(), Self::Error> {
        if signers.is_empty() {
            return Err(BLSError::EmptyPublicKeys);
        }

        for pub_key in signers {
            if pub_key.0.len() != BLS_PUBLIC_KEY_LENGTH {
                return Err(BLSError::InvalidPublicKeyLength(pub_key.0.len()));
            }
        }

        let bdn = BDNAggregation::new(signers)?;
        let agg_pub_key = bdn.aggregate_pub_keys()?;
        let agg_pub_key_bytes = PubKey(agg_pub_key.as_bytes().to_vec());
        self.verify_single(&agg_pub_key_bytes, payload, agg_sig)
    }
}
