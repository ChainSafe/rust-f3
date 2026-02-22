// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use super::BLSVerifier;
use crate::bdn::BDNAggregation;
use bls_signatures::{PrivateKey, Serialize};
use filecoin_f3_gpbft::PubKey;
use filecoin_f3_gpbft::api::Verifier;

/// BLS signer implementation for testing
pub struct BLSSigner {
    private_key: PrivateKey,
    public_key: PubKey,
}

impl BLSSigner {
    pub fn new(private_key: PrivateKey) -> Self {
        let public_key = PubKey(private_key.public_key().as_bytes().to_vec());
        Self {
            private_key,
            public_key,
        }
    }

    pub fn public_key(&self) -> &PubKey {
        &self.public_key
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let signature = self.private_key.sign(msg);
        signature.as_bytes().to_vec()
    }
}

/// Verifies that a signature created by our BLS signer can be verified by our BLS verifier
#[test]
fn test_single_signature_verification() {
    let verifier = BLSVerifier::new();

    // Generate test key pair and sign a message
    let private_key = PrivateKey::generate(&mut rand::thread_rng());
    let signer = BLSSigner::new(private_key);
    let message = b"test message";
    let signature = signer.sign(message);

    // Verify the signature
    let result = verifier.verify(signer.public_key(), message, &signature);
    assert!(result.is_ok(), "Signature verification should succeed");
}

/// Verifies that corrupted signatures properly fail verification
#[test]
fn test_invalid_signature() {
    let verifier = BLSVerifier::new();

    // Generate test key pair
    let private_key = PrivateKey::generate(&mut rand::thread_rng());
    let signer = BLSSigner::new(private_key);
    let message = b"test message";
    let mut signature = signer.sign(message);

    // Corrupt the signature
    signature[0] ^= 0x01;

    // Verify should fail
    let result = verifier.verify(signer.public_key(), message, &signature);
    assert!(
        result.is_err(),
        "corrupted signature should fail verification"
    );
}

#[test]
fn test_aggregate_signature_verification() {
    let verifier = BLSVerifier::new();
    let message = b"consensus message";

    // Generate 10 validators for the power table
    let mut signers = Vec::new();
    let mut power_table = Vec::new();
    for _ in 0..10 {
        let private_key = PrivateKey::generate(&mut rand::thread_rng());
        let signer = BLSSigner::new(private_key);
        power_table.push(signer.public_key().clone());
        signers.push(signer);
    }

    // Only 5 validators sign (indices 0, 2, 4, 6, 8)
    let signers_subset = vec![0u64, 2, 4, 6, 8];
    let sigs: Vec<Vec<u8>> = signers_subset
        .iter()
        .map(|&i| signers[i as usize].sign(message))
        .collect();

    // Aggregate using BDN with full power table
    let typed_pub_keys: Vec<_> = power_table
        .iter()
        .map(|pk| bls_signatures::PublicKey::from_bytes(&pk.0).unwrap())
        .collect();
    let typed_sigs: Vec<_> = sigs
        .iter()
        .map(|sig| bls_signatures::Signature::from_bytes(sig).unwrap())
        .collect();

    let bdn = BDNAggregation::new(typed_pub_keys).expect("BDN creation should succeed");
    let agg_sig = bdn
        .aggregate_sigs(&signers_subset, &typed_sigs)
        .expect("aggregation should succeed");

    // Verify aggregate using full power table and signer indices
    let result =
        verifier.verify_aggregate(message, &agg_sig.as_bytes(), &power_table, &signers_subset);
    assert!(
        result.is_ok(),
        "aggregate signature verification should succeed"
    );
}
