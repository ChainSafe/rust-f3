// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use super::BLSVerifier;
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
