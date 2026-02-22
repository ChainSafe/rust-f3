// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

//! Tests for BDN (Boneh-Drijvers-Neven) signature aggregation.
//!
//! ## Tested scenarios
//!
//! ### Correctness
//! - [`test_bdn_aggregate_and_verify`]: aggregate of N distinct signers verifies correctly.
//!- [`test_bdn_mismatched_key_order_fails`]: BDN coefficients depend on the full ordered key
//!   list; re-ordering keys produces a different aggregate that does not verify under the
//!   original order.
//! - [`test_bdn_wrong_signer_indices_fails`]: verifying with a different signer set than was
//!   used to produce the aggregate must fail.
//! - [`test_bdn_corrupted_agg_sig_fails`]: a bit-flipped aggregate signature is rejected.
//! - [`test_bdn_wrong_message_fails`]: verification against a different message is rejected.
//!
//! ### Input validation
//! - [`test_bdn_empty_pub_keys_fails`]: `BDNAggregation::new`: an empty key list.
//! - [`test_bdn_aggregate_sigs_length_mismatch_fails`]: mismatched indices / signatures lengths.
//! - [`test_bdn_aggregate_sigs_out_of_range_fails`]: index >= power-table size.
//! - [`test_bdn_aggregate_pub_keys_out_of_range_fails`]: same for `aggregate_pub_keys`.
//! - [`test_verifier_aggregate_empty_pub_keys_fails`]: `Verifier::aggregate` rejects empty keys.
//! - [`test_verifier_aggregate_length_mismatch_fails`]: mismatched public keys / signatures.

use crate::bdn::BDNAggregation;
use crate::verifier::{BLSError, BLSVerifier};
use bls_signatures::{PrivateKey, Serialize};
use filecoin_f3_gpbft::api::Verifier;
use filecoin_f3_gpbft::PubKey;

#[test]
fn test_bdn_aggregate_and_verify() {
    let verifier = BLSVerifier::new();
    let msg = b"test bdn distinct keys";

    let keys: Vec<PrivateKey> = (0..3).map(|_| random_key()).collect();
    let pub_keys: Vec<PubKey> = keys.iter().map(|k| pub_key_bytes(k)).collect();
    let sigs: Vec<Vec<u8>> = keys.iter().map(|k| sign_bytes(k, msg)).collect();

    let agg_sig = verifier
        .aggregate(&pub_keys, &sigs)
        .expect("aggregation should succeed");
    verifier
        .verify_aggregate(msg, &agg_sig, &pub_keys, &[0, 1, 2])
        .expect("verification should succeed");
}

#[test]
fn test_bdn_mismatched_key_order_fails() {
    let verifier = BLSVerifier::new();
    let msg = b"test bdn key order";

    let key1 = random_key();
    let key2 = random_key();

    let pub_keys_ab = vec![pub_key_bytes(&key1), pub_key_bytes(&key2)];
    let pub_keys_ba = vec![pub_key_bytes(&key2), pub_key_bytes(&key1)];

    // Aggregate with order [A, B]: A is index 0, B is index 1
    let sigs_ab = vec![sign_bytes(&key1, msg), sign_bytes(&key2, msg)];
    let agg_ab = verifier
        .aggregate(&pub_keys_ab, &sigs_ab)
        .expect("aggregation should succeed");

    // Aggregate with order [B, A]: B is index 0, A is index 1
    let sigs_ba = vec![sign_bytes(&key2, msg), sign_bytes(&key1, msg)];
    let agg_ba = verifier
        .aggregate(&pub_keys_ba, &sigs_ba)
        .expect("aggregation should succeed");

    // Different orderings must produce different aggregates
    assert_ne!(
        agg_ab, agg_ba,
        "different key orderings must produce different aggregates"
    );

    // agg_ab must not verify under the [B, A] power table
    let result = verifier.verify_aggregate(msg, &agg_ab, &pub_keys_ba, &[0, 1]);
    assert!(
        result.is_err(),
        "aggregate from [A,B] order must not verify under [B,A] order"
    );
}

#[test]
fn test_bdn_wrong_signer_indices_fails() {
    let verifier = BLSVerifier::new();
    let msg = b"test bdn wrong indices";

    let keys: Vec<PrivateKey> = (0..3).map(|_| random_key()).collect();
    let power_table: Vec<PubKey> = keys.iter().map(|k| pub_key_bytes(k)).collect();

    // Keys 0 and 1 sign
    let signer_indices = [0u64, 1];
    let typed_pub_keys: Vec<_> = power_table
        .iter()
        .map(|pk| bls_signatures::PublicKey::from_bytes(&pk.0).unwrap())
        .collect();
    let typed_sigs: Vec<bls_signatures::Signature> = signer_indices
        .iter()
        .map(|&i| keys[i as usize].sign(msg))
        .collect();

    let bdn = BDNAggregation::new(typed_pub_keys).expect("BDN creation should succeed");
    let agg_sig = bdn
        .aggregate_sigs(&signer_indices, &typed_sigs)
        .expect("aggregation should succeed");

    // Claim indices [0, 2] instead of the actual [0, 1]
    let result = verifier.verify_aggregate(msg, &agg_sig.as_bytes(), &power_table, &[0, 2]);
    assert!(
        result.is_err(),
        "verification with wrong signer indices must fail"
    );
}

#[test]
fn test_bdn_corrupted_agg_sig_fails() {
    let verifier = BLSVerifier::new();
    let msg = b"test bdn corruption";

    let key1 = random_key();
    let key2 = random_key();
    let pub_keys = vec![pub_key_bytes(&key1), pub_key_bytes(&key2)];
    let sigs = vec![sign_bytes(&key1, msg), sign_bytes(&key2, msg)];

    let mut agg_sig = verifier
        .aggregate(&pub_keys, &sigs)
        .expect("aggregation should succeed");
    agg_sig[0] ^= 0xff;

    let result = verifier.verify_aggregate(msg, &agg_sig, &pub_keys, &[0, 1]);
    assert!(result.is_err(), "corrupted aggregate signature must be rejected");
}

#[test]
fn test_bdn_wrong_message_fails() {
    let verifier = BLSVerifier::new();
    let msg = b"correct message";

    let key1 = random_key();
    let key2 = random_key();
    let pub_keys = vec![pub_key_bytes(&key1), pub_key_bytes(&key2)];
    let sigs = vec![sign_bytes(&key1, msg), sign_bytes(&key2, msg)];

    let agg_sig = verifier
        .aggregate(&pub_keys, &sigs)
        .expect("aggregation should succeed");

    let result = verifier.verify_aggregate(b"wrong message", &agg_sig, &pub_keys, &[0, 1]);
    assert!(result.is_err(), "verification against wrong message must fail");
}

// -- Input validation ---------------------------------------------------------

#[test]
fn test_bdn_empty_pub_keys_fails() {
    let result = BDNAggregation::new(vec![]);
    assert!(matches!(result, Err(BLSError::EmptyPublicKeys)));
}

#[test]
fn test_bdn_aggregate_sigs_length_mismatch_fails() {
    let key = random_key();
    let typed_pub_key =
        bls_signatures::PublicKey::from_bytes(&pub_key_bytes(&key).0).unwrap();
    let bdn = BDNAggregation::new(vec![typed_pub_key]).expect("BDN creation should succeed");

    let sig = key.sign(b"msg");
    let result = bdn.aggregate_sigs(&[0, 1], &[sig]);
    assert!(matches!(result, Err(BLSError::LengthMismatch { .. })));
}

#[test]
fn test_bdn_aggregate_sigs_out_of_range_fails() {
    let key = random_key();
    let typed_pub_key =
        bls_signatures::PublicKey::from_bytes(&pub_key_bytes(&key).0).unwrap();
    let bdn = BDNAggregation::new(vec![typed_pub_key]).expect("BDN creation should succeed");

    let sig = key.sign(b"msg");
    let result = bdn.aggregate_sigs(&[5], &[sig]);
    assert!(matches!(result, Err(BLSError::SignerIndexOutOfRange(5))));
}

#[test]
fn test_bdn_aggregate_pub_keys_out_of_range_fails() {
    let key = random_key();
    let typed_pub_key =
        bls_signatures::PublicKey::from_bytes(&pub_key_bytes(&key).0).unwrap();
    let bdn = BDNAggregation::new(vec![typed_pub_key]).expect("BDN creation should succeed");

    let result = bdn.aggregate_pub_keys(&[5]);
    assert!(matches!(result, Err(BLSError::SignerIndexOutOfRange(5))));
}

#[test]
fn test_verifier_aggregate_empty_pub_keys_fails() {
    let verifier = BLSVerifier::new();
    let result = verifier.aggregate(&[], &[]);
    assert!(matches!(result, Err(BLSError::EmptyPublicKeys)));
}

#[test]
fn test_verifier_aggregate_length_mismatch_fails() {
    let verifier = BLSVerifier::new();
    let key = random_key();
    let pk = pub_key_bytes(&key);
    let sig = sign_bytes(&key, b"msg");

    let result = verifier.aggregate(&[pk.clone(), pk], &[sig]);
    assert!(matches!(result, Err(BLSError::LengthMismatch { .. })));
}

fn random_key() -> PrivateKey {
    PrivateKey::generate(&mut rand::thread_rng())
}

fn pub_key_bytes(key: &PrivateKey) -> PubKey {
    PubKey(key.public_key().as_bytes().to_vec())
}

fn sign_bytes(key: &PrivateKey, msg: &[u8]) -> Vec<u8> {
    key.sign(msg).as_bytes().to_vec()
}
