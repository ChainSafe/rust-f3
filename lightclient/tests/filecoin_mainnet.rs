// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

//! Integration tests for F3 certificate validation against real Filecoin mainnet data.
//!
//! Uses static fixtures fetched from the mainnet RPC (see `src/bin/fetch_fixtures.rs`).
//! No network access is required to run these tests.

use filecoin_f3_blssig::BLSVerifier;
use filecoin_f3_certs::{CertsError, PowerTableDelta, validate_finality_certificates};
use filecoin_f3_gpbft::{NetworkName, PowerEntries, PubKey, StoragePower};
use filecoin_f3_lightclient::rpc_to_internal;
use filecoin_f3_rpc as rpc;

/// Validates 10 consecutive mainnet certificates starting from instance 0, using the
/// real initial power table and a real BLS verifier. This exercises the full pipeline:
/// BLS aggregate signature verification, power table diff application, and CID matching.
#[test]
fn test_validate_filecoin_mainnet_certificates() {
    let power_table = load_initial_power_table();
    let certs = load_certificates();

    assert!(!certs.is_empty(), "no certificates loaded");

    let num_certs = certs.len() as u64;
    let last_cert = certs.last().unwrap();
    let expected_final_power_table_cid = last_cert.supplemental_data.power_table;

    let (final_instance, _chain, final_power_table) = validate_finality_certificates(
        &BLSVerifier::new(),
        NetworkName::Mainnet,
        power_table,
        0,
        None,
        &certs,
    )
    .expect("certificate validation failed");

    assert_eq!(final_instance, num_certs);

    // The final power table CID must match what the last certificate committed to
    let final_power_table_cid = filecoin_f3_gpbft::cid_from_bytes(&final_power_table.serialize_cbor());
    assert_eq!(
        final_power_table_cid, expected_final_power_table_cid,
        "final power table CID does not match last certificate's supplemental data"
    );
}

/// Flipping bits in the aggregate BLS signature must fail with a signature error.
/// This proves the verifier actually runs the cryptographic check.
#[test]
fn test_corrupted_signature_fails() {
    let power_table = load_initial_power_table();
    let mut certs = load_certificates();

    certs[0].signature[0] ^= 0xff;

    let result = validate_finality_certificates(
        &BLSVerifier::new(),
        NetworkName::Mainnet,
        power_table,
        0,
        None,
        &certs,
    );

    assert!(
        matches!(result, Err(CertsError::SignatureVerificationFailed { instance: 0, .. })),
        "expected SignatureVerificationFailed, got: {:?}",
        result
    );
}

/// Validating mainnet certificates under a different network name must fail.
#[test]
fn test_wrong_network_fails() {
    let power_table = load_initial_power_table();
    let certs = load_certificates();

    let result = validate_finality_certificates(
        &BLSVerifier::new(),
        NetworkName::TestnetCalibration,
        power_table,
        0,
        None,
        &certs,
    );

    assert!(
        matches!(result, Err(CertsError::SignatureVerificationFailed { .. })),
        "expected SignatureVerificationFailed, got: {:?}",
        result
    );
}

/// Presenting certificates out of instance order must fail with an instance mismatch.
#[test]
fn test_out_of_order_certificates_fails() {
    let power_table = load_initial_power_table();
    let mut certs = load_certificates();

    certs.swap(0, 1);

    let result = validate_finality_certificates(
        &BLSVerifier::new(),
        NetworkName::Mainnet,
        power_table,
        0,
        None,
        &certs,
    );

    assert!(
        matches!(
            result,
            Err(CertsError::InstanceMismatch { expected: 0, actual: 1 })
        ),
        "expected InstanceMismatch, got: {:?}",
        result
    );
}

/// A tampered power table diff causes the computed power table CID to diverge from
/// the CID committed in the certificate's supplemental data.
#[test]
fn test_tampered_power_diff_fails() {
    let power_table = load_initial_power_table();
    let mut certs = load_certificates();

    // Inject a bogus delta into the first certificate. Actor ID u64::MAX - 1
    // sorts after any real actor, keeping the diff sorted ascending by ID.
    certs[0].power_table_delta.push(PowerTableDelta {
        participant_id: u64::MAX - 1,
        power_delta: StoragePower::from(1_000_000),
        signing_key: PubKey::new(vec![0xAB; 48]),
    });

    let result = validate_finality_certificates(
        &BLSVerifier::new(),
        NetworkName::Mainnet,
        power_table,
        0,
        None,
        &certs,
    );

    assert!(
        matches!(result, Err(CertsError::IncorrectPowerDiff { instance: 0, .. })),
        "expected IncorrectPowerDiff, got: {:?}",
        result
    );
}

fn load_initial_power_table() -> PowerEntries {
    let path = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../f3initialpowertable_filecoin.json"
    );
    let json = std::fs::read_to_string(path).expect("f3initialpowertable_filecoin.json not found");
    let rpc_entries: Vec<rpc::PowerEntry> =
        serde_json::from_str(&json).expect("failed to parse initial power table");

    let entries = rpc_entries
        .into_iter()
        .map(rpc_to_internal::convert_power_entry)
        .collect::<Result<Vec<_>, _>>()
        .expect("failed to convert power table entries");

    PowerEntries(entries)
}

fn load_certificates() -> Vec<filecoin_f3_certs::FinalityCertificate> {
    let path = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/filecoin_certs.json"
    );
    let json = std::fs::read_to_string(path).expect("filecoin_certs.json not found");
    let rpc_certs: Vec<rpc::FinalityCertificate> =
        serde_json::from_str(&json).expect("failed to parse certificate fixtures");

    rpc_certs
        .into_iter()
        .map(rpc_to_internal::convert_certificate)
        .collect::<Result<Vec<_>, _>>()
        .expect("failed to convert certificates")
}
