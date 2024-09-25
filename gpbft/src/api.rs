// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use crate::PubKey;

/// Verifier trait for signature verification in the GPBFT consensus protocol
pub trait Verifier {
    /// Error type. Once there is a concrete implementation of the `Verifier` trait,
    /// this might just be a concrete error type.
    type Error;
    /// Verifies a signature for the given public key
    ///
    /// This method must be safe for concurrent use.
    ///
    /// # Arguments
    /// * `pub_key` - The public key to verify against
    /// * `msg` - The message that was signed
    /// * `sig` - The signature to verify
    ///
    /// # Returns
    /// A Result indicating success or failure with an error message
    fn verify(&self, pub_key: &PubKey, msg: &[u8], sig: &[u8]) -> Result<(), Self::Error>;

    /// Aggregates signatures from participants
    ///
    /// # Arguments
    /// * `pub_keys` - The public keys of the signers
    /// * `sigs` - The signatures to aggregate
    ///
    /// # Returns
    /// A Result containing the aggregated signature
    fn aggregate(&self, pub_keys: &[PubKey], sigs: &[Vec<u8>]) -> Result<Vec<u8>, Self::Error>;

    /// Verifies an aggregate signature
    ///
    /// This method must be safe for concurrent use.
    ///
    /// # Arguments
    /// * `payload` - The payload that was signed
    /// * `agg_sig` - The aggregate signature to verify
    /// * `signers` - The public keys of the signers
    ///
    /// # Returns
    /// A Result indicating success or failure with an error message
    fn verify_aggregate(
        &self,
        payload: &[u8],
        agg_sig: &[u8],
        signers: &[PubKey],
    ) -> Result<(), Self::Error>;
}
