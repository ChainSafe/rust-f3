// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

mod error;

use crate::error::CertsError;
use crate::error::CertsError::UnsortedDiff;
/// The `certs` package provides functionality for handling finality certificates in the GPBFT consensus protocol.
///
/// This package includes:
/// - Structures and types for representing finality certificates and power table changes
/// - Functions for creating and applying power table diffs
/// - Methods for verifying finality certificates
///
/// Key components:
/// - `FinalityCertificate`: Represents a single finalized GPBFT instance
/// - `PowerTableDelta`: Represents a change in power for a single participant
/// - `PowerTableDiff`: A collection of power table deltas
///
/// The package allows for:
/// - Creating new finality certificates from justifications
/// - Applying power table diffs to update the network's power distribution
/// - Verifying the signatures of finality certificates
///
/// Note: The signature verification only checks that the certificate's value has been signed by a majority
/// of the power. It does not validate the power delta or other parts of the certificate.
use ahash::HashMap;
use filecoin_f3_gpbft::api::Verifier;
use filecoin_f3_gpbft::chain::Tipset;
use filecoin_f3_gpbft::{
    cid_from_bytes, to_vec_cbor, ActorId, BitField, ECChain, Justification, NetworkName, Phase,
    PowerEntries, PowerEntry, PubKey, Sign, StoragePower, SupplementalData, Zero,
};
use std::ops::Neg;

type Result<T> = std::result::Result<T, error::CertsError>;

/// `PowerTableDelta` represents a single power table change between GPBFT instances. If the resulting
/// power is 0 after applying the delta, the participant is removed from the power table.
#[derive(Debug)]
pub struct PowerTableDelta {
    /// Participant with changed power
    pub participant_id: ActorId,
    /// Change in power from base (signed)
    pub power_delta: StoragePower,
    /// New signing key if relevant (else empty)
    pub signing_key: PubKey,
}

impl PowerTableDelta {
    /// Checks if the power delta is zero (no change)
    ///
    /// Returns true if both the `power_delta` is zero and the `signing_key` is empty,
    /// indicating no change for this participant.
    pub fn is_zero(&self) -> bool {
        self.power_delta.is_zero() && self.signing_key.is_empty()
    }
}

/// Represents a set of changes to the power table
///
/// `PowerTableDiff` is a collection of individual power table deltas, each representing
/// a change in power or signing key for a specific participant in the network.
/// It is used to track and apply changes to the power table between GPBFT instances.
pub type PowerTableDiff = Vec<PowerTableDelta>;

/// Represents a single finalized GPBFT instance
#[derive(Debug)]
pub struct FinalityCertificate {
    /// The GPBFT instance to which this finality certificate corresponds
    pub gpbft_instance: u64,
    /// The ECChain finalized during this instance, starting with the last tipset finalized in
    /// the previous instance
    pub ec_chain: ECChain,
    /// Additional data signed by the participants in this instance. Currently used to certify
    /// the power table used in the next instance
    pub supplemental_data: SupplementalData,
    /// Indexes in the base power table of the `certifiers` (`bitset`)
    pub signers: BitField,
    /// Aggregated signature of the `certifiers`
    pub signature: Vec<u8>,
    /// Changes between the power table used to validate this finality certificate and the power
    /// used to validate the next finality certificate. Sorted by `ParticipantID`, ascending
    pub power_table_delta: PowerTableDiff,
}

impl FinalityCertificate {
    /// Creates a new `FinalityCertificate` from a `PowerTableDiff` and a Justification
    ///
    /// # Arguments
    /// * `power_delta` - The changes in the power table
    /// * `justification` - The justification for the decision
    ///
    /// # Returns
    /// A Result containing the new `FinalityCertificate` if successful
    pub fn new(power_delta: PowerTableDiff, justification: &Justification) -> Result<Self> {
        if justification.vote.step != Phase::Decide {
            return Err(CertsError::InvalidJustification(
                justification.vote.step.to_string(),
            ));
        }

        if justification.vote.round != 0 {
            return Err(CertsError::InvalidRound(justification.vote.round));
        }

        if justification.vote.value.is_empty() {
            return Err(CertsError::BottomDecision(justification.vote.instance));
        }

        Ok(FinalityCertificate {
            gpbft_instance: justification.vote.instance,
            supplemental_data: justification.vote.supplemental_data.clone(),
            ec_chain: justification.vote.value.clone(),
            signers: justification.signers.clone(),
            signature: justification.signature.clone(),
            power_table_delta: power_delta,
        })
    }
}

/// Apply a set of power table diffs to the passed power table.
///
/// - The delta must be sorted by participant ID, ascending.
/// - The returned power table is sorted by power, descending.
pub fn apply_power_table_diffs(
    prev_power_table: &PowerEntries,
    diffs: &[&PowerTableDiff],
) -> Result<PowerEntries> {
    let mut power_table_map: HashMap<ActorId, PowerEntry> = prev_power_table
        .iter()
        .map(|pe| (pe.id, pe.clone()))
        .collect();

    for (j, diff) in diffs.iter().enumerate() {
        let mut last_actor_id = 0;
        for (i, d) in diff.iter().enumerate() {
            // We assert this to make sure the finality certificate has a consistent power-table
            // diff.
            if i > 0 && d.participant_id <= last_actor_id {
                return Err(UnsortedDiff(j));
            }

            // Empty power diffs aren't allowed.
            if d.is_zero() {
                return Err(CertsError::EmptyDelta(j, d.participant_id));
            }

            last_actor_id = d.participant_id;

            if !power_table_map.contains_key(&d.participant_id) {
                // New power entries must specify positive power.
                if d.power_delta <= StoragePower::from(0) {
                    return Err(CertsError::NonPositivePowerDeltaForNewEntry(
                        j,
                        d.participant_id,
                    ));
                }
            }

            let pe = power_table_map
                .entry(d.participant_id)
                .or_insert_with(|| PowerEntry {
                    id: d.participant_id,
                    power: StoragePower::from(0),
                    pub_key: PubKey::default(),
                });

            // Power deltas can't replace a key with the same key.
            // This also implicitly checks the key for emptiness on a new entry, because that is the
            // default.
            if pe.pub_key == d.signing_key {
                return Err(CertsError::UnchangedKey(j, pe.id));
            }

            if !d.power_delta.is_zero() {
                pe.power += &d.power_delta;
            }

            if !d.signing_key.is_empty() {
                // If we end up with no power, we shouldn't replace the key.
                // This condition will never be true for a new entry.
                if pe.power.is_zero() {
                    return Err(CertsError::RemovesAllPowerWithNewKey(j, pe.id));
                }
                pe.pub_key = d.signing_key.clone();
            }

            match pe.power.sign() {
                Sign::Minus => return Err(CertsError::NegativePower(j, pe.id)),
                Sign::NoSign => {
                    power_table_map.remove(&d.participant_id);
                }
                Sign::Plus => {
                    // Already inserted, nothing to do.
                }
            }
        }
    }

    let mut new_power_table: PowerEntries = power_table_map.into_values().collect();
    new_power_table.sort();
    Ok(new_power_table)
}

/// Create a power table diff between the two given power tables. It makes no assumptions about
/// order, but does assume that the power table entries are unique. The returned diff is sorted by
/// participant ID ascending.
pub fn make_power_table_diff(
    old_power_table: &PowerEntries,
    new_power_table: &PowerEntries,
) -> PowerTableDiff {
    let mut old_power_map: HashMap<ActorId, &PowerEntry> =
        old_power_table.iter().map(|e| (e.id, e)).collect();

    let mut diff = PowerTableDiff::new();

    for new_entry in new_power_table.iter() {
        let mut delta = PowerTableDelta {
            participant_id: new_entry.id,
            power_delta: StoragePower::from(0),
            signing_key: PubKey::default(),
        };

        let delta = match old_power_map.remove(&new_entry.id) {
            Some(old_entry) => {
                delta.power_delta = &new_entry.power - &old_entry.power;
                if new_entry.pub_key != old_entry.pub_key {
                    delta.signing_key = new_entry.pub_key.clone();
                }
                delta
            }
            None => {
                delta.power_delta = new_entry.power.clone();
                delta.signing_key = new_entry.pub_key.clone();
                delta
            }
        };

        if !delta.is_zero() {
            diff.push(delta);
        }
    }

    for old_entry in old_power_map.values() {
        diff.push(PowerTableDelta {
            participant_id: old_entry.id,
            power_delta: old_entry.power.clone().neg(),
            signing_key: PubKey::default(),
        });
    }

    diff.sort_by_key(|delta| delta.participant_id);
    diff
}

/// Validates a sequence of finality certificates.
///
/// This function checks the validity of a series of finality certificates, ensuring they form a
/// consistent chain and that the power table changes are correctly applied and verified.
///
/// # Arguments
/// * `verifier` - The signature verifier implementation
/// * `network` - The network name
/// * `prev_power_table` - The initial power table
/// * `next_instance` - The expected next instance number
/// * `base` - The optional base tipset
/// * `certs` - The sequence of finality certificates to validate
///
/// # Returns
/// A Result containing a tuple of:
/// * The next instance number
/// * The validated ECChain
/// * The final power table after applying all changes
///
/// # Errors
/// Returns a `CertsError` if any validation step fails, including instance mismatches,
/// invalid certificates, power table inconsistencies, or serialization errors.
///
/// # Note: verifier and network are currently unused, but are expected to be used once the crypto
/// library has been ported.
#[allow(unused)]
pub fn validate_finality_certificates<'a>(
    verifier: impl Verifier,
    network: &NetworkName,
    prev_power_table: PowerEntries,
    mut next_instance: u64,
    mut base: Option<&'a Tipset>,
    certs: &'a [FinalityCertificate],
) -> Result<(u64, ECChain, PowerEntries)> {
    let mut chain: Option<ECChain> = None;
    let mut current_power_table = prev_power_table;

    for cert in certs {
        if cert.gpbft_instance != next_instance {
            return Err(CertsError::InstanceMismatch {
                expected: next_instance,
                found: cert.gpbft_instance,
            });
        }

        // Basic sanity checks
        if let Err(e) = cert.ec_chain.validate() {
            return Err(CertsError::InvalidFinalityCertificate(
                cert.gpbft_instance,
                e,
            ));
        }

        if cert.ec_chain.is_empty() {
            return Err(CertsError::EmptyFinalityCertificate(cert.gpbft_instance));
        }

        // Validate base tipset if specified
        if base.is_some() && base != cert.ec_chain.base() {
            return Err(CertsError::BaseTipsetMismatch(cert.gpbft_instance));
        }

        // Compute new power table and validate
        let new_power_table =
            apply_power_table_diffs(&current_power_table, &[&cert.power_table_delta])?;

        let bytes = to_vec_cbor(&new_power_table)?;
        let power_table_cid = cid_from_bytes(&bytes);

        if cert.supplemental_data.power_table != power_table_cid {
            return Err(CertsError::IncorrectPowerDiff {
                instance: cert.gpbft_instance,
                expected: cert.supplemental_data.power_table.to_string(),
                got: power_table_cid.to_string(),
            });
        }

        next_instance += 1;
        if cert.ec_chain.has_suffix() {
            chain = match chain {
                Some(existing) => existing.extend(
                    &cert
                        .ec_chain
                        .suffix()
                        .iter()
                        .map(|ts| ts.key.clone())
                        .collect::<Vec<_>>(),
                ),
                None => Some(ECChain::new_unvalidated(cert.ec_chain.suffix().to_vec())),
            };
        }

        current_power_table = new_power_table;
        base = cert.ec_chain.head();
    }

    Ok((
        next_instance,
        chain.ok_or(CertsError::EmptyChain)?,
        current_power_table,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use filecoin_f3_gpbft::chain::Tipset;
    use filecoin_f3_gpbft::test_utils::powertable_cid;
    use filecoin_f3_gpbft::Payload;

    fn create_mock_justification(step: Phase) -> anyhow::Result<Justification> {
        let base_tipset = Tipset {
            epoch: 1,
            key: vec![1, 2, 3],
            power_table: powertable_cid()?,
            commitments: keccak_hash::H256::zero(),
        };
        let j = Justification {
            vote: Payload {
                instance: 1,
                round: 0,
                step,
                supplemental_data: SupplementalData {
                    commitments: keccak_hash::H256::zero(),
                    power_table: powertable_cid()?,
                },
                value: ECChain::new(base_tipset, vec![]).unwrap(),
            },
            signers: BitField::new(),
            signature: vec![7, 8, 9],
        };
        Ok(j)
    }

    #[test]
    fn test_power_table_delta_is_zero() {
        let zero_delta = PowerTableDelta {
            participant_id: 1,
            power_delta: StoragePower::from(0),
            signing_key: PubKey::default(),
        };
        assert!(zero_delta.is_zero());

        let non_zero_power_delta = PowerTableDelta {
            participant_id: 1,
            power_delta: StoragePower::from(100),
            signing_key: PubKey::default(),
        };
        assert!(!non_zero_power_delta.is_zero());

        let non_zero_key_delta = PowerTableDelta {
            participant_id: 1,
            power_delta: StoragePower::from(0),
            signing_key: PubKey::new(vec![1, 2, 3]),
        };
        assert!(!non_zero_key_delta.is_zero());
    }

    #[test]
    fn test_finality_certificate_new_success() -> anyhow::Result<()> {
        let power_delta = PowerTableDiff::new();
        let justification = create_mock_justification(Phase::Decide)?;

        let result = FinalityCertificate::new(power_delta, &justification);
        assert!(result.is_ok());

        let cert = result.unwrap();
        assert_eq!(cert.gpbft_instance, justification.vote.instance);
        assert_eq!(cert.ec_chain, justification.vote.value);
        assert_eq!(cert.supplemental_data, justification.vote.supplemental_data);
        assert_eq!(cert.signers, justification.signers);
        assert_eq!(cert.signature, justification.signature);
        Ok(())
    }

    #[test]
    fn test_finality_certificate_new_wrong_phase() -> anyhow::Result<()> {
        let power_delta = PowerTableDiff::new();
        let justification = create_mock_justification(Phase::Commit);

        let result = FinalityCertificate::new(power_delta, &justification?);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            CertsError::InvalidJustification(Phase::Commit.to_string())
        );
        Ok(())
    }

    #[test]
    fn test_finality_certificate_new_wrong_round() -> anyhow::Result<()> {
        let power_delta = PowerTableDiff::new();
        let mut justification = create_mock_justification(Phase::Decide)?;
        justification.vote.round = 1;

        let result = FinalityCertificate::new(power_delta, &justification);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CertsError::InvalidRound(1));
        Ok(())
    }

    // It makes no sense that ECChain can be empty. Perhaps this warrants a discussion.
    #[test]
    fn test_finality_certificate_new_empty_value() -> anyhow::Result<()> {
        let power_delta = PowerTableDiff::new();
        let mut justification = create_mock_justification(Phase::Decide)?;
        justification.vote.value = ECChain::new_unvalidated(Vec::new());

        let result = FinalityCertificate::new(power_delta, &justification);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CertsError::BottomDecision(1));
        Ok(())
    }

    #[test]
    fn test_make_power_table_diff() {
        let old_power_table = vec![
            PowerEntry {
                id: 1,
                power: StoragePower::from(100),
                pub_key: PubKey::new(vec![1, 2, 3]),
            },
            PowerEntry {
                id: 2,
                power: StoragePower::from(200),
                pub_key: PubKey::new(vec![4, 5, 6]),
            },
        ];
        let new_power_table = vec![
            PowerEntry {
                id: 1,
                power: StoragePower::from(150),
                pub_key: PubKey::new(vec![1, 2, 3]),
            },
            PowerEntry {
                id: 3,
                power: StoragePower::from(300),
                pub_key: PubKey::new(vec![7, 8, 9]),
            },
        ];

        let diff = make_power_table_diff(
            &PowerEntries(old_power_table),
            &PowerEntries(new_power_table),
        );

        assert_eq!(diff.len(), 3);
        assert_eq!(diff[0].participant_id, 1);
        assert_eq!(diff[0].power_delta, StoragePower::from(50));
        assert!(diff[0].signing_key.is_empty());
        assert_eq!(diff[1].participant_id, 2);
        assert_eq!(diff[1].power_delta, StoragePower::from(-200));
        assert!(diff[1].signing_key.is_empty());
        assert_eq!(diff[2].participant_id, 3);
        assert_eq!(diff[2].power_delta, StoragePower::from(300));
        assert_eq!(diff[2].signing_key, PubKey::new(vec![7, 8, 9]));
    }

    #[test]
    fn test_apply_power_table_diffs() {
        let prev_power_table = vec![
            PowerEntry {
                id: 1,
                power: StoragePower::from(100),
                pub_key: PubKey::new(vec![1, 2, 3]),
            },
            PowerEntry {
                id: 2,
                power: StoragePower::from(200),
                pub_key: PubKey::new(vec![4, 5, 6]),
            },
        ];
        let diff_one = vec![
            PowerTableDelta {
                participant_id: 1,
                power_delta: StoragePower::from(50),
                signing_key: PubKey::default(),
            },
            PowerTableDelta {
                participant_id: 3,
                power_delta: StoragePower::from(300),
                signing_key: PubKey::new(vec![7, 8, 9]),
            },
        ];

        let diff_two = vec![PowerTableDelta {
            participant_id: 2,
            power_delta: StoragePower::from(-200),
            signing_key: PubKey::default(),
        }];

        let diffs = vec![&diff_one, &diff_two];

        let result = apply_power_table_diffs(&PowerEntries(prev_power_table), &diffs).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].id, 3);
        assert_eq!(result[0].power, StoragePower::from(300));
        assert_eq!(result[0].pub_key, PubKey::new(vec![7, 8, 9]));
        assert_eq!(result[1].id, 1);
        assert_eq!(result[1].power, StoragePower::from(150));
        assert_eq!(result[1].pub_key, PubKey::new(vec![1, 2, 3]));
    }
}
