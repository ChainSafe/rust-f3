use filecoin_f3_gpbft::api::Verifier;
use filecoin_f3_gpbft::chain::Tipset;
use filecoin_f3_gpbft::{
    ActorId, BitField, ECChain, Justification, NetworkName, Phase, PowerEntries, PowerEntry,
    PubKey, Sign, StoragePower, SupplementalData, Zero,
};
use std::collections::HashMap;

pub struct PowerTableDelta {
    pub participant_id: ActorId,
    pub power_delta: StoragePower,
    pub signing_key: PubKey,
}

impl PowerTableDelta {
    pub fn is_zero(&self) -> bool {
        self.power_delta.is_zero() && self.signing_key.is_empty()
    }
}

pub type PowerTableDiff = Vec<PowerTableDelta>;

pub struct FinalityCertificate {
    pub gpbft_instance: u64,
    pub ec_chain: ECChain,
    pub supplemental_data: SupplementalData,
    pub signers: BitField,
    pub signature: Vec<u8>,
    pub power_table_delta: PowerTableDiff,
}

impl FinalityCertificate {
    pub fn new(power_delta: PowerTableDiff, justification: &Justification) -> Result<Self, String> {
        if justification.vote.step != Phase::Decide {
            return Err(format!(
                "can only create a finality certificate from a decide vote, got phase {:?}",
                justification.vote.step
            ));
        }

        if justification.vote.round != 0 {
            return Err(format!(
                "expected decide round to be 0, got round {}",
                justification.vote.round
            ));
        }

        if justification.vote.value.is_empty() {
            return Err(format!(
                "got a decision for bottom for instance {}",
                justification.vote.instance
            ));
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
// WIP
// pub fn validate_finality_certificates(
//     verifier: &dyn Verifier,
//     network: &NetworkName,
//     prev_power_table: PowerEntries,
//     next_instance: u64,
//     base: Option<&Tipset>,
//     certs: &[FinalityCertificate],
// ) -> Result<(u64, ECChain, PowerEntries), String> {
//     let mut next_instance = next_instance;
//     let mut chain = ECChain::new();
//     let mut prev_power_table = prev_power_table;
//     let mut base = base;
//
//     for cert in certs {
//         if cert.gpbft_instance != next_instance {
//             return Err(format!("expected instance {}, found instance {}", next_instance, cert.gpbft_instance));
//         }
//
//         if let Err(e) = cert.ec_chain.validate() {
//             return Err(format!("invalid finality certificate at instance {}: {}", cert.gpbft_instance, e));
//         }
//
//         if cert.ec_chain.is_zero() {
//             return Err(format!("empty finality certificate for instance {}", cert.gpbft_instance));
//         }
//
//         if let Some(b) = base {
//             if !b.equal(cert.ec_chain.base()) {
//                 return Err(format!("base tipset does not match finalized chain at instance {}", cert.gpbft_instance));
//             }
//         }
//
//         verifyFinalityCertificateSignature(verifier, &prev_power_table, network, cert)?;
//
//         let new_power_table = ApplyPowerTableDiffs(&prev_power_table, &cert.power_table_delta)?;
//
//         let power_table_cid = MakePowerTableCID(&new_power_table)?;
//
//         if cert.supplemental_data.power_table != power_table_cid {
//             return Err(format!(
//                 "incorrect power diff from finality certificate for instance {}: expected {:?}, got {:?}",
//                 cert.gpbft_instance, cert.supplemental_data.power_table, power_table_cid
//             ));
//         }
//
//         next_instance += 1;
//         chain.extend(cert.ec_chain.suffix());
//         prev_power_table = new_power_table;
//         base = Some(cert.ec_chain.head());
//     }
//
//     Ok((next_instance, chain, prev_power_table))
// }

pub fn apply_power_table_diffs(
    prev_power_table: &PowerEntries,
    diffs: &[PowerTableDiff],
) -> Result<PowerEntries, String> {
    let mut power_table_map: HashMap<ActorId, PowerEntry> = prev_power_table
        .iter()
        .map(|pe| (pe.id, pe.clone()))
        .collect();

    for (j, diff) in diffs.iter().enumerate() {
        let mut last_actor_id = 0;
        for (i, d) in diff.iter().enumerate() {
            if i > 0 && d.participant_id <= last_actor_id {
                return Err(format!("diff {} not sorted by participant ID", j));
            }

            if d.is_zero() {
                return Err(format!(
                    "diff {} contains an empty delta for participant {}",
                    j, d.participant_id
                ));
            }

            last_actor_id = d.participant_id;

            if !power_table_map.contains_key(&d.participant_id) {
                if d.power_delta <= StoragePower::from(0) {
                    return Err(format!("diff {} includes a new entry with a non-positive power delta for participant {}", j, d.participant_id));
                }
            }

            let pe = power_table_map
                .entry(d.participant_id)
                .or_insert_with(|| PowerEntry {
                    id: d.participant_id,
                    power: StoragePower::from(0),
                    pub_key: Vec::new(),
                });

            // This implicitly checks the key for emptiness on a new entry, because that is the
            // default.
            if pe.pub_key == d.signing_key {
                return Err(format!(
                    "diff {} delta for participant {} includes an unchanged key",
                    j, pe.id
                ));
            }

            if !d.power_delta.is_zero() {
                pe.power += &d.power_delta;
            }

            if !d.signing_key.is_empty() {
                // This condition will never be true for a new entry.
                if pe.power.is_zero() {
                    return Err(format!(
                        "diff {} removes all power for participant {} while specifying a new key",
                        j, pe.id
                    ));
                }
                pe.pub_key = d.signing_key.clone();
            }

            match pe.power.sign() {
                Sign::Minus => {
                    return Err(format!(
                        "diff {} resulted in negative power for participant {}",
                        j, pe.id
                    ))
                }
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