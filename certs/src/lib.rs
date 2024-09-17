use ahash::HashMap;
use filecoin_f3_gpbft::{
    ActorId, BitField, ECChain, Justification, Phase, PowerEntries, PowerEntry, PubKey, Sign,
    StoragePower, SupplementalData, Zero,
};
use std::ops::Neg;

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

/// Apply a set of power table diffs to the passed power table.
///
/// - The delta must be sorted by participant ID, ascending.
/// - The returned power table is sorted by power, descending.
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
            // We assert this to make sure the finality certificate has a consistent power-table
            // diff.
            if i > 0 && d.participant_id <= last_actor_id {
                return Err(format!("diff {} not sorted by participant ID", j));
            }

            // Empty power diffs aren't allowed.
            if d.is_zero() {
                return Err(format!(
                    "diff {} contains an empty delta for participant {}",
                    j, d.participant_id
                ));
            }

            last_actor_id = d.participant_id;

            if !power_table_map.contains_key(&d.participant_id) {
                // New power entries must specify positive power.
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

            // Power deltas can't replace a key with the same key.
            // This also implicitly checks the key for emptiness on a new entry, because that is the
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
                // If we end up with no power, we shouldn't replace the key.
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
            signing_key: Vec::new(),
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
            signing_key: Vec::new(),
        });
    }

    diff.sort_by_key(|delta| delta.participant_id);
    diff
}
