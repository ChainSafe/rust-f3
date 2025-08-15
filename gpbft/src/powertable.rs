// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use crate::{ActorId, PubKey, StoragePower};
use ahash::HashMap;
use anyhow::anyhow;
use num_traits::{ToPrimitive, Zero as NumZero};
use serde::Deserialize;
use fvm_ipld_encoding::tuple::{Deserialize_tuple, serde_tuple};
use std::ops::{Deref, DerefMut};

const MAX_POWER: i64 = 0xffff; // = 65535

/// Represents a participant's power and public key in the network
#[derive(Debug, Clone, Eq, PartialEq, Deserialize_tuple)]
pub struct PowerEntry {
    /// Unique identifier for the participant
    pub id: ActorId,
    /// The amount of storage power the participant has
    pub power: StoragePower,
    /// The public key of the participant
    pub pub_key: PubKey,
}

impl PartialOrd for PowerEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PowerEntry {
    // Note the ordering here. In order to mimic the behavior of the reference implementation,
    // we reverse the ordering of the power comparison to be able to use Rust's default sorting
    // algorithm.
    // Entries are sorted descending order of their power, where entries with equal power are
    // sorted by ascending order of their ID.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.power.cmp(&other.power) {
            std::cmp::Ordering::Greater => std::cmp::Ordering::Less,
            std::cmp::Ordering::Equal => self.id.cmp(&other.id),
            std::cmp::Ordering::Less => std::cmp::Ordering::Greater,
        }
    }
}

impl PowerEntry {
    /// Scales power proportionally within the total power.
    pub fn scale_power(&self, total: &StoragePower) -> anyhow::Result<i64> {
        if total < &self.power {
            return Err(anyhow!(
                "total power {} is less than the power of a single participant {}",
                total,
                self.power
            ));
        }

        let scaled = (&self.power * MAX_POWER) / total;
        Ok(scaled.to_i64().unwrap_or(0))
    }
}

/// A collection of `PowerEntry` instances representing the power distribution in the network
#[derive(Clone, Deserialize, PartialEq, Debug)]
#[serde(transparent)]
pub struct PowerEntries(pub Vec<PowerEntry>);

impl Deref for PowerEntries {
    type Target = Vec<PowerEntry>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for PowerEntries {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl FromIterator<PowerEntry> for PowerEntries {
    fn from_iter<T: IntoIterator<Item = PowerEntry>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl PowerEntries {
    /// Scales power entries proportionally within the total power
    pub fn scaled(&self) -> anyhow::Result<(Vec<i64>, i64)> {
        // First pass: calculate total unscaled power
        let mut total_unscaled = StoragePower::from(0);

        for entry in self.iter() {
            if entry.power <= NumZero::zero() {
                return Err(anyhow!(
                    "invalid non-positive power {} for participant {}",
                    entry.power,
                    entry.id
                ));
            }

            total_unscaled += &entry.power;
        }

        // Second pass: scale each power and accumulate total
        let mut scaled_powers = Vec::with_capacity(self.len());
        let mut scaled_total = 0;

        for entry in self.iter() {
            let scaled_power = entry.scale_power(&total_unscaled)?;
            scaled_powers.push(scaled_power);
            scaled_total += scaled_power;
        }

        Ok((scaled_powers, scaled_total))
    }

    /// Serialize power table entries to CBOR format
    pub fn serialize_cbor(&self) -> Vec<u8> {
        use serde_cbor::Value;

        let cbor_entries: Vec<Value> = self
            .0
            .iter()
            .map(|entry| {
                // Convert StoragePower to bytes like Go's big.Int.MarshalCBOR
                // Go adds a leading zero byte to the big-endian representation
                let power_bytes = {
                    let mut bytes = entry.power.to_bytes_be().1;
                    bytes.insert(0, 0);
                    bytes
                };

                Value::Array(vec![
                    Value::Integer(entry.id as i128),
                    Value::Bytes(power_bytes),
                    Value::Bytes(entry.pub_key.0.clone()),
                ])
            })
            .collect();

        let cbor_array = Value::Array(cbor_entries);
        serde_cbor::to_vec(&cbor_array).unwrap()
    }
}

/// Calculate the total power of a set of signers using their indices
pub fn signer_scaled_total(scaled_powers: &[i64], signer_indices: &[u64]) -> anyhow::Result<i64> {
    let mut signer_total = 0;
    for &index in signer_indices {
        let idx = index as usize;
        if idx < scaled_powers.len() {
            signer_total += scaled_powers[idx];
        }
    }

    Ok(signer_total)
}

/// Check whether a portion of storage power is a strong quorum of the total
pub fn is_strong_quorum(power: i64, power_total: i64) -> bool {
    power >= div_ceil(2 * power_total, 3)
}

/// Integer division with ceiling (rounds up)
fn div_ceil(a: i64, b: i64) -> i64 {
    if b == 0 {
        return 0;
    }
    let quo = a / b;
    let rem = a % b;
    if rem != 0 {
        quo + 1
    } else {
        quo
    }
}

/// Represents the power distribution and lookup table for actors in the network
pub struct PowerTable {
    /// Ordered list of power entries, maintained in descending order by power and ascending order by ID
    pub entries: PowerEntries,
    /// Scaled power values for each entry
    pub scaled_power: Vec<u16>,
    /// Maps `ActorId` to the index of the associated entry in entries
    pub lookup: HashMap<ActorId, usize>,
    /// Total storage power in the network
    pub total: StoragePower,
    /// Total scaled power in the network
    pub scaled_total: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cid_from_bytes;
    use std::cmp::Ordering;

    #[test]
    fn test_power_entry_ord() {
        let entry1 = PowerEntry {
            id: 1,
            power: StoragePower::from(100),
            pub_key: PubKey::new(vec![1, 2, 3]),
        };
        let entry2 = PowerEntry {
            id: 2,
            power: StoragePower::from(200),
            pub_key: PubKey::new(vec![4, 5, 6]),
        };
        let entry3 = PowerEntry {
            id: 3,
            power: StoragePower::from(100),
            pub_key: PubKey::new(vec![7, 8, 9]),
        };

        // Test ordering based on power
        assert_eq!(entry1.cmp(&entry2), Ordering::Greater);
        assert_eq!(entry2.cmp(&entry1), Ordering::Less);
        assert_eq!(entry1.cmp(&entry3), Ordering::Less);

        // Test sorting a vector of PowerEntry
        let mut entries = PowerEntries(vec![entry2.clone(), entry1.clone(), entry3.clone()]);
        entries.sort();
        assert_eq!(entries.deref(), &vec![entry2, entry1, entry3]);
    }

    #[test]
    fn test_calibrationnet_initial_powertable_cid() {
        let powertable = load_powertable("../f3initialpowertable_calibrationnet.json");
        let cbor_bytes = powertable.serialize_cbor();
        let cid = cid_from_bytes(&cbor_bytes);
        let expected_cid = load_cid_from_manifest("../f3manifest_calibrationnet.json");
        assert_eq!(cid.to_string(), expected_cid);
    }

    #[test]
    fn test_filecoin_initial_powertable_cid() {
        let powertable = load_powertable("../f3initialpowertable_filecoin.json");
        let cbor = powertable.serialize_cbor();
        let cid = cid_from_bytes(&cbor);
        let expected_cid = load_cid_from_manifest("../f3manifest_filecoin.json");
        assert_eq!(cid.to_string(), expected_cid);
    }

    /// Loads and parses power table entries from a JSON file
    fn load_powertable(path: &str) -> PowerEntries {
        use base64::Engine;
        use serde_json::Value;
        use std::fs;

        let json_content =
            fs::read_to_string(path).unwrap_or_else(|_| panic!("failed to read {}", path));

        let entries_json: Vec<Value> =
            serde_json::from_str(&json_content).expect("failed to parse JSON");

        // Convert JSON entries to PowerEntry structs
        let mut entries = Vec::new();
        for entry_json in entries_json {
            let id = entry_json["ID"].as_u64().expect("invalid ID");
            let power_str = entry_json["Power"].as_str().expect("invalid Power");
            let power = power_str.parse::<u64>().expect("failed to parse Power");
            let pubkey_b64 = entry_json["PubKey"].as_str().expect("invalid PubKey");
            let pubkey_bytes = base64::prelude::BASE64_STANDARD
                .decode(pubkey_b64)
                .expect("failed to decode base64 public key");

            entries.push(PowerEntry {
                id,
                power: StoragePower::from(power),
                pub_key: PubKey(pubkey_bytes),
            });
        }

        PowerEntries(entries)
    }

    /// Loads powertable expected CID from manifest file
    fn load_cid_from_manifest(path: &str) -> String {
        use serde_json::Value;
        use std::fs;

        let json_content =
            fs::read_to_string(path).unwrap_or_else(|_| panic!("failed to read {}", path));

        let manifest: Value =
            serde_json::from_str(&json_content).expect("failed to parse manifest JSON");

        manifest["InitialPowerTable"]["/"]
            .as_str()
            .expect("failed to extract CID from manifest")
            .to_string()
    }
}
