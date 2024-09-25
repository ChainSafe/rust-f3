// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use crate::{ActorId, PubKey, StoragePower};
use ahash::HashMap;
use std::ops::{Deref, DerefMut};

/// Represents a participant's power and public key in the network
#[derive(Debug, Clone, Eq, PartialEq)]
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

/// A collection of `PowerEntry` instances representing the power distribution in the network
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
    use std::cmp::Ordering;

    #[test]
    fn test_power_entry_create() {
        let id = 1;
        let power = StoragePower::from(100);
        let pub_key = PubKey::new(vec![1, 2, 3]);
        let entry = PowerEntry {
            id,
            power: power.clone(),
            pub_key: pub_key.clone(),
        };

        assert_eq!(entry.id, id);
        assert_eq!(entry.power, power);
        assert_eq!(entry.pub_key, pub_key);
    }

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
}
