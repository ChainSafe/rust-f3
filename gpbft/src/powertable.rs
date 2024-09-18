// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use crate::{ActorId, PubKey, StoragePower};
use ahash::HashMap;
use std::ops::{Deref, DerefMut};

/// Represents a participant's power and public key in the network
#[derive(Clone, Eq, PartialEq)]
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
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.power.cmp(&other.power) {
            std::cmp::Ordering::Greater => std::cmp::Ordering::Less,
            std::cmp::Ordering::Equal => other.id.cmp(&self.id),
            std::cmp::Ordering::Less => std::cmp::Ordering::Greater,
        }
    }
}

/// A collection of `PowerEntry` instances representing the power distribution in the network
pub struct PowerEntries(Vec<PowerEntry>);

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
