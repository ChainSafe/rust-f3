// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use crate::{ActorId, PubKey, StoragePower};
use ahash::HashMap;
use std::ops::{Deref, DerefMut};

#[derive(Clone, Eq, PartialEq)]
pub struct PowerEntry {
    pub id: ActorId,
    pub power: StoragePower,
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

pub struct PowerTable {
    pub entries: PowerEntries,
    pub scaled_power: Vec<u16>,
    pub lookup: HashMap<ActorId, usize>,
    pub total: StoragePower,
    pub scaled_total: u16,
}
