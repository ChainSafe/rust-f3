// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use crate::chain::{Tipset, TIPSET_KEY_MAX_LEN};
use crate::{cid_from_bytes, PowerEntries, PowerEntry, PubKey};
use cid::Cid;

pub fn create_test_tipset(epoch: i64) -> Tipset {
    Tipset {
        epoch,
        key: vec![1; TIPSET_KEY_MAX_LEN / 2],
        // Unwrap is fine here as `powertable_cid` should never fail.
        power_table: powertable_cid().unwrap(),
        commitments: keccak_hash::H256::zero(),
    }
}

pub fn create_powertable() -> PowerEntries {
    PowerEntries(vec![PowerEntry {
        id: 0,
        power: 1.into(),
        pub_key: PubKey::new(vec![1; 32]),
    }])
}

pub fn powertable_cid() -> anyhow::Result<Cid> {
    let powertable = create_powertable();
    let cbor = fvm_ipld_encoding::to_vec(&powertable)?;
    Ok(cid_from_bytes(&cbor))
}
