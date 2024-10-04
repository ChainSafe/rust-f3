use crate::chain::{Tipset, TIPSET_KEY_MAX_LEN};
use crate::{cid_from_bytes, PowerEntries, PowerEntry, PubKey};
use cid::Cid;

pub fn create_test_tipset(epoch: i64) -> Tipset {
    Tipset {
        epoch,
        key: vec![1; TIPSET_KEY_MAX_LEN / 2],
        power_table: Cid::default(),
        commitments: keccak_hash::H256::zero(),
    }
}

pub fn create_powertable() -> PowerEntries {
    let power_table = PowerEntries(vec![PowerEntry {
        id: 0,
        power: 1.into(),
        pub_key: PubKey::new(vec![1; 32]),
    }]);
    power_table
}

pub fn powertable_cid() -> anyhow::Result<Cid> {
    let powertable = create_powertable();
    let cbor = fvm_ipld_encoding::to_vec(&powertable)?;
    Ok(cid_from_bytes(&cbor))
}
