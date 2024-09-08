/// CHAIN_MAX_LEN specifies the maximum length of a chain value.
pub const CHAIN_MAX_LEN: usize = 100;

/// CID_MAX_LEN specifies the maximum length of a CID.
pub const CID_MAX_LEN: usize = 38;

/// TIPSET_KEY_MAX_LEN specifies the maximum length of a tipset. The max size is
/// chosen such that it allows ample space for an impossibly-unlikely number of
/// blocks in a tipset, while maintaining a practical limit to prevent abuse.
pub const TIPSET_KEY_MAX_LEN: usize = 20 * CID_MAX_LEN;

pub type TipsetKey = Vec<u8>;

pub type Cid = Vec<u8>;

// Tipset represents a single EC tipset.
#[derive(Clone, PartialEq, Eq)]
pub struct Tipset {
    /// The EC epoch (strictly increasing).
    pub epoch: i64,
    /// The tipset key (canonically ordered concatenated block-header CIDs).
    pub key: TipsetKey,
    /// Blake2b256-32 CID of the CBOR-encoded power table.
    pub power_table: Cid,
    /// Keccak256 root hash of the commitments merkle tree.
    pub commitments: keccak_hash::H256,
}

impl Tipset {
    pub fn validate(&self) -> Result<(), String> {
        if self.key.is_empty() {
            return Err("tipset key must not be empty".to_string());
        }
        if self.key.len() > TIPSET_KEY_MAX_LEN {
            return Err("tipset key too long".to_string());
        }
        if self.power_table.is_empty() {
            return Err("power table CID must not be empty".to_string());
        }
        if self.power_table.len() > CID_MAX_LEN {
            return Err("power table CID too long".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ECChain(Vec<Tipset>);

impl std::ops::Deref for ECChain {
    type Target = Vec<Tipset>;
    fn deref(&self) -> &Vec<Tipset> {
        &self.0
    }
}
impl ECChain {
    pub fn validate(&self) -> anyhow::Result<(), String> {
        if self.is_empty() {
            return Ok(());
        }
        if self.len() > CHAIN_MAX_LEN {
            return Err("chain too long".to_string());
        }
        let mut last_epoch: i64 = -1;
        for (i, ts) in self.iter().enumerate() {
            ts.validate().map_err(|e| format!("tipset {}: {}", i, e))?;
            if ts.epoch <= last_epoch {
                return Err(format!("chain must have increasing epochs {} <= {}", ts.epoch, last_epoch));
            }
            last_epoch = ts.epoch;
        }
        Ok(())
    }
}
