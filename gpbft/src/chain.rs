use anyhow::anyhow;
use std::fmt::Display;
use std::{cmp, fmt};

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

/// A map key for a chain. The zero value means "bottom".
/// Note that in reference Go implementation this is a string, but we use
/// a byte slice here as in Rust a string is assumed to be UTF-8 encoded.
type ChainKey = Vec<u8>;

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

    pub fn is_empty(&self) -> bool {
        self.key.is_empty()
    }
}

impl fmt::Display for Tipset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let enc_ts = base32::encode(base32::Alphabet::Rfc4648 { padding: true }, &self.key);
        let display_len = cmp::min(16, enc_ts.len());
        write!(f, "{}@{}", &enc_ts[..display_len], self.epoch)
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

impl std::ops::DerefMut for ECChain {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl ECChain {
    pub fn new(ts: Vec<Tipset>) -> Self {
        ECChain(ts)
    }
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
                return Err(format!(
                    "chain must have increasing epochs {} <= {}",
                    ts.epoch, last_epoch
                ));
            }
            last_epoch = ts.epoch;
        }
        Ok(())
    }

    pub fn has_suffix(&self) -> bool {
        !self.suffix().is_empty()
    }

    pub fn base(&self) -> Option<&Tipset> {
        self.first()
    }

    pub fn suffix(&self) -> &[Tipset] {
        if self.is_empty() {
            &[]
        } else {
            &self[1..]
        }
    }

    pub fn base_chain(&self) -> Option<ECChain> {
        self.base().map(|ts| ECChain(vec![ts.clone()]))
    }

    pub fn extend(&self, tips: &[TipsetKey]) -> Option<ECChain> {
        let mut new_chain = self.clone();
        let mut offset = self.last()?.epoch + 1;
        let pt = self.last()?.power_table.clone();
        for tip in tips {
            new_chain.push(Tipset {
                epoch: offset,
                key: tip.clone(),
                power_table: pt.clone(),
                commitments: keccak_hash::H256::zero(),
            });
            offset += 1;
        }
        Some(new_chain)
    }

    pub fn prefix(&self, to: usize) -> anyhow::Result<ECChain> {
        if self.is_empty() {
            return Err(anyhow!("can't get prefix from zero-valued chain"));
        }
        let length = cmp::min(to + 1, self.len());
        Ok(ECChain(self[..length].to_vec()))
    }

    pub fn same_base(&self, other: &ECChain) -> bool {
        !self.is_empty() && !other.is_empty() && self.base() == other.base()
    }

    pub fn has_base(&self, t: &Tipset) -> bool {
        if t.is_empty() || self.is_empty() {
            return false;
        }

        if let Some(base) = self.base() {
            return base == t;
        }

        false
    }

    pub fn has_prefix(&self, other: &ECChain) -> bool {
        if self.is_empty() || other.is_empty() {
            return false;
        }
        if other.len() > self.len() {
            return false;
        }

        self[..other.len()] == other[..]
    }

    pub fn has_tipset(&self, t: &Tipset) -> bool {
        !t.is_empty() && self.contains(t)
    }

    pub fn key(&self) -> ChainKey {
        let mut capacity = self.len() * (8 + 32 + 4); // epoch + commitment + ts length
        for ts in self.iter() {
            capacity += ts.key.len() + ts.power_table.len();
        }
        let mut buf = Vec::with_capacity(capacity);
        for ts in self.iter() {
            buf.extend_from_slice(&ts.epoch.to_be_bytes());
            buf.extend_from_slice(&ts.commitments.0);
            buf.extend_from_slice(&(ts.key.len() as u32).to_be_bytes());
            buf.extend_from_slice(&ts.key);
            buf.extend_from_slice(&ts.power_table);
        }
        buf
    }
}

impl Display for ECChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_empty() {
            return write!(f, "丄");
        }
        let mut result = String::from("[");
        for (i, ts) in self.iter().enumerate() {
            result.push_str(&ts.to_string());
            if i < self.len() - 1 {
                result.push_str(", ");
            }
            if result.len() > 77 {
                result.push_str("...");
                break;
            }
        }
        result.push(']');
        write!(f, "{}", result)
    }
}
