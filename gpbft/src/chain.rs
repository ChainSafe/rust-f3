// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use crate::GPBFTError;
pub use cid::Cid;
use cid::multihash::Code::Blake2b256;
use cid::multihash::MultihashDigest;
use fvm_ipld_encoding::DAG_CBOR;
use std::fmt::Display;
use std::{cmp, fmt};

/// `CHAIN_MAX_LEN` specifies the maximum length of a chain value.
pub const CHAIN_MAX_LEN: usize = 100;

/// `CID_MAX_LEN` specifies the maximum length of a CID.
pub const CID_MAX_LEN: usize = 38;

/// `TIPSET_KEY_MAX_LEN` specifies the maximum length of a tipset. The max size is
/// chosen such that it allows ample space for an impossibly-unlikely number of
/// blocks in a tipset, while maintaining a practical limit to prevent abuse.
pub const TIPSET_KEY_MAX_LEN: usize = 20 * CID_MAX_LEN;

pub type TipsetKey = Vec<u8>;

/// A map key for a chain. The zero value means "bottom".
/// Note that in reference Go implementation this is a string, but we use
/// a byte slice here as in Rust a string is assumed to be UTF-8 encoded.
type ChainKey = Vec<u8>;

/// Tipset represents a single EC tipset.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
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
    /// Validates the tipset
    ///
    /// Checks if the tipset key is not empty and not too long,
    /// and if the power table CID is not empty and not too long.
    ///
    /// # Returns
    /// A Result indicating success or failure with an error message
    pub fn validate(&self) -> crate::Result<()> {
        if self.key.is_empty() {
            return Err(GPBFTError::TipsetKeyEmpty);
        }
        if self.key.len() > TIPSET_KEY_MAX_LEN {
            return Err(GPBFTError::TipsetKeyTooLong {
                len: self.key.len(),
                max_len: TIPSET_KEY_MAX_LEN,
            });
        }
        if self.power_table == Cid::default() {
            return Err(GPBFTError::PowerTableCidEmpty);
        }
        if self.power_table.encoded_len() > CID_MAX_LEN {
            return Err(GPBFTError::PowerTableCidTooLong {
                len: self.power_table.encoded_len(),
                max_len: CID_MAX_LEN,
            });
        }
        Ok(())
    }

    /// Checks if the tipset is empty
    pub fn is_empty(&self) -> bool {
        self.key.is_empty()
    }

    /// Serializes for signing
    /// Returns bytes in this exact order:
    /// 1. epoch (8 bytes, big-endian)
    /// 2. commitments (32 bytes)  
    /// 3. tipset_cid
    /// 4. power_table_cid
    pub fn serialize_for_signing(&self) -> Vec<u8> {
        // CBOR-encode the tipset key using serde_cbor to match go-f3's cbg.WriteByteArray
        use serde_cbor::Value;
        let cbor_value = Value::Bytes(self.key.clone());
        let cbor_bytes = serde_cbor::to_vec(&cbor_value).unwrap();
        let tipset_cid = cid_from_bytes(&cbor_bytes);

        // Calculate capacity: 8 + 32 + tipset_cid + power_table_cid
        let mut buf =
            Vec::with_capacity(8 + 32 + tipset_cid.encoded_len() + self.power_table.encoded_len());

        // epoch || commitments || tipset_cid || power_table_cid
        buf.extend_from_slice(&self.epoch.to_be_bytes()); // 8 bytes
        buf.extend_from_slice(&self.commitments.0); // 32 bytes
        buf.extend_from_slice(&tipset_cid.to_bytes());
        buf.extend_from_slice(&self.power_table.to_bytes());

        buf
    }
}

impl fmt::Display for Tipset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let enc_ts = base32::encode(base32::Alphabet::Rfc4648 { padding: true }, &self.key);
        let display_len = cmp::min(16, enc_ts.len());
        write!(f, "{}@{}", &enc_ts[..display_len], self.epoch)
    }
}

/// A chain of tipsets comprising a base and a possibly empty suffix
///
/// The base is the last finalized tipset from which the chain extends.
/// Tipsets are assumed to be built contiguously on each other,
/// though epochs may be missing due to null rounds.
///
/// The zero value (empty chain) is not valid and represents a "bottom" value
/// when used in a GPBFT message.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
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
    /// Creates a new ECChain with a base tipset and optional suffix
    ///
    /// # Arguments
    /// * `base` - The base tipset
    /// * `suffix` - Optional additional tipsets
    ///
    /// # Returns
    /// A Result containing the new ECChain
    ///
    /// Note: To conform to the reference implementation we should allow empty ECChain.
    pub fn new(base: Tipset, suffix: Vec<Tipset>) -> crate::Result<Self> {
        let mut tipsets = vec![base];
        tipsets.extend(suffix);
        let chain = ECChain(tipsets);
        chain.validate()?;
        Ok(chain)
    }
    /// Creates a new ECChain without validation to allow for creation of empty ECChain or ECChain
    /// from a suffix.
    pub fn new_unvalidated(tipsets: Vec<Tipset>) -> Self {
        ECChain(tipsets)
    }

    /// Validates the chain
    pub fn validate(&self) -> crate::Result<()> {
        if self.is_empty() {
            return Ok(());
        }
        if self.len() > CHAIN_MAX_LEN {
            return Err(GPBFTError::ChainTooLong {
                len: self.len(),
                max_len: CHAIN_MAX_LEN,
            });
        }
        let mut last_epoch: i64 = -1;
        for ts in self.iter() {
            ts.validate()?;
            if ts.epoch <= last_epoch {
                return Err(GPBFTError::Epochs {
                    current: ts.epoch,
                    last: last_epoch,
                });
            }
            last_epoch = ts.epoch;
        }
        Ok(())
    }

    /// Checks if the ECChain has a non-empty suffix
    pub fn has_suffix(&self) -> bool {
        !self.suffix().is_empty()
    }

    /// Returns the base tipset of the chain
    pub fn base(&self) -> Option<&Tipset> {
        self.first()
    }

    pub fn head(&self) -> Option<&Tipset> {
        self.last()
    }

    /// Returns the suffix of the chain after the base
    pub fn suffix(&self) -> &[Tipset] {
        if self.is_empty() { &[] } else { &self[1..] }
    }

    /// Returns a new chain with the same base and no suffix
    pub fn base_chain(&self) -> Option<ECChain> {
        self.base().map(|ts| ECChain(vec![ts.clone()]))
    }

    /// Extends the chain with new tipset keys
    pub fn extend(&self, tips: &[TipsetKey]) -> Option<ECChain> {
        let mut new_chain = self.clone();
        let mut offset = self.last()?.epoch + 1;
        let pt = self.last()?.power_table;
        for tip in tips {
            new_chain.push(Tipset {
                epoch: offset,
                key: tip.clone(),
                power_table: pt,
                commitments: keccak_hash::H256::zero(),
            });
            offset += 1;
        }
        Some(new_chain)
    }

    /// Returns a chain with suffix truncated to a maximum length
    pub fn prefix(&self, to: usize) -> crate::Result<ECChain> {
        if self.is_empty() {
            return Err(GPBFTError::ChainEmpty);
        }
        let length = cmp::min(to + 1, self.len());
        Ok(ECChain(self[..length].to_vec()))
    }

    /// Checks if two chains have the same base
    pub fn same_base(&self, other: &ECChain) -> bool {
        !self.is_empty() && !other.is_empty() && self.base() == other.base()
    }

    /// Checks if the chain has a specific base tipset
    pub fn has_base(&self, t: &Tipset) -> bool {
        if t.is_empty() || self.is_empty() {
            return false;
        }

        if let Some(base) = self.base() {
            return base == t;
        }

        false
    }

    /// Checks if the chain has a specific prefix
    pub fn has_prefix(&self, other: &ECChain) -> bool {
        if self.is_empty() || other.is_empty() {
            return false;
        }
        if other.len() > self.len() {
            return false;
        }

        self[..other.len()] == other[..]
    }

    /// Checks if the chain contains a specific tipset
    pub fn has_tipset(&self, t: &Tipset) -> bool {
        !t.is_empty() && self.contains(t)
    }

    /// Returns an identifier for the chain suitable for use as a map key
    pub fn key(&self) -> ChainKey {
        if self.is_empty() {
            return filecoin_f3_merkle::ZERO_DIGEST.to_vec();
        }

        // Collect serialized bytes for each tipset
        let values: Vec<Vec<u8>> = self.iter().map(|ts| ts.serialize_for_signing()).collect();

        // Compute merkle tree root (matches go-f3)
        let merkle_root = filecoin_f3_merkle::tree(&values);
        merkle_root.to_vec()
    }
}

/// Hashes the given data and returns a `DAG_CBOR + blake2b-256 CID`.
pub fn cid_from_bytes(bytes: &[u8]) -> Cid {
    let hash = Blake2b256.digest(bytes);
    Cid::new_v1(DAG_CBOR, hash)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{create_test_tipset, powertable_cid};
    use cid::Version;

    #[test]
    fn test_tipset_create_and_validate() {
        let tipset = Tipset {
            epoch: 1,
            key: vec![1, 2, 3],
            power_table: powertable_cid(),
            commitments: keccak_hash::H256::zero(),
        };

        assert_eq!(tipset.epoch, 1);
        assert_eq!(tipset.key, vec![1, 2, 3]);
        assert_eq!(tipset.power_table, powertable_cid());
        assert_eq!(tipset.commitments, keccak_hash::H256::zero());

        assert!(tipset.validate().is_ok());
    }

    #[test]
    fn test_tipset_is_empty() {
        let empty_tipset = Tipset {
            epoch: 0,
            key: vec![],
            power_table: Cid::default(),
            commitments: keccak_hash::H256::zero(),
        };

        assert!(empty_tipset.is_empty());

        let non_empty_tipset = Tipset {
            epoch: 1,
            key: vec![1, 2, 3],
            power_table: Cid::default(),
            commitments: keccak_hash::H256::zero(),
        };

        assert!(!non_empty_tipset.is_empty());
    }

    #[test]
    fn test_tipset_display() {
        let tipset = Tipset {
            epoch: 10,
            key: vec![1, 2, 3],
            power_table: Cid::default(),
            commitments: keccak_hash::H256::zero(),
        };

        let display_string = format!("{}", tipset);
        assert!(display_string.contains("@10"));
    }

    #[test]
    fn test_ecchain_new() {
        let base = Tipset {
            epoch: 1,
            key: vec![1, 2, 3],
            power_table: powertable_cid(),
            commitments: keccak_hash::H256::zero(),
        };
        let suffix = vec![
            Tipset {
                epoch: 2,
                key: vec![7, 8, 9],
                power_table: powertable_cid(),
                commitments: keccak_hash::H256::zero(),
            },
            Tipset {
                epoch: 3,
                key: vec![13, 14, 15],
                power_table: powertable_cid(),
                commitments: keccak_hash::H256::zero(),
            },
        ];

        let chain = ECChain::new(base.clone(), suffix.clone()).unwrap();

        assert_eq!(chain.base(), Some(&base));
        assert_eq!(chain.suffix(), &suffix);
        assert_eq!(chain.len(), 3); // base + 2 suffix tipsets
    }
    #[test]
    fn test_ecchain_base_and_suffix() {
        let base = create_test_tipset(1);
        let suffix = vec![create_test_tipset(2), create_test_tipset(3)];
        let chain = ECChain::new(base.clone(), suffix.clone()).unwrap();

        assert_eq!(chain.base(), Some(&base));
        assert_eq!(chain.suffix(), &suffix);
    }
    #[test]
    fn test_ecchain_base_chain() {
        let base = create_test_tipset(1);
        let suffix = vec![create_test_tipset(2)];
        let chain = ECChain::new(base.clone(), suffix).unwrap();

        let base_chain = chain.base_chain().unwrap();
        assert_eq!(base_chain.len(), 1);
        assert_eq!(base_chain.base(), Some(&base));
    }
    #[test]
    fn test_ecchain_extend() {
        let base = create_test_tipset(1);
        let chain = ECChain::new(base, vec![]).unwrap();

        let new_tips = vec![vec![2], vec![3]];
        let extended_chain = chain.extend(&new_tips).unwrap();

        assert_eq!(extended_chain.len(), 3);
        assert_eq!(extended_chain.last().unwrap().epoch, 3);
    }
    #[test]
    fn test_ecchain_prefix() {
        let base = create_test_tipset(1);
        let suffix = vec![create_test_tipset(2), create_test_tipset(3)];
        let chain = ECChain::new(base, suffix).unwrap();

        let prefix = chain.prefix(1).unwrap();
        assert_eq!(prefix.len(), 2);
        assert_eq!(prefix.last().unwrap().epoch, 2);
    }
    #[test]
    fn test_ecchain_has_suffix() {
        let base = create_test_tipset(1);
        let chain_with_suffix = ECChain::new(base.clone(), vec![create_test_tipset(2)]).unwrap();
        let chain_without_suffix = ECChain::new(base, vec![]).unwrap();

        assert!(chain_with_suffix.has_suffix());
        assert!(!chain_without_suffix.has_suffix());
    }

    #[test]
    fn test_ecchain_has_base_and_same_base() {
        let base = create_test_tipset(1);
        let chain1 = ECChain::new(base.clone(), vec![create_test_tipset(2)]).unwrap();
        let chain2 = ECChain::new(base.clone(), vec![create_test_tipset(3)]).unwrap();
        let chain3 = ECChain::new(create_test_tipset(4), vec![]).unwrap();

        assert!(chain1.has_base(&base));
        assert!(chain2.has_base(&base));
        assert!(!chain3.has_base(&base));

        assert!(chain1.same_base(&chain2));
        assert!(!chain1.same_base(&chain3));
    }

    #[test]
    fn test_ecchain_has_prefix() {
        let base = create_test_tipset(1);
        let chain = ECChain::new(
            base.clone(),
            vec![create_test_tipset(2), create_test_tipset(3)],
        )
        .unwrap();
        let prefix = ECChain::new(base, vec![create_test_tipset(2)]).unwrap();
        let non_prefix = ECChain::new(create_test_tipset(4), vec![]).unwrap();

        assert!(chain.has_prefix(&prefix));
        assert!(!chain.has_prefix(&non_prefix));
    }

    #[test]
    fn test_ecchain_has_tipset() {
        let base = create_test_tipset(1);
        let tipset2 = create_test_tipset(2);
        let chain = ECChain::new(base.clone(), vec![tipset2.clone()]).unwrap();
        let non_member = create_test_tipset(3);

        assert!(chain.has_tipset(&base));
        assert!(chain.has_tipset(&tipset2));
        assert!(!chain.has_tipset(&non_member));
    }

    #[test]
    fn test_ecchain_key_merkle_tree() {
        let base = create_test_tipset(1);
        let tipset2 = create_test_tipset(2);
        let tipset3 = create_test_tipset(3);
        let chain = ECChain::new(base, vec![tipset2, tipset3]).unwrap();

        let key = chain.key();
        assert_eq!(key.len(), 32);

        // Different chains should produce different keys
        let different_chain = ECChain::new(create_test_tipset(10), vec![]).unwrap();
        let different_key = different_chain.key();
        assert_ne!(key, different_key);
    }

    #[test]
    fn test_cid_from_bytes() {
        let bytes = vec![1, 2, 3, 4, 5];
        let cid = cid_from_bytes(&bytes);

        // Check that the CID has the expected properties
        assert_eq!(cid.version(), Version::V1);
        assert_eq!(cid.codec(), DAG_CBOR);

        // Verify that the CID's hash matches the input bytes, thus verifying the algorithm
        let expected_hash = Blake2b256.digest(&bytes);
        assert_eq!(cid.hash().digest(), expected_hash.digest());
    }

    /// Clone of TestTipSetMarshalForSigning from go-f3/gpbft/signature_test.go
    /// with active test vectors, to ensure correctness.
    #[test]
    fn test_tipset_serialize_for_signing() {
        const EXPECTED_LEN: usize = 8 + 32 + 38 + 38; // epoch + commitments + tipset_cid + power_table_cid

        // Setup matching go-f3
        let mut tsk = vec![0u8; 38 * 5]; // 190 bytes
        tsk[0] = 110;
        let comm = {
            let mut c = [0u8; 32];
            c[0] = 0x42;
            keccak_hash::H256(c)
        };
        let pt_cid = cid_from_bytes(b"pt");

        let ts = Tipset {
            epoch: 1,
            key: tsk.clone(),
            power_table: pt_cid,
            commitments: comm,
        };

        // Generate tipset CID matching go-f3
        use serde_cbor::Value;
        let cbor_value = Value::Bytes(tsk);
        let cbor_bytes = serde_cbor::to_vec(&cbor_value).unwrap();
        let ts_cid = cid_from_bytes(&cbor_bytes);

        let encoded = ts.serialize_for_signing();

        // Structural assertions from go-f3
        assert_eq!(encoded.len(), EXPECTED_LEN);
        assert_eq!(
            u64::from_be_bytes(encoded[..8].try_into().unwrap()),
            ts.epoch as u64
        );
        assert_eq!(&encoded[8..40], &ts.commitments.0);
        assert_eq!(&encoded[40..78], &ts_cid.to_bytes());
        assert_eq!(&encoded[78..], &ts.power_table.to_bytes());
    }
}
