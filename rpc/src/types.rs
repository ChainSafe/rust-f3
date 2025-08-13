use filecoin_f3_gpbft::ActorId;
use num_bigint::BigInt;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct FinalityCertificate {
    #[serde(rename = "GPBFTInstance")]
    pub instance: u64,

    #[serde(rename = "ECChain")]
    pub ec_chain: Vec<ECTipSet>,

    #[serde(rename = "SupplementalData")]
    pub supplemental_data: SupplementalData,

    #[serde(rename = "Signers")]
    pub signers: Vec<u64>,

    #[serde(rename = "Signature")]
    pub signature: String,

    #[serde(rename = "PowerTableDelta", default)]
    pub power_table_delta: Vec<PowerTableDelta>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ECTipSet {
    #[serde(rename = "Key")]
    pub key: Vec<CidRef>,

    #[serde(rename = "Commitments")]
    pub commitments: String,

    #[serde(rename = "Epoch")]
    pub epoch: u64,

    #[serde(rename = "PowerTable")]
    pub power_table: CidRef,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SupplementalData {
    #[serde(rename = "Commitments")]
    pub commitments: String,

    #[serde(rename = "PowerTable")]
    pub power_table: CidRef,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PowerTableDelta {
    #[serde(rename = "ParticipantID")]
    pub participant_id: ActorId,

    #[serde(rename = "PowerDelta", with = "stringify")]
    pub power_delta: BigInt,

    #[serde(rename = "SigningKey")]
    pub signing_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CidRef {
    #[serde(rename = "/")]
    pub cid: String,
}

pub type ActorID = u64;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct PowerEntry {
    #[serde(rename = "ID")]
    pub id: ActorId,
    #[serde(rename = "Power", with = "stringify")]
    pub power: BigInt,
    #[serde(rename = "PubKey")]
    pub pub_key: String,
}

/// Usage: `#[serde(with = "stringify")]`
pub mod stringify {
    use super::*;
    use serde::Serializer;
    use std::fmt::Display;
    use std::str::FromStr;

    pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Display,
        S: Serializer,
    {
        serializer.collect_str(value)
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: FromStr,
        T::Err: Display,
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}
