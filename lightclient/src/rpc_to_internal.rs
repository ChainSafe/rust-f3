use anyhow::Context;
use base64::{engine::general_purpose, Engine as _};
use filecoin_f3_certs as certs;
use filecoin_f3_gpbft::chain;
use filecoin_f3_gpbft::{BitField, Cid, ECChain, PubKey, SupplementalData};
use filecoin_f3_rpc::{self as rpc};
use keccak_hash::H256;

/// Converts RPC power entry to the internal format
pub fn convert_power_entry(val: rpc::PowerEntry) -> anyhow::Result<filecoin_f3_gpbft::PowerEntry> {
    Ok(filecoin_f3_gpbft::PowerEntry {
        id: val.id,
        power: val.power,
        pub_key: PubKey(general_purpose::STANDARD.decode(&val.pub_key)?), // base64 -> bytes -> PubKey
    })
}

/// Converts RPC finality certificate to the internal format
pub fn convert_certificate(
    val: rpc::FinalityCertificate,
) -> anyhow::Result<certs::FinalityCertificate> {
    Ok(certs::FinalityCertificate {
        gpbft_instance: val.instance,
        ec_chain: convert_chain(val.ec_chain)?,
        supplemental_data: SupplementalData {
            commitments: Default::default(),
            power_table: Cid::try_from(val.supplemental_data.power_table.cid.as_str())?,
        },
        power_table_delta: val
            .power_table_delta
            .into_iter()
            .map(|delta| convert_power_table_delta(delta))
            .collect::<anyhow::Result<Vec<_>, _>>()?,
        signers: convert_bitfield(val.signers)?,
        signature: general_purpose::STANDARD.decode(&val.signature)?, // base64 -> bytes
    })
}

fn convert_chain(val: Vec<rpc::ECTipSet>) -> anyhow::Result<ECChain> {
    if val.is_empty() {
        return Err(anyhow::anyhow!("empty ec_chain"));
    }

    let tipsets = val
        .into_iter()
        .map(convert_tipset)
        .collect::<anyhow::Result<Vec<_>, _>>();
    let tipsets = tipsets?;

    let base_native = tipsets[0].clone();
    let suffix = tipsets[1..].to_vec();

    ECChain::new(base_native, suffix).context("failed to create ECChain")
}

fn convert_tipset(val: rpc::ECTipSet) -> anyhow::Result<certs::Tipset> {
    Ok(certs::Tipset {
        epoch: val.epoch as i64,
        key: convert_tipset_key(&val.key)?,
        power_table: Cid::try_from(val.power_table.cid)?,
        commitments: H256::from_slice(&general_purpose::STANDARD.decode(&val.commitments)?), // base64 -> bytes -> H256
    })
}

fn convert_tipset_key(cid_refs: &[rpc::CidRef]) -> anyhow::Result<chain::TipsetKey> {
    let mut key = Vec::new();
    for cid_ref in cid_refs {
        let cid = Cid::try_from(cid_ref.cid.as_str())?;
        key.extend(cid.to_bytes());
    }

    Ok(key)
}

fn convert_power_table_delta(val: rpc::PowerTableDelta) -> anyhow::Result<certs::PowerTableDelta> {
    Ok(certs::PowerTableDelta {
        participant_id: val.participant_id,
        power_delta: filecoin_f3_gpbft::StoragePower::from(val.power_delta),
        signing_key: match val.signing_key {
            Some(base64_str) => {
                PubKey::new(general_purpose::STANDARD.decode(&base64_str)?) // base64 -> bytes -> PubKey
            }
            None => PubKey::default(),
        },
    })
}

fn convert_bitfield(signers: Vec<u64>) -> anyhow::Result<BitField> {
    // RPC receives RLE run lengths as Vec<u64>, but fvm_ipld_bitfield expects
    // individual bit indices, so converting runs to indices is needed
    let mut indices = Vec::new();
    let mut bit_position = 0;
    for (i, &run_length) in signers.iter().enumerate() {
        if i % 2 == 1 {
            // Odd indices are set runs
            for offset in 0..run_length {
                indices.push(bit_position + offset);
            }
        }
        bit_position += run_length;
    }

    BitField::try_from_bits(indices).context("failed to create bitfield")
}
