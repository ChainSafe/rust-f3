mod rpc_to_internal;

extern crate core;

use anyhow::Result;
use filecoin_f3_blssig::BLSVerifier;
use filecoin_f3_certs as certs;
use filecoin_f3_certs::validate_finality_certificates;
use filecoin_f3_gpbft::{ECChain, PowerEntries};
use filecoin_f3_rpc::RPCClient;

pub struct LightClient {
    pub rpc: RPCClient,
    pub network_name: String,
    pub verifier: BLSVerifier,
}

#[derive(Debug, Clone)]
pub struct LightClientState {
    pub instance: u64,
    pub chain: Option<ECChain>,
    pub power_table: PowerEntries,
}

impl LightClient {
    pub fn new(endpoint: &str, network_name: &str) -> Result<Self> {
        Ok(Self {
            rpc: RPCClient::new(endpoint)?,
            network_name: network_name.to_string(),
            verifier: BLSVerifier::new(),
        })
    }

    pub async fn initialize(&mut self, instance: u64) -> Result<LightClientState> {
        let power_table = self.rpc.get_power_table(instance).await?;
        let power_table = power_table
            .into_iter()
            .map(rpc_to_internal::convert_power_entry)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(LightClientState {
            instance,
            chain: None,
            power_table: PowerEntries(power_table),
        })
    }

    pub async fn get_certificate(&self, instance: u64) -> Result<certs::FinalityCertificate> {
        let rpc_cert = self.rpc.get_certificate(instance).await?;
        rpc_to_internal::convert_certificate(rpc_cert)
    }

    pub fn validate_certificates(
        &mut self,
        state: &LightClientState,
        certs: &[certs::FinalityCertificate],
    ) -> certs::Result<LightClientState> {
        let (new_instance, new_chain, new_power_table) = validate_finality_certificates(
            &self.verifier,
            &self.network_name,
            state.power_table.clone(),
            state.instance,
            state.chain.as_ref().and_then(|c| c.last()),
            certs,
        )?;

        Ok(LightClientState {
            instance: new_instance,
            chain: Some(new_chain),
            power_table: new_power_table,
        })
    }
}
