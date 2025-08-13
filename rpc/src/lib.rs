pub mod types;

pub use crate::types::*;
use anyhow::Result;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::core::params::ArrayParams;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};

pub struct RPCClient {
    client: HttpClient,
}

impl RPCClient {
    pub fn new(endpoint: &str) -> Result<Self> {
        let client = HttpClientBuilder::default().build(endpoint)?;
        Ok(Self { client })
    }

    pub async fn get_power_table(&self, instance: u64) -> Result<Vec<PowerEntry>> {
        let mut params = ArrayParams::new();
        params.insert(instance)?;

        let response: Vec<PowerEntry> = self
            .client
            .request("Filecoin.F3GetPowerTableByInstance", params)
            .await?;
        Ok(response)
    }

    pub async fn get_certificate(&self, instance: u64) -> Result<FinalityCertificate> {
        let mut params = ArrayParams::new();
        params.insert(instance)?;

        let response: FinalityCertificate = self
            .client
            .request("Filecoin.F3GetCertificate", params)
            .await?;
        Ok(response)
    }
}
