pub const CHAIN_MAX_LEN: usize = 100;

pub type TipsetKey = Vec<u8>;

pub type Cid = Vec<u8>;

#[derive(Clone, PartialEq, Eq)]
pub struct Tipset {
    pub epoch: i64,
    pub key: TipsetKey,
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
        // for (i, ts) in self.iter().enumerate() {
        //     ts.validate().map_err(|e| format!("tipset {}: {}", i, e))?;
        //     if ts.epoch <= last_epoch {
        //         return Err(format!("chain must have increasing epochs {} <= {}", ts.epoch, last_epoch));
        //     }
        //     last_epoch = ts.epoch;
        // }
        Ok(())
    }
}
