use crate::PubKey;

pub trait Verifier {
    fn verify(&self, pub_key: &PubKey, msg: &[u8], sig: &[u8]) -> Result<(), String>;

    fn aggregate(&self, pub_keys: &[PubKey], sigs: &[Vec<u8>]) -> Result<Vec<u8>, String>;

    fn verify_aggregate(
        &self,
        payload: &[u8],
        agg_sig: &[u8],
        signers: &[PubKey],
    ) -> Result<(), String>;
}
