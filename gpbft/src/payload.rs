use crate::chain::{Cid, ECChain};
use strum_macros::Display;

/// Fields of the message that make up the signature payload in the GPBFT consensus protocol
#[derive(PartialEq, Eq)]
pub struct Payload {
    /// GPBFT instance number
    pub instance: u64,
    /// GPBFT round number
    pub round: u64,
    /// Current phase of the GPBFT protocol
    pub phase: Phase,
    /// Additional data related to this consensus instance
    pub supplemental_data: SupplementalData,
    /// The agreed-upon value for this instance
    pub value: ECChain,
}

impl Payload {
    /// Creates a new Payload instance
    ///
    /// # Arguments
    ///
    /// * `instance` - The GPBFT instance number
    /// * `round` - The current round number
    /// * `phase` - The current phase of the protocol
    /// * `supplemental_data` - Additional data for this instance
    /// * `value` - The agreed-upon ECChain
    pub fn new(
        instance: u64,
        round: u64,
        phase: Phase,
        supplemental_data: SupplementalData,
        value: ECChain,
    ) -> Self {
        Payload {
            instance,
            round,
            phase,
            supplemental_data,
            value,
        }
    }

    /// Serializes the payload for signing.
    /// Format: "GPBFT:network_name:phase+round+instance+commitments+chain_key+power_table_cid"
    pub fn serialize_for_signing(&self, network_name: &str) -> Vec<u8> {
        // Domain separation constants
        const DOMAIN_SEPARATION_TAG: &str = "GPBFT";
        const SEPARATOR: &str = ":";

        // Compute ECChain key
        let chain_key = self.value.key();

        // Pre-calculate buffer size for efficiency
        let power_table_bytes = self.supplemental_data.power_table.to_bytes();
        let estimated_size = DOMAIN_SEPARATION_TAG.len() +
            network_name.len() +
            SEPARATOR.len() * 2 +
            1 + // Phase
            8 + // Round  
            8 + // Instance
            self.supplemental_data.commitments.as_bytes().len() +
            chain_key.len() +
            power_table_bytes.len();

        let mut buf = Vec::with_capacity(estimated_size);

        // Write domain separation tag
        buf.extend_from_slice(DOMAIN_SEPARATION_TAG.as_bytes());
        buf.extend_from_slice(SEPARATOR.as_bytes());

        // Write network name
        buf.extend_from_slice(network_name.as_bytes());
        buf.extend_from_slice(SEPARATOR.as_bytes());

        // Write step (1 byte)
        buf.push(self.phase as u8);

        // Write round (8 bytes, big-endian)
        buf.extend_from_slice(&self.round.to_be_bytes());

        // Write instance (8 bytes, big-endian)
        buf.extend_from_slice(&self.instance.to_be_bytes());

        // Write commitments (32 bytes)
        buf.extend_from_slice(&self.supplemental_data.commitments.0);

        // Write chain key (32 bytes)
        buf.extend_from_slice(&chain_key);

        // Write power table CID
        buf.extend_from_slice(&power_table_bytes);

        buf
    }
}

/// Additional data signed by participants in a GPBFT instance
#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct SupplementalData {
    /// Merkle-tree root of instance-specific commitments
    ///
    /// Currently empty, but will eventually include things like
    /// snark-friendly power-table commitments.
    pub commitments: keccak_hash::H256,
    /// The DagCBOR-blake2b256 CID of the power table used to validate the next instance
    ///
    /// This takes look-back into account and represents a `[]PowerEntry`.
    /// The CID is limited to a maximum length of 38 bytes.
    pub power_table: Cid,
}

/// Represents the different phases of the GPBFT consensus protocol
#[repr(u8)]
#[derive(Display, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[strum(serialize_all = "UPPERCASE")]
pub enum Phase {
    /// This phase marks the beginning of a new consensus round. During this phase,
    /// participants typically initialize their local state and prepare for the
    /// subsequent phases of the protocol.
    Initial,
    /// Initial phase for quality assessment
    Quality,
    /// Phase for convergence of opinions
    Converge,
    /// Preparation phase before commitment
    Prepare,
    /// Commitment phase of the consensus
    Commit,
    /// Decision-making phase
    Decide,
    /// Final phase indicating termination of the consensus round
    Terminated,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cid_from_bytes;

    #[test]
    fn test_payload_new() {
        let instance = 1;
        let round = 2;
        let phase = Phase::Commit;
        let supplemental_data = SupplementalData {
            commitments: keccak_hash::H256::zero(),
            power_table: Cid::default(),
        };
        let value = ECChain::new_unvalidated(vec![]);

        let payload = Payload::new(
            instance,
            round,
            phase,
            supplemental_data.clone(),
            value.clone(),
        );

        assert_eq!(payload.instance, instance);
        assert_eq!(payload.round, round);
        assert_eq!(payload.phase, phase);
        assert_eq!(payload.supplemental_data, supplemental_data);
        assert_eq!(payload.value, value);
    }

    #[test]
    fn test_phase_repr() {
        assert_eq!(Phase::Initial as u8, 0);
        assert_eq!(Phase::Quality as u8, 1);
        assert_eq!(Phase::Converge as u8, 2);
        assert_eq!(Phase::Prepare as u8, 3);
        assert_eq!(Phase::Commit as u8, 4);
        assert_eq!(Phase::Decide as u8, 5);
        assert_eq!(Phase::Terminated as u8, 6);
    }

    #[test]
    fn test_phase_display() {
        assert_eq!(format!("{}", Phase::Initial), "INITIAL");
        assert_eq!(format!("{}", Phase::Quality), "QUALITY");
        assert_eq!(format!("{}", Phase::Converge), "CONVERGE");
        assert_eq!(format!("{}", Phase::Prepare), "PREPARE");
        assert_eq!(format!("{}", Phase::Commit), "COMMIT");
        assert_eq!(format!("{}", Phase::Decide), "DECIDE");
        assert_eq!(format!("{}", Phase::Terminated), "TERMINATED");
    }

    /// Clone of TestPayloadMarshalForSigning from go-f3/gpbft/signature_test.go
    /// with active test vectors, to ensure correctness.
    #[test]
    fn test_payload_serialize_for_signing() {
        // Test setup matching go-f3
        let nn = "filecoin";
        let power_table_cid = cid_from_bytes(b"foo");

        // First test case: basic payload serialization
        let payload = Payload {
            instance: 1,
            round: 2,
            phase: Phase::Prepare, // 3
            supplemental_data: SupplementalData {
                commitments: {
                    let mut commits = [0u8; 32];
                    commits[0] = 0x42;
                    keccak_hash::H256(commits)
                },
                power_table: power_table_cid,
            },
            value: ECChain::new_unvalidated(vec![]), // empty chain = all zeros merkle hash
        };

        let encoded = payload.serialize_for_signing(nn);

        // Structural assertions from go-f3
        assert_eq!(encoded.len(), 96 + power_table_cid.encoded_len());
        assert_eq!(&encoded[..15], b"GPBFT:filecoin:"); // separators
        assert_eq!(encoded[15], 3u8); // phase
        assert_eq!(
            u64::from_be_bytes(encoded[16..24].try_into().unwrap()),
            2u64
        ); // round
        assert_eq!(
            u64::from_be_bytes(encoded[24..32].try_into().unwrap()),
            1u64
        ); // instance

        // Check commitments (bytes 32-64)
        let mut expected_commits = [0u8; 32];
        expected_commits[0] = 0x42;
        assert_eq!(&encoded[32..64], &expected_commits); // commitments root

        // Check empty chain hash (bytes 64-96) - should be all zeros for empty chain
        let expected_chain_hash = [0u8; 32];
        assert_eq!(&encoded[64..96], &expected_chain_hash); // tipsets (empty chain)

        // Check power table CID at the end
        assert_eq!(&encoded[96..], &power_table_cid.to_bytes()); // next power table

        // Second test case: DECIDE phase payload
        let decide_payload = Payload {
            instance: 29,
            round: 0,
            phase: Phase::Decide,
            supplemental_data: SupplementalData {
                commitments: keccak_hash::H256::zero(),
                power_table: power_table_cid,
            },
            value: ECChain::new_unvalidated(vec![]),
        };

        let encoded2 = decide_payload.serialize_for_signing(nn);

        // Build expected result matching go-f3 logic
        let mut expected = vec![0u8; 96];
        expected[..16].copy_from_slice(b"GPBFT:filecoin:\x05"); // prefix + DECIDE_PHASE
        expected[31] = 29; // instance in last 8 bytes, 32-byte right-aligned
        expected.extend_from_slice(&power_table_cid.to_bytes());

        assert_eq!(encoded2, expected);
    }
}
