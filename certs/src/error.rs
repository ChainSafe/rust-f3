// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use filecoin_f3_gpbft::{ActorId, GPBFTError};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum CertsError {
    #[error("empty chain")]
    EmptyChain,

    #[error("empty power delta")]
    EmptyPowerDelta,

    #[error("invalid justification: {0}")]
    InvalidJustification(String),

    #[error("got a decision for bottom for instance {0}")]
    BottomDecision(u64),

    #[error("invalid power table delta: {0}")]
    InvalidPowerTableDelta(String),

    #[error("serialization error: {0}")]
    SerializationError(String),

    #[error("expected instance {expected}, found instance {found}")]
    InstanceMismatch { expected: u64, found: u64 },

    #[error("invalid round: expected 0, got {0}")]
    InvalidRound(u64),

    #[error("diff {0} not sorted by participant ID")]
    UnsortedDiff(usize),

    #[error("diff {0} contains an empty delta for participant {1}")]
    EmptyDelta(usize, ActorId),

    #[error("diff {0} includes a new entry with a non-positive power delta for participant {1}")]
    NonPositivePowerDeltaForNewEntry(usize, ActorId),

    #[error("diff {0} delta for participant {1} includes an unchanged key")]
    UnchangedKey(usize, ActorId),

    #[error("diff {0} removes all power for participant {1} while specifying a new key")]
    RemovesAllPowerWithNewKey(usize, ActorId),

    #[error("diff {0} resulted in negative power for participant {1}")]
    NegativePower(usize, ActorId),

    #[error("invalid finality certificate at instance {0}: {1}")]
    InvalidFinalityCertificate(u64, GPBFTError),

    #[error("empty finality certificate for instance {0}")]
    EmptyFinalityCertificate(u64),

    #[error("base tipset does not match finalized chain at instance {0}")]
    BaseTipsetMismatch(u64),

    #[error("incorrect power diff from finality certificate for instance {instance}: expected {expected:?}, got {got:?}")]
    IncorrectPowerDiff {
        instance: u64,
        expected: String,
        got: String,
    },
    #[error("BLS signature verification failed for instance {instance}: {error}")]
    SignatureVerificationFailed { instance: u64, error: String },

    #[error("insufficient power for finality certificate at instance {instance}: {signer_power} < 2/3 * {total_power}")]
    InsufficientPower {
        instance: u64,
        signer_power: i64,
        total_power: i64,
    },

    #[error("signer index {signer_index} out of bounds for power table of size {power_table_size} at instance {instance}")]
    SignerIndexOutOfBounds {
        instance: u64,
        signer_index: usize,
        power_table_size: usize,
    },

    #[error("signer {signer_id} has zero effective power at instance {instance}")]
    ZeroEffectivePower { instance: u64, signer_id: u64 },
}
