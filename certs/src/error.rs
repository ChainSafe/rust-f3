// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use std::borrow::Cow;

use filecoin_f3_gpbft::{ActorId, CborError, Cid, GPBFTError, Phase};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum CertsError {
    /// Error when the chain is empty.
    #[error("empty chain")]
    EmptyChain,

    /// Error when the power table delta is empty.
    #[error("empty power delta")]
    EmptyPowerDelta,

    /// Error when the justification vote phase doesn't match the expected phase
    #[error("invalid justification vote phase: expected {expected}, got {actual}")]
    InvalidJustificationVotePhase { expected: Phase, actual: Phase },

    /// Error when the justification vote value chain is invalid
    #[error("invalid justification vote value chain: {0}")]
    InvalidJustificationVoteValueChain(Cow<'static, str>),

    /// Error when getting a decision for bottom for a instance.
    #[error("got a decision for bottom for instance {0}")]
    BottomDecision(u64),

    /// Error when the power table delta is invalid.
    #[error("invalid power table delta: {0}")]
    InvalidPowerTableDelta(Cow<'static, str>),

    /// Error when serialization fails.
    #[error("serialization error: {0}")]
    SerializationError(Cow<'static, str>),

    /// Error when the instance doesn't match the expected instance.
    #[error("expected instance {expected}, found instance {actual}")]
    InstanceMismatch { expected: u64, actual: u64 },

    /// Error when the round is invalid.
    #[error("invalid round: expected {expected}, got {actual}")]
    InvalidRound { expected: u64, actual: u64 },

    /// Error when the diff is not sorted by participant ID.
    #[error("diff {0} not sorted by participant ID")]
    UnsortedDiff(usize),

    /// Error when the power table delta is empty for a participant.
    #[error("diff {0} contains an empty delta for participant {1}")]
    EmptyDelta(usize, ActorId),

    /// Error when the power delta for a participant is non-positive.
    #[error("diff {0} includes a new entry with a non-positive power delta for participant {1}")]
    NonPositivePowerDeltaForNewEntry(usize, ActorId),

    /// Error when the power table delta includes an unchanged key.
    #[error("diff {0} delta for participant {1} includes an unchanged key")]
    UnchangedKey(usize, ActorId),

    /// Error when the new key removes all storage power for a participant.
    #[error("diff {0} removes all power for participant {1} while specifying a new key")]
    RemovesAllPowerWithNewKey(usize, ActorId),

    /// Error when the storage power is negative for a participant.
    #[error("diff {0} resulted in negative power for participant {1}")]
    NegativePower(usize, ActorId),

    /// Error when the finality certificate is invalid for a certain instance.
    #[error("invalid finality certificate at instance {0}: {1}")]
    InvalidFinalityCertificate(u64, GPBFTError),

    /// Error when the finality certificate is empty for a certain instance.
    #[error("empty finality certificate for instance {0}")]
    EmptyFinalityCertificate(u64),

    /// Error that occurs when the power diff from a finality certificate doesn't match the expected value.
    ///
    /// # Fields
    /// * `instance` - The instance identifier for which the power diff mismatch occurred
    /// * `expected` - The expected power diff CID
    /// * `actual` - The actual power diff CID that was received
    ///
    /// Note: `Box<Cid>` is used instead of `Cid` to reduce the overall size of the error enum
    /// and suppress "largest variant" warnings.
    #[error("base tipset does not match finalized chain at instance {0}")]
    BaseTipsetMismatch(u64),

    /// Error when the power diff is incorrect.
    #[error(
        "incorrect power diff from finality certificate for instance {instance}: expected {expected}, got {actual}"
    )]
    IncorrectPowerDiff {
        instance: u64,
        expected: Box<Cid>,
        actual: Box<Cid>,
    },

    /// Error when encoding fails.
    #[error("cbor encoding error")]
    EncodingError(#[from] CborError),

    #[error("BLS signature verification failed for instance {instance}: {error}")]
    SignatureVerificationFailed { instance: u64, error: String },

    #[error(
        "insufficient power for finality certificate at instance {instance}: {signer_power} < 2/3 * {total_power}"
    )]
    InsufficientPower {
        instance: u64,
        signer_power: i64,
        total_power: i64,
    },

    #[error(
        "signer index {signer_index} out of bounds for power table of size {power_table_size} at instance {instance}"
    )]
    SignerIndexOutOfBounds {
        instance: u64,
        signer_index: usize,
        power_table_size: usize,
    },

    #[error("signer {signer_id} has zero effective power at instance {instance}")]
    ZeroEffectivePower { instance: u64, signer_id: u64 },
}
