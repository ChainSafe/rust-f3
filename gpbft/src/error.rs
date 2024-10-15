// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use thiserror::Error;
#[derive(Error, Debug, PartialEq)]
pub enum GPBFTError {
    #[error("chain too long: {len} > {max_len}")]
    ChainTooLong { max_len: usize, len: usize },

    #[error("chain must have increasing epochs {current} <= {last}")]
    Epochs { current: i64, last: i64 },

    #[error("zero-valued chain")]
    ChainEmpty,

    #[error("tipset key is empty")]
    TipsetKeyEmpty,

    #[error("tipset key is too long: {len} > {max_len}")]
    TipsetKeyTooLong { len: usize, max_len: usize },

    #[error("power table CID is empty")]
    PowerTableCidEmpty,

    #[error("power table CID is too long: {len} > {max_len}")]
    PowerTableCidTooLong { len: usize, max_len: usize },
}
