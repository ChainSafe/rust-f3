//! Merkle tree implementation matching go-f3's merkle package
//!
//! This implements the same merkle tree algorithm used by go-f3 for ECChain key generation.
//! Uses Legacy Keccak-256 (NOT SHA3-256) with specific leaf/internal node markers.

#[cfg(test)]
mod tests;

use anyhow::anyhow;
use sha3::{Digest, Keccak256};

/// 32-byte digest matching go-f3's merkle.Digest
pub type MerkleDigest = [u8; 32];

/// Zero digest (32 zero bytes)
pub const ZERO_DIGEST: MerkleDigest = [0u8; 32];

/// Markers used in go-f3's merkle implementation
const INTERNAL_MARKER: &[u8] = &[0x00];
const LEAF_MARKER: &[u8] = &[0x01];

/// Computes a merkle tree root from a list of byte values
pub fn tree(values: &[Vec<u8>]) -> anyhow::Result<MerkleDigest> {
    if values.is_empty() {
        return Ok(ZERO_DIGEST);
    }

    let depth = calculate_depth(values.len());
    build_tree(depth, values, &mut Keccak256::new())
}

/// Calculates the depth of the merkle tree
fn calculate_depth(length: usize) -> usize {
    if length <= 1 {
        return 0;
    }

    let bits_len = (length - 1).leading_zeros();
    (usize::BITS - bits_len) as usize
}

/// Recursive function to build the merkle tree
fn build_tree(depth: usize, values: &[Vec<u8>], hasher: &mut Keccak256) -> anyhow::Result<MerkleDigest> {
    if values.is_empty() {
        return Ok(ZERO_DIGEST);
    }

    if depth == 0 {
        if values.len() != 1 {
            return Err(anyhow!("expected one value at the leaf"))
        }
        // Leaf node: hash(0x01 || value)
        hasher.update(LEAF_MARKER);
        hasher.update(&values[0]);
        let result = hasher.finalize_reset();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);
        Ok(digest)
    } else {
        // Split point: min(1<<(depth-1), len(values))
        let split = std::cmp::min(1 << (depth - 1), values.len());

        let left_hash = build_tree(depth - 1, &values[..split], hasher)?;
        let right_hash = build_tree(depth - 1, &values[split..], hasher)?;

        // Internal node: hash(0x00 || left || right)
        hasher.update(INTERNAL_MARKER);
        hasher.update(&left_hash);
        hasher.update(&right_hash);
        let result = hasher.finalize_reset();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);
        Ok(digest)
    }
}
