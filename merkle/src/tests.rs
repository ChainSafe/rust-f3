// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use super::*;

/// Helper function to generate test inputs matching go-f3's `generateInputs`
fn generate_inputs(dst: &str, n: usize) -> Vec<Vec<u8>> {
    let mut res = Vec::new();
    for i in 0..n {
        res.push(format!("{}{:09}", dst, i).into_bytes());
    }
    res
}

/// Clone of `TestHashZero` from `go-f3/merkle/merkle_test.go`
#[test]
fn test_hash_zero() {
    let test: &[Vec<u8>] = &[];
    let root = tree(test).unwrap();
    assert_eq!(root, ZERO_DIGEST);
}

/// Clone of `TestHashTreeGolden` from `go-f3/merkle/merkle_test.go`
/// with active test vectors, to ensure correctness.
#[test]
fn test_hash_tree_golden() {
    let expected_hex = [
        "3d4395573ce4d2acbce4fe8a4be67ca5e7cdfb8ee2e85b2f6733c16b24c3b175",
        "91b7c899421ca7f3228e10265c6970a03bc2ccba44367b1d44a9d8597b20a32e",
        "69abe78dc2390b4666b60d0582e1799e73e48766f6e502c515e79d6cd2ae3c45",
        "bc4ce8dbf993eb2e87c02bbf19cd4faeb3a0672188bc6be6c8d867cef9b08917",
        "538cfd0c1f6b7ab4c3d20466d4e01b438972212fe5257eae213ae0a040da977f",
        "e28aa108b0263820dfe2c7f051ddc8794ab48ebd3c1813db28bf9f06bedc52f3",
        "875cb1d5027522b344b8adc62cd6bd110d97eaedd40a35bcb2fe142a9cb4612b",
        "63804e8b6cb16993d5d43d9d7faf17ba967365dac141a4afbce1d794157a1b8e",
        "07105bd8716bebc90036c8ebfe23a92bd775c09664b076ffa1d9a29d30647f91",
        "960b7eb6440789f76f5d53965e8b208e34777bc4aab78edf6827d71c7eea4933",
        "d55e07222c786722e1ad1b5bcc2ebaf04b2b4e92c07f3f7b61b0fbf0fd78fb9b",
        "ee5a34dfae748e088a1b99386274158266f44ceeb2c5190f4e9bbc39cd8a4d26",
        "15def4fc077ccfb0e48b32bc07ea3b91acecc5b73ed9caf13b10adf17052c371",
        "07cfe4ec2efa9075763f921e9f29794ec6b945694e41cc19911101270d8b1087",
        "84cdf541cbb3b9b3f26dbdeb9ca3a2721d15447a8b47074c3b08b560f79e5d85",
        "af8e9fc2f15aaedadb96da1afb339b93e3174661327dcc6aad70ea67e183369d",
    ];

    let n = 16;
    for (i, expected) in expected_hex.iter().enumerate().take(n) {
        let inputs = generate_inputs("golden", i + 1);
        let res = tree(&inputs).unwrap();
        let res_hex = hex::encode(res);
        assert_eq!(
            *expected, res_hex,
            "mismatch at index {}: expected {}, got {}",
            i, expected, res_hex
        );
    }
}
