//! Chainwork calculation for block metadata.
//!
//! Chainwork = cumulative sum of block work from genesis.
//! Work for a block = (~target / (target + 1)) + 1 (Bitcoin Core formula).
//! Ref: bitcoin/src/chain.cpp GetBitsProof, bitcoin/src/rpc/blockchain.cpp nChainWork

use primitive_types::U256;

use crate::validate::pow::{bits_to_target, calculate_work};

/// Convert chainwork U256 to 32-byte big-endian (Bitcoin Core format)
pub fn chainwork_to_bytes(cw: U256) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    cw.to_big_endian(&mut bytes);
    bytes
}

/// Convert 32-byte big-endian chainwork to U256
pub fn bytes_to_chainwork(bytes: &[u8; 32]) -> U256 {
    U256::from_big_endian(bytes)
}

/// Compute chainwork for a block: prev_chainwork + work(bits)
///
/// For genesis (height 0), pass [0u8; 32] as prev_chainwork.
/// Work uses Bitcoin Core formula: (~target / (target + 1)) + 1
pub fn compute_chainwork(prev_chainwork: &[u8; 32], bits: u32) -> [u8; 32] {
    let prev = bytes_to_chainwork(prev_chainwork);
    let target = bits_to_target(bits);
    let work = calculate_work(target);
    let new_chainwork = prev + work;
    chainwork_to_bytes(new_chainwork)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_chainwork_matches_bitcoin_core_formula() {
        // Genesis block (bits 0x1d00ffff) chainwork = work of first block.
        // Bitcoin Core uses: work = (~target / (target + 1)) + 1
        let genesis_bits = 0x1d00ffffu32;
        let prev_chainwork = [0u8; 32];
        let genesis_chainwork = compute_chainwork(&prev_chainwork, genesis_bits);

        let target = bits_to_target(genesis_bits);
        let expected_work = calculate_work(target);
        let expected_bytes = chainwork_to_bytes(expected_work);

        assert_eq!(genesis_chainwork, expected_bytes);
        assert_ne!(genesis_chainwork, [0u8; 32], "Genesis chainwork must be non-zero");
    }
}
