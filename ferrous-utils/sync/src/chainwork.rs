//! Chainwork calculation for block metadata.
//!
//! Chainwork = cumulative sum of block work from genesis.
//! Work for a block = (2^256) / (target + 1) ≈ max_target / target.
//! Ref: bitcoin/src/rpc/blockchain.cpp nChainWork, arith_uint256

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
pub fn compute_chainwork(prev_chainwork: &[u8; 32], bits: u32) -> [u8; 32] {
    let prev = bytes_to_chainwork(prev_chainwork);
    let target = bits_to_target(bits);
    let work = calculate_work(target);
    let new_chainwork = prev + work;
    chainwork_to_bytes(new_chainwork)
}
