// Fast sync module with PyO3 bindings

pub mod chain_params;
pub mod chainwork;
pub mod versionbits;

use std::env;
pub mod storage;
pub mod validate;
pub mod network;

use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use bitcoin::Network;
use bitcoin::hashes::Hash;
use pyo3::prelude::*;
use tokio::sync::Mutex;

use common::{OutPointWrapper, UTXO, BlockWrapper, BlockHeaderWrapper, BlockMetadata};
use common::verify_ecdsa_signature_der;
// Hardware-accelerated crypto
use common::crypto::sha256::{
    sha256 as hw_sha256, double_sha256 as hw_double_sha256,
    detect_implementation as sha256_detect_impl, implementation_string as sha256_impl_string,
};
use common::crypto::secp::{
    verify_ecdsa_compact as secp_verify_ecdsa_compact,
    verify_ecdsa_der as secp_verify_ecdsa_der,
    verify_schnorr as secp_verify_schnorr,
    batch_verify_schnorr as secp_batch_verify_schnorr,
    SchnorrVerifyItem,
};
use crate::storage::db::{BlockchainDB, DbError};
use crate::validate::header::HeaderValidator;
use crate::validate::block::BlockValidator;
use crate::network::peer_manager::PeerManager;
use crate::network::header_sync::HeaderSync;
use crate::network::block_sync::{BlockSync, BlockProgressCache};

/// Initialize logging. If RUST_LOG is not set, defaults to sync=warn.
/// When OUROBOROS_VERBOSE=1, sets RUST_LOG=sync=debug for verbose output.
fn init_logging() {
    if env::var("RUST_LOG").is_err() {
        let level = if env::var("OUROBOROS_VERBOSE").as_deref() == Ok("1") {
            "sync=debug"
        } else {
            "sync=warn"
        };
        env::set_var("RUST_LOG", level);
    }
    let _ = env_logger::try_init();
}

/// Verify ECDSA signature (DER-encoded, as in Bitcoin script_sig).
#[pyfunction]
fn verify_ecdsa(der_sig: Vec<u8>, pubkey: Vec<u8>, msg_hash: Vec<u8>) -> PyResult<bool> {
    match verify_ecdsa_signature_der(&der_sig, &pubkey, &msg_hash) {
        Ok(valid) => Ok(valid),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "ECDSA verification error: {}",
            e
        ))),
    }
}

// ============================================================================
// Hardware-accelerated cryptographic functions
// ============================================================================

/// Get the detected SHA256 implementation (hardware-accelerated or software).
/// Returns one of: "sha256:x86_shani", "sha256:arm_sha2", "sha256:software"
#[pyfunction]
fn crypto_sha256_implementation() -> String {
    sha256_impl_string()
}

/// Compute SHA256 hash using hardware acceleration when available.
/// Uses SHA-NI on x86 (Intel/AMD) or SHA2 extensions on ARM (Apple Silicon).
#[pyfunction]
fn crypto_sha256(data: Vec<u8>) -> Vec<u8> {
    hw_sha256(&data).to_vec()
}

/// Compute double SHA256 (SHA256(SHA256(data))) using hardware acceleration.
/// This is Bitcoin's primary hash function for block headers, merkle trees, etc.
#[pyfunction]
fn crypto_double_sha256(data: Vec<u8>) -> Vec<u8> {
    hw_double_sha256(&data).to_vec()
}

/// Verify Schnorr signature (BIP340, used in Taproot).
///
/// Args:
///     sig: 64-byte Schnorr signature
///     pubkey: 32-byte x-only public key
///     msg_hash: 32-byte message hash
///
/// Returns:
///     True if signature is valid, False otherwise
#[pyfunction]
fn crypto_verify_schnorr(sig: Vec<u8>, pubkey: Vec<u8>, msg_hash: Vec<u8>) -> PyResult<bool> {
    match secp_verify_schnorr(&sig, &pubkey, &msg_hash) {
        Ok(valid) => Ok(valid),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "Schnorr verification error: {}",
            e
        ))),
    }
}

/// Batch verify multiple Schnorr signatures.
/// More efficient than verifying individually when processing Taproot transactions.
///
/// Args:
///     items: List of (sig, pubkey, msg_hash) tuples
///
/// Returns:
///     True if ALL signatures are valid, False if ANY is invalid
#[pyfunction]
fn crypto_batch_verify_schnorr(items: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>) -> PyResult<bool> {
    let verify_items: Vec<SchnorrVerifyItem> = items
        .iter()
        .map(|(sig, pubkey, msg)| SchnorrVerifyItem {
            sig,
            pubkey,
            msg_hash: msg,
        })
        .collect();

    match secp_batch_verify_schnorr(&verify_items) {
        Ok(valid) => Ok(valid),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "Batch Schnorr verification error: {}",
            e
        ))),
    }
}

/// Verify ECDSA signature with compact 64-byte format (for use with global context).
#[pyfunction]
fn crypto_verify_ecdsa_compact(sig: Vec<u8>, pubkey: Vec<u8>, msg_hash: Vec<u8>) -> PyResult<bool> {
    match secp_verify_ecdsa_compact(&sig, &pubkey, &msg_hash) {
        Ok(valid) => Ok(valid),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "ECDSA verification error: {}",
            e
        ))),
    }
}

// Re-export script verification types for use by Python
use crate::validate::script::{ScriptVerifyFlags, activation_heights};
use crate::validate::sequence_lock;
use crate::validate::difficulty::{self, BlockIndexInfo};
use crate::chain_params::get_consensus_params;
use crate::versionbits::{VersionBitsCache, DeploymentPos, BlockIndexProvider};

/// Get script verification flags for a given block height and network.
///
/// This mirrors Bitcoin Core's GetBlockScriptFlags() and determines which
/// consensus rules are active at a given height.
///
/// Networks: "mainnet"/"bitcoin", "testnet"/"testnet3", "testnet4", "regtest", "signet"
#[pyfunction]
fn get_script_flags_for_height(height: u32, network: String) -> PyResult<u32> {
    let network_enum = match network.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" | "testnet3" => Network::Testnet,
        "testnet4" => Network::Testnet4,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid network: {}", network),
            ));
        }
    };
    Ok(activation_heights::get_script_flags_for_height(height, network_enum).bits())
}

/// Get SegWit activation height for a network.
/// NULLFAIL (BIP146) is consensus-mandatory at this height.
#[pyfunction]
fn segwit_activation_height(network: String) -> PyResult<u32> {
    let network_enum = match network.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" | "testnet3" => Network::Testnet,
        "testnet4" => Network::Testnet4,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid network: {}", network),
            ));
        }
    };
    Ok(activation_heights::segwit_height(network_enum))
}

/// Get BIP68 (CSV) activation height for a network.
#[pyfunction]
fn bip68_activation_height(network: String) -> PyResult<u32> {
    let network_enum = match network.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" | "testnet3" => Network::Testnet,
        "testnet4" => Network::Testnet4,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid network: {}", network),
            ));
        }
    };
    Ok(sequence_lock::csv_activation_height(network_enum))
}

/// Check if BIP68 sequence locks are active at a given height for a network.
#[pyfunction]
fn is_bip68_active(height: u32, network: String) -> PyResult<bool> {
    let network_enum = match network.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" | "testnet3" => Network::Testnet,
        "testnet4" => Network::Testnet4,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid network: {}", network),
            ));
        }
    };
    Ok(sequence_lock::is_bip68_active(height, network_enum))
}

/// Calculate sequence locks for a transaction.
///
/// # Arguments
/// * `tx_version` - Transaction version (BIP68 only applies to version >= 2)
/// * `inputs` - List of tuples: (sequence, prev_height, prev_median_time)
/// * `enforce_bip68` - Whether BIP68 is active
///
/// # Returns
/// Tuple (min_height, min_time) representing sequence lock requirements.
/// Values of -1 mean "no lock of this type required".
#[pyfunction]
fn calculate_sequence_locks(
    tx_version: i32,
    inputs: Vec<(u32, u32, i64)>,
) -> PyResult<(i32, i64)> {
    let input_infos: Vec<sequence_lock::InputLockInfo> = inputs
        .into_iter()
        .map(|(seq, height, mtp)| sequence_lock::InputLockInfo {
            sequence: seq,
            prev_height: height,
            prev_median_time: mtp,
        })
        .collect();

    let lock = sequence_lock::calculate_sequence_locks(tx_version, &input_infos, true);
    Ok((lock.min_height, lock.min_time))
}

/// Check if sequence locks are satisfied for inclusion in a block.
///
/// # Arguments
/// * `tx_version` - Transaction version
/// * `inputs` - List of tuples: (sequence, prev_height, prev_median_time)
/// * `block_height` - Height of the block where the tx would be included
/// * `block_median_time` - Median time past of the previous block
/// * `enforce_bip68` - Whether BIP68 is active
///
/// # Returns
/// True if sequence locks are satisfied.
#[pyfunction]
fn check_sequence_locks(
    tx_version: i32,
    inputs: Vec<(u32, u32, i64)>,
    block_height: u32,
    block_median_time: i64,
    enforce_bip68: bool,
) -> PyResult<bool> {
    let input_infos: Vec<sequence_lock::InputLockInfo> = inputs
        .into_iter()
        .map(|(seq, height, mtp)| sequence_lock::InputLockInfo {
            sequence: seq,
            prev_height: height,
            prev_median_time: mtp,
        })
        .collect();

    Ok(sequence_lock::check_sequence_locks(
        tx_version,
        &input_infos,
        block_height,
        block_median_time,
        enforce_bip68,
    ))
}

/// Check if a transaction is final for inclusion in a block.
///
/// A transaction is final if:
/// - nLockTime == 0, OR
/// - nLockTime < threshold (block height or MTP depending on type), OR
/// - All inputs have nSequence == 0xFFFFFFFF
///
/// Reference: Bitcoin Core IsFinalTx() in consensus/tx_verify.cpp
///
/// # Arguments
/// * `locktime` - Transaction nLockTime
/// * `sequences` - List of nSequence values for each input
/// * `block_height` - Height of the block where the tx would be included
/// * `block_mtp` - Median time past of the previous block (BIP 113)
///
/// # Returns
/// True if the transaction is final.
#[pyfunction]
fn is_final_tx(
    locktime: u32,
    sequences: Vec<u32>,
    block_height: u32,
    block_mtp: i64,
) -> PyResult<bool> {
    Ok(sequence_lock::is_final_tx(
        locktime,
        &sequences,
        block_height,
        block_mtp,
    ))
}

/// Get the locktime threshold constant.
///
/// Values below this are block heights, values at or above are Unix timestamps.
#[pyfunction]
fn locktime_threshold() -> u32 {
    sequence_lock::LOCKTIME_THRESHOLD
}

/// Get the COINBASE_MATURITY constant (100 blocks).
///
/// Coinbase transaction outputs cannot be spent until they have at least
/// this many confirmations.
///
/// Reference: Bitcoin Core consensus/consensus.h
#[pyfunction]
fn coinbase_maturity_constant() -> u32 {
    crate::validate::COINBASE_MATURITY
}

/// Check if spending a coinbase output is allowed at the given height.
///
/// Coinbase outputs require COINBASE_MATURITY (100) confirmations before
/// they can be spent.
///
/// # Arguments
/// * `is_coinbase` - Whether the UTXO being spent is from a coinbase transaction
/// * `utxo_height` - The height at which the UTXO was created
/// * `spending_height` - The height of the block where the spending tx will be included
///
/// # Returns
/// * None if the coinbase maturity requirement is satisfied (spend allowed)
/// * String error message if premature spend ("bad-txns-premature-spend-of-coinbase")
///
/// Reference: Bitcoin Core consensus/tx_verify.cpp line 179
#[pyfunction]
fn check_coinbase_maturity(
    is_coinbase: bool,
    utxo_height: u32,
    spending_height: u32,
) -> Option<String> {
    match crate::validate::check_coinbase_maturity(is_coinbase, utxo_height, spending_height) {
        Ok(()) => None,
        Err((depth, _required)) => Some(format!(
            "bad-txns-premature-spend-of-coinbase: tried to spend coinbase at depth {}",
            depth
        )),
    }
}

/// Calculate the next work required (difficulty) for a block.
///
/// This implements Bitcoin's difficulty adjustment algorithm including:
/// - Mainnet: standard 2016-block retarget with timespan clamping
/// - Testnet3: 20-minute rule and walk-back to last non-min-diff block
/// - Testnet4/BIP94: similar to testnet3 with time warp fix
/// - Regtest: always returns pow_limit (no retargeting)
///
/// # Arguments
/// * `last_height` - Height of the previous block (tip)
/// * `last_bits` - nBits of the previous block
/// * `last_timestamp` - Timestamp of the previous block
/// * `new_block_time` - Timestamp of the new block
/// * `network` - Network name ("mainnet", "testnet", "testnet4", "regtest", "signet")
/// * `ancestors` - List of (height, bits, timestamp) tuples for ancestor blocks
///
/// # Returns
/// The expected nBits value for the next block
#[pyfunction]
fn get_next_work_required(
    last_height: u32,
    last_bits: u32,
    last_timestamp: u32,
    new_block_time: u32,
    network: String,
    ancestors: Vec<(u32, u32, u32)>,
) -> PyResult<u32> {
    let network_enum = match network.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" | "testnet3" => Network::Testnet,
        "testnet4" => Network::Testnet4,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid network: {}", network),
            ));
        }
    };

    let last_block = BlockIndexInfo {
        height: last_height,
        bits: last_bits,
        timestamp: last_timestamp,
    };

    // Build ancestor lookup from the provided list
    let ancestor_map: std::collections::HashMap<u32, BlockIndexInfo> = ancestors
        .into_iter()
        .map(|(h, b, t)| (h, BlockIndexInfo { height: h, bits: b, timestamp: t }))
        .collect();

    let result = difficulty::get_next_work_required(
        &last_block,
        new_block_time,
        network_enum,
        |height| ancestor_map.get(&height).cloned(),
    );

    Ok(result)
}

/// Calculate difficulty at a retarget boundary.
///
/// This is the core calculation: new_target = old_target * (actual_time / target_time)
/// with clamping to [target_time/4, target_time*4].
///
/// # Arguments
/// * `last_bits` - nBits of the last block in the period
/// * `first_timestamp` - Timestamp of the first block in the period
/// * `last_timestamp` - Timestamp of the last block in the period
/// * `network` - Network name
///
/// # Returns
/// New difficulty in compact "bits" format
#[pyfunction]
fn calculate_next_difficulty(
    last_bits: u32,
    first_timestamp: u32,
    last_timestamp: u32,
    network: String,
) -> PyResult<u32> {
    let network_enum = match network.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" | "testnet3" => Network::Testnet,
        "testnet4" => Network::Testnet4,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid network: {}", network),
            ));
        }
    };

    let params = get_consensus_params(network_enum);

    let last_block = BlockIndexInfo {
        height: 2015, // Dummy, not used in calculation
        bits: last_bits,
        timestamp: last_timestamp,
    };

    let new_bits = difficulty::calculate_next_work_required(&last_block, first_timestamp, &params);
    Ok(new_bits)
}

/// Get the PoW limit (minimum difficulty) bits for a network.
#[pyfunction]
fn pow_limit_bits(network: String) -> PyResult<u32> {
    let network_enum = match network.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" | "testnet3" => Network::Testnet,
        "testnet4" => Network::Testnet4,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid network: {}", network),
            ));
        }
    };

    let params = get_consensus_params(network_enum);
    Ok(params.pow_limit_bits)
}

/// Check if a difficulty transition is permitted.
///
/// Validates that the difficulty change between two consecutive blocks
/// follows consensus rules (within 4x at adjustment boundaries, unchanged otherwise).
#[pyfunction]
fn check_difficulty_transition(
    height: u32,
    old_bits: u32,
    new_bits: u32,
    network: String,
) -> PyResult<bool> {
    let network_enum = match network.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" | "testnet3" => Network::Testnet,
        "testnet4" => Network::Testnet4,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid network: {}", network),
            ));
        }
    };

    Ok(difficulty::permitted_difficulty_transition(height, old_bits, new_bits, network_enum))
}

/// Get the difficulty adjustment interval (2016 blocks).
#[pyfunction]
fn difficulty_adjustment_interval() -> u32 {
    difficulty::DIFFICULTY_ADJUSTMENT_INTERVAL
}

/// Get the target timespan for difficulty adjustment (2 weeks in seconds).
#[pyfunction]
fn target_timespan() -> i64 {
    difficulty::TARGET_TIMESPAN
}

/// Get the target block spacing (10 minutes in seconds).
#[pyfunction]
fn target_spacing() -> i64 {
    difficulty::TARGET_SPACING
}

/// Python wrapper for ScriptVerifyFlags
/// Provides constants and helper methods for script verification flags.
#[pyclass]
#[derive(Clone)]
pub struct PyScriptVerifyFlags {
    flags: u32,
}

#[pymethods]
impl PyScriptVerifyFlags {
    #[new]
    fn new(flags: u32) -> Self {
        Self { flags }
    }

    /// Get the raw flags value
    #[getter]
    fn value(&self) -> u32 {
        self.flags
    }

    /// Check if NULLFAIL flag is set
    fn has_nullfail(&self) -> bool {
        self.flags & ScriptVerifyFlags::NULLFAIL.bits() != 0
    }

    /// Check if WITNESS flag is set
    fn has_witness(&self) -> bool {
        self.flags & ScriptVerifyFlags::WITNESS.bits() != 0
    }

    /// Check if P2SH flag is set
    fn has_p2sh(&self) -> bool {
        self.flags & ScriptVerifyFlags::P2SH.bits() != 0
    }

    // Script verification flag constants
    #[classattr]
    const NONE: u32 = 0;
    #[classattr]
    const P2SH: u32 = 1 << 0;
    #[classattr]
    const STRICTENC: u32 = 1 << 1;
    #[classattr]
    const DERSIG: u32 = 1 << 2;
    #[classattr]
    const LOW_S: u32 = 1 << 3;
    #[classattr]
    const NULLDUMMY: u32 = 1 << 4;
    #[classattr]
    const SIGPUSHONLY: u32 = 1 << 5;
    #[classattr]
    const MINIMALDATA: u32 = 1 << 6;
    #[classattr]
    const DISCOURAGE_UPGRADABLE_NOPS: u32 = 1 << 7;
    #[classattr]
    const CLEANSTACK: u32 = 1 << 8;
    #[classattr]
    const CHECKLOCKTIMEVERIFY: u32 = 1 << 9;
    #[classattr]
    const CHECKSEQUENCEVERIFY: u32 = 1 << 10;
    #[classattr]
    const WITNESS: u32 = 1 << 11;
    #[classattr]
    const DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: u32 = 1 << 12;
    #[classattr]
    const MINIMALIF: u32 = 1 << 13;
    #[classattr]
    const NULLFAIL: u32 = 1 << 14;
    #[classattr]
    const WITNESS_PUBKEYTYPE: u32 = 1 << 15;
    #[classattr]
    const CONST_SCRIPTCODE: u32 = 1 << 16;
    #[classattr]
    const TAPROOT: u32 = 1 << 17;
}

/// Get BIP9 deployment state for a deployment at a given height.
///
/// # Arguments
/// * `deployment` - Deployment name ("taproot", "testdummy")
/// * `height` - Block height to query
/// * `network` - Network name
/// * `block_versions` - List of (height, version) tuples for blocks in the chain
/// * `block_mtps` - List of (height, mtp) tuples for median time past values
///
/// # Returns
/// State name: "defined", "started", "locked_in", "active", or "failed"
#[pyfunction]
fn get_deployment_state(
    deployment: String,
    height: u32,
    network: String,
    block_versions: Vec<(u32, i32)>,
    block_mtps: Vec<(u32, i64)>,
) -> PyResult<String> {
    let network_enum = match network.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" | "testnet3" => Network::Testnet,
        "testnet4" => Network::Testnet4,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid network: {}", network),
            ));
        }
    };

    // Map deployment name to position
    let dep_pos = match deployment.to_lowercase().as_str() {
        "taproot" => DeploymentPos::Taproot,
        "testdummy" => DeploymentPos::TestDummy,
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Unknown deployment: {}", deployment),
            ));
        }
    };

    // Create provider from the provided data
    let provider = PyBlockIndexProvider {
        versions: block_versions.into_iter().collect(),
        mtps: block_mtps.into_iter().collect(),
        height,
    };

    let mut cache = VersionBitsCache::new(network_enum);
    let state = cache.get_state(dep_pos, height, &provider)
        .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>(
            format!("Deployment {} not found for network {}", deployment, network),
        ))?;

    Ok(state.name().to_string())
}

/// Get all BIP9 deployment info for a network (for getblockchaininfo RPC).
///
/// # Arguments
/// * `height` - Current chain height
/// * `network` - Network name
/// * `block_versions` - List of (height, version) tuples
/// * `block_mtps` - List of (height, mtp) tuples
///
/// # Returns
/// List of deployment info dictionaries
#[pyfunction]
fn get_all_deployments_info(
    height: u32,
    network: String,
    block_versions: Vec<(u32, i32)>,
    block_mtps: Vec<(u32, i64)>,
) -> PyResult<Vec<PyDeploymentInfo>> {
    let network_enum = match network.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" | "testnet3" => Network::Testnet,
        "testnet4" => Network::Testnet4,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid network: {}", network),
            ));
        }
    };

    let provider = PyBlockIndexProvider {
        versions: block_versions.into_iter().collect(),
        mtps: block_mtps.into_iter().collect(),
        height,
    };

    let mut cache = VersionBitsCache::new(network_enum);
    let infos = cache.get_all_deployment_info(height, &provider);

    Ok(infos.into_iter().map(|info| PyDeploymentInfo {
        name: info.name,
        bit: info.bit,
        state: info.state.name().to_string(),
        since: info.since,
        start_time: info.start_time,
        timeout: info.timeout,
        min_activation_height: info.min_activation_height,
        period: info.stats.as_ref().map(|s| s.period),
        threshold: info.stats.as_ref().map(|s| s.threshold),
        elapsed: info.stats.as_ref().map(|s| s.elapsed),
        count: info.stats.as_ref().map(|s| s.count),
        possible: info.stats.as_ref().map(|s| s.possible),
    }).collect())
}

/// Check if a deployment is active at a given height.
#[pyfunction]
fn is_deployment_active(
    deployment: String,
    height: u32,
    network: String,
    block_versions: Vec<(u32, i32)>,
    block_mtps: Vec<(u32, i64)>,
) -> PyResult<bool> {
    let state = get_deployment_state(deployment, height, network, block_versions, block_mtps)?;
    Ok(state == "active")
}

/// Get the versionbits constants.
#[pyfunction]
fn versionbits_top_bits() -> i32 {
    versionbits::VERSIONBITS_TOP_BITS
}

/// Get the versionbits top mask.
#[pyfunction]
fn versionbits_top_mask() -> i32 {
    versionbits::VERSIONBITS_TOP_MASK
}

/// Check if a block version signals for a deployment.
///
/// # Arguments
/// * `version` - Block version
/// * `bit` - Deployment bit (0-28)
///
/// # Returns
/// True if the version signals for the deployment
#[pyfunction]
fn check_version_signal(version: i32, bit: u8) -> bool {
    // Top 3 bits must be 001 (version bits signaling active)
    if (version & versionbits::VERSIONBITS_TOP_MASK) != versionbits::VERSIONBITS_TOP_BITS {
        return false;
    }
    // Check the specific bit
    let mask = 1i32 << bit;
    (version & mask) != 0
}

/// Python wrapper for deployment info
#[pyclass]
#[derive(Clone)]
pub struct PyDeploymentInfo {
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub bit: u8,
    #[pyo3(get)]
    pub state: String,
    #[pyo3(get)]
    pub since: u32,
    #[pyo3(get)]
    pub start_time: i64,
    #[pyo3(get)]
    pub timeout: i64,
    #[pyo3(get)]
    pub min_activation_height: u32,
    // Statistics (only present for STARTED/LOCKED_IN states)
    #[pyo3(get)]
    pub period: Option<u32>,
    #[pyo3(get)]
    pub threshold: Option<u32>,
    #[pyo3(get)]
    pub elapsed: Option<u32>,
    #[pyo3(get)]
    pub count: Option<u32>,
    #[pyo3(get)]
    pub possible: Option<bool>,
}

/// Internal provider for versionbits calculations from Python data
struct PyBlockIndexProvider {
    versions: std::collections::HashMap<u32, i32>,
    mtps: std::collections::HashMap<u32, i64>,
    height: u32,
}

impl BlockIndexProvider for PyBlockIndexProvider {
    fn get_median_time_past(&self, height: u32) -> Option<i64> {
        self.mtps.get(&height).copied()
    }

    fn get_block_version(&self, height: u32) -> Option<i32> {
        self.versions.get(&height).copied()
    }

    fn get_chain_height(&self) -> u32 {
        self.height
    }
}

/// Python wrapper for BIP68 sequence lock constants.
/// Provides constants for interpreting sequence numbers per BIP68.
#[pyclass]
#[derive(Clone)]
pub struct PySequenceLockConstants;

#[pymethods]
impl PySequenceLockConstants {
    #[new]
    fn new() -> Self {
        Self
    }

    /// If bit 31 is set, sequence is NOT treated as a relative lock-time
    #[classattr]
    const DISABLE_FLAG: u32 = sequence_lock::SEQUENCE_LOCKTIME_DISABLE_FLAG;

    /// If bit 22 is set, lock is time-based; otherwise block-height-based
    #[classattr]
    const TYPE_FLAG: u32 = sequence_lock::SEQUENCE_LOCKTIME_TYPE_FLAG;

    /// Mask for lower 16 bits containing the lock value
    #[classattr]
    const MASK: u32 = sequence_lock::SEQUENCE_LOCKTIME_MASK;

    /// Time-based locks use 512-second granularity (2^9)
    #[classattr]
    const GRANULARITY: u32 = sequence_lock::SEQUENCE_LOCKTIME_GRANULARITY;

    /// Sequence value 0xFFFFFFFF means the input is final (no lock)
    #[classattr]
    const FINAL: u32 = sequence_lock::SEQUENCE_FINAL;
}

// =============================================================================
// Headers Presync Anti-DoS (PRESYNC/REDOWNLOAD)
// =============================================================================

use crate::validate::headers_presync::{
    HeadersSyncState, HeadersSyncPhase, HeadersSyncResult as RustHeadersSyncResult,
    MAX_HEADERS_PER_MESSAGE,
};
use crate::chain_params::{
    minimum_chain_work, headers_presync_commitment_period, headers_redownload_buffer_size,
    get_checkpoints, get_last_checkpoint, get_checkpoint_at_height, verify_checkpoint,
    is_below_last_checkpoint, Checkpoint,
};

/// Get minimum chain work for a network (anti-DoS threshold).
///
/// Returns the value as a hex string (big-endian, no 0x prefix).
#[pyfunction]
fn get_minimum_chain_work(network: String) -> PyResult<String> {
    let network_enum = match network.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" | "testnet3" => Network::Testnet,
        "testnet4" => Network::Testnet4,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid network: {}", network),
            ));
        }
    };

    let work = minimum_chain_work(network_enum);
    // Convert to hex string
    let bytes = work.to_big_endian();
    Ok(hex::encode(bytes))
}

/// Get headers presync commitment period for a network.
#[pyfunction]
fn get_headers_commitment_period(network: String) -> PyResult<u32> {
    let network_enum = match network.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" | "testnet3" => Network::Testnet,
        "testnet4" => Network::Testnet4,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid network: {}", network),
            ));
        }
    };

    Ok(headers_presync_commitment_period(network_enum))
}

/// Get headers redownload buffer size for a network.
#[pyfunction]
fn get_headers_redownload_buffer_size(network: String) -> PyResult<u32> {
    let network_enum = match network.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" | "testnet3" => Network::Testnet,
        "testnet4" => Network::Testnet4,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid network: {}", network),
            ));
        }
    };

    Ok(headers_redownload_buffer_size(network_enum))
}

/// Get max headers per P2P message.
#[pyfunction]
fn max_headers_per_message() -> usize {
    MAX_HEADERS_PER_MESSAGE
}

// =============================================================================
// Checkpoint Functions
// =============================================================================

/// Python wrapper for Checkpoint
#[pyclass]
#[derive(Clone)]
pub struct PyCheckpoint {
    #[pyo3(get)]
    pub height: u32,
    #[pyo3(get)]
    pub hash: Vec<u8>,
}

impl From<Checkpoint> for PyCheckpoint {
    fn from(cp: Checkpoint) -> Self {
        Self {
            height: cp.height,
            hash: cp.hash.to_vec(),
        }
    }
}

#[pymethods]
impl PyCheckpoint {
    /// Get the hash as a hex string (big-endian display format).
    fn hash_hex(&self) -> String {
        // Convert from internal (little-endian) to display (big-endian)
        let mut display = self.hash.clone();
        display.reverse();
        hex::encode(display)
    }

    fn __repr__(&self) -> String {
        format!("Checkpoint(height={}, hash={})", self.height, self.hash_hex())
    }
}

/// Get all checkpoints for a network.
///
/// Returns a list of Checkpoint objects (height, hash) representing known-good blocks.
#[pyfunction]
fn get_network_checkpoints(network: String) -> PyResult<Vec<PyCheckpoint>> {
    let network_enum = match network.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" | "testnet3" => Network::Testnet,
        "testnet4" => Network::Testnet4,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid network: {}", network),
            ));
        }
    };

    Ok(get_checkpoints(network_enum)
        .into_iter()
        .map(PyCheckpoint::from)
        .collect())
}

/// Get the last checkpoint for a network.
///
/// Returns None if no checkpoints are defined.
#[pyfunction]
fn get_last_network_checkpoint(network: String) -> PyResult<Option<PyCheckpoint>> {
    let network_enum = match network.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" | "testnet3" => Network::Testnet,
        "testnet4" => Network::Testnet4,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid network: {}", network),
            ));
        }
    };

    Ok(get_last_checkpoint(network_enum).map(PyCheckpoint::from))
}

/// Check if a height is at or below the last checkpoint.
///
/// Used to determine if script validation can be skipped during IBD.
#[pyfunction]
fn check_is_below_checkpoint(network: String, height: u32) -> PyResult<bool> {
    let network_enum = match network.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" | "testnet3" => Network::Testnet,
        "testnet4" => Network::Testnet4,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid network: {}", network),
            ));
        }
    };

    Ok(is_below_last_checkpoint(network_enum, height))
}

/// Verify a block hash matches the checkpoint at a given height.
///
/// Returns:
/// - True if checkpoint exists and hash matches
/// - False if checkpoint exists and hash does NOT match
/// - None if no checkpoint at that height
#[pyfunction]
fn verify_block_checkpoint(network: String, height: u32, block_hash: Vec<u8>) -> PyResult<Option<bool>> {
    let network_enum = match network.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" | "testnet3" => Network::Testnet,
        "testnet4" => Network::Testnet4,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid network: {}", network),
            ));
        }
    };

    if block_hash.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "Block hash must be 32 bytes",
        ));
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&block_hash);

    Ok(verify_checkpoint(network_enum, height, &hash))
}

/// Check if script validation can be skipped for a block during IBD.
///
/// Two script-skip gates, matching Bitcoin Core's distinction between hard
/// consensus checkpoints (hash-committed) and the softer assumevalid trust
/// anchor:
///
///   1. Below the last hard checkpoint, script verification is skipped
///      unconditionally once the hash matches — this is a consensus rule,
///      not a trust knob.
///   2. Below the assumevalid height, script verification is skipped as a
///      performance optimisation. Core does the same (see src/validation.cpp,
///      `fScriptChecks = !IsAssumeValidSupportedByChainstate(...)`).
///
/// Without branch 2, mainnet blocks between the last checkpoint (850k) and
/// the v28 assumevalid height (938_343) forced every signature through
/// Python verification — ~12 s/block ceiling observed on the plan-w98 mainnet
/// soak, vs the ~1500 blk/hr expected steady state (see project memory
/// `project_plan_w98_mainnet_deploy.md`).
#[pyfunction]
fn can_skip_scripts_for_block(network: String, height: u32, block_hash: Vec<u8>) -> PyResult<bool> {
    let network_enum = match network.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" | "testnet3" => Network::Testnet,
        "testnet4" => Network::Testnet4,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid network: {}", network),
            ));
        }
    };

    if block_hash.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "Block hash must be 32 bytes",
        ));
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&block_hash);

    // Branch 1: below last hard checkpoint.
    if is_below_last_checkpoint(network_enum, height) {
        if let Some(matches) = verify_checkpoint(network_enum, height, &hash) {
            if !matches {
                return Ok(false); // Checkpoint mismatch — reject, don't skip.
            }
        }
        return Ok(true);
    }

    // Branch 2: below assumevalid height (soft trust anchor, Core-compatible).
    let assumevalid = crate::validate::block::get_assumevalid_height(network_enum);
    if assumevalid > 0 && height <= assumevalid {
        return Ok(true);
    }

    Ok(false)
}

/// Python wrapper for HeadersSyncPhase enum
#[pyclass]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PyHeadersSyncPhase {
    Presync,
    Redownload,
    Final,
}

impl From<HeadersSyncPhase> for PyHeadersSyncPhase {
    fn from(phase: HeadersSyncPhase) -> Self {
        match phase {
            HeadersSyncPhase::Presync => PyHeadersSyncPhase::Presync,
            HeadersSyncPhase::Redownload => PyHeadersSyncPhase::Redownload,
            HeadersSyncPhase::Final => PyHeadersSyncPhase::Final,
        }
    }
}

/// Python wrapper for HeadersSyncResult
#[pyclass]
#[derive(Clone)]
pub struct PyHeadersSyncResult {
    #[pyo3(get)]
    pub success: bool,
    #[pyo3(get)]
    pub request_more: bool,
    #[pyo3(get)]
    pub headers_to_store: Vec<Vec<u8>>,
    #[pyo3(get)]
    pub error: Option<String>,
}

impl From<RustHeadersSyncResult> for PyHeadersSyncResult {
    fn from(result: RustHeadersSyncResult) -> Self {
        Self {
            success: result.success,
            request_more: result.request_more,
            headers_to_store: result.headers_to_store
                .iter()
                .map(|h| {
                    use bitcoin::consensus::Encodable;
                    let mut buf = Vec::new();
                    h.consensus_encode(&mut buf).unwrap();
                    buf
                })
                .collect(),
            error: result.error,
        }
    }
}

/// Python wrapper for HeadersSyncState
///
/// Provides anti-DoS protection during header synchronization.
/// Implements PRESYNC/REDOWNLOAD phases per Bitcoin Core's HeadersSyncState.
#[pyclass]
pub struct PyHeadersSyncState {
    inner: HeadersSyncState,
}

#[pymethods]
impl PyHeadersSyncState {
    /// Create a new header sync state.
    ///
    /// # Arguments
    /// * `network` - Network name ("mainnet", "testnet", etc.)
    /// * `chain_start_hash` - 32-byte hash of the block we're syncing from
    /// * `chain_start_time` - Median time past of chain_start
    #[new]
    fn new(network: String, chain_start_hash: Vec<u8>, chain_start_time: u32) -> PyResult<Self> {
        if chain_start_hash.len() != 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "chain_start_hash must be 32 bytes",
            ));
        }

        let network_enum = match network.to_lowercase().as_str() {
            "mainnet" | "bitcoin" => Network::Bitcoin,
            "testnet" | "testnet3" => Network::Testnet,
            "testnet4" => Network::Testnet4,
            "regtest" => Network::Regtest,
            "signet" => Network::Signet,
            _ => {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!("Invalid network: {}", network),
                ));
            }
        };

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&chain_start_hash);

        Ok(Self {
            inner: HeadersSyncState::new(network_enum, hash, chain_start_time),
        })
    }

    /// Get current sync phase.
    fn phase(&self) -> PyHeadersSyncPhase {
        self.inner.phase().into()
    }

    /// Get cumulative work seen during presync (as hex string).
    fn presync_work(&self) -> String {
        let work = self.inner.presync_work();
        let bytes = work.to_big_endian();
        hex::encode(bytes)
    }

    /// Get presync height.
    fn presync_height(&self) -> u32 {
        self.inner.presync_height()
    }

    /// Get number of commitments stored.
    fn commitment_count(&self) -> usize {
        self.inner.commitment_count()
    }

    /// Process headers received from peer.
    ///
    /// # Arguments
    /// * `headers` - List of serialized headers (80 bytes each)
    /// * `full_message` - True if this is a complete 2000-header message
    ///
    /// # Returns
    /// PyHeadersSyncResult with success, request_more, headers_to_store, error
    fn process_headers(&mut self, headers: Vec<Vec<u8>>, full_message: bool) -> PyResult<PyHeadersSyncResult> {
        use bitcoin::consensus::Decodable;

        // Deserialize headers
        let mut parsed: Vec<bitcoin::blockdata::block::Header> = Vec::with_capacity(headers.len());
        for (i, header_bytes) in headers.iter().enumerate() {
            if header_bytes.len() != 80 {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!("Header {} has invalid length: {} (expected 80)", i, header_bytes.len()),
                ));
            }

            let mut cursor = std::io::Cursor::new(header_bytes);
            let header = bitcoin::blockdata::block::Header::consensus_decode(&mut cursor)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!("Failed to deserialize header {}: {}", i, e),
                ))?;
            parsed.push(header);
        }

        let result = self.inner.process_headers(&parsed, full_message);
        Ok(result.into())
    }

    /// Build locator for next headers request.
    ///
    /// Returns list of 32-byte block hashes.
    fn next_headers_request_locator(&self) -> Vec<Vec<u8>> {
        self.inner.next_headers_request_locator()
            .into_iter()
            .map(|h| h.to_vec())
            .collect()
    }

    /// Finalize and clean up state.
    fn finalize(&mut self) {
        self.inner.finalize();
    }
}

// ============================================================================
// PyBlockStore: Flat file block storage (blk*.dat/rev*.dat format)
// ============================================================================

use crate::storage::blockstore::{BlockStore, BlockFileInfo, BlockPosition};
use crate::storage::undo::BlockUndo;
use bitcoin::consensus::{Decodable, Encodable};

/// Python wrapper for flat file block storage (blk*.dat/rev*.dat format).
///
/// This provides Bitcoin Core compatible block storage in flat files, with
/// automatic file rollover at 128MB and a RocksDB index for block positions.
#[pyclass]
pub struct PyBlockStore {
    store: Arc<std::sync::RwLock<BlockStore>>,
}

#[pymethods]
impl PyBlockStore {
    /// Create a new block store.
    ///
    /// Args:
    ///     data_dir: Base data directory (blocks stored in data_dir/blocks/)
    ///     network: Network name ("mainnet", "testnet", "testnet4", "regtest", "signet")
    #[new]
    fn new(data_dir: String, network: String) -> PyResult<Self> {
        let network_enum = match network.to_lowercase().as_str() {
            "mainnet" | "bitcoin" => Network::Bitcoin,
            "testnet" | "testnet3" => Network::Testnet,
            "testnet4" => Network::Testnet4,
            "regtest" => Network::Regtest,
            "signet" => Network::Signet,
            _ => {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!("Invalid network: {}", network),
                ));
            }
        };

        let store = BlockStore::new(&data_dir, network_enum).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to open block store: {}",
                e
            ))
        })?;

        Ok(Self {
            store: Arc::new(std::sync::RwLock::new(store)),
        })
    }

    /// Write a block to disk.
    ///
    /// Args:
    ///     block_data: Serialized block data (Bitcoin consensus encoding)
    ///     height: Block height
    ///
    /// Returns:
    ///     Tuple of (file_num, data_pos) indicating where block was stored.
    fn write_block(&self, block_data: Vec<u8>, height: u32) -> PyResult<(i32, u32)> {
        let block = bitcoin::Block::consensus_decode(&mut std::io::Cursor::new(&block_data))
            .map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Invalid block data: {}",
                    e
                ))
            })?;

        let store = self.store.write().unwrap();
        let pos = store.write_block(&block, height).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to write block: {}",
                e
            ))
        })?;

        Ok((pos.file, pos.data_pos))
    }

    /// Read a block from disk by hash.
    ///
    /// Args:
    ///     block_hash: 32-byte block hash
    ///
    /// Returns:
    ///     Serialized block data, or None if not found.
    fn read_block(&self, block_hash: &[u8]) -> PyResult<Option<Vec<u8>>> {
        if block_hash.len() != 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Block hash must be 32 bytes",
            ));
        }

        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(block_hash);
        let block_hash = bitcoin::BlockHash::from_byte_array(hash_bytes);

        let store = self.store.read().unwrap();
        match store.read_block(&block_hash) {
            Ok(Some(block)) => {
                let mut data = Vec::new();
                block.consensus_encode(&mut data).map_err(|e| {
                    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                        "Failed to serialize block: {}",
                        e
                    ))
                })?;
                Ok(Some(data))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to read block: {}",
                e
            ))),
        }
    }

    /// Read a block from disk by file position.
    ///
    /// Args:
    ///     file_num: Block file number
    ///     data_pos: Position in block file (after header)
    ///
    /// Returns:
    ///     Serialized block data, or None if not found.
    fn read_block_at(&self, file_num: i32, data_pos: u32) -> PyResult<Option<Vec<u8>>> {
        let store = self.store.read().unwrap();
        match store.read_block_at(file_num, data_pos) {
            Ok(Some(block)) => {
                let mut data = Vec::new();
                block.consensus_encode(&mut data).map_err(|e| {
                    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                        "Failed to serialize block: {}",
                        e
                    ))
                })?;
                Ok(Some(data))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to read block: {}",
                e
            ))),
        }
    }

    /// Check if a block exists in the store.
    fn has_block(&self, block_hash: &[u8]) -> PyResult<bool> {
        if block_hash.len() != 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Block hash must be 32 bytes",
            ));
        }

        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(block_hash);
        let block_hash = bitcoin::BlockHash::from_byte_array(hash_bytes);

        let store = self.store.read().unwrap();
        store.has_block(&block_hash).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to check block: {}",
                e
            ))
        })
    }

    /// Get block position (file_num, data_pos, undo_pos) for a block hash.
    fn get_block_pos(&self, block_hash: &[u8]) -> PyResult<Option<(i32, u32, u32)>> {
        if block_hash.len() != 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Block hash must be 32 bytes",
            ));
        }

        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(block_hash);
        let block_hash = bitcoin::BlockHash::from_byte_array(hash_bytes);

        let store = self.store.read().unwrap();
        match store.get_block_pos(&block_hash) {
            Ok(Some(pos)) => Ok(Some((pos.file, pos.data_pos, pos.undo_pos))),
            Ok(None) => Ok(None),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to get block position: {}",
                e
            ))),
        }
    }

    /// Get current block file number.
    fn current_file(&self) -> i32 {
        let store = self.store.read().unwrap();
        store.current_file()
    }

    /// Get current position in block file.
    fn current_pos(&self) -> u32 {
        let store = self.store.read().unwrap();
        store.current_pos()
    }

    /// Get file info for a block file.
    ///
    /// Returns: Tuple of (num_blocks, size, undo_size, height_first, height_last, time_first, time_last)
    fn get_file_info(&self, file_num: i32) -> Option<(u32, u32, u32, u32, u32, u64, u64)> {
        let store = self.store.read().unwrap();
        store.get_file_info(file_num).map(|info| {
            (
                info.num_blocks,
                info.size,
                info.undo_size,
                info.height_first,
                info.height_last,
                info.time_first,
                info.time_last,
            )
        })
    }

    /// Flush all pending writes to disk.
    fn flush(&self) -> PyResult<()> {
        let store = self.store.read().unwrap();
        store.flush().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to flush: {}", e))
        })
    }

    /// Get the blocks directory path.
    fn blocks_dir(&self) -> String {
        let store = self.store.read().unwrap();
        store.blocks_dir().to_string_lossy().to_string()
    }

    // =========================================================================
    // Pruning Methods
    // =========================================================================

    /// Get the maximum block file number currently in use.
    fn max_blockfile_num(&self) -> i32 {
        let store = self.store.read().unwrap();
        store.max_blockfile_num()
    }

    /// Calculate total disk usage of all block and undo files.
    fn calculate_current_usage(&self) -> u64 {
        let store = self.store.read().unwrap();
        store.calculate_current_usage()
    }

    /// Find block files eligible for pruning.
    ///
    /// Args:
    ///     last_block_can_prune: Highest block height that can be pruned
    ///     min_block_to_prune: Lowest block height that can be pruned (usually 0)
    ///     target_bytes: Target disk usage in bytes (0 = no target, prune all eligible)
    ///
    /// Returns:
    ///     List of file numbers that can be pruned.
    fn find_files_to_prune(
        &self,
        last_block_can_prune: u32,
        min_block_to_prune: u32,
        target_bytes: u64,
    ) -> Vec<i32> {
        let store = self.store.read().unwrap();
        store.find_files_to_prune(last_block_can_prune, min_block_to_prune, target_bytes)
    }

    /// Prune block files to meet a target size.
    ///
    /// Args:
    ///     current_height: Current best block height
    ///     target_bytes: Target disk usage (minimum 550MB)
    ///
    /// Returns:
    ///     Tuple of (files_pruned, bytes_freed).
    fn prune_to_target(&self, current_height: u32, target_bytes: u64) -> PyResult<(usize, u64)> {
        let store = self.store.read().unwrap();
        store.prune_to_target(current_height, target_bytes).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Prune error: {}", e))
        })
    }

    /// Prune block files up to a specific height (for pruneblockchain RPC).
    ///
    /// Args:
    ///     target_height: Prune all files with blocks fully below this height
    ///     current_height: Current best block height (for safety check)
    ///
    /// Returns:
    ///     Tuple of (files_pruned, bytes_freed, actual_prune_height).
    fn prune_to_height(
        &self,
        target_height: u32,
        current_height: u32,
    ) -> PyResult<(usize, u64, u32)> {
        let store = self.store.read().unwrap();
        store.prune_to_height(target_height, current_height).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Prune error: {}", e))
        })
    }

    /// Get the lowest height that still has block data available.
    fn get_prune_height(&self) -> u32 {
        let store = self.store.read().unwrap();
        store.get_prune_height()
    }

    /// Check if block data is available for a given height.
    fn has_block_data_at_height(&self, height: u32) -> bool {
        let store = self.store.read().unwrap();
        store.has_block_data_at_height(height)
    }

    /// Get pruning statistics.
    ///
    /// Returns:
    ///     Tuple of (total_files, pruned_files, data_bytes, undo_bytes, prune_height).
    fn get_prune_stats(&self) -> (usize, usize, u64, u64, u32) {
        let store = self.store.read().unwrap();
        let stats = store.get_prune_stats();
        (
            stats.total_files,
            stats.pruned_files,
            stats.data_bytes,
            stats.undo_bytes,
            stats.prune_height,
        )
    }

    /// Get minimum blocks to keep for reorg safety (288 blocks).
    #[staticmethod]
    fn min_blocks_to_keep() -> u32 {
        BlockStore::MIN_BLOCKS_TO_KEEP
    }

    /// Get minimum prune target in bytes (550 MB).
    #[staticmethod]
    fn min_prune_target() -> u64 {
        BlockStore::MIN_DISK_SPACE_FOR_BLOCK_FILES
    }
}

// =============================================================================
// UTXO Cache Statistics for Python
// =============================================================================

use crate::storage::coins::{CacheStats, DEFAULT_DBCACHE_BYTES};

/// Python wrapper for UTXO cache statistics.
///
/// Provides read-only access to cache performance metrics.
#[pyclass]
#[derive(Clone)]
pub struct PyUtxoCacheStats {
    /// Total number of entries in the cache (including tombstones).
    #[pyo3(get)]
    pub entries: usize,
    /// Number of unspent entries.
    #[pyo3(get)]
    pub unspent: usize,
    /// Number of spent entries (tombstones).
    #[pyo3(get)]
    pub spent: usize,
    /// Number of dirty entries (modified since last flush).
    #[pyo3(get)]
    pub dirty: usize,
    /// Number of fresh entries (created in cache, not from DB).
    #[pyo3(get)]
    pub fresh: usize,
    /// Approximate memory usage in bytes.
    #[pyo3(get)]
    pub memory_bytes: usize,
    /// Number of cache hits.
    #[pyo3(get)]
    pub hits: u64,
    /// Number of cache misses.
    #[pyo3(get)]
    pub misses: u64,
    /// Number of flushes performed.
    #[pyo3(get)]
    pub flushes: u64,
    /// Total entries written in all flushes.
    #[pyo3(get)]
    pub entries_flushed: u64,
}

impl From<CacheStats> for PyUtxoCacheStats {
    fn from(stats: CacheStats) -> Self {
        Self {
            entries: stats.entries,
            unspent: stats.unspent,
            spent: stats.spent,
            dirty: stats.dirty,
            fresh: stats.fresh,
            memory_bytes: stats.memory_bytes,
            hits: stats.hits,
            misses: stats.misses,
            flushes: stats.flushes,
            entries_flushed: stats.entries_flushed,
        }
    }
}

#[pymethods]
impl PyUtxoCacheStats {
    /// Memory usage as a human-readable string (e.g., "450 MB").
    fn memory_human(&self) -> String {
        let bytes = self.memory_bytes as f64;
        if bytes >= 1_073_741_824.0 {
            format!("{:.2} GB", bytes / 1_073_741_824.0)
        } else if bytes >= 1_048_576.0 {
            format!("{:.2} MB", bytes / 1_048_576.0)
        } else if bytes >= 1024.0 {
            format!("{:.2} KB", bytes / 1024.0)
        } else {
            format!("{} B", self.memory_bytes)
        }
    }

    /// Cache hit rate as a percentage (0.0-100.0).
    fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "UtxoCacheStats(entries={}, unspent={}, dirty={}, memory={}, hit_rate={:.1}%)",
            self.entries,
            self.unspent,
            self.dirty,
            self.memory_human(),
            self.hit_rate()
        )
    }
}

/// Get the default UTXO cache size in bytes (450 MB).
#[pyfunction]
fn utxo_cache_default_size() -> usize {
    DEFAULT_DBCACHE_BYTES
}

// =============================================================================
// Transaction Index (TxIndex)
// =============================================================================

use crate::storage::txindex::{TxIndex, DiskTxPos};

/// Python wrapper for transaction disk position.
#[pyclass]
#[derive(Clone)]
pub struct PyDiskTxPos {
    /// Block file number (blk?????.dat).
    #[pyo3(get)]
    pub file_number: i32,
    /// Position of block data within file (after 8-byte header).
    #[pyo3(get)]
    pub block_offset: u32,
    /// Offset of transaction within block (after tx count varint).
    #[pyo3(get)]
    pub tx_offset: u32,
}

#[pymethods]
impl PyDiskTxPos {
    #[new]
    fn new(file_number: i32, block_offset: u32, tx_offset: u32) -> Self {
        Self { file_number, block_offset, tx_offset }
    }

    fn __repr__(&self) -> String {
        format!(
            "DiskTxPos(file={}, block_offset={}, tx_offset={})",
            self.file_number, self.block_offset, self.tx_offset
        )
    }
}

impl From<DiskTxPos> for PyDiskTxPos {
    fn from(pos: DiskTxPos) -> Self {
        Self {
            file_number: pos.file_number,
            block_offset: pos.block_offset,
            tx_offset: pos.tx_offset,
        }
    }
}

impl From<PyDiskTxPos> for DiskTxPos {
    fn from(pos: PyDiskTxPos) -> Self {
        Self::new(pos.file_number, pos.block_offset, pos.tx_offset)
    }
}

/// Python wrapper for transaction index.
///
/// Provides O(1) lookup of confirmed transactions by txid, storing the
/// file position where each transaction is located.
#[pyclass]
pub struct PyTxIndex {
    inner: TxIndex,
}

#[pymethods]
impl PyTxIndex {
    /// Open or create a transaction index.
    ///
    /// # Arguments
    ///
    /// * `path` - Directory for the index database
    /// * `enabled` - Whether the index is enabled (default: true)
    #[new]
    #[pyo3(signature = (path, enabled=true))]
    fn new(path: String, enabled: bool) -> PyResult<Self> {
        let inner = TxIndex::open(&path, enabled)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Failed to open TxIndex: {}", e)
            ))?;
        Ok(Self { inner })
    }

    /// Check if the index is enabled.
    fn is_enabled(&self) -> bool {
        self.inner.is_enabled()
    }

    /// Write a transaction position to the index.
    ///
    /// # Arguments
    ///
    /// * `txid` - Transaction ID as 32-byte array
    /// * `file_number` - Block file number
    /// * `block_offset` - Position of block data within file
    /// * `tx_offset` - Offset of transaction within block
    fn write_tx(
        &self,
        txid: Vec<u8>,
        file_number: i32,
        block_offset: u32,
        tx_offset: u32,
    ) -> PyResult<()> {
        if txid.len() != 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "txid must be 32 bytes"
            ));
        }
        let mut txid_arr = [0u8; 32];
        txid_arr.copy_from_slice(&txid);
        let txid = bitcoin::Txid::from_byte_array(txid_arr);
        let pos = DiskTxPos::new(file_number, block_offset, tx_offset);

        self.inner.write_tx(&txid, &pos)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Failed to write tx: {}", e)
            ))
    }

    /// Write multiple transaction positions in a batch.
    ///
    /// # Arguments
    ///
    /// * `txs` - List of (txid, file_number, block_offset, tx_offset) tuples
    fn write_txs(&self, txs: Vec<(Vec<u8>, i32, u32, u32)>) -> PyResult<()> {
        let txs: Result<Vec<(bitcoin::Txid, DiskTxPos)>, _> = txs
            .into_iter()
            .map(|(txid, file_num, block_off, tx_off)| {
                if txid.len() != 32 {
                    return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                        "txid must be 32 bytes"
                    ));
                }
                let mut txid_arr = [0u8; 32];
                txid_arr.copy_from_slice(&txid);
                Ok((
                    bitcoin::Txid::from_byte_array(txid_arr),
                    DiskTxPos::new(file_num, block_off, tx_off),
                ))
            })
            .collect();

        self.inner.write_txs(&txs?)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Failed to write txs: {}", e)
            ))
    }

    /// Read a transaction position from the index.
    ///
    /// # Arguments
    ///
    /// * `txid` - Transaction ID as 32-byte array
    ///
    /// # Returns
    ///
    /// DiskTxPos if found, None otherwise.
    fn read_tx(&self, txid: Vec<u8>) -> PyResult<Option<PyDiskTxPos>> {
        if txid.len() != 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "txid must be 32 bytes"
            ));
        }
        let mut txid_arr = [0u8; 32];
        txid_arr.copy_from_slice(&txid);
        let txid = bitcoin::Txid::from_byte_array(txid_arr);

        self.inner.read_tx(&txid)
            .map(|opt| opt.map(PyDiskTxPos::from))
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Failed to read tx: {}", e)
            ))
    }

    /// Delete a transaction from the index.
    fn delete_tx(&self, txid: Vec<u8>) -> PyResult<()> {
        if txid.len() != 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "txid must be 32 bytes"
            ));
        }
        let mut txid_arr = [0u8; 32];
        txid_arr.copy_from_slice(&txid);
        let txid = bitcoin::Txid::from_byte_array(txid_arr);

        self.inner.delete_tx(&txid)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Failed to delete tx: {}", e)
            ))
    }

    /// Delete multiple transactions in a batch.
    fn delete_txs(&self, txids: Vec<Vec<u8>>) -> PyResult<()> {
        let txids: Result<Vec<bitcoin::Txid>, _> = txids
            .into_iter()
            .map(|txid| {
                if txid.len() != 32 {
                    return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                        "txid must be 32 bytes"
                    ));
                }
                let mut txid_arr = [0u8; 32];
                txid_arr.copy_from_slice(&txid);
                Ok(bitcoin::Txid::from_byte_array(txid_arr))
            })
            .collect();

        self.inner.delete_txs(&txids?)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Failed to delete txs: {}", e)
            ))
    }

    /// Check if a transaction exists in the index.
    fn has_tx(&self, txid: Vec<u8>) -> PyResult<bool> {
        if txid.len() != 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "txid must be 32 bytes"
            ));
        }
        let mut txid_arr = [0u8; 32];
        txid_arr.copy_from_slice(&txid);
        let txid = bitcoin::Txid::from_byte_array(txid_arr);

        self.inner.has_tx(&txid)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Failed to check tx: {}", e)
            ))
    }

    /// Flush pending writes.
    fn flush(&self) -> PyResult<()> {
        self.inner.flush()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Failed to flush: {}", e)
            ))
    }
}

// =============================================================================
// Minisketch (BIP 330 Erlay)
// =============================================================================

use common::minisketch::{
    Minisketch as RustMinisketch,
    compute_short_txid as rust_compute_short_txid,
    compute_reconciliation_salt as rust_compute_reconciliation_salt,
    estimate_sketch_capacity as rust_estimate_sketch_capacity,
};

/// Python wrapper for Minisketch (BIP 330 set reconciliation).
#[pyclass]
#[derive(Clone)]
pub struct PyMinisketch {
    inner: RustMinisketch,
}

#[pymethods]
impl PyMinisketch {
    /// Create a new sketch with the given capacity.
    #[new]
    fn new(capacity: usize) -> Self {
        Self {
            inner: RustMinisketch::new(capacity),
        }
    }

    /// Create a sketch from serialized bytes.
    #[staticmethod]
    fn from_bytes(data: Vec<u8>, capacity: usize) -> PyResult<Self> {
        RustMinisketch::deserialize(&data, capacity)
            .map(|inner| Self { inner })
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))
    }

    /// Get the capacity of this sketch.
    #[getter]
    fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Add a non-zero element to the sketch.
    fn add(&mut self, element: u32) -> PyResult<()> {
        if element == 0 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Cannot add zero element to sketch"
            ));
        }
        self.inner.add(element);
        Ok(())
    }

    /// Merge another sketch into this one (XOR).
    fn merge(&mut self, other: &PyMinisketch) -> PyResult<()> {
        if self.inner.capacity() != other.inner.capacity() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Cannot merge sketches with different capacities"
            ));
        }
        self.inner.merge(&other.inner);
        Ok(())
    }

    /// Merge two sketches, returning a new sketch encoding the symmetric difference.
    fn merge_new(&self, other: &PyMinisketch) -> PyResult<PyMinisketch> {
        if self.inner.capacity() != other.inner.capacity() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Cannot merge sketches with different capacities"
            ));
        }
        Ok(PyMinisketch {
            inner: self.inner.merge_new(&other.inner),
        })
    }

    /// Decode the sketch into its elements.
    /// Returns None if the difference exceeds capacity.
    fn decode(&self) -> Option<Vec<u32>> {
        self.inner.decode().map(|set| set.into_iter().collect())
    }

    /// Serialize to bytes.
    fn serialize(&self) -> Vec<u8> {
        self.inner.serialize()
    }

    /// Get the syndromes as a list.
    fn syndromes(&self) -> Vec<u32> {
        self.inner.syndromes().to_vec()
    }

    fn __repr__(&self) -> String {
        format!("Minisketch(capacity={})", self.inner.capacity())
    }
}

/// Compute a 32-bit short txid from a wtxid using SipHash.
#[pyfunction]
fn minisketch_compute_short_txid(wtxid: Vec<u8>, k0: u64, k1: u64) -> PyResult<u32> {
    if wtxid.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "wtxid must be 32 bytes"
        ));
    }
    let mut wtxid_arr = [0u8; 32];
    wtxid_arr.copy_from_slice(&wtxid);
    Ok(rust_compute_short_txid(&wtxid_arr, k0, k1))
}

/// Compute the reconciliation salt from two peer salts per BIP 330.
#[pyfunction]
fn minisketch_compute_salt(salt1: u64, salt2: u64) -> (u64, u64) {
    rust_compute_reconciliation_salt(salt1, salt2)
}

/// Estimate sketch capacity based on set sizes per BIP 330.
#[pyfunction]
fn minisketch_estimate_capacity(local_size: usize, remote_size: usize, q: f64) -> usize {
    rust_estimate_sketch_capacity(local_size, remote_size, q)
}

// =============================================================================
// BIP305 assumeUTXO Snapshot Functions
// =============================================================================

use crate::storage::snapshot::{
    self as snapshot_mod, AssumeutxoData, SnapshotMetadata,
    get_assumeutxo_data as rust_get_assumeutxo_data,
    get_assumeutxo_by_hash as rust_get_assumeutxo_by_hash,
    get_available_snapshot_heights as rust_get_available_heights,
};

/// Python wrapper for assumeUTXO data
#[pyclass]
#[derive(Clone)]
pub struct PyAssumeutxoData {
    #[pyo3(get)]
    pub height: u32,
    #[pyo3(get)]
    pub block_hash: Vec<u8>,
    #[pyo3(get)]
    pub hash_serialized: Vec<u8>,
    #[pyo3(get)]
    pub chain_tx_count: u64,
}

impl From<AssumeutxoData> for PyAssumeutxoData {
    fn from(data: AssumeutxoData) -> Self {
        Self {
            height: data.height,
            block_hash: data.block_hash.to_vec(),
            hash_serialized: data.hash_serialized.to_vec(),
            chain_tx_count: data.chain_tx_count,
        }
    }
}

#[pymethods]
impl PyAssumeutxoData {
    /// Get block hash as hex string (big-endian display format)
    fn block_hash_hex(&self) -> String {
        let mut display = self.block_hash.clone();
        display.reverse();
        hex::encode(display)
    }

    /// Get hash_serialized as hex string
    fn hash_serialized_hex(&self) -> String {
        let mut display = self.hash_serialized.clone();
        display.reverse();
        hex::encode(display)
    }

    fn __repr__(&self) -> String {
        format!(
            "AssumeutxoData(height={}, block_hash={}, chain_tx_count={})",
            self.height,
            self.block_hash_hex(),
            self.chain_tx_count
        )
    }
}

/// Python wrapper for snapshot metadata
#[pyclass]
#[derive(Clone)]
pub struct PySnapshotMetadata {
    #[pyo3(get)]
    pub version: u16,
    #[pyo3(get)]
    pub network: String,
    #[pyo3(get)]
    pub base_blockhash: Vec<u8>,
    #[pyo3(get)]
    pub coins_count: u64,
}

#[pymethods]
impl PySnapshotMetadata {
    /// Get base block hash as hex string (big-endian display format)
    fn base_blockhash_hex(&self) -> String {
        let mut display = self.base_blockhash.clone();
        display.reverse();
        hex::encode(display)
    }

    fn __repr__(&self) -> String {
        format!(
            "SnapshotMetadata(version={}, network={}, base_blockhash={}, coins_count={})",
            self.version,
            self.network,
            self.base_blockhash_hex(),
            self.coins_count
        )
    }
}

/// Get assumeUTXO data for a network and height.
///
/// Returns None if no assumeUTXO data exists for the given height.
#[pyfunction]
fn get_assumeutxo_data(network: String, height: u32) -> PyResult<Option<PyAssumeutxoData>> {
    let network_enum = match network.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" | "testnet3" => Network::Testnet,
        "testnet4" => Network::Testnet4,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid network: {}", network),
            ));
        }
    };

    Ok(rust_get_assumeutxo_data(network_enum, height).map(Into::into))
}

/// Get assumeUTXO data for a network by block hash.
///
/// Returns None if no assumeUTXO data exists for the given block hash.
#[pyfunction]
fn get_assumeutxo_by_blockhash(network: String, block_hash: Vec<u8>) -> PyResult<Option<PyAssumeutxoData>> {
    let network_enum = match network.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" | "testnet3" => Network::Testnet,
        "testnet4" => Network::Testnet4,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid network: {}", network),
            ));
        }
    };

    if block_hash.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "Block hash must be 32 bytes",
        ));
    }

    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(&block_hash);

    Ok(rust_get_assumeutxo_by_hash(network_enum, &hash_arr).map(Into::into))
}

/// Get all available snapshot heights for a network.
#[pyfunction]
fn get_available_snapshot_heights(network: String) -> PyResult<Vec<u32>> {
    let network_enum = match network.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" | "testnet3" => Network::Testnet,
        "testnet4" => Network::Testnet4,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid network: {}", network),
            ));
        }
    };

    Ok(rust_get_available_heights(network_enum))
}

/// Get the snapshot magic bytes (b"utxo\xff")
#[pyfunction]
fn snapshot_magic_bytes() -> Vec<u8> {
    snapshot_mod::SNAPSHOT_MAGIC.to_vec()
}

/// Get the current snapshot format version
#[pyfunction]
fn snapshot_format_version() -> u16 {
    snapshot_mod::SNAPSHOT_VERSION
}

/// Read snapshot metadata from a file.
///
/// Returns the metadata if the file is a valid snapshot for the given network.
#[pyfunction]
fn read_snapshot_metadata(path: String, network: String) -> PyResult<PySnapshotMetadata> {
    let network_enum = match network.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" | "testnet3" => Network::Testnet,
        "testnet4" => Network::Testnet4,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid network: {}", network),
            ));
        }
    };

    let metadata = SnapshotMetadata::from_file(&path, network_enum)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("{}", e)))?;

    Ok(PySnapshotMetadata {
        version: metadata.version,
        network: format!("{:?}", metadata.network),
        base_blockhash: metadata.base_blockhash.to_vec(),
        coins_count: metadata.coins_count,
    })
}

/// Fast sync module for Bitcoin blockchain synchronization
#[pymodule]
fn sync(m: &Bound<'_, PyModule>) -> PyResult<()> {
    init_logging();
    m.add_function(pyo3::wrap_pyfunction!(verify_ecdsa, m)?)?;
    // Hardware-accelerated crypto functions
    m.add_function(pyo3::wrap_pyfunction!(crypto_sha256_implementation, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(crypto_sha256, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(crypto_double_sha256, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(crypto_verify_schnorr, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(crypto_batch_verify_schnorr, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(crypto_verify_ecdsa_compact, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(get_script_flags_for_height, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(segwit_activation_height, m)?)?;
    // BIP68 sequence lock functions
    m.add_function(pyo3::wrap_pyfunction!(bip68_activation_height, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(is_bip68_active, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(calculate_sequence_locks, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(check_sequence_locks, m)?)?;
    // Transaction finality (locktime) functions
    m.add_function(pyo3::wrap_pyfunction!(is_final_tx, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(locktime_threshold, m)?)?;
    // Coinbase maturity functions
    m.add_function(pyo3::wrap_pyfunction!(check_coinbase_maturity, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(coinbase_maturity_constant, m)?)?;
    // Difficulty adjustment functions
    m.add_function(pyo3::wrap_pyfunction!(get_next_work_required, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(calculate_next_difficulty, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(pow_limit_bits, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(check_difficulty_transition, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(difficulty_adjustment_interval, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(target_timespan, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(target_spacing, m)?)?;
    m.add_class::<PyUTXO>()?;
    m.add_class::<SyncEngine>()?;
    m.add_class::<FastSync>()?;
    m.add_class::<SyncCanceller>()?;
    m.add_class::<SyncProgressReporter>()?;
    m.add_class::<SyncProgress>()?;
    m.add_class::<PyBlockchainDB>()?;
    m.add_class::<PyBlockStore>()?;
    m.add_class::<PyBlock>()?;
    m.add_class::<PyTransaction>()?;
    m.add_class::<PyScriptVerifyFlags>()?;
    m.add_class::<PySequenceLockConstants>()?;
    // BIP9 versionbits functions
    m.add_function(pyo3::wrap_pyfunction!(get_deployment_state, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(get_all_deployments_info, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(is_deployment_active, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(versionbits_top_bits, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(versionbits_top_mask, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(check_version_signal, m)?)?;
    m.add_class::<PyDeploymentInfo>()?;
    // Headers presync anti-DoS functions
    m.add_function(pyo3::wrap_pyfunction!(get_minimum_chain_work, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(get_headers_commitment_period, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(get_headers_redownload_buffer_size, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(max_headers_per_message, m)?)?;
    m.add_class::<PyHeadersSyncPhase>()?;
    m.add_class::<PyHeadersSyncResult>()?;
    m.add_class::<PyHeadersSyncState>()?;
    // Checkpoint functions
    m.add_class::<PyCheckpoint>()?;
    m.add_function(pyo3::wrap_pyfunction!(get_network_checkpoints, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(get_last_network_checkpoint, m)?)?;
    // UTXO cache statistics
    m.add_class::<PyUtxoCacheStats>()?;
    m.add_function(pyo3::wrap_pyfunction!(utxo_cache_default_size, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(check_is_below_checkpoint, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(verify_block_checkpoint, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(can_skip_scripts_for_block, m)?)?;
    // Transaction index
    m.add_class::<PyTxIndex>()?;
    m.add_class::<PyDiskTxPos>()?;
    // BIP 330 Minisketch (Erlay)
    m.add_class::<PyMinisketch>()?;
    m.add_function(pyo3::wrap_pyfunction!(minisketch_compute_short_txid, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(minisketch_compute_salt, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(minisketch_estimate_capacity, m)?)?;
    // BIP305 assumeUTXO snapshot functions
    m.add_class::<PyAssumeutxoData>()?;
    m.add_class::<PySnapshotMetadata>()?;
    m.add_function(pyo3::wrap_pyfunction!(get_assumeutxo_data, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(get_assumeutxo_by_blockhash, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(get_available_snapshot_heights, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(snapshot_magic_bytes, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(snapshot_format_version, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(read_snapshot_metadata, m)?)?;
    Ok(())
}

/// Python wrapper for UTXO
#[pyclass]
#[derive(Clone)]
pub struct PyUTXO {
    #[pyo3(get)]
    pub txid: String,
    #[pyo3(get)]
    pub vout: u32,
    #[pyo3(get)]
    pub value: u64,
    #[pyo3(get)]
    pub script_pubkey: Vec<u8>,
    #[pyo3(get)]
    pub height: Option<u32>,
}

impl From<UTXO> for PyUTXO {
    fn from(utxo: UTXO) -> Self {
        Self {
            txid: utxo.txid().to_string(),
            vout: utxo.vout(),
            value: utxo.value(),
            script_pubkey: utxo.script_pubkey.as_bytes().to_vec(),
            height: utxo.height,
        }
    }
}

impl From<&UTXO> for PyUTXO {
    fn from(utxo: &UTXO) -> Self {
        Self {
            txid: utxo.txid().to_string(),
            vout: utxo.vout(),
            value: utxo.value(),
            script_pubkey: utxo.script_pubkey.as_bytes().to_vec(),
            height: utxo.height,
        }
    }
}

/// Python wrapper for Block
#[pyclass]
#[derive(Clone)]
pub struct PyBlock {
    #[pyo3(get)]
    pub version: i32,
    #[pyo3(get)]
    pub prev_blockhash: Vec<u8>,
    #[pyo3(get)]
    pub merkle_root: Vec<u8>,
    #[pyo3(get)]
    pub timestamp: u32,
    #[pyo3(get)]
    pub bits: u32,
    #[pyo3(get)]
    pub nonce: u32,
    #[pyo3(get)]
    pub transactions: Vec<PyTransaction>,
    #[pyo3(get)]
    pub hash: Vec<u8>,
}

impl PyBlock {
    fn from_block_wrapper(block: &BlockWrapper) -> Self {
        let inner_block = block.inner();
        let header = &inner_block.header;
        let hash = block.block_hash();
        
        Self {
            version: header.version.to_consensus(),
            prev_blockhash: header.prev_blockhash.to_byte_array().to_vec(),
            merkle_root: header.merkle_root.to_byte_array().to_vec(),
            timestamp: header.time,
            bits: header.bits.to_consensus(),
            nonce: header.nonce,
            transactions: inner_block.txdata.iter().map(|tx| PyTransaction::from_transaction(tx)).collect(),
            hash: hash.to_byte_array().to_vec(),
        }
    }
}

#[pymethods]
impl PyBlock {
    /// Compute block hash
    fn hash(&self) -> Vec<u8> {
        self.hash.clone()
    }
    
    /// Serialize block to bytes
    fn serialize(&self) -> PyResult<Vec<u8>> {
        // Convert back to BlockWrapper and serialize
        // This is a simplified version - full implementation would reconstruct BlockWrapper
        Err(PyErr::new::<pyo3::exceptions::PyNotImplementedError, _>(
            "Block serialization requires full BlockWrapper reconstruction"
        ))
    }
    
    // Note: Block deserialization would require BitcoinDeserialize implementation
    // For now, blocks are deserialized in Rust and converted to PyBlock
}

/// Python wrapper for Transaction
#[pyclass]
#[derive(Clone)]
pub struct PyTransaction {
    #[pyo3(get)]
    pub txid: Vec<u8>,
    #[pyo3(get)]
    pub version: i32,
    #[pyo3(get)]
    pub locktime: u32,
    #[pyo3(get)]
    pub inputs: Vec<PyTxIn>,
    #[pyo3(get)]
    pub outputs: Vec<PyTxOut>,
}

impl PyTransaction {
    fn from_transaction(tx: &bitcoin::Transaction) -> Self {
        let txid = tx.compute_txid();
        // TODO: Fix type conversions - these types need proper conversion methods
        // For now, serialize the transaction and extract values
        let mut tx_bytes = Vec::new();
        use bitcoin::consensus::Encodable;
        tx.consensus_encode(&mut tx_bytes).unwrap();
        
        // Version is first 4 bytes (little-endian i32)
        let version = if tx_bytes.len() >= 4 {
            i32::from_le_bytes([tx_bytes[0], tx_bytes[1], tx_bytes[2], tx_bytes[3]])
        } else {
            2i32
        };
        
        // Locktime is at the end (last 4 bytes before it)
        // This is a simplified extraction - in practice we'd parse the full structure
        let locktime = if tx_bytes.len() >= 8 {
            // Locktime is typically the last 4 bytes
            let len = tx_bytes.len();
            u32::from_le_bytes([tx_bytes[len-4], tx_bytes[len-3], tx_bytes[len-2], tx_bytes[len-1]])
        } else {
            0u32
        };
        
        Self {
            txid: txid.to_byte_array().to_vec(),
            version,
            locktime,
            inputs: tx.input.iter().map(|input| PyTxIn::from_txin(input)).collect::<Vec<_>>(),
            outputs: tx.output.iter().map(|output| PyTxOut::from_txout(output)).collect::<Vec<_>>(),
        }
    }
}

/// Python wrapper for Transaction Input
#[pyclass]
#[derive(Clone)]
pub struct PyTxIn {
    #[pyo3(get)]
    pub prev_txid: Vec<u8>,
    #[pyo3(get)]
    pub prev_vout: u32,
    #[pyo3(get)]
    pub script_sig: Vec<u8>,
    #[pyo3(get)]
    pub sequence: u32,
}

impl PyTxIn {
    fn from_txin(txin: &bitcoin::TxIn) -> Self {
        // Convert sequence - serialize the whole TxIn and extract sequence (last 4 bytes)
        let mut txin_bytes = Vec::new();
        use bitcoin::consensus::Encodable;
        txin.consensus_encode(&mut txin_bytes).unwrap();
        
        // Sequence is the last 4 bytes of TxIn serialization
        let sequence = if txin_bytes.len() >= 4 {
            let len = txin_bytes.len();
            u32::from_le_bytes([txin_bytes[len-4], txin_bytes[len-3], txin_bytes[len-2], txin_bytes[len-1]])
        } else {
            0xFFFFFFFFu32
        };
        
        Self {
            prev_txid: txin.previous_output.txid.to_byte_array().to_vec(),
            prev_vout: txin.previous_output.vout,
            script_sig: txin.script_sig.as_bytes().to_vec(),
            sequence,
        }
    }
}

/// Python wrapper for Transaction Output
#[pyclass]
#[derive(Clone)]
pub struct PyTxOut {
    #[pyo3(get)]
    pub value: u64,
    #[pyo3(get)]
    pub script_pubkey: Vec<u8>,
}

impl PyTxOut {
    fn from_txout(txout: &bitcoin::TxOut) -> Self {
        Self {
            value: txout.value.to_sat(),
            script_pubkey: txout.script_pubkey.as_bytes().to_vec(),
        }
    }
}

/// Python wrapper for BlockchainDB
#[pyclass]
pub struct PyBlockchainDB {
    db: Arc<BlockchainDB>,
    /// Lazily-initialized BlockValidator for `validate_block_from_bytes`.
    /// Constructed on first call with the caller-supplied network — network
    /// is stable per datadir so the first value is cached for the life of
    /// the PyBlockchainDB. See OUROBOROS-B3-STAGE1-KICKOFF.md.
    block_validator: std::sync::OnceLock<Arc<BlockValidator>>,
}

#[pymethods]
impl PyBlockchainDB {
    /// Attempt to repair a corrupted database at the given path.
    #[staticmethod]
    fn repair(data_dir: String) -> PyResult<()> {
        BlockchainDB::repair(&data_dir)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Failed to repair database: {}", e)
            ))
    }

    #[new]
    fn new(data_dir: String) -> PyResult<Self> {
        let db = BlockchainDB::open(&data_dir)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Failed to open database: {}", e)
            ))?;

        // Check for and recover from a crash during the previous apply_block()
        if let Err(e) = db.recover_from_crash() {
            log::error!("Crash recovery failed: {} — continuing anyway", e);
        }

        Ok(Self {
            db: Arc::new(db),
            block_validator: std::sync::OnceLock::new(),
        })
    }

    /// Get block by hash
    fn get_block(&self, block_hash: &[u8]) -> PyResult<Option<PyBlock>> {
        if block_hash.len() != 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Block hash must be 32 bytes"
            ));
        }

        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(block_hash);

        match self.db.get_block(&hash_bytes) {
            Ok(Some(block)) => Ok(Some(PyBlock::from_block_wrapper(&block))),
            Ok(None) => Ok(None),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Database error: {}", e)
            )),
        }
    }

    /// Existence probe for a block by hash. Cheap alternative to `get_block`
    /// when the caller only needs a truthy/falsy answer: no block body is
    /// deserialized and no `PyBlock` is constructed.
    fn has_block_hash(&self, block_hash: &[u8]) -> PyResult<bool> {
        if block_hash.len() != 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Block hash must be 32 bytes"
            ));
        }

        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(block_hash);

        self.db.has_block_hash(&hash_bytes).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Database error: {}", e)
            )
        })
    }

    /// Get block by height
    fn get_block_by_height(&self, height: u32) -> PyResult<Option<PyBlock>> {
        match self.db.get_block_by_height(height) {
            Ok(Some(block)) => Ok(Some(PyBlock::from_block_wrapper(&block))),
            Ok(None) => Ok(None),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Database error: {}", e)
            )),
        }
    }

    /// Cheap block-hash lookup by height: reads only the BLOCK_INDEX_CF
    /// row (32-byte header prefix) rather than deserialising the full
    /// block body. Used by block_sync's _build_locator hot path, which
    /// rebuilds the locator every 1 s during IBD.
    fn get_block_hash_by_height(&self, height: u32) -> PyResult<Option<[u8; 32]>> {
        self.db.get_block_hash_by_height(height).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Database error: {}", e)
            )
        })
    }
    
    /// Get the median-time-past for a given height (11-block median timestamp).
    /// Uses lightweight block metadata instead of deserializing full blocks.
    fn get_median_time_past(&self, height: u32) -> PyResult<Option<u32>> {
        let start = if height >= 10 { height - 10 } else { 0 };
        let mut timestamps = Vec::with_capacity(11);
        for h in start..=height {
            match self.db.get_block_metadata(h) {
                Ok(Some(meta)) => timestamps.push(meta.timestamp),
                Ok(None) => {
                    // Fall back to full block if metadata missing
                    match self.db.get_block_by_height(h) {
                        Ok(Some(block)) => timestamps.push(block.header().time),
                        Ok(None) => {}
                        Err(_) => {}
                    }
                }
                Err(_) => {}
            }
        }
        if timestamps.is_empty() {
            return Ok(None);
        }
        timestamps.sort_unstable();
        Ok(Some(timestamps[timestamps.len() / 2]))
    }

    /// Get UTXO
    fn get_utxo(&self, txid: &[u8], vout: u32) -> PyResult<Option<PyUTXO>> {
        if txid.len() != 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Transaction ID must be 32 bytes"
            ));
        }
        
        let mut txid_bytes = [0u8; 32];
        txid_bytes.copy_from_slice(txid);
        
        let txid = bitcoin::Txid::from_byte_array(txid_bytes);
        let outpoint = bitcoin::OutPoint {
            txid,
            vout,
        };
        
        match self.db.get_utxo(&outpoint) {
            Ok(Some(utxo)) => Ok(Some(PyUTXO::from(&utxo))),
            Ok(None) => Ok(None),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Database error: {}", e)
            )),
        }
    }

    /// Batch-get multiple UTXOs in a single FFI call.
    ///
    /// Takes a list of (txid_bytes, vout) pairs and returns a list of
    /// Option<PyUTXO> in the same order.  Using one batch call instead of N
    /// individual get_utxo() calls reduces Python→Rust boundary crossings
    /// and GIL re-acquisition overhead during transaction validation.
    ///
    /// Each txid_bytes must be exactly 32 bytes; any invalid entry yields None.
    fn get_utxo_batch(&self, outpoints: Vec<(Vec<u8>, u32)>) -> PyResult<Vec<Option<PyUTXO>>> {
        let mut results = Vec::with_capacity(outpoints.len());
        for (txid_bytes, vout) in outpoints {
            if txid_bytes.len() != 32 {
                results.push(None);
                continue;
            }
            let mut txid_arr = [0u8; 32];
            txid_arr.copy_from_slice(&txid_bytes);
            let txid = bitcoin::Txid::from_byte_array(txid_arr);
            let outpoint = bitcoin::OutPoint { txid, vout };
            match self.db.get_utxo(&outpoint) {
                Ok(Some(utxo)) => results.push(Some(PyUTXO::from(&utxo))),
                Ok(None) => results.push(None),
                Err(_) => results.push(None),
            }
        }
        Ok(results)
    }

    /// Store block
    fn store_block(&self, _block: &PyBlock) -> PyResult<()> {
        // This would require reconstructing BlockWrapper from PyBlock
        // For now, return NotImplemented
        Err(PyErr::new::<pyo3::exceptions::PyNotImplementedError, _>(
            "store_block requires BlockWrapper reconstruction - use Rust API directly"
        ))
    }

    /// Validate a block from raw wire-format bytes.
    ///
    /// Entry point for B3 Stage 1 — moves the Python IBD drain path's
    /// `validate_block` call into Rust behind a single GIL-releasing FFI
    /// call.  Matches Python's `skip_scripts=True` semantics: performs all
    /// structural, amount, coinbase-maturity, and lock-time checks, but
    /// does not verify signatures (today Rust never verifies signatures
    /// in the production validate path; `skip_scripts` is plumbed through
    /// for forward compat when script verification lands).
    ///
    /// On first call the `BlockValidator` is constructed from the
    /// caller-supplied network and cached for the life of this
    /// `PyBlockchainDB`.  Subsequent calls reuse the cached validator —
    /// the `network` argument after the first call is ignored.
    ///
    /// # Arguments
    /// * `block_bytes` — raw Bitcoin wire-format block
    /// * `prev_height` — height of the block *before* this one (so this
    ///   block's height is `prev_height + 1`)
    /// * `skip_scripts` — reserved; today Rust never calls
    ///   `script::verify_*` in the validate path
    /// * `network` — network name ("mainnet", "testnet", "testnet4",
    ///   "regtest", "signet"); used only on the first call to construct
    ///   the cached validator
    ///
    /// Returns `Ok(())` on successful validation; `PyValueError` with a
    /// descriptive message on any validation failure.
    ///
    /// Reference: OUROBOROS-B3-RUST-VALIDATE-SCOPE.md,
    /// OUROBOROS-B3-STAGE1-KICKOFF.md.
    fn validate_block_from_bytes(
        &self,
        py: Python,
        block_bytes: Vec<u8>,
        prev_height: u32,
        skip_scripts: bool,
        network: String,
    ) -> PyResult<()> {
        use common::BitcoinDeserialize;

        // Resolve (and cache) the BlockValidator.  Construction only runs
        // on the first call; subsequent calls hit the OnceLock fast path.
        let validator = self.block_validator.get_or_init(|| {
            let network_enum = match network.to_lowercase().as_str() {
                "mainnet" | "bitcoin" => Network::Bitcoin,
                "testnet" | "testnet3" => Network::Testnet,
                "testnet4" => Network::Testnet4,
                "regtest" => Network::Regtest,
                "signet" => Network::Signet,
                _ => Network::Bitcoin, // fall back to mainnet; caller-side validation is expected
            };
            Arc::new(BlockValidator::new(Arc::clone(&self.db), network_enum))
        });
        let validator = Arc::clone(validator);

        // Deserialize + validate off-GIL.  This is the whole point of the
        // pymethod — releases the GIL for the duration of validation so
        // the Python drain loop can overlap deserialize(N+1) / peer I/O
        // / RPC servicing with validate(N).
        py.detach(|| {
            let (block, _) = BlockWrapper::bitcoin_deserialize(&block_bytes)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!("deserialize: {}", e)
                ))?;
            validator
                .validate_block_with_flags(&block, prev_height, skip_scripts)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!("validate: {}", e)
                ))
        })
    }

    /// Accept a fully-serialised block (Bitcoin wire format) and connect it
    /// to the active chain.  This performs the same work as
    /// `BlockValidator::apply_block()`:
    ///
    /// 1. Deserialize block bytes into a `BlockWrapper`.
    /// 2. Store the block body in BLOCKS_CF.
    /// 3. Update UTXO set (spend inputs, create outputs).
    /// 4. Store transaction index entries.
    /// 5. Store block metadata (height, chainwork, timestamp) in BLOCK_INDEX_CF.
    /// 6. Update the chain tip.
    ///
    /// This is used by `generatetoaddress` (regtest mining) where the block
    /// is constructed in Python and needs to be persisted via the Rust DB.
    fn connect_block_from_bytes(&self, block_bytes: Vec<u8>, height: u32) -> PyResult<Vec<u8>> {
        use common::BitcoinDeserialize;
        use crate::storage::schema::{encode_outpoint, CHAINSTATE_CF, SPENT_CF};

        // Deserialize
        let (block, _) = BlockWrapper::bitcoin_deserialize(&block_bytes).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Failed to deserialize block: {}", e)
            )
        })?;

        let block_hash = *block.block_hash().as_byte_array();
        let inner = block.inner();

        // Validate proof-of-work (consensus-critical)
        // Reference: Bitcoin Core src/pow.cpp CheckProofOfWork() + DeriveTarget()
        {
            let n_bits = inner.header.bits.to_consensus();
            let exponent = (n_bits >> 24) as u32;
            let mantissa = n_bits & 0x7f_ffff;

            // Reject negative target
            if n_bits & 0x80_0000 != 0 {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    "Invalid nBits: negative target".to_string()
                ));
            }

            // Reject zero target
            if mantissa == 0 {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    "Invalid nBits: zero target".to_string()
                ));
            }

            // Compute 256-bit target from compact nBits
            // target = mantissa * 2^(8*(exponent-3))
            let target: [u8; 32] = {
                let mut t = [0u8; 32];
                if exponent <= 3 {
                    let shifted = mantissa >> (8 * (3 - exponent));
                    if shifted > 0 {
                        t[0] = (shifted & 0xff) as u8;
                        t[1] = ((shifted >> 8) & 0xff) as u8;
                        t[2] = ((shifted >> 16) & 0xff) as u8;
                    }
                } else {
                    let byte_offset = (exponent - 3) as usize;
                    if byte_offset + 2 < 32 {
                        t[byte_offset] = (mantissa & 0xff) as u8;
                        t[byte_offset + 1] = ((mantissa >> 8) & 0xff) as u8;
                        t[byte_offset + 2] = ((mantissa >> 16) & 0xff) as u8;
                    }
                    // If byte_offset + 2 >= 32, target overflows → reject below
                }
                t
            };

            // Reject overflow (target > 2^256 - 1, effectively all zeros after overflow)
            let target_is_zero = target.iter().all(|&b| b == 0);
            if target_is_zero {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    "Invalid nBits: target overflow or zero".to_string()
                ));
            }

            // block_hash is already in internal byte order (little-endian uint256)
            // Compare hash <= target as little-endian 256-bit integers
            // Compare from most significant byte (index 31) down
            let hash_le = &block_hash;
            let mut pow_ok = false;
            for i in (0..32).rev() {
                if hash_le[i] < target[i] {
                    pow_ok = true;
                    break;
                } else if hash_le[i] > target[i] {
                    break;
                }
                // equal bytes: continue to next
                if i == 0 {
                    pow_ok = true; // all bytes equal → hash == target → ok
                }
            }

            if !pow_ok {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!("high-hash: block hash exceeds PoW target")
                ));
            }
        }

        // Verify merkle root matches transactions (consensus-critical)
        {
            use common::crypto::compute_merkle_root;
            let txids: Vec<[u8; 32]> = inner.txdata
                .iter()
                .map(|tx| *tx.compute_txid().as_byte_array())
                .collect();
            let computed_root = compute_merkle_root(&txids);
            let header_root = inner.header.merkle_root.as_byte_array();
            if computed_root != *header_root {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!(
                        "Invalid merkle root: header={} computed={}",
                        hex::encode(header_root),
                        hex::encode(computed_root),
                    )
                ));
            }
        }

        // Validate prevhash links to current chain tip (consensus-critical)
        let prev_blockhash = *inner.header.prev_blockhash.as_byte_array();
        if height == 0 {
            // Genesis block must have all-zero prevhash
            if prev_blockhash != [0u8; 32] {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    "Genesis block prev_hash must be all zeros".to_string()
                ));
            }
        } else {
            let (tip_hash, _tip_height) = self.db.get_best_block().map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    format!("Failed to get current chain tip: {}", e)
                )
            })?;
            if prev_blockhash != tip_hash {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!(
                        "Block prev_hash {} does not match chain tip {}",
                        hex::encode(prev_blockhash),
                        hex::encode(tip_hash),
                    )
                ));
            }
        }

        // Single WriteBatch for all DB mutations in this block
        let mut batch = self.db.create_batch();

        // HEAD_BLOCKS marker (crash-safety)
        let (old_tip_hash, old_tip_height) = if height == 0 {
            ([0u8; 32], 0u32)
        } else {
            self.db.get_best_block().unwrap_or(([0u8; 32], 0))
        };
        self.db.write_head_blocks_batch(&mut batch, &old_tip_hash, old_tip_height, &block_hash, height)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{}", e)))?;

        // --- Phase 1: Collect all input outpoint keys for MultiGet ---
        let raw_db = self.db.raw_db();
        let chainstate_cf = raw_db.cf_handle(CHAINSTATE_CF)
            .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("chainstate CF not found"))?;
        let spent_cf = raw_db.cf_handle(SPENT_CF)
            .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("spent CF not found"))?;

        // Collect all input outpoint keys (skip coinbase)
        let mut input_keys: Vec<[u8; 36]> = Vec::new();
        let mut input_spending_txids: Vec<[u8; 32]> = Vec::new();
        for tx in inner.txdata.iter() {
            if tx.is_coinbase() {
                continue;
            }
            let txid = *tx.compute_txid().as_byte_array();
            for input in &tx.input {
                let prev_txid = *input.previous_output.txid.as_byte_array();
                let key = encode_outpoint(&prev_txid, input.previous_output.vout);
                input_keys.push(key);
                input_spending_txids.push(txid);
            }
        }

        // MultiGet all spent UTXOs in a single RocksDB call
        let utxo_values: Vec<_> = if !input_keys.is_empty() {
            let cf_keys: Vec<_> = input_keys.iter()
                .map(|k| (&*chainstate_cf, k.as_slice()))
                .collect();
            raw_db.multi_get_cf(cf_keys)
        } else {
            Vec::new()
        };

        // --- Phase 2: Process spends using pre-fetched data ---
        for (idx, (key, spending_txid)) in input_keys.iter().zip(input_spending_txids.iter()).enumerate() {
            // Delete from chainstate
            batch.delete_cf(&chainstate_cf, key);

            // Store undo record if UTXO was found
            match &utxo_values[idx] {
                Ok(Some(utxo_bytes)) => {
                    let mut undo_value = Vec::with_capacity(32 + utxo_bytes.len());
                    undo_value.extend_from_slice(spending_txid);
                    undo_value.extend_from_slice(utxo_bytes);
                    batch.put_cf(&spent_cf, key, &undo_value);
                }
                _ => {} // UTXO not found — skip undo (early blocks may have missing UTXOs)
            }
        }

        // --- Phase 3: Add outputs + tx index ---
        for (tx_pos, tx) in inner.txdata.iter().enumerate() {
            let txid = tx.compute_txid();

            for (vout, output) in tx.output.iter().enumerate() {
                let outpoint = OutPointWrapper::from_txid_vout(txid, vout as u32);
                let utxo = UTXO::new(
                    outpoint.clone(),
                    output.value.to_sat(),
                    output.script_pubkey.clone(),
                    Some(height),
                    tx.is_coinbase(),
                );
                self.db.add_utxo_batch(&mut batch, outpoint.inner(), &utxo)
                    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{}", e)))?;
            }

            self.db.store_tx_index_batch(&mut batch, txid.as_byte_array(), &block_hash, height, tx_pos as u32)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{}", e)))?;
        }

        // Store block body + metadata
        self.db.store_block_batch(&mut batch, &block)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{}", e)))?;

        let timestamp = inner.header.time;
        let bits = inner.header.bits.to_consensus();
        let prev_chainwork = if height == 0 {
            [0u8; 32]
        } else {
            self.db.get_block_metadata(height - 1)
                .ok()
                .and_then(|opt| opt.map(|m| m.chainwork))
                .unwrap_or([0u8; 32])
        };
        let chainwork = crate::chainwork::compute_chainwork(&prev_chainwork, bits);
        let metadata = BlockMetadata::new(height, chainwork, timestamp);
        self.db.store_block_metadata_batch(&mut batch, height, &block_hash, &metadata)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{}", e)))?;

        // Update chain tip + delete marker
        self.db.update_best_block_batch(&mut batch, &block_hash, height)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{}", e)))?;
        self.db.delete_head_blocks_batch(&mut batch)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{}", e)))?;

        // Atomically apply all writes for this block
        self.db.apply_batch(batch)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{}", e)))?;

        Ok(block_hash.to_vec())
    }

    /// Import blocks from a framed binary file.
    ///
    /// Frame format: [4 bytes height LE] [4 bytes size LE] [size bytes raw block]
    ///
    /// Reads all frames from the file, skipping blocks at or below `start_height`.
    /// Connects each block using `connect_block_from_bytes`.
    /// Returns the number of blocks imported.
    fn import_blocks_from_file(
        &self,
        path: String,
        start_height: u32,
        progress_interval: Option<u32>,
    ) -> PyResult<u32> {
        use std::io::Read;

        let interval = progress_interval.unwrap_or(10000);

        let mut file: Box<dyn Read> = if path == "-" {
            Box::new(std::io::stdin().lock())
        } else {
            let f = std::fs::File::open(&path).map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("Cannot open {}: {}", path, e))
            })?;
            Box::new(std::io::BufReader::with_capacity(4 * 1024 * 1024, f))
        };

        let mut frame_header = [0u8; 8];
        let mut imported = 0u32;
        let mut skipped = 0u32;
        let start = std::time::Instant::now();

        loop {
            match file.read_exact(&mut frame_header) {
                Ok(()) => {},
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => {
                    return Err(PyErr::new::<pyo3::exceptions::PyIOError, _>(
                        format!("Error reading frame header: {}", e)
                    ));
                }
            }

            let frame_height = u32::from_le_bytes([
                frame_header[0], frame_header[1], frame_header[2], frame_header[3],
            ]);
            let frame_size = u32::from_le_bytes([
                frame_header[4], frame_header[5], frame_header[6], frame_header[7],
            ]);

            if frame_size == 0 || frame_size > 4 * 1024 * 1024 {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!("Invalid frame size {} at height {}", frame_size, frame_height)
                ));
            }

            let mut block_data = vec![0u8; frame_size as usize];
            file.read_exact(&mut block_data).map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyIOError, _>(
                    format!("Error reading block at height {}: {}", frame_height, e)
                )
            })?;

            if frame_height <= start_height {
                skipped += 1;
                continue;
            }

            self.connect_block_from_bytes(block_data, frame_height)?;
            imported += 1;

            if interval > 0 && imported % interval == 0 {
                let elapsed = start.elapsed().as_secs_f64();
                let rate = imported as f64 / elapsed.max(0.001);
                log::info!(
                    "import-blocks: height={} imported={} skipped={} rate={:.1} blk/s",
                    frame_height, imported, skipped, rate,
                );
            }
        }

        let elapsed = start.elapsed().as_secs_f64();
        let rate = imported as f64 / elapsed.max(0.001);
        log::info!(
            "import-blocks complete: imported={} skipped={} elapsed={:.1}s rate={:.1} blk/s",
            imported, skipped, elapsed, rate,
        );

        Ok(imported)
    }

    /// Import a UTXO snapshot in HDOG binary format.
    ///
    /// HDOG format:
    /// ```text
    /// Header (52 bytes):
    ///   Magic:        4 bytes    "HDOG"
    ///   Version:      u32 LE     (1)
    ///   Block Hash:   32 bytes   (little-endian)
    ///   Block Height: u32 LE
    ///   UTXO Count:   u64 LE
    ///
    /// Per UTXO:
    ///   TxID:         32 bytes   (little-endian)
    ///   Vout:         u32 LE
    ///   Amount:       i64 LE     (satoshis)
    ///   Height+CB:    u32 LE     (height in bits [31:1], coinbase flag in bit [0])
    ///   Script Len:   u16 LE
    ///   Script:       N bytes    (raw scriptPubKey)
    /// ```
    ///
    /// Clears existing chainstate, loads all UTXOs using WriteBatch (flushed
    /// every `batch_size` entries), and sets the chain tip.
    ///
    /// Returns `(block_hash_hex, height, utxo_count)`.
    fn import_hdog_snapshot(
        &self,
        path: String,
        batch_size: Option<u64>,
    ) -> PyResult<(String, u32, u64)> {
        use std::io::{BufReader, Read};

        let batch_size = batch_size.unwrap_or(100_000);

        // Open file
        let file = std::fs::File::open(&path).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("Cannot open {}: {}", path, e))
        })?;
        let mut reader = BufReader::with_capacity(8 * 1024 * 1024, file);

        // Read header (52 bytes)
        let mut header = [0u8; 52];
        reader.read_exact(&mut header).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("Failed to read header: {}", e))
        })?;

        // Validate magic
        if &header[0..4] != b"HDOG" {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid magic: expected HDOG, got {:?}", &header[0..4]),
            ));
        }

        let version = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        if version != 1 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Unsupported HDOG version: {}", version),
            ));
        }

        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&header[8..40]);

        let block_height = u32::from_le_bytes([header[40], header[41], header[42], header[43]]);
        let utxo_count = u64::from_le_bytes([
            header[44], header[45], header[46], header[47],
            header[48], header[49], header[50], header[51],
        ]);

        // Block hash display (big-endian hex)
        let mut display_hash = block_hash;
        display_hash.reverse();
        let block_hash_hex = hex::encode(display_hash);

        log::info!(
            "[hdog] Importing snapshot: height={}, utxo_count={}, block={}",
            block_height, utxo_count, block_hash_hex,
        );

        // Clear existing chainstate
        log::info!("[hdog] Clearing existing chainstate...");
        self.db.clear_chainstate().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to clear chainstate: {}", e))
        })?;

        // Get column family handle
        let cf = self.db.raw_db().cf_handle(crate::storage::schema::CHAINSTATE_CF)
            .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("chainstate CF not found"))?;

        // Import UTXOs in batches
        let mut batch = self.db.create_batch();
        let mut loaded: u64 = 0;
        let start_time = std::time::Instant::now();
        let mut last_log_time = start_time;

        // Pre-allocate a buffer for the fixed-size part of each UTXO record (32+4+8+4+2 = 50 bytes)
        let mut utxo_fixed = [0u8; 50];

        for _ in 0..utxo_count {
            // Read fixed-size fields (50 bytes)
            reader.read_exact(&mut utxo_fixed).map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyIOError, _>(
                    format!("Failed to read UTXO {} of {}: {}", loaded, utxo_count, e),
                )
            })?;

            let txid_bytes: [u8; 32] = utxo_fixed[0..32].try_into().unwrap();
            let vout = u32::from_le_bytes(utxo_fixed[32..36].try_into().unwrap());
            let amount = i64::from_le_bytes(utxo_fixed[36..44].try_into().unwrap()) as u64;
            let height_cb = u32::from_le_bytes(utxo_fixed[44..48].try_into().unwrap());
            let script_len = u16::from_le_bytes(utxo_fixed[48..50].try_into().unwrap()) as usize;

            let coin_height = height_cb >> 1;
            let is_coinbase = (height_cb & 1) != 0;

            // Read script
            let mut script = vec![0u8; script_len];
            if script_len > 0 {
                reader.read_exact(&mut script).map_err(|e| {
                    PyErr::new::<pyo3::exceptions::PyIOError, _>(
                        format!("Failed to read script for UTXO {}: {}", loaded, e),
                    )
                })?;
            }

            // Build the RocksDB key: [32-byte txid LE] + [4-byte vout LE]
            let key = crate::storage::schema::encode_outpoint(&txid_bytes, vout);

            // Build the RocksDB value using the same serialization as UTXO::to_bytes():
            // [OutPoint consensus (txid LE 32 + vout LE 4)] + [amount u64 LE 8]
            // + [script_pubkey (varint len + bytes)] + [1 byte height flag] + [4 bytes height] + [1 byte is_coinbase]
            let mut value = Vec::with_capacity(36 + 8 + 1 + script_len + 1 + 4 + 1);
            // OutPoint: txid (32 bytes) + vout (4 bytes LE) — consensus encoding
            value.extend_from_slice(&txid_bytes);
            value.extend_from_slice(&vout.to_le_bytes());
            // Amount (u64 LE)
            value.extend_from_slice(&amount.to_le_bytes());
            // ScriptPubKey: varint length + bytes (Bitcoin consensus encoding)
            let script_len_varint = common::encode_varint(script_len as u64);
            value.extend_from_slice(&script_len_varint);
            value.extend_from_slice(&script);
            // Height: flag byte (1 = Some) + u32 LE
            value.push(1u8);
            value.extend_from_slice(&coin_height.to_le_bytes());
            // is_coinbase: bool as u8
            value.push(if is_coinbase { 1u8 } else { 0u8 });

            batch.put_cf(&cf, key, value);
            loaded += 1;

            if loaded % batch_size == 0 {
                self.db.apply_batch(batch).map_err(|e| {
                    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                        format!("WriteBatch failed at UTXO {}: {}", loaded, e),
                    )
                })?;
                batch = rocksdb::WriteBatch::default();

                let now = std::time::Instant::now();
                if now.duration_since(last_log_time).as_secs() >= 5 || loaded % 1_000_000 == 0 {
                    let elapsed = now.duration_since(start_time).as_secs_f64();
                    let rate = loaded as f64 / elapsed;
                    let eta = (utxo_count - loaded) as f64 / rate;
                    log::info!(
                        "[hdog] Loaded {}/{} UTXOs ({:.1}%) — {:.0} utxo/s — ETA {:.0}s",
                        loaded, utxo_count,
                        loaded as f64 / utxo_count as f64 * 100.0,
                        rate, eta,
                    );
                    last_log_time = now;
                }
            }
        }

        // Flush remaining batch
        if batch.len() > 0 {
            self.db.apply_batch(batch).map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    format!("Final WriteBatch failed: {}", e),
                )
            })?;
        }

        let elapsed = start_time.elapsed().as_secs_f64();
        let rate = loaded as f64 / elapsed;
        log::info!(
            "[hdog] Loaded all {} UTXOs in {:.1}s ({:.0} utxo/s)",
            loaded, elapsed, rate,
        );

        // Set chain tip
        self.db.update_best_block(&block_hash, block_height).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Failed to update chain tip: {}", e),
            )
        })?;

        log::info!(
            "[hdog] Chain tip set to height {} ({})",
            block_height, block_hash_hex,
        );

        Ok((block_hash_hex, block_height, loaded))
    }

    /// Update UTXO set atomically
    fn update_utxo_set(
        &self,
        spent: Vec<(Vec<u8>, u32)>,
        created: Vec<PyUTXO>,
    ) -> PyResult<()> {
        // Convert spent outpoints
        let mut spent_outpoints = Vec::new();
        for (txid_bytes, vout) in spent {
            if txid_bytes.len() != 32 {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    "Transaction ID must be 32 bytes"
                ));
            }
            let mut txid = [0u8; 32];
            txid.copy_from_slice(&txid_bytes);
            spent_outpoints.push(bitcoin::OutPoint {
                txid: bitcoin::Txid::from_byte_array(txid),
                vout,
            });
        }
        
        // Convert created UTXOs
        let _created_utxos: Vec<UTXO> = Vec::new();
        for _py_utxo in created {
            // This is simplified - would need to reconstruct full UTXO
            // For now, return NotImplemented
            return Err(PyErr::new::<pyo3::exceptions::PyNotImplementedError, _>(
                "update_utxo_set requires UTXO reconstruction - use Rust API directly"
            ));
        }
        
        // Would call: self.db.batch_update_utxos(&spent_outpoints, &created_utxos)?;
        Ok(())
    }
    
    /// Get chainwork at height (from block metadata, persisted in DB)
    fn get_chainwork_by_height(&self, height: u32) -> PyResult<Vec<u8>> {
        match self.db.get_chainwork_by_height(height) {
            Ok(cw) => Ok(cw.to_vec()),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Database error: {}", e),
            )),
        }
    }

    /// Get best block (chain tip)
    fn get_best_block(&self) -> PyResult<(Vec<u8>, u32)> {
        match self.db.get_best_block() {
            Ok((hash, height)) => Ok((hash.to_vec(), height)),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Database error: {}", e)
            )),
        }
    }

    /// Update the best block (chain tip). Used during reorg.
    fn update_best_block(&self, block_hash: &[u8], height: u32) -> PyResult<()> {
        if block_hash.len() != 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Block hash must be 32 bytes"
            ));
        }
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(block_hash);
        self.db.update_best_block(&hash_bytes, height).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Database error: {}", e)
            )
        })
    }
    
    // ========== Pruning Methods ==========

    /// Delete raw block data for heights in [from_height, to_height].
    /// Block index (headers + metadata) is preserved.
    /// Returns the number of blocks pruned.
    fn prune_blocks_range(&self, from_height: u32, to_height: u32) -> PyResult<u32> {
        self.db.prune_blocks_range(from_height, to_height).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Prune error: {}", e)
            )
        })
    }

    /// Delete raw block data at a single height. Returns True if data was deleted.
    fn prune_block_at_height(&self, height: u32) -> PyResult<bool> {
        self.db.prune_block_at_height(height).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Prune error: {}", e)
            )
        })
    }

    /// Get the lowest block height whose data has NOT been pruned.
    /// Returns 0 if pruning has never run.
    fn get_prune_height(&self) -> PyResult<u32> {
        self.db.get_prune_height().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Database error: {}", e)
            )
        })
    }

    /// Check whether block body data exists for a given height.
    fn has_block_data(&self, height: u32) -> PyResult<bool> {
        self.db.has_block_data(height).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Database error: {}", e)
            )
        })
    }

    /// Estimate total size of all block data in bytes (approximate).
    fn estimate_blocks_size(&self) -> PyResult<u64> {
        self.db.estimate_blocks_size().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Database error: {}", e)
            )
        })
    }

    /// Check for and recover from a mid-apply crash (two-phase commit).
    ///
    /// If a HEAD_BLOCKS marker exists in META_CF, the previous process
    /// crashed during apply_block(). This method rolls back the partial
    /// apply by disconnecting the incomplete block and restoring the UTXO
    /// set to the previous chain tip.
    ///
    /// Should be called once at startup before any new blocks are applied.
    ///
    /// Returns True if a recovery was performed, False if the database was clean.
    fn recover_from_crash(&self) -> PyResult<bool> {
        self.db.recover_from_crash().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Crash recovery failed: {}", e)
            )
        })
    }

    /// Look up a confirmed transaction's block location by txid.
    ///
    /// Returns a dict with keys: block_hash (bytes), height (int),
    /// tx_position (int), or None if the transaction is not indexed.
    fn get_tx_index(&self, txid: &[u8]) -> PyResult<Option<(Vec<u8>, u32, u32)>> {
        if txid.len() != 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Transaction ID must be 32 bytes"
            ));
        }
        let mut txid_bytes = [0u8; 32];
        txid_bytes.copy_from_slice(txid);
        self.db.get_tx_index(&txid_bytes).map(|opt| {
            opt.map(|(block_hash, height, tx_pos)| {
                (block_hash.to_vec(), height, tx_pos)
            })
        }).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Database error: {}", e)
            )
        })
    }

    /// Build and store undo data for a block.
    ///
    /// This should be called after the UTXO set has been updated during
    /// connect_block. It reads spent UTXOs from SPENT_CF and stores
    /// structured undo data in UNDO_CF.
    ///
    /// # Arguments
    /// * `block_hash` - Hash of the block being connected
    /// * `height` - Block height
    /// * `prev_block_hash` - Hash of the previous block
    fn store_block_undo(&self, block_hash: &[u8], height: u32, prev_block_hash: &[u8]) -> PyResult<()> {
        if block_hash.len() != 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Block hash must be 32 bytes"
            ));
        }
        if prev_block_hash.len() != 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Previous block hash must be 32 bytes"
            ));
        }

        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(block_hash);
        let mut prev_hash_bytes = [0u8; 32];
        prev_hash_bytes.copy_from_slice(prev_block_hash);

        // Get the block
        let block = self.db.get_block(&hash_bytes).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Failed to get block: {}", e)
            )
        })?.ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Block not found")
        })?;

        self.db.build_and_store_undo_data(&block, height, &prev_hash_bytes).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Failed to store undo data: {}", e)
            )
        })
    }

    /// Check if undo data exists for a block at the given height.
    fn has_block_undo(&self, height: u32) -> PyResult<bool> {
        self.db.has_block_undo(height).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Database error: {}", e)
            )
        })
    }

    /// Disconnect the block at the given height — reverse all UTXO changes.
    ///
    /// Removes outputs created by the block from the UTXO set and restores
    /// spent inputs from undo data in UNDO_CF (or SPENT_CF for backward
    /// compatibility). Updates the chain tip to the previous block.
    ///
    /// Returns the hash of the disconnected block.
    fn disconnect_block(&self, height: u32) -> PyResult<Vec<u8>> {
        match self.db.disconnect_block_at_height(height) {
            Ok(hash) => Ok(hash.to_vec()),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Failed to disconnect block at height {}: {}", height, e)
            )),
        }
    }

    // ========== Block Invalidation Methods ==========

    /// Invalidate a block and all its descendants.
    ///
    /// Marks the block as BLOCK_FAILED_VALID and all its descendants as
    /// BLOCK_FAILED_CHILD. If the block is in the active chain, disconnects
    /// blocks back to the invalid block's parent.
    ///
    /// # Arguments
    /// * `block_hash` - Hash of the block to invalidate (32 bytes)
    ///
    /// # Returns
    /// The height of the new chain tip after invalidation.
    ///
    /// # Reference
    /// Bitcoin Core: validation.cpp `InvalidateBlock()`
    fn invalidate_block(&self, block_hash: &[u8]) -> PyResult<u32> {
        if block_hash.len() != 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Block hash must be 32 bytes"
            ));
        }

        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(block_hash);

        self.db.invalidate_block(&hash_bytes).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Failed to invalidate block: {}", e)
            )
        })
    }

    /// Reconsider a previously-invalidated block.
    ///
    /// Removes the invalid flag from the block and its descendants/ancestors,
    /// allowing them to be considered for chain selection again.
    ///
    /// # Arguments
    /// * `block_hash` - Hash of the block to reconsider (32 bytes)
    ///
    /// # Returns
    /// The height of the chain tip after reconsideration (may change if the
    /// reconsidered chain is now best).
    ///
    /// # Reference
    /// Bitcoin Core: rpc/blockchain.cpp `ReconsiderBlock()`
    fn reconsider_block(&self, block_hash: &[u8]) -> PyResult<u32> {
        if block_hash.len() != 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Block hash must be 32 bytes"
            ));
        }

        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(block_hash);

        self.db.reconsider_block(&hash_bytes).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Failed to reconsider block: {}", e)
            )
        })
    }

    /// Check if a block at a given height is marked as invalid.
    ///
    /// Returns True if the block has BLOCK_FAILED_VALID or BLOCK_FAILED_CHILD
    /// flags set, False otherwise.
    fn is_block_invalid(&self, height: u32) -> PyResult<bool> {
        self.db.is_block_invalid(height).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Database error: {}", e)
            )
        })
    }

    /// Get list of all invalid blocks.
    ///
    /// Returns a list of (height, hash) tuples for all blocks marked as invalid.
    fn get_invalid_blocks(&self) -> PyResult<Vec<(u32, Vec<u8>)>> {
        self.db.get_invalid_blocks()
            .map(|blocks| {
                blocks.into_iter()
                    .map(|(height, hash)| (height, hash.to_vec()))
                    .collect()
            })
            .map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    format!("Database error: {}", e)
                )
            })
    }

    /// Context manager support for transactions
    fn __enter__(&self) -> PyResult<Self> {
        Ok(self.clone())
    }
    
    fn __exit__(
        &self,
        _exc_type: &Bound<'_, PyAny>,
        _exc_val: &Bound<'_, PyAny>,
        _exc_tb: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        // Database operations are already atomic via RocksDB
        Ok(())
    }
}

impl Clone for PyBlockchainDB {
    fn clone(&self) -> Self {
        Self {
            db: Arc::clone(&self.db),
            // Each clone starts with a fresh empty OnceLock; the cached
            // validator is local to each instance.  First call on the
            // clone re-initializes it (cheap — BlockValidator::new just
            // bundles Arcs + reads env).
            block_validator: std::sync::OnceLock::new(),
        }
    }
}

/// Fast sync engine for Bitcoin blockchain
#[pyclass]
pub struct SyncEngine {
    // Add your sync engine fields here
}

#[pymethods]
impl SyncEngine {
    #[new]
    fn new() -> Self {
        SyncEngine {}
    }

    /// Sync blocks from the blockchain
    #[pyo3(signature = (blocks))]
    fn sync_blocks(&mut self, blocks: Vec<Vec<u8>>) -> PyResult<usize> {
        // TODO: Implement block syncing logic
        Ok(blocks.len())
    }

    /// Get all UTXOs from chainstate (for address balance/scan).
    /// Note: SyncEngine is a stub with no database; returns example UTXOs.
    fn get_utxos(&self) -> PyResult<Vec<PyUTXO>> {
        self.get_example_utxos()
    }

    /// Get example UTXOs for demonstration purposes
    fn get_example_utxos(&self) -> PyResult<Vec<PyUTXO>> {
        use bitcoin::hashes::Hash;
        use bitcoin::ScriptBuf;

        // Create some example UTXOs for demonstration
        let mut utxos = Vec::new();

        // Example UTXO 1
        let txid1 = bitcoin::Txid::from_byte_array([1u8; 32]);
        let outpoint1 = OutPointWrapper::from_txid_vout(txid1, 0);
        let script1 = ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14, 0x88, 0xac]); // P2PKH script
        let utxo1 = UTXO::new(outpoint1, 50_000_000, script1, None, false); // 0.5 BTC
        utxos.push(PyUTXO::from(utxo1));

        // Example UTXO 2
        let txid2 = bitcoin::Txid::from_byte_array([2u8; 32]);
        let outpoint2 = OutPointWrapper::from_txid_vout(txid2, 1);
        let script2 = ScriptBuf::from_bytes(vec![0x51]); // OP_1
        let utxo2 = UTXO::new(outpoint2, 100_000_000, script2, None, false); // 1.0 BTC
        utxos.push(PyUTXO::from(utxo2));

        // Example UTXO 3
        let txid3 = bitcoin::Txid::from_byte_array([3u8; 32]);
        let outpoint3 = OutPointWrapper::from_txid_vout(txid3, 0);
        let script3 = ScriptBuf::from_bytes(vec![0x52]); // OP_2
        let utxo3 = UTXO::new(outpoint3, 25_000_000, script3, None, false); // 0.25 BTC
        utxos.push(PyUTXO::from(utxo3));

        Ok(utxos)
    }
}

/// Progress reporter that reads from shared cache without borrowing FastSync.
/// Use this during sync to avoid "Already borrowed" when the sync thread holds FastSync.
#[pyclass]
pub struct SyncProgressReporter {
    db: Arc<BlockchainDB>,
    progress_cache: Arc<StdMutex<BlockProgressCache>>,
    network: Network,
}

#[pymethods]
impl SyncProgressReporter {
    /// Get current sync progress. Safe to call while sync is running (no FastSync borrow).
    fn get_progress(&self) -> PyResult<SyncProgress> {
        let db_height = match self.db.get_best_block() {
            Ok((_, h)) => h,
            Err(DbError::BlockNotFound) => 0,
            Err(e) => {
                return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    format!("Failed to get best block: {}", e),
                ));
            }
        };

        let cache = self.progress_cache.lock().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Progress cache lock error: {}", e),
            )
        })?;

        let (current_height, total_height, progress_percent, blocks_per_second, eta_seconds, phase, total_known) =
            if cache.total_to_download > 0 {
                // Block phase: show "blocks we have / block height (chain tip)"
                // blocks_we_have = had at start + downloaded this run
                let blocks_downloaded = cache.blocks_downloaded;
                let total_chain_blocks = cache.total_chain_blocks.max(1);
                let total_to_download = cache.total_to_download;
                let blocks_we_have = total_chain_blocks
                    .saturating_sub(total_to_download)
                    .saturating_add(blocks_downloaded);
                // block_height = tip (0-indexed), i.e. total_chain_blocks - 1; use total_chain_blocks for %
                let block_height = total_chain_blocks;
                let percent = if block_height > 0 {
                    ((blocks_we_have as f64 / block_height as f64) * 100.0).min(100.0)
                } else {
                    0.0
                };
                (
                    blocks_we_have,
                    block_height,
                    percent,
                    cache.blocks_per_second,
                    cache.eta_seconds,
                    "block",
                    true, // block phase always has known total
                )
            } else {
                // Header phase
                let total_known = cache.header_sync_tip.is_some();
                let estimated_tip = match self.network {
                    Network::Testnet => 18_000_000u32,
                    Network::Testnet4 => 150_000u32,
                    Network::Bitcoin => 900_000u32,
                    _ => 1_000_000u32,
                };
                // Use discovered tip when we got a short batch (chain shorter than estimate)
                let total = cache
                    .header_sync_tip
                    .map(|h| h.saturating_add(1))
                    .unwrap_or_else(|| estimated_tip.max(db_height.saturating_add(1)));
                // blocks_in_chain = db_height + 1 (genesis + blocks 1..tip)
                let blocks_in_chain = db_height.saturating_add(1);
                // When total not known, don't show misleading % - use 0 (CLI shows "requesting..." instead)
                let percent = if total_known && total > 0 {
                    ((blocks_in_chain as f64 / total as f64) * 100.0).min(100.0)
                } else {
                    0.0
                };
                (
                    blocks_in_chain,
                    total,
                    percent,
                    0.0,
                    0.0,
                    "header",
                    total_known,
                )
            };

        // Cap ETA at 999h to avoid overflow/absurd display when speed is very low
        const MAX_ETA_SECS: u64 = 999 * 3600;
        let eta_capped = eta_seconds.min(MAX_ETA_SECS as f64) as u64;

        Ok(SyncProgress {
            current_height,
            total_height,
            progress_percent: progress_percent.min(100.0),
            blocks_per_second,
            eta_seconds: eta_capped,
            phase: phase.to_string(),
            total_known,
            peer_count: cache.peer_count,
        })
    }
}

/// Handle to cancel sync without borrowing FastSync (avoids "Already borrowed" when sync is running).
#[pyclass]
pub struct SyncCanceller {
    cancelled: Arc<StdMutex<bool>>,
}

#[pymethods]
impl SyncCanceller {
    /// Request sync to stop. Safe to call from any thread.
    fn cancel(&self) -> PyResult<()> {
        let mut c = self.cancelled.lock().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Lock error: {}", e))
        })?;
        *c = true;
        Ok(())
    }
}

/// Sync progress information
#[pyclass]
#[derive(Clone)]
pub struct SyncProgress {
    #[pyo3(get)]
    pub current_height: u32,
    #[pyo3(get)]
    pub total_height: u32,
    #[pyo3(get)]
    pub progress_percent: f64,
    #[pyo3(get)]
    pub blocks_per_second: f64,
    #[pyo3(get)]
    pub eta_seconds: u64,
    /// Phase: "header" (syncing headers) or "block" (downloading full blocks)
    #[pyo3(get)]
    pub phase: String,
    /// When false (header phase, tip unknown): CLI should show "Requesting current block height..." instead of %
    #[pyo3(get)]
    pub total_known: bool,
    /// Number of connected peers
    #[pyo3(get)]
    pub peer_count: u32,
}

/// Fast sync orchestrator for Bitcoin blockchain
#[pyclass]
pub struct FastSync {
    data_dir: PathBuf,
    network: Network,
    db: Option<Arc<BlockchainDB>>,
    peer_manager: Option<Arc<Mutex<PeerManager>>>,
    header_sync: Option<HeaderSync>,
    block_sync: Option<BlockSync>,
    /// Shared progress cache: updated by block_sync, read by SyncProgressReporter.
    /// Allows progress polling during sync without borrowing FastSync (avoids "Already borrowed").
    progress_cache: Arc<StdMutex<BlockProgressCache>>,
    /// Cancellation flag
    cancelled: Arc<StdMutex<bool>>,
}

#[pymethods]
impl FastSync {
    #[new]
    fn new(data_dir: String, network: String) -> PyResult<Self> {
        // Parse network
        let network_enum = match network.to_lowercase().as_str() {
            "mainnet" | "bitcoin" => Network::Bitcoin,
            "testnet" | "testnet3" => Network::Testnet,
            "regtest" => Network::Regtest,
            "signet" => Network::Signet,
            "testnet4" => Network::Testnet4,
            _ => {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!("Invalid network: {}. Must be one of: mainnet, testnet, regtest, signet", network)
                ));
            }
        };

        // Initialize database
        let db_path = PathBuf::from(data_dir.clone());
        let db = Arc::new(
            BlockchainDB::open(db_path.to_str().ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid data directory path")
            })?)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Failed to open database: {}", e)
            ))?,
        );

        // Check for and recover from a crash during the previous apply_block()
        if let Err(e) = db.recover_from_crash() {
            log::error!("Crash recovery failed: {} — continuing anyway", e);
        }

        // Create validator components
        let header_validator = Arc::new(HeaderValidator::new(Arc::clone(&db), network_enum));
        let block_validator = Arc::new(BlockValidator::new(Arc::clone(&db), network_enum));

        // Create peer manager (max_peers=125 matches Bitcoin Core DEFAULT_MAX_PEER_CONNECTIONS)
        let peer_manager = Arc::new(Mutex::new(PeerManager::new(
            network_enum,
            "/Ouroboros:0.1.0/".to_string(),
            0, // start_height
            crate::network::peer_manager::max_peers_from_env(),
        )));

        let progress_cache = Arc::new(StdMutex::new(BlockProgressCache::default()));

        // Create sync components
        let header_sync = HeaderSync::new(
            Arc::clone(&peer_manager),
            Arc::clone(&header_validator),
            Arc::clone(&db),
            network_enum,
            Some(Arc::clone(&progress_cache)),
        );

        let block_sync = BlockSync::new(
            Arc::clone(&peer_manager),
            block_validator,
            Arc::clone(&db),
            network_enum,
            Arc::clone(&progress_cache),
        );

        Ok(Self {
            data_dir: db_path,
            network: network_enum,
            db: Some(db),
            peer_manager: Some(peer_manager),
            header_sync: Some(header_sync),
            block_sync: Some(block_sync),
            progress_cache,
            cancelled: Arc::new(StdMutex::new(false)),
        })
    }

    /// Get a progress reporter that can be used during sync without borrowing FastSync.
    /// Call this before starting sync; use reporter.get_progress() while sync runs.
    fn get_progress_reporter(&self) -> PyResult<SyncProgressReporter> {
        let db = self.db.as_ref().ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Database not initialized")
        })?;
        Ok(SyncProgressReporter {
            db: Arc::clone(db),
            progress_cache: Arc::clone(&self.progress_cache),
            network: self.network,
        })
    }

    /// Synchronize the blockchain
    ///
    /// Phase 1: Sync headers
    /// Phase 2: Sync blocks
    ///
    /// If `limit` is set, only sync the first N blocks (useful for quick validation).
    #[pyo3(signature = (limit=None))]
    fn sync_blockchain(&mut self, py: Python, limit: Option<u32>) -> PyResult<()> {
        // Reset cancellation flag
        {
            let mut cancelled = self.cancelled.lock().unwrap();
            *cancelled = false;
        }

        // Release GIL for long-running operation
        py.allow_threads(|| {
            // Create runtime for async operations
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    format!("Failed to create tokio runtime: {}", e)
                ))?;

            rt.block_on(async {
                // Get components
                let db = self.db.as_ref().ok_or_else(|| {
                    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Database not initialized")
                })?;

                // Initialize genesis block if database is empty (enables header sync to proceed)
                if db.get_best_block().is_err() {
                    let genesis_hash = crate::chain_params::genesis_block_hash(self.network);
                    let genesis_timestamp = crate::chain_params::genesis_block_timestamp(self.network);
                    let genesis_bits = crate::chain_params::genesis_bits(self.network);
                    let genesis_chainwork = crate::chainwork::compute_chainwork(&[0u8; 32], genesis_bits);
                    let metadata = BlockMetadata::new(0, genesis_chainwork, genesis_timestamp);
                    db.store_block_metadata(0, &genesis_hash, &metadata).map_err(|e| {
                        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                            format!("Failed to store genesis metadata: {}", e),
                        )
                    })?;
                    db.update_best_block(&genesis_hash, 0).map_err(|e| {
                        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                            format!("Failed to set genesis as best block: {}", e),
                        )
                    })?;
                }

                // Start peer manager
                let peer_manager = self.peer_manager.as_ref().ok_or_else(|| {
                    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Peer manager not initialized")
                })?;

                {
                    let mut pm = peer_manager.lock().await;
                    pm.start().await.map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                        format!("Failed to start peer manager: {}", e)
                    ))?;
                }

                // Phase 1: Sync headers
                if let Some(ref mut header_sync) = self.header_sync {
                    header_sync.sync_headers().await.map_err(|e| {
                        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                            format!("Header sync failed: {}", e)
                        )
                    })?;
                }

                // Check cancellation
                {
                    let cancelled = self.cancelled.lock().unwrap();
                    if *cancelled {
                        return Err(PyErr::new::<pyo3::exceptions::PyKeyboardInterrupt, _>(
                            "Sync cancelled"
                        ));
                    }
                }

                // Phase 2: Sync blocks
                if let Some(ref mut block_sync) = self.block_sync {
                    // Get current height for block sync
                    let (_, current_height) = db.get_best_block().map_err(|e| {
                        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                            format!("Failed to get best block: {}", e)
                        )
                    })?;

                    log::info!("Header sync completed. Starting block sync from height {}...", current_height);
                    
                    // For block sync, we want to sync all blocks from genesis to current height
                    // Since we only have headers, we need to download the full blocks
                    // Start from height 0 (genesis) and go up to current_height (or limit if set)
                    let start_height = 0u32;
                    let end_height = limit.map(|n| n.min(current_height)).unwrap_or(current_height);
                    
                    log::info!("Block sync: downloading blocks from height {} to {}", start_height, end_height);
                    
                    block_sync.sync_blocks(start_height, end_height).await.map_err(|e| {
                        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                            format!("Block sync failed: {}", e)
                        )
                    })?;
                    
                    log::info!("Block sync completed successfully!");
                } else {
                    log::warn!("Block sync not initialized, skipping block download");
                }

                Ok(())
            })
        })
    }

    /// Get synchronization progress
    fn get_sync_progress(&self) -> PyResult<SyncProgress> {
        let db = self.db.as_ref().ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Database not initialized")
        })?;

        // Get current height from DB (0 if empty / no best block yet)
        let db_height = match db.get_best_block() {
            Ok((_, h)) => h,
            Err(DbError::BlockNotFound) => 0,
            Err(e) => {
                return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    format!("Failed to get best block: {}", e),
                ));
            }
        };

        // When block sync is active, use its stats for accurate progress (blocks_downloaded updates
        // as blocks are stored; DB best_block may lag). Otherwise use DB height.
        let block_sync_stats = self.block_sync.as_ref().and_then(|bs| bs.get_progress_stats());

        let (current_height, total_height, progress_percent, blocks_per_second, eta_seconds, phase, total_known) =
            if let Some((blocks_downloaded, total_to_download, speed, eta)) = block_sync_stats {
                if total_to_download > 0 {
                    // Block sync active: use blocks_downloaded only (not db_height)
                    let current = blocks_downloaded;
                    let total = total_to_download;
                    let percent = if total > 0 {
                        ((current as f64 / total as f64) * 100.0).min(100.0)
                    } else {
                        0.0
                    };
                    (current, total, percent, speed, eta, "block", true)
                } else {
                    // Block sync not fully initialized, fall back to DB
                    (db_height, 0, 0.0, speed, eta, "header", false)
                }
            } else {
                // No block sync (e.g. header-only phase): use DB height and estimated tip
                let estimated_tip = match self.network {
                    Network::Testnet => 18_000_000u32,
                    Network::Testnet4 => 150_000u32, // testnet4 tip varies; 122k+ as of 2025
                    Network::Bitcoin => 900_000u32,
                    _ => 1_000_000u32,
                };
                let total = estimated_tip.max(db_height.saturating_add(1));
                let percent = if total > 0 && db_height > 0 {
                    ((db_height as f64 / total as f64) * 100.0).min(100.0)
                } else if db_height == 0 {
                    0.0
                } else {
                    100.0
                };
                (db_height, total, percent, 0.0, 0.0, "header", false)
            };

        // If we have block sync stats but total was 0, we still need total_height for display
        let total_height = if total_height == 0 {
            let estimated_tip = match self.network {
                Network::Testnet => 18_000_000u32,
                Network::Testnet4 => 150_000u32,
                Network::Bitcoin => 900_000u32,
                _ => 1_000_000u32,
            };
            estimated_tip.max(current_height.saturating_add(1))
        } else {
            total_height
        };

        // Cap ETA at 999h to avoid overflow/absurd display
        const MAX_ETA_SECS: u64 = 999 * 3600;
        let eta_capped = eta_seconds.min(MAX_ETA_SECS as f64) as u64;

        let peer_count = self.progress_cache.lock()
            .map(|c| c.peer_count)
            .unwrap_or(0);

        Ok(SyncProgress {
            current_height,
            total_height,
            progress_percent: progress_percent.min(100.0),
            blocks_per_second,
            eta_seconds: eta_capped,
            phase: phase.to_string(),
            total_known,
            peer_count,
        })
    }

    /// Check if blockchain is synced
    fn is_synced(&self) -> PyResult<bool> {
        // For now, return false (in practice would check against network tip)
        // This is a simplified version
        Ok(false)
    }

    /// Get a canceller handle. Use this instead of cancel_sync() to avoid "Already borrowed"
    /// when sync is running in another thread.
    fn get_canceller(&self) -> SyncCanceller {
        SyncCanceller {
            cancelled: Arc::clone(&self.cancelled),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::ScriptBuf;
    use common::UTXO;

    fn create_test_utxo() -> UTXO {
        let txid = bitcoin::Txid::from_byte_array([0u8; 32]);
        let outpoint = OutPointWrapper::from_txid_vout(txid, 0);
        let script_pubkey = ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14, 0x88, 0xac]);
        UTXO::new(outpoint, 100000, script_pubkey, Some(1), false)
    }

    #[test]
    fn test_pyutxo_from_utxo() {
        let utxo = create_test_utxo();
        let py_utxo = PyUTXO::from(&utxo);

        assert_eq!(py_utxo.txid, utxo.txid().to_string());
        assert_eq!(py_utxo.vout, utxo.vout());
        assert_eq!(py_utxo.value, utxo.value());
        assert_eq!(
            py_utxo.script_pubkey,
            utxo.script_pubkey.as_bytes().to_vec()
        );
    }

    #[test]
    fn test_pyutxo_from_owned_utxo() {
        let utxo = create_test_utxo();
        let py_utxo = PyUTXO::from(utxo.clone());

        assert_eq!(py_utxo.txid, utxo.txid().to_string());
        assert_eq!(py_utxo.vout, utxo.vout());
        assert_eq!(py_utxo.value, utxo.value());
    }

    #[test]
    fn test_pyutxo_clone() {
        let utxo = create_test_utxo();
        let py_utxo1 = PyUTXO::from(&utxo);
        let py_utxo2 = py_utxo1.clone();

        assert_eq!(py_utxo1.txid, py_utxo2.txid);
        assert_eq!(py_utxo1.vout, py_utxo2.vout);
        assert_eq!(py_utxo1.value, py_utxo2.value);
        assert_eq!(py_utxo1.script_pubkey, py_utxo2.script_pubkey);
    }

    #[test]
    fn test_sync_engine_new() {
        let engine = SyncEngine::new();
        // Just verify it can be created
        let _ = engine;
    }

    #[test]
    fn test_sync_engine_sync_blocks() {
        let mut engine = SyncEngine::new();
        let blocks = vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]];

        let result = engine.sync_blocks(blocks.clone());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), blocks.len());
    }

    #[test]
    fn test_sync_engine_sync_empty_blocks() {
        let mut engine = SyncEngine::new();
        let blocks = vec![];

        let result = engine.sync_blocks(blocks);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_sync_engine_get_utxos() {
        let engine = SyncEngine::new();
        let result = engine.get_utxos();

        assert!(result.is_ok());
        let utxos = result.unwrap();
        assert_eq!(utxos.len(), 3); // Returns 3 example/demo UTXOs
    }

    #[test]
    fn test_pyutxo_conversion_multiple() {
        let utxo1 = create_test_utxo();
        // Create a second UTXO with different values
        let txid2 = bitcoin::Txid::from_byte_array([1u8; 32]);
        let outpoint2 = OutPointWrapper::from_txid_vout(txid2, 1);
        let script_pubkey2 = ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14, 0x88, 0xac]);
        let utxo2 = UTXO::new(outpoint2, 200000, script_pubkey2, Some(1), false);

        let py_utxos: Vec<PyUTXO> = vec![&utxo1, &utxo2]
            .into_iter()
            .map(|u| PyUTXO::from(u))
            .collect();

        assert_eq!(py_utxos.len(), 2);
        assert_eq!(py_utxos[0].value, 100000);
        assert_eq!(py_utxos[1].value, 200000);
        assert_eq!(py_utxos[0].vout, 0);
        assert_eq!(py_utxos[1].vout, 1);
    }

    #[test]
    fn test_pyutxo_script_pubkey_bytes() {
        use bitcoin::hashes::Hash;
        let script_bytes = vec![0x76, 0xa9, 0x14, 0x88, 0xac];
        let script = ScriptBuf::from_bytes(script_bytes.clone());
        let txid = bitcoin::Txid::from_byte_array([1u8; 32]);
        let outpoint = OutPointWrapper::from_txid_vout(txid, 0);
        let utxo = UTXO::new(outpoint, 50000, script, None, false);

        let py_utxo = PyUTXO::from(&utxo);
        assert_eq!(py_utxo.script_pubkey, script_bytes);
    }
}
