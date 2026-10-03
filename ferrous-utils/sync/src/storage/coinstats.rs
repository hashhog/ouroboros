//! Point-in-time UTXO-set statistics for ``gettxoutsetinfo``.
//!
//! Core walks a coins-DB cursor snapshot and labels the reply with that
//! cursor's best block (`kernel/coinstats.cpp` `ComputeUTXOStats`,
//! `TxOutSer` at coinstats.cpp:46-51, `GetBogoSize` at :36-43). The hash
//! is SHA256d over the serialized coins in `(txid, numeric vout)` order,
//! or MuHash3072 over the same elements (`crypto/muhash.cpp`).
//!
//! Hashing lives here, not in a Python callback, so the scan can run
//! without the GIL. Do not use `common::crypto::sha256::Sha256` — its
//! streaming `update` disagrees with SHA-256.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

use common::{encode_varint, BitcoinDeserialize, UTXO};

use crate::storage::db::{DbError, Result};
use crate::storage::schema::decode_outpoint;

/// Which digest `gettxoutsetinfo` asked for. `hash_serialized_2` is the
/// same SHA256d construction as `hash_serialized_3` (Core's rename).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtxoStatsKind {
    HashSerialized,
    Muhash,
    None,
}

impl UtxoStatsKind {
    pub fn parse(hash_type: &str) -> std::result::Result<Self, String> {
        match hash_type {
            "hash_serialized_3" | "hash_serialized_2" | "hash_serialized" => {
                Ok(Self::HashSerialized)
            }
            "muhash" => Ok(Self::Muhash),
            "none" => Ok(Self::None),
            other => Err(format!("{other} is not a valid hash_type")),
        }
    }
}

/// Counts and digests over one cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoSetDigest {
    pub txouts: u64,
    pub transactions: u64,
    pub total_amount: u64,
    pub bogosize: u64,
    pub hash_serialized: Option<[u8; 32]>,
    pub muhash: Option<[u8; 32]>,
}

/// `UtxoSetDigest` plus the best-block marker from the same snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoStats {
    pub best_hash: [u8; 32],
    pub best_height: u32,
    pub txouts: u64,
    pub transactions: u64,
    pub total_amount: u64,
    pub bogosize: u64,
    pub hash_serialized: Option<[u8; 32]>,
    pub muhash: Option<[u8; 32]>,
}

impl UtxoStats {
    pub(crate) fn from_parts(best_hash: [u8; 32], best_height: u32, d: UtxoSetDigest) -> Self {
        Self {
            best_hash,
            best_height,
            txouts: d.txouts,
            transactions: d.transactions,
            total_amount: d.total_amount,
            bogosize: d.bogosize,
            hash_serialized: d.hash_serialized,
            muhash: d.muhash,
        }
    }
}

/// `TxOutSer` (`kernel/coinstats.cpp:46-51`).
pub(crate) fn txout_ser(
    txid: &[u8; 32],
    vout: u32,
    height: u32,
    is_coinbase: bool,
    amount: u64,
    script: &[u8],
) -> Vec<u8> {
    let mut ser = Vec::with_capacity(32 + 4 + 4 + 8 + 9 + script.len());
    ser.extend_from_slice(txid);
    ser.extend_from_slice(&vout.to_le_bytes());
    let code: u32 = height << 1 | u32::from(is_coinbase);
    ser.extend_from_slice(&code.to_le_bytes());
    ser.extend_from_slice(&(amount as i64).to_le_bytes());
    ser.extend_from_slice(&encode_varint(script.len() as u64));
    ser.extend_from_slice(script);
    ser
}

fn sha256d(first_pass: Sha256) -> [u8; 32] {
    // HashWriter::GetHash: SHA256(SHA256(bytes)).
    Sha256::digest(first_pass.finalize()).into()
}

/// 2^3072 - 1103717 (`crypto/muhash.cpp` `MAX_PRIME_DIFF`).
fn muhash_modulus() -> &'static BigUint {
    static M: OnceLock<BigUint> = OnceLock::new();
    M.get_or_init(|| (BigUint::from(1u32) << 3072) - BigUint::from(1_103_717u32))
}

/// SHA-256 the element, expand to 384 bytes with ChaCha20 (IETF, zero
/// nonce, counters 0..5), interpret little-endian. Matches
/// `MuHash3072::ToNum3072` and `ouroboros.muhash.data_to_num3072`.
fn element_to_num(element: &[u8]) -> BigUint {
    let digest = Sha256::digest(element);
    let nonce = [0u8; 12];
    let mut cipher = ChaCha20::new_from_slices(digest.as_slice(), &nonce)
        .expect("ChaCha20 key is 32 bytes and nonce is 12");
    let mut out = [0u8; 384];
    cipher.apply_keystream(&mut out);
    BigUint::from_bytes_le(&out)
}

struct MuHash3072 {
    num: BigUint,
    den: BigUint,
}

impl MuHash3072 {
    fn new() -> Self {
        Self {
            num: BigUint::from(1u32),
            den: BigUint::from(1u32),
        }
    }

    fn insert(&mut self, element: &[u8]) {
        let m = muhash_modulus();
        let factor = element_to_num(element) % m;
        self.num = (&self.num * factor) % m;
    }

    fn digest(&self) -> [u8; 32] {
        let m = muhash_modulus();
        let exp = m - &BigUint::from(2u32);
        let inv = self.den.modpow(&exp, m);
        let val = (&self.num * inv) % m;
        let mut le = val.to_bytes_le();
        le.resize(384, 0);
        Sha256::digest(&le).into()
    }
}

/// Fold one chainstate iterator (already a snapshot cursor) into stats.
///
/// Within a txid, coins are hashed in numeric vout order. RocksDB key
/// order is `txid || vout_le`, so vout 256 sorts before vout 1; the
/// `BTreeMap` is what puts them back into Core's `std::map<uint32_t, Coin>`.
pub fn accumulate<I, E>(iter: I, kind: UtxoStatsKind) -> Result<UtxoSetDigest>
where
    I: Iterator<Item = std::result::Result<(Box<[u8]>, Box<[u8]>), E>>,
    E: std::fmt::Display,
{
    let mut txouts = 0u64;
    let mut transactions = 0u64;
    let mut total_amount = 0u64;
    let mut bogosize = 0u64;
    let mut sha = if kind == UtxoStatsKind::HashSerialized {
        Some(Sha256::new())
    } else {
        None
    };
    let mut mu = if kind == UtxoStatsKind::Muhash {
        Some(MuHash3072::new())
    } else {
        None
    };

    let mut prev: Option<[u8; 32]> = None;
    let mut group: BTreeMap<u32, UTXO> = BTreeMap::new();

    let flush = |txid: [u8; 32],
                 group: &BTreeMap<u32, UTXO>,
                 txouts: &mut u64,
                 transactions: &mut u64,
                 total_amount: &mut u64,
                 bogosize: &mut u64,
                 sha: &mut Option<Sha256>,
                 mu: &mut Option<MuHash3072>| {
        if group.is_empty() {
            return;
        }
        *transactions += 1;
        for (vout, utxo) in group {
            *txouts += 1;
            let amount = utxo.amount;
            *total_amount += amount;
            let spk = utxo.script_pubkey.as_bytes();
            // GetBogoSize: 32 + 4 + 4 + 8 + 2 + script len.
            *bogosize += 50 + spk.len() as u64;
            let element = txout_ser(
                &txid,
                *vout,
                utxo.height.unwrap_or(0),
                utxo.is_coinbase,
                amount,
                spk,
            );
            if let Some(h) = sha.as_mut() {
                h.update(&element);
            }
            if let Some(m) = mu.as_mut() {
                m.insert(&element);
            }
        }
    };

    for item in iter {
        let (key, value) = item.map_err(|e| DbError::InvalidData(format!("chainstate iterator: {e}")))?;
        if key.len() != 36 {
            continue;
        }
        let Ok((utxo, _)) = UTXO::bitcoin_deserialize(&value) else {
            continue;
        };
        let mut key_arr = [0u8; 36];
        key_arr.copy_from_slice(&key);
        let (txid, vout) = decode_outpoint(&key_arr);
        if let Some(prev_txid) = prev {
            if prev_txid != txid {
                flush(
                    prev_txid,
                    &group,
                    &mut txouts,
                    &mut transactions,
                    &mut total_amount,
                    &mut bogosize,
                    &mut sha,
                    &mut mu,
                );
                group.clear();
            }
        }
        prev = Some(txid);
        group.insert(vout, utxo);
    }
    if let Some(txid) = prev {
        flush(
            txid,
            &group,
            &mut txouts,
            &mut transactions,
            &mut total_amount,
            &mut bogosize,
            &mut sha,
            &mut mu,
        );
    }

    Ok(UtxoSetDigest {
        txouts,
        transactions,
        total_amount,
        bogosize,
        hash_serialized: sha.map(sha256d),
        muhash: mu.as_ref().map(MuHash3072::digest),
    })
}

// Test hook. Armed by pytest; a no-op in production. The pause sits
// AFTER the snapshot is opened and BEFORE the scan, and it does not
// touch the GIL — `std::thread::sleep` runs inside `allow_threads`.
// Phase: 0 idle, 1 paused, 2 released, 3 timed out (GIL was not free,
// so the Python side could not release the gate).
static GATE_ARMED: Mutex<bool> = Mutex::new(false);
static GATE_PHASE: AtomicU8 = AtomicU8::new(0);

pub fn arm_utxo_stats_walk_gate() {
    GATE_PHASE.store(0, Ordering::SeqCst);
    *GATE_ARMED.lock().unwrap() = true;
}

pub fn utxo_stats_walk_phase() -> u8 {
    GATE_PHASE.load(Ordering::SeqCst)
}

pub fn release_utxo_stats_walk_gate() {
    GATE_PHASE.store(2, Ordering::SeqCst);
}

pub(crate) fn pause_if_armed() {
    let armed = {
        let mut armed = GATE_ARMED.lock().unwrap();
        if *armed {
            *armed = false;
            true
        } else {
            false
        }
    };
    if !armed {
        return;
    }
    GATE_PHASE.store(1, Ordering::SeqCst);
    let start = Instant::now();
    loop {
        if GATE_PHASE.load(Ordering::SeqCst) == 2 {
            return;
        }
        if start.elapsed() > Duration::from_secs(8) {
            GATE_PHASE.store(3, Ordering::SeqCst);
            return;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txout_ser_sha256d_and_muhash_match_python_vectors() {
        // Generated by ouroboros.muhash / HashWriter (2026-10-03). One
        // coin: txid 0x11*32, vout 7, height 3, not coinbase, amount 50,
        // script 76a91488ac.
        let txid = [0x11u8; 32];
        let spk = [0x76u8, 0xa9, 0x14, 0x88, 0xac];
        let element = txout_ser(&txid, 7, 3, false, 50, &spk);
        assert_eq!(
            hex::encode(&element),
            "1111111111111111111111111111111111111111111111111111111111111111\
             070000000600000032000000000000000576a91488ac"
        );
        let mut sha = Sha256::new();
        sha.update(&element);
        let digest: [u8; 32] = sha256d(sha);
        assert_eq!(
            hex::encode(digest),
            "747078a6f7005de8b0b30cea82f6d57a7d34273e0ec22c309d6f7d224a2fc946"
        );
        let mut mu = MuHash3072::new();
        mu.insert(&element);
        assert_eq!(
            hex::encode(mu.digest()),
            "cf333bf50895eed6f6b004d13c2732ecce668541e3086adfd69631ccd6b52038"
        );
    }

    #[test]
    fn empty_hash_serialized_is_sha256d_of_nothing() {
        let digest: [u8; 32] = sha256d(Sha256::new());
        assert_eq!(
            hex::encode(digest),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
    }
}
