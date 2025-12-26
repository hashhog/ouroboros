// Shared Bitcoin types

use bitcoin::{Block, Transaction};
use serde::{Deserialize, Serialize};

/// Represents a Bitcoin block
pub type BitcoinBlock = Block;

/// Represents a Bitcoin transaction
pub type BitcoinTransaction = Transaction;

/// Unspent Transaction Output
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UTXO {
    /// Transaction ID (hash)
    pub txid: bitcoin::Txid,
    /// Output index
    pub vout: u32,
    /// Output value in satoshis
    pub value: u64,
    /// Script public key
    pub script_pubkey: bitcoin::ScriptBuf,
}

impl UTXO {
    /// Create a new UTXO
    pub fn new(
        txid: bitcoin::Txid,
        vout: u32,
        value: u64,
        script_pubkey: bitcoin::ScriptBuf,
    ) -> Self {
        Self {
            txid,
            vout,
            value,
            script_pubkey,
        }
    }
}

