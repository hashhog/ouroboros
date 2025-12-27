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

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::ScriptBuf;
    // Import Hash trait from bitcoin's re-export to ensure version compatibility
    use bitcoin::hashes::Hash;

    fn create_test_utxo() -> UTXO {
        let txid = bitcoin::Txid::from_byte_array([0u8; 32]);
        let script_pubkey = ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14, 0x88, 0xac]);
        UTXO::new(txid, 0, 100000, script_pubkey)
    }

    #[test]
    fn test_utxo_new() {
        use bitcoin::hashes::Hash;
        let txid = bitcoin::Txid::from_byte_array([1u8; 32]);
        let script_pubkey = ScriptBuf::from_bytes(vec![0x51]); // OP_1
        let utxo = UTXO::new(txid, 1, 50000, script_pubkey.clone());

        assert_eq!(utxo.txid, txid);
        assert_eq!(utxo.vout, 1);
        assert_eq!(utxo.value, 50000);
        assert_eq!(utxo.script_pubkey, script_pubkey);
    }

    #[test]
    fn test_utxo_equality() {
        let utxo1 = create_test_utxo();
        let utxo2 = create_test_utxo();
        assert_eq!(utxo1, utxo2);

        let mut utxo3 = create_test_utxo();
        utxo3.value = 200000;
        assert_ne!(utxo1, utxo3);
    }

    #[test]
    fn test_utxo_clone() {
        let utxo1 = create_test_utxo();
        let utxo2 = utxo1.clone();
        assert_eq!(utxo1, utxo2);
    }

    #[test]
    fn test_utxo_serialize() {
        let utxo = create_test_utxo();
        let serialized = serde_json::to_string(&utxo).expect("Failed to serialize UTXO");
        assert!(!serialized.is_empty());
        assert!(serialized.contains("txid"));
        assert!(serialized.contains("vout"));
        assert!(serialized.contains("value"));
    }

    #[test]
    fn test_utxo_deserialize() {
        let utxo = create_test_utxo();
        let serialized = serde_json::to_string(&utxo).expect("Failed to serialize UTXO");
        let deserialized: UTXO = serde_json::from_str(&serialized)
            .expect("Failed to deserialize UTXO");
        assert_eq!(utxo, deserialized);
    }

    #[test]
    fn test_utxo_roundtrip() {
        let original = create_test_utxo();
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: UTXO = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_utxo_different_values() {
        use bitcoin::hashes::Hash;
        let txid = bitcoin::Txid::from_byte_array([2u8; 32]);
        let script = ScriptBuf::from_bytes(vec![0x52]); // OP_2

        let utxo1 = UTXO::new(txid, 0, 1000, script.clone());
        let utxo2 = UTXO::new(txid, 1, 1000, script.clone());
        let utxo3 = UTXO::new(txid, 0, 2000, script);

        assert_ne!(utxo1, utxo2); // Different vout
        assert_ne!(utxo1, utxo3); // Different value
    }
}

