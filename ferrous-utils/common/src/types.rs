// Bitcoin wrapper types with custom serialization

use bitcoin::{
    Block, OutPoint, Transaction, TxIn, TxOut,
    consensus::{Decodable, Encodable, encode::Error as EncodeError},
};

use serde::{Deserialize, Serialize};

/// Bitcoin block header wrapper
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeaderWrapper {
    inner: bitcoin::blockdata::block::Header,
}

impl BlockHeaderWrapper {
    /// Create a new block header wrapper
    pub fn new(header: bitcoin::blockdata::block::Header) -> Self {
        Self { inner: header }
    }

    /// Get the inner block header
    pub fn inner(&self) -> &bitcoin::blockdata::block::Header {
        &self.inner
    }

    /// Get the inner block header (mutable)
    pub fn inner_mut(&mut self) -> &mut bitcoin::blockdata::block::Header {
        &mut self.inner
    }

    /// Get the block hash
    pub fn block_hash(&self) -> bitcoin::BlockHash {
        self.inner.block_hash()
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoder = Vec::new();
        self.inner.consensus_encode(&mut encoder).expect("encoding failed");
        encoder
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncodeError> {
        let header = bitcoin::blockdata::block::Header::consensus_decode(&mut &bytes[..])?;
        Ok(Self::new(header))
    }
}

impl From<bitcoin::blockdata::block::Header> for BlockHeaderWrapper {
    fn from(header: bitcoin::blockdata::block::Header) -> Self {
        Self::new(header)
    }
}

impl From<BlockHeaderWrapper> for bitcoin::blockdata::block::Header {
    fn from(wrapper: BlockHeaderWrapper) -> Self {
        wrapper.inner
    }
}

/// Bitcoin block wrapper
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockWrapper {
    inner: Block,
}

impl BlockWrapper {
    /// Create a new block wrapper
    pub fn new(block: Block) -> Self {
        Self { inner: block }
    }

    /// Get the inner block
    pub fn inner(&self) -> &Block {
        &self.inner
    }

    /// Get the inner block (mutable)
    pub fn inner_mut(&mut self) -> &mut Block {
        &mut self.inner
    }

    /// Get the block header
    pub fn header(&self) -> &bitcoin::blockdata::block::Header {
        &self.inner.header
    }

    /// Get the block hash
    pub fn block_hash(&self) -> bitcoin::BlockHash {
        self.inner.block_hash()
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoder = Vec::new();
        self.inner.consensus_encode(&mut encoder).expect("encoding failed");
        encoder
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncodeError> {
        let block = Block::consensus_decode(&mut &bytes[..])?;
        Ok(Self::new(block))
    }
}

impl From<Block> for BlockWrapper {
    fn from(block: Block) -> Self {
        Self::new(block)
    }
}

impl From<BlockWrapper> for Block {
    fn from(wrapper: BlockWrapper) -> Self {
        wrapper.inner
    }
}

/// Bitcoin transaction wrapper
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionWrapper {
    inner: Transaction,
}

impl TransactionWrapper {
    /// Create a new transaction wrapper
    pub fn new(tx: Transaction) -> Self {
        Self { inner: tx }
    }

    /// Get the inner transaction
    pub fn inner(&self) -> &Transaction {
        &self.inner
    }

    /// Get the inner transaction (mutable)
    pub fn inner_mut(&mut self) -> &mut Transaction {
        &mut self.inner
    }

    /// Get the transaction ID
    pub fn txid(&self) -> bitcoin::Txid {
        self.inner.compute_txid()
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoder = Vec::new();
        self.inner.consensus_encode(&mut encoder).expect("encoding failed");
        encoder
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncodeError> {
        let tx = Transaction::consensus_decode(&mut &bytes[..])?;
        Ok(Self::new(tx))
    }
}

impl From<Transaction> for TransactionWrapper {
    fn from(tx: Transaction) -> Self {
        Self::new(tx)
    }
}

impl From<TransactionWrapper> for Transaction {
    fn from(wrapper: TransactionWrapper) -> Self {
        wrapper.inner
    }
}

/// Bitcoin transaction input wrapper
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxInWrapper {
    inner: TxIn,
}

impl TxInWrapper {
    /// Create a new transaction input wrapper
    pub fn new(txin: TxIn) -> Self {
        Self { inner: txin }
    }

    /// Get the inner transaction input
    pub fn inner(&self) -> &TxIn {
        &self.inner
    }

    /// Get the inner transaction input (mutable)
    pub fn inner_mut(&mut self) -> &mut TxIn {
        &mut self.inner
    }

    /// Get the previous output point
    pub fn previous_output(&self) -> &OutPoint {
        &self.inner.previous_output
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoder = Vec::new();
        self.inner.consensus_encode(&mut encoder).expect("encoding failed");
        encoder
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncodeError> {
        let txin = TxIn::consensus_decode(&mut &bytes[..])?;
        Ok(Self::new(txin))
    }
}

impl From<TxIn> for TxInWrapper {
    fn from(txin: TxIn) -> Self {
        Self::new(txin)
    }
}

impl From<TxInWrapper> for TxIn {
    fn from(wrapper: TxInWrapper) -> Self {
        wrapper.inner
    }
}

/// Bitcoin transaction output wrapper
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutWrapper {
    inner: TxOut,
}

impl TxOutWrapper {
    /// Create a new transaction output wrapper
    pub fn new(txout: TxOut) -> Self {
        Self { inner: txout }
    }

    /// Get the inner transaction output
    pub fn inner(&self) -> &TxOut {
        &self.inner
    }

    /// Get the inner transaction output (mutable)
    pub fn inner_mut(&mut self) -> &mut TxOut {
        &mut self.inner
    }

    /// Get the value in satoshis
    pub fn value(&self) -> u64 {
        self.inner.value.to_sat()
    }

    /// Get the script public key
    pub fn script_pubkey(&self) -> &bitcoin::ScriptBuf {
        &self.inner.script_pubkey
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoder = Vec::new();
        self.inner.consensus_encode(&mut encoder).expect("encoding failed");
        encoder
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncodeError> {
        let txout = TxOut::consensus_decode(&mut &bytes[..])?;
        Ok(Self::new(txout))
    }
}

impl From<TxOut> for TxOutWrapper {
    fn from(txout: TxOut) -> Self {
        Self::new(txout)
    }
}

impl From<TxOutWrapper> for TxOut {
    fn from(wrapper: TxOutWrapper) -> Self {
        wrapper.inner
    }
}

/// Bitcoin outpoint wrapper
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct OutPointWrapper {
    inner: OutPoint,
}

impl OutPointWrapper {
    /// Create a new outpoint wrapper
    pub fn new(outpoint: OutPoint) -> Self {
        Self { inner: outpoint }
    }

    /// Create from txid and vout
    pub fn from_txid_vout(txid: bitcoin::Txid, vout: u32) -> Self {
        Self::new(OutPoint::new(txid, vout))
    }

    /// Get the inner outpoint
    pub fn inner(&self) -> &OutPoint {
        &self.inner
    }

    /// Get the transaction ID
    pub fn txid(&self) -> bitcoin::Txid {
        self.inner.txid
    }

    /// Get the output index
    pub fn vout(&self) -> u32 {
        self.inner.vout
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoder = Vec::new();
        self.inner.consensus_encode(&mut encoder).expect("encoding failed");
        encoder
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncodeError> {
        let outpoint = OutPoint::consensus_decode(&mut &bytes[..])?;
        Ok(Self::new(outpoint))
    }
}

impl From<OutPoint> for OutPointWrapper {
    fn from(outpoint: OutPoint) -> Self {
        Self::new(outpoint)
    }
}

impl From<OutPointWrapper> for OutPoint {
    fn from(wrapper: OutPointWrapper) -> Self {
        wrapper.inner
    }
}

/// Enhanced UTXO with additional metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UTXO {
    /// The outpoint (txid + vout)
    pub outpoint: OutPointWrapper,
    /// Output value in satoshis
    pub amount: u64,
    /// Script public key
    pub script_pubkey: bitcoin::ScriptBuf,
    /// Block height where this UTXO was created
    pub height: Option<u32>,
    /// Whether this is a coinbase output
    pub is_coinbase: bool,
}

impl UTXO {
    /// Create a new UTXO
    pub fn new(
        outpoint: OutPointWrapper,
        amount: u64,
        script_pubkey: bitcoin::ScriptBuf,
        height: Option<u32>,
        is_coinbase: bool,
    ) -> Self {
        Self {
            outpoint,
            amount,
            script_pubkey,
            height,
            is_coinbase,
        }
    }

    /// Create from legacy fields (for backward compatibility)
    pub fn from_legacy(
        txid: bitcoin::Txid,
        vout: u32,
        value: u64,
        script_pubkey: bitcoin::ScriptBuf,
    ) -> Self {
        let outpoint = OutPointWrapper::from_txid_vout(txid, vout);
        Self::new(outpoint, value, script_pubkey, None, false)
    }

    /// Get the transaction ID
    pub fn txid(&self) -> bitcoin::Txid {
        self.outpoint.txid()
    }

    /// Get the output index
    pub fn vout(&self) -> u32 {
        self.outpoint.vout()
    }

    /// Get the value (alias for amount, for backward compatibility)
    pub fn value(&self) -> u64 {
        self.amount
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut encoder = Vec::new();
        // Custom serialization: outpoint + amount + script_pubkey + height + is_coinbase
        // Encode outpoint directly, not its bytes
        self.outpoint.inner().consensus_encode(&mut encoder)?;
        self.amount.consensus_encode(&mut encoder)?;
        self.script_pubkey.consensus_encode(&mut encoder)?;
        // Encode Option<u32> as: 1 byte flag (0 = None, 1 = Some) + optional u32
        match self.height {
            None => {
                0u8.consensus_encode(&mut encoder)?;
            }
            Some(h) => {
                1u8.consensus_encode(&mut encoder)?;
                h.consensus_encode(&mut encoder)?;
            }
        }
        self.is_coinbase.consensus_encode(&mut encoder)?;
        Ok(encoder)
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncodeError> {
        let mut decoder = &bytes[..];
        
        // Decode outpoint
        let outpoint = OutPoint::consensus_decode(&mut decoder)?;
        let outpoint = OutPointWrapper::new(outpoint);
        
        let amount = u64::consensus_decode(&mut decoder)?;
        let script_pubkey = bitcoin::ScriptBuf::consensus_decode(&mut decoder)?;
        // Decode Option<u32>
        let height = match u8::consensus_decode(&mut decoder)? {
            0 => None,
            1 => Some(u32::consensus_decode(&mut decoder)?),
            _ => return Err(EncodeError::ParseFailed("invalid height flag")),
        };
        let is_coinbase = bool::consensus_decode(&mut decoder)?;
        
        Ok(Self::new(outpoint, amount, script_pubkey, height, is_coinbase))
    }
}

/// Block metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockMetadata {
    /// Block height
    pub height: u32,
    /// Chainwork (cumulative proof-of-work) as a 32-byte array
    pub chainwork: [u8; 32],
    /// Block timestamp
    pub timestamp: u32,
}

impl BlockMetadata {
    /// Create new block metadata
    pub fn new(height: u32, chainwork: [u8; 32], timestamp: u32) -> Self {
        Self {
            height,
            chainwork,
            timestamp,
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut encoder = Vec::new();
        self.height.consensus_encode(&mut encoder)?;
        self.chainwork.consensus_encode(&mut encoder)?;
        self.timestamp.consensus_encode(&mut encoder)?;
        Ok(encoder)
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncodeError> {
        let mut decoder = &bytes[..];
        let height = u32::consensus_decode(&mut decoder)?;
        let chainwork = <[u8; 32]>::consensus_decode(&mut decoder)?;
        let timestamp = u32::consensus_decode(&mut decoder)?;
        Ok(Self::new(height, chainwork, timestamp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        Amount, ScriptBuf, TxIn, TxOut,
        consensus::Decodable,
    };
    use bitcoin::hashes::Hash;

    // Bitcoin Core test vectors
    // Genesis block hash
    const GENESIS_BLOCK_HASH: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    
    // Genesis block header (first 80 bytes)
    const GENESIS_BLOCK_HEADER_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
    
    // Example transaction (coinbase from genesis block)
    const GENESIS_COINBASE_TX_HEX: &str = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

    fn create_test_utxo() -> UTXO {
        let txid = bitcoin::Txid::from_byte_array([0u8; 32]);
        let outpoint = OutPointWrapper::from_txid_vout(txid, 0);
        let script_pubkey = ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14, 0x88, 0xac]);
        UTXO::new(outpoint, 100000, script_pubkey, Some(1), false)
    }

    #[test]
    fn test_block_header_wrapper() {
        use bitcoin::hashes::Hash;
        
        // Create a test block header
        let header = bitcoin::blockdata::block::Header {
            version: bitcoin::blockdata::block::Version::ONE,
            prev_blockhash: bitcoin::BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1231006505,
            bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
            nonce: 2083236893,
        };
        
        let wrapper = BlockHeaderWrapper::new(header.clone());
        
        // Test block_hash
        let hash = wrapper.block_hash();
        assert_eq!(hash, header.block_hash());
        
        // Test serialization roundtrip
        let bytes = wrapper.to_bytes();
        let deserialized = BlockHeaderWrapper::from_bytes(&bytes).unwrap();
        assert_eq!(wrapper, deserialized);
    }

    #[test]
    fn test_genesis_block_header() {
        // Test with actual genesis block header
        let header_bytes = hex::decode(GENESIS_BLOCK_HEADER_HEX).unwrap();
        let header = bitcoin::blockdata::block::Header::consensus_decode(&mut &header_bytes[..]).unwrap();
        let wrapper = BlockHeaderWrapper::new(header);
        
        let hash = wrapper.block_hash();
        // Genesis block hash string is in display format (reversed bytes for human readability)
        // block_hash() returns the hash in internal format (little-endian)
        // Convert display format to internal format by reversing bytes
        let mut expected_hash_bytes = hex::decode(GENESIS_BLOCK_HASH).unwrap();
        expected_hash_bytes.reverse();
        let expected_hash = bitcoin::BlockHash::from_byte_array(
            expected_hash_bytes.try_into().unwrap()
        );
        
        assert_eq!(hash, expected_hash);
        
        // Test roundtrip
        let bytes = wrapper.to_bytes();
        let deserialized = BlockHeaderWrapper::from_bytes(&bytes).unwrap();
        assert_eq!(wrapper.block_hash(), deserialized.block_hash());
    }

    #[test]
    fn test_transaction_wrapper() {
        // Create a simple transaction
        let tx = Transaction {
            version: bitcoin::blockdata::transaction::Version::ONE,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(5000000000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        
        let wrapper = TransactionWrapper::new(tx.clone());
        
        // Test txid
        let txid = wrapper.txid();
        assert_eq!(txid, tx.compute_txid());
        
        // Test serialization roundtrip
        let bytes = wrapper.to_bytes();
        let deserialized = TransactionWrapper::from_bytes(&bytes).unwrap();
        assert_eq!(wrapper.txid(), deserialized.txid());
    }

    #[test]
    fn test_genesis_coinbase_transaction() {
        // Test with actual genesis coinbase transaction
        let tx_bytes = hex::decode(GENESIS_COINBASE_TX_HEX).unwrap();
        let tx = Transaction::consensus_decode(&mut &tx_bytes[..]).unwrap();
        let wrapper = TransactionWrapper::new(tx);
        
        // Test roundtrip
        let bytes = wrapper.to_bytes();
        let deserialized = TransactionWrapper::from_bytes(&bytes).unwrap();
        assert_eq!(wrapper.txid(), deserialized.txid());
    }

    #[test]
    fn test_txin_wrapper() {
        let txid = bitcoin::Txid::from_byte_array([1u8; 32]);
        let outpoint = OutPoint::new(txid, 0);
        let txin = TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        };
        
        let wrapper = TxInWrapper::new(txin.clone());
        assert_eq!(wrapper.previous_output(), &txin.previous_output);
        
        // Test serialization roundtrip
        let bytes = wrapper.to_bytes();
        let deserialized = TxInWrapper::from_bytes(&bytes).unwrap();
        assert_eq!(wrapper.previous_output(), deserialized.previous_output());
    }

    #[test]
    fn test_txout_wrapper() {
        let txout = TxOut {
            value: Amount::from_sat(100000000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14, 0x88, 0xac]),
        };
        
        let wrapper = TxOutWrapper::new(txout.clone());
        assert_eq!(wrapper.value(), 100000000);
        assert_eq!(wrapper.script_pubkey(), &txout.script_pubkey);
        
        // Test serialization roundtrip
        let bytes = wrapper.to_bytes();
        let deserialized = TxOutWrapper::from_bytes(&bytes).unwrap();
        assert_eq!(wrapper.value(), deserialized.value());
    }

    #[test]
    fn test_outpoint_wrapper() {
        let txid = bitcoin::Txid::from_byte_array([2u8; 32]);
        let outpoint = OutPointWrapper::from_txid_vout(txid, 1);
        
        assert_eq!(outpoint.txid(), txid);
        assert_eq!(outpoint.vout(), 1);
        
        // Test serialization roundtrip
        let bytes = outpoint.to_bytes();
        let deserialized = OutPointWrapper::from_bytes(&bytes).unwrap();
        assert_eq!(outpoint.txid(), deserialized.txid());
        assert_eq!(outpoint.vout(), deserialized.vout());
    }

    #[test]
    fn test_utxo_new() {
        use bitcoin::hashes::Hash;
        let txid = bitcoin::Txid::from_byte_array([1u8; 32]);
        let outpoint = OutPointWrapper::from_txid_vout(txid, 1);
        let script_pubkey = ScriptBuf::from_bytes(vec![0x51]); // OP_1
        let utxo = UTXO::new(outpoint.clone(), 50000, script_pubkey.clone(), Some(100), false);

        assert_eq!(utxo.outpoint.txid(), txid);
        assert_eq!(utxo.outpoint.vout(), 1);
        assert_eq!(utxo.amount, 50000);
        assert_eq!(utxo.script_pubkey, script_pubkey);
        assert_eq!(utxo.height, Some(100));
        assert_eq!(utxo.is_coinbase, false);
    }

    #[test]
    fn test_utxo_from_legacy() {
        use bitcoin::hashes::Hash;
        let txid = bitcoin::Txid::from_byte_array([3u8; 32]);
        let script = ScriptBuf::from_bytes(vec![0x52]); // OP_2
        let utxo = UTXO::from_legacy(txid, 2, 2000, script);

        assert_eq!(utxo.txid(), txid);
        assert_eq!(utxo.vout(), 2);
        assert_eq!(utxo.value(), 2000);
        assert_eq!(utxo.height, None);
        assert_eq!(utxo.is_coinbase, false);
    }

    #[test]
    fn test_utxo_coinbase() {
        let utxo = create_test_utxo();
        let mut coinbase_utxo = utxo.clone();
        coinbase_utxo.is_coinbase = true;
        coinbase_utxo.height = Some(0);

        assert!(coinbase_utxo.is_coinbase);
        assert_eq!(coinbase_utxo.height, Some(0));
        assert!(!utxo.is_coinbase);
    }

    #[test]
    fn test_utxo_equality() {
        let utxo1 = create_test_utxo();
        let utxo2 = create_test_utxo();
        assert_eq!(utxo1, utxo2);

        let mut utxo3 = create_test_utxo();
        utxo3.amount = 200000;
        assert_ne!(utxo1, utxo3);
    }

    #[test]
    fn test_utxo_clone() {
        let utxo1 = create_test_utxo();
        let utxo2 = utxo1.clone();
        assert_eq!(utxo1, utxo2);
    }

    #[test]
    fn test_utxo_serialize_deserialize() {
        let utxo = create_test_utxo();
        let serialized = serde_json::to_string(&utxo).expect("Failed to serialize UTXO");
        assert!(!serialized.is_empty());
        assert!(serialized.contains("outpoint"));
        assert!(serialized.contains("amount"));
        
        let deserialized: UTXO = serde_json::from_str(&serialized)
            .expect("Failed to deserialize UTXO");
        assert_eq!(utxo, deserialized);
    }

    #[test]
    fn test_utxo_to_from_bytes() {
        let utxo = create_test_utxo();
        let bytes = utxo.to_bytes().unwrap();
        assert!(!bytes.is_empty());
        
        let deserialized = UTXO::from_bytes(&bytes).unwrap();
        assert_eq!(utxo.outpoint.txid(), deserialized.outpoint.txid());
        assert_eq!(utxo.outpoint.vout(), deserialized.outpoint.vout());
        assert_eq!(utxo.amount, deserialized.amount);
        assert_eq!(utxo.script_pubkey, deserialized.script_pubkey);
        assert_eq!(utxo.height, deserialized.height);
        assert_eq!(utxo.is_coinbase, deserialized.is_coinbase);
    }

    #[test]
    fn test_block_metadata() {
        let chainwork = [1u8; 32];
        let metadata = BlockMetadata::new(100, chainwork, 1234567890);
        
        assert_eq!(metadata.height, 100);
        assert_eq!(metadata.chainwork, chainwork);
        assert_eq!(metadata.timestamp, 1234567890);
        
        // Test serialization roundtrip
        let bytes = metadata.to_bytes().unwrap();
        let deserialized = BlockMetadata::from_bytes(&bytes).unwrap();
        assert_eq!(metadata, deserialized);
    }

    #[test]
    fn test_block_wrapper() {
        // Create a minimal block
        let header = bitcoin::blockdata::block::Header {
            version: bitcoin::blockdata::block::Version::ONE,
            prev_blockhash: bitcoin::BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1231006505,
            bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
            nonce: 2083236893,
        };
        
        let tx = Transaction {
            version: bitcoin::blockdata::transaction::Version::ONE,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        
        let block = Block {
            header,
            txdata: vec![tx],
        };
        
        let wrapper = BlockWrapper::new(block.clone());
        assert_eq!(wrapper.block_hash(), block.block_hash());
        
        // Test serialization roundtrip
        let bytes = wrapper.to_bytes();
        let deserialized = BlockWrapper::from_bytes(&bytes).unwrap();
        assert_eq!(wrapper.block_hash(), deserialized.block_hash());
    }

    #[test]
    fn test_wrapper_conversions() {
        // Test BlockHeaderWrapper
        let header = bitcoin::blockdata::block::Header {
            version: bitcoin::blockdata::block::Version::ONE,
            prev_blockhash: bitcoin::BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 0,
            bits: bitcoin::CompactTarget::from_consensus(0),
            nonce: 0,
        };
        let wrapper: BlockHeaderWrapper = header.clone().into();
        let back: bitcoin::blockdata::block::Header = wrapper.into();
        assert_eq!(header.block_hash(), back.block_hash());
        
        // Test TransactionWrapper
        let tx = Transaction {
            version: bitcoin::blockdata::transaction::Version::ONE,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let wrapper: TransactionWrapper = tx.clone().into();
        let back: Transaction = wrapper.into();
        assert_eq!(tx.compute_txid(), back.compute_txid());
    }

    #[test]
    fn test_multiple_utxos() {
        use bitcoin::hashes::Hash;
        let txid1 = bitcoin::Txid::from_byte_array([1u8; 32]);
        let txid2 = bitcoin::Txid::from_byte_array([2u8; 32]);
        
        let outpoint1 = OutPointWrapper::from_txid_vout(txid1, 0);
        let outpoint2 = OutPointWrapper::from_txid_vout(txid2, 1);
        
        let script = ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14, 0x88, 0xac]);
        
        let utxo1 = UTXO::new(outpoint1, 1000, script.clone(), Some(1), false);
        let utxo2 = UTXO::new(outpoint2, 2000, script, Some(2), false);
        
        assert_ne!(utxo1, utxo2);
        assert_eq!(utxo1.amount, 1000);
        assert_eq!(utxo2.amount, 2000);
    }
}

