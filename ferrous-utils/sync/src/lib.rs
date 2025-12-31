// Fast sync module with PyO3 bindings

pub mod storage;

use common::{OutPointWrapper, UTXO};
use pyo3::prelude::*;

/// Fast sync module for Bitcoin blockchain synchronization
#[pymodule]
fn sync(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyUTXO>()?;
    m.add_class::<SyncEngine>()?;
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
}

impl From<UTXO> for PyUTXO {
    fn from(utxo: UTXO) -> Self {
        Self {
            txid: utxo.txid().to_string(),
            vout: utxo.vout(),
            value: utxo.value(),
            script_pubkey: utxo.script_pubkey.as_bytes().to_vec(),
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

    /// Get UTXO set
    fn get_utxos(&self) -> PyResult<Vec<PyUTXO>> {
        // TODO: Implement UTXO retrieval
        // Convert UTXO to PyUTXO when returning
        Ok(vec![])
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
        assert_eq!(utxos.len(), 0); // Currently returns empty vec
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
