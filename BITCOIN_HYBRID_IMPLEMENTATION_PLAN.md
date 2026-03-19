# Bitcoin Hybrid Implementation Plan
## Rust (Fast Sync) + Python (Node Operations)

---

## Project Overview

**Project Name:** bitcoin-hybrid  
**Goal:** Create a Bitcoin full node with Rust-powered initial blockchain sync and Python-based ongoing operations  
**Timeline:** 6-9 months solo development  
**Architecture:** Rust handles computationally intensive initial sync; Python handles networking, mempool, RPC, and ongoing validation

---

## Phase 0: Project Setup (Week 1-2)

### Setup Tasks
1. Initialize Git repository
2. Set up Rust workspace with PyO3
3. Set up Python package structure
4. Configure build system (maturin for Rust→Python)
5. Set up testing framework for both languages

### Directory Structure
```
bitcoin-hybrid/
├── rust/
│   ├── sync/          # Fast sync module
│   └── common/        # Shared types
├── python/
│   └── bitcoin_node/  # Python node
├── tests/
├── docs/
└── data/              # Blockchain storage
```

### Cursor Prompts

**Prompt 1: Initialize Rust Project**
```
Create a Rust workspace with two crates:
1. `common` - shared Bitcoin types (Block, Transaction, UTXO)
2. `sync` - fast sync module with PyO3 bindings

Dependencies needed:
- pyo3 = "0.20"
- bitcoin = "0.31"
- tokio = { version = "1", features = ["full"] }
- rocksdb = "0.21"
- secp256k1 = "0.28"
- bitcoin_hashes = "0.13"
- serde = { version = "1.0", features = ["derive"] }

Create Cargo.toml for workspace and both crates.
```

**Prompt 2: Initialize Python Project**
```
Create a Python package structure for a Bitcoin node:

bitcoin_node/
├── __init__.py
├── node.py
├── p2p.py
├── mempool.py
├── validation.py
├── rpc.py
├── database.py
├── wallet.py
└── cli.py

Use pyproject.toml with:
- asyncio for networking
- fastapi for RPC
- click for CLI
- pydantic for data validation
- rocksdb-python for database access

Generate the pyproject.toml and basic __init__.py
```

**Prompt 3: Build Configuration**
```
Set up maturin for building the Rust module as a Python package.
Create:
1. maturin.toml configuration
2. GitHub Actions workflow for building wheels
3. Development setup script (setup.sh) that:
   - Installs Rust toolchain
   - Installs Python dependencies
   - Builds Rust module
   - Installs in development mode
```

---

## Phase 1: Rust Core Types (Weeks 2-4)

### Module 1.1: Bitcoin Data Structures

**File:** `rust/common/src/types.rs`

**Cursor Prompt:**
```
Implement core Bitcoin data structures in Rust using the `bitcoin` crate:

1. Re-export these types from bitcoin crate with custom wrappers:
   - BlockHeader
   - Block
   - Transaction
   - TxIn, TxOut
   - OutPoint

2. Create custom types:
   - UTXO struct with fields: outpoint, amount, script_pubkey, height, is_coinbase
   - BlockMetadata: height, chainwork, timestamp

3. Implement serialization/deserialization for all types
4. Add methods:
   - block_hash() for BlockHeader
   - txid() for Transaction
   - to_bytes() and from_bytes() for all types

5. Add comprehensive unit tests with test vectors from Bitcoin Core

Use derive macros for Serialize, Deserialize, Clone, Debug.
```

### Module 1.2: Cryptographic Operations

**File:** `rust/common/src/crypto.rs`

**Cursor Prompt:**
```
Implement Bitcoin cryptographic operations:

1. Signature verification:
   - verify_ecdsa_signature(sig: &[u8], pubkey: &[u8], msg: &[u8]) -> Result<bool>
   - Use secp256k1 crate

2. Hash functions:
   - double_sha256(data: &[u8]) -> [u8; 32]
   - hash160(data: &[u8]) -> [u8; 20]
   - Use bitcoin_hashes crate

3. Merkle tree:
   - compute_merkle_root(txids: &[[u8; 32]]) -> [u8; 32]
   - Implement Bitcoin's specific merkle tree algorithm

4. Target conversion:
   - bits_to_target(bits: u32) -> U256
   - target_to_bits(target: U256) -> u32

Add benchmarks for all crypto operations using criterion crate.
Include test vectors from Bitcoin test suite.
```

### Module 1.3: Bitcoin Serialization

**File:** `rust/common/src/serialize.rs`

**Cursor Prompt:**
```
Implement Bitcoin's compact size (VarInt) and serialization:

1. VarInt encoding/decoding:
   - encode_varint(n: u64) -> Vec<u8>
   - decode_varint(data: &[u8]) -> Result<(u64, usize)>

2. Generic serialization traits:
   - trait BitcoinSerialize
   - trait BitcoinDeserialize

3. Implement for all types in types.rs

4. Add helpers:
   - serialize_to_vec<T: BitcoinSerialize>(item: &T) -> Vec<u8>
   - deserialize_from_slice<T: BitcoinDeserialize>(data: &[u8]) -> Result<T>

Test with real Bitcoin block data.
```

---

## Phase 2: Rust Storage Layer (Weeks 4-6)

### Module 2.1: Database Schema Design

**File:** `rust/sync/src/storage/schema.rs`

**Cursor Prompt:**
```
Design RocksDB database schema for Bitcoin blockchain:

1. Define column families:
   - BLOCKS_CF: block_hash -> serialized Block
   - BLOCK_INDEX_CF: height -> BlockMetadata
   - CHAINSTATE_CF: (txid + vout) -> UTXO
   - SPENT_CF: (txid + vout) -> spending_txid (for reorgs)
   - META_CF: metadata (best_block_hash, best_height, etc.)

2. Create key encoding functions:
   - encode_outpoint(txid: &[u8; 32], vout: u32) -> [u8; 36]
   - encode_height(height: u32) -> [u8; 4]

3. Define constants for all column family names

4. Document the schema with examples
```

### Module 2.2: Database Implementation

**File:** `rust/sync/src/storage/db.rs`

**Cursor Prompt:**
```
Implement BlockchainDB using RocksDB:

pub struct BlockchainDB {
    db: Arc<rocksdb::DB>,
}

Implement methods:

1. Block storage:
   - store_block(&self, block: &Block) -> Result<()>
   - get_block(&self, hash: &[u8; 32]) -> Result<Option<Block>>
   - get_block_by_height(&self, height: u32) -> Result<Option<Block>>

2. UTXO set:
   - add_utxo(&self, outpoint: &OutPoint, utxo: &UTXO) -> Result<()>
   - spend_utxo(&self, outpoint: &OutPoint) -> Result<Option<UTXO>>
   - get_utxo(&self, outpoint: &OutPoint) -> Result<Option<UTXO>>
   - utxo_exists(&self, outpoint: &OutPoint) -> bool

3. Chain state:
   - get_best_block(&self) -> Result<([u8; 32], u32)>
   - update_best_block(&self, hash: &[u8; 32], height: u32) -> Result<()>
   - get_block_metadata(&self, height: u32) -> Result<Option<BlockMetadata>>

4. Batch operations:
   - create_batch(&self) -> WriteBatch
   - apply_batch(&self, batch: WriteBatch) -> Result<()>

Use appropriate RocksDB options for performance (bloom filters, compression).
Add error handling with custom error types.
```

### Module 2.3: Database Testing

**File:** `rust/sync/src/storage/db_tests.rs`

**Cursor Prompt:**
```
Create comprehensive integration tests for BlockchainDB:

1. Test basic operations:
   - Store and retrieve blocks
   - Add and query UTXOs
   - Update chain state

2. Test batch operations:
   - Apply multiple UTXO updates atomically
   - Test rollback on error

3. Test edge cases:
   - Large blocks
   - Many UTXOs
   - Reorg scenarios

4. Benchmark:
   - UTXO lookup speed
   - Block storage speed
   - Batch write performance

Use tempdir for test databases.
Generate realistic test data.
```

---

## Phase 3: Rust Block Validation (Weeks 6-10)

### Module 3.1: Proof of Work Validation

**File:** `rust/sync/src/validate/pow.rs`

**Cursor Prompt:**
```
Implement Bitcoin Proof of Work validation:

1. PoW verification:
   - validate_pow(header: &BlockHeader, target: U256) -> bool
   - Compute double SHA-256 of header
   - Compare to target (header hash must be <= target)

2. Target/difficulty conversion:
   - bits_to_target(bits: u32) -> U256
   - Parse nBits compact representation

3. Difficulty adjustment:
   - calculate_next_difficulty(
       prev_height: u32,
       prev_time: u32,
       first_block_time: u32
     ) -> u32
   - Implements 2016-block difficulty adjustment
   - Handle edge cases (min/max difficulty, testnet rules)

4. Chain work calculation:
   - calculate_work(target: U256) -> U256
   - Accumulate total work for chain selection

Include test vectors from Bitcoin Core for all difficulty adjustments in history.
Test mainnet, testnet, and regtest rules.
```

### Module 3.2: Block Header Validation

**File:** `rust/sync/src/validate/header.rs`

**Cursor Prompt:**
```
Implement block header validation chain:

pub struct HeaderValidator {
    db: Arc<BlockchainDB>,
    network: Network,
}

Implement:

1. validate_header(&self, header: &BlockHeader, prev_header: &BlockHeader) -> Result<()>
   - Check PoW
   - Verify prev_blockhash matches
   - Validate timestamp (not too far in future, greater than median of last 11)
   - Check version for soft fork compliance
   - Verify difficulty matches expected

2. validate_header_chain(&self, headers: &[BlockHeader]) -> Result<()>
   - Validate entire header chain
   - Check all headers connect
   - Verify difficulty adjustments

3. get_median_time_past(&self, height: u32) -> Result<u32>
   - Get median timestamp of last 11 blocks

4. get_next_work_required(&self, height: u32) -> Result<u32>
   - Calculate next difficulty target

Add tests with real Bitcoin headers from multiple difficulty adjustments.
```

### Module 3.3: Script Validation

**File:** `rust/sync/src/validate/script.rs`

**Cursor Prompt:**
```
Implement Bitcoin Script interpreter:

1. Script execution engine:
   - evaluate_script(script: &Script, stack: &mut Stack) -> Result<bool>
   - Implement all Bitcoin opcodes (OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, etc.)
   - Handle P2PKH, P2SH, P2WPKH, P2WSH scripts

2. Signature verification within scripts:
   - verify_signature_in_script(tx: &Transaction, input_idx: usize, script_pubkey: &Script) -> Result<bool>
   - Extract signature and pubkey from script
   - Verify against transaction data

3. Script type identification:
   - identify_script_type(script: &Script) -> ScriptType
   - Enum: P2PKH, P2SH, P2WPKH, P2WSH, P2PK, Nonstandard

4. SegWit support:
   - verify_witness(tx: &Transaction, input_idx: usize) -> Result<bool>

Use the `bitcoin` crate's script module as foundation.
Test with Bitcoin Core's script test vectors.
Include tests for all standard script types and edge cases.
```

### Module 3.4: Transaction Validation

**File:** `rust/sync/src/validate/transaction.rs`

**Cursor Prompt:**
```
Implement transaction validation:

pub struct TransactionValidator {
    db: Arc<BlockchainDB>,
}

Implement:

1. validate_transaction(&self, tx: &Transaction, height: u32, check_inputs: bool) -> Result<()>
   
   Structure checks:
   - Non-empty inputs and outputs
   - No duplicate inputs
   - Coinbase structure (if is_coinbase)
   - Size limits
   - Lock time validation

2. validate_transaction_inputs(&self, tx: &Transaction) -> Result<u64>
   - Check all inputs exist in UTXO set
   - Verify no double spends
   - Verify all signatures
   - Return total input amount

3. validate_amounts(&self, tx: &Transaction, total_input: u64) -> Result<u64>
   - Check output amounts are valid (> 0, no overflow)
   - Verify total_output <= total_input
   - Return fee

4. check_coinbase(&self, tx: &Transaction, height: u32) -> Result<()>
   - Verify coinbase structure
   - Check block height in coinbase
   - Validate output amount (subsidy + fees)

5. Helper methods:
   - is_final(tx: &Transaction, height: u32, time: u32) -> bool
   - get_sigop_count(tx: &Transaction) -> usize

Test with various transaction types from mainnet.
Include edge cases: very large transactions, maximum outputs, etc.
```

### Module 3.5: Block Validation

**File:** `rust/sync/src/validate/block.rs`

**Cursor Prompt:**
```
Implement full block validation:

pub struct BlockValidator {
    db: Arc<BlockchainDB>,
    header_validator: HeaderValidator,
    tx_validator: TransactionValidator,
}

Implement:

1. validate_block(&self, block: &Block, prev_height: u32) -> Result<()>
   
   Steps:
   - Validate header (use HeaderValidator)
   - Check block size/weight limits
   - Verify merkle root matches transactions
   - Validate coinbase transaction
   - Validate all other transactions
   - Check total sigops
   - Verify no duplicate transactions

2. verify_merkle_root(&self, block: &Block) -> bool
   - Compute merkle root from all txids
   - Compare to header.merkle_root

3. validate_block_subsidy(&self, block: &Block, height: u32, total_fees: u64) -> Result<()>
   - Calculate expected subsidy (50 BTC halving every 210,000 blocks)
   - Verify coinbase output <= subsidy + fees

4. apply_block(&self, block: &Block, height: u32) -> Result<()>
   - Update UTXO set (remove spent, add new)
   - Store block
   - Update best block
   - All in atomic batch operation

5. disconnect_block(&self, block: &Block) -> Result<()>
   - Reverse UTXO changes (for reorgs)

Add extensive tests:
- Genesis block
- First few blocks
- Blocks with various transaction types
- Large blocks near size limit
- Edge cases (duplicate coinbase, invalid merkle root, etc.)
```

---

## Phase 4: Rust Block Download (Weeks 10-13)

### Module 4.1: P2P Message Types

**File:** `rust/sync/src/network/messages.rs`

**Cursor Prompt:**
```
Implement Bitcoin P2P protocol messages:

1. Message envelope:
   pub struct Message {
       magic: u32,
       command: [u8; 12],
       payload_size: u32,
       checksum: u32,
       payload: Vec<u8>,
   }

2. Implement message types:
   - VersionMessage: version handshake
   - VerAckMessage: version acknowledgment
   - PingMessage / PongMessage: keepalive
   - GetHeadersMessage: request headers
   - HeadersMessage: deliver headers
   - GetDataMessage: request blocks/transactions
   - BlockMessage: deliver block
   - InvMessage: announce inventory (blocks/txs)
   - AddrMessage: share peer addresses

3. Serialization/deserialization for all messages following Bitcoin protocol

4. Message validation:
   - Verify magic bytes
   - Verify checksum
   - Validate payload size

Test with actual Bitcoin message captures (Wireshark pcap files).
```

### Module 4.2: Peer Connection

**File:** `rust/sync/src/network/peer.rs`

**Cursor Prompt:**
```
Implement peer connection and communication:

pub struct Peer {
    addr: SocketAddr,
    stream: TcpStream,
    version: Option<i32>,
    services: u64,
    state: PeerState,
}

enum PeerState {
    Connecting,
    Connected,
    Disconnected,
}

Implement:

1. async fn connect(addr: SocketAddr) -> Result<Self>
   - Establish TCP connection
   - Send version message
   - Wait for verack
   - Return connected peer

2. async fn send_message(&mut self, msg: Message) -> Result<()>
   - Serialize and send message
   - Handle write errors

3. async fn receive_message(&mut self) -> Result<Message>
   - Read message header
   - Read payload
   - Validate checksum
   - Deserialize

4. async fn handshake(&mut self) -> Result<()>
   - Complete version handshake
   - Exchange verack

5. Keepalive:
   - async fn ping(&mut self) -> Result<()>
   - Handle pong responses

Use tokio for async I/O.
Add timeout handling (disconnect slow peers).
Add peer scoring (latency, reliability).
```

### Module 4.3: Peer Manager

**File:** `rust/sync/src/network/peer_manager.rs`

**Cursor Prompt:**
```
Implement peer discovery and management:

pub struct PeerManager {
    peers: HashMap<SocketAddr, Peer>,
    max_peers: usize,
    known_addrs: HashSet<SocketAddr>,
}

Implement:

1. async fn start(&mut self) -> Result<()>
   - Connect to DNS seeds
   - Resolve seed addresses
   - Connect to initial peers
   - Start peer maintenance task

2. async fn connect_to_seeds(&mut self) -> Result<()>
   - DNS seeds for mainnet:
     - seed.bitcoin.sipa.be
     - dnsseed.bluematt.me
     - dnsseed.bitcoin.dashjr.org
   - Resolve and connect to 8 peers

3. async fn maintain_connections(&mut self)
   - Keep 8-10 outbound connections
   - Replace disconnected peers
   - Disconnect misbehaving peers

4. async fn broadcast_message(&mut self, msg: Message)
   - Send to all connected peers

5. async fn request_from_best_peer(&mut self, msg: Message) -> Result<Peer>
   - Choose peer with lowest latency
   - Send request

6. fn ban_peer(&mut self, addr: SocketAddr, duration: Duration)
   - Add to ban list
   - Disconnect if connected

Use tokio::select! for concurrent peer management.
Implement exponential backoff for reconnection.
```

### Module 4.4: Header Sync

**File:** `rust/sync/src/network/header_sync.rs`

**Cursor Prompt:**
```
Implement headers-first synchronization:

pub struct HeaderSync {
    peer_manager: Arc<PeerManager>,
    validator: Arc<HeaderValidator>,
    db: Arc<BlockchainDB>,
}

Implement:

1. async fn sync_headers(&mut self) -> Result<u32>
   - Start from current best height
   - Request headers in batches of 2000
   - Validate header chain
   - Store validated headers
   - Return final height

2. async fn request_headers(&mut self, start_height: u32) -> Result<Vec<BlockHeader>>
   - Build GetHeaders message with locator
   - Request from peer
   - Receive headers response
   - Validate connects to known chain

3. fn build_locator(&self) -> Vec<[u8; 32]>
   - Create block locator (exponential spacing)
   - Include genesis, recent blocks, exponentially spaced

4. async fn save_headers(&self, headers: &[BlockHeader]) -> Result<()>
   - Validate all headers
   - Store in database
   - Update best header

Progress reporting:
- Track downloaded headers
- Calculate percentage
- Report to Python layer

Handle edge cases:
- Reorgs during sync
- Invalid headers
- Peer timeouts
```

### Module 4.5: Block Download

**File:** `rust/sync/src/network/block_sync.rs`

**Cursor Prompt:**
```
Implement parallel block download and validation:

pub struct BlockSync {
    peer_manager: Arc<PeerManager>,
    validator: Arc<BlockValidator>,
    db: Arc<BlockchainDB>,
    download_queue: VecDeque<u32>, // Heights to download
    in_flight: HashMap<u32, SocketAddr>, // Height -> peer
}

Implement:

1. async fn sync_blocks(&mut self, start_height: u32, end_height: u32) -> Result<()>
   - Fill download queue with missing blocks
   - Request blocks from multiple peers in parallel
   - Validate as they arrive
   - Apply to database
   - Track progress

2. async fn download_block_parallel(&mut self)
   - Request up to 16 blocks simultaneously
   - Different blocks from different peers
   - Handle responses as they arrive

3. async fn handle_block(&mut self, height: u32, block: Block) -> Result<()>
   - Validate block
   - Apply to database (may need to wait for previous blocks)
   - Remove from in_flight
   - Update progress

4. fn schedule_downloads(&mut self)
   - Assign heights to available peers
   - Balance load across peers
   - Track requests per peer

5. async fn handle_timeout(&mut self, height: u32)
   - Re-request from different peer
   - Score peer negatively

Optimization:
- Pipeline: download while validating previous
- Prioritize block validation CPU time
- Use tokio tasks for parallel validation

Progress tracking:
- Blocks downloaded vs total
- Validation speed (blocks/sec)
- Estimated time remaining
```

### Module 4.6: Sync Orchestration

**File:** `rust/sync/src/lib.rs`

**Cursor Prompt:**
```
Create main sync orchestrator with Python bindings:

use pyo3::prelude::*;

#[pyclass]
pub struct FastSync {
    data_dir: PathBuf,
    network: Network,
    db: Option<Arc<BlockchainDB>>,
    peer_manager: Option<Arc<PeerManager>>,
    header_sync: Option<HeaderSync>,
    block_sync: Option<BlockSync>,
}

#[pymethods]
impl FastSync {
    #[new]
    fn new(data_dir: String, network: String) -> PyResult<Self> {
        // Parse network (mainnet/testnet/regtest)
        // Initialize database
        // Create validator components
        // Create peer manager
    }

    fn sync_blockchain(&mut self, py: Python) -> PyResult<()> {
        // Release GIL for long-running operation
        py.allow_threads(|| {
            // Run async sync
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                // Phase 1: Sync headers
                self.sync_headers().await?;
                
                // Phase 2: Sync blocks
                self.sync_blocks().await?;
                
                Ok(())
            })
        })
    }

    fn get_sync_progress(&self) -> PyResult<SyncProgress> {
        // Return progress info
    }

    fn is_synced(&self) -> PyResult<bool> {
        // Check if caught up
    }

    fn cancel_sync(&mut self) -> PyResult<()> {
        // Graceful shutdown
    }
}

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
}

#[pymodule]
fn bitcoin_sync(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<FastSync>()?;
    m.add_class::<SyncProgress>()?;
    Ok(())
}

Add error handling, logging, and graceful shutdown.
```

---

## Phase 5: Python Integration Layer (Weeks 13-15)

### Module 5.1: Database Access

**File:** `python/bitcoin_node/database.py`

**Cursor Prompt:**
```
Create Python wrapper for blockchain database:

import rocksdb
from typing import Optional, List, Tuple
from dataclasses import dataclass

@dataclass
class Block:
    version: int
    prev_blockhash: bytes
    merkle_root: bytes
    timestamp: int
    bits: int
    nonce: int
    transactions: List['Transaction']
    
    def hash(self) -> bytes:
        """Compute block hash"""
        pass
    
    def serialize(self) -> bytes:
        """Serialize to bytes"""
        pass
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'Block':
        """Deserialize from bytes"""
        pass

class BlockchainDatabase:
    """Read/write access to blockchain data"""
    
    def __init__(self, data_dir: str):
        # Open RocksDB databases
        # blocks, chainstate, indexes
        pass
    
    def get_block(self, block_hash: bytes) -> Optional[Block]:
        """Get block by hash"""
        pass
    
    def get_block_by_height(self, height: int) -> Optional[Block]:
        """Get block by height"""
        pass
    
    def get_utxo(self, txid: bytes, vout: int) -> Optional[dict]:
        """Get UTXO"""
        pass
    
    def store_block(self, block: Block) -> None:
        """Store new block"""
        pass
    
    def update_utxo_set(self, spent: List[Tuple[bytes, int]], 
                       created: List[dict]) -> None:
        """Atomic UTXO update"""
        pass
    
    def get_best_block(self) -> Tuple[bytes, int]:
        """Get chain tip"""
        pass

Implement all database operations.
Add proper error handling.
Use context managers for transactions.
```

### Module 5.2: Sync Manager

**File:** `python/bitcoin_node/sync.py`

**Cursor Prompt:**
```
Create sync manager that wraps Rust FastSync:

from bitcoin_sync import FastSync, SyncProgress
from typing import Callable, Optional
import time

class SyncManager:
    """Manages initial blockchain synchronization"""
    
    def __init__(self, data_dir: str, network: str = "mainnet"):
        self.fast_sync = FastSync(data_dir, network)
        self.data_dir = data_dir
        self.network = network
        
    def perform_initial_sync(self, 
                            progress_callback: Optional[Callable[[SyncProgress], None]] = None,
                            cancel_check: Optional[Callable[[], bool]] = None) -> bool:
        """
        Run initial blockchain sync.
        
        Args:
            progress_callback: Called periodically with progress info
            cancel_check: Called periodically, return True to cancel
            
        Returns:
            True if completed, False if cancelled
        """
        pass
    
    def is_synced(self) -> bool:
        """Check if blockchain is fully synced"""
        pass
    
    def get_progress(self) -> SyncProgress:
        """Get current sync progress"""
        pass

Implement with:
- Progress reporting every 5 seconds
- Graceful cancellation
- Error recovery (auto-retry on network errors)
- Resume from interruption
```

### Module 5.3: CLI Application

**File:** `python/bitcoin_node/cli.py`

**Cursor Prompt:**
```
Create command-line interface using Click:

import click
from .sync import SyncManager
from .node import BitcoinNode
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console()

@click.group()
@click.option('--data-dir', default='~/.bitcoin-hybrid', 
              help='Data directory')
@click.option('--network', default='mainnet', 
              type=click.Choice(['mainnet', 'testnet', 'regtest']))
@click.pass_context
def cli(ctx, data_dir, network):
    """Bitcoin Hybrid Node - Rust sync, Python operations"""
    ctx.obj = {
        'data_dir': data_dir,
        'network': network
    }

@cli.command()
@click.pass_context
def sync(ctx):
    """Synchronize blockchain (initial download)"""
    # Create SyncManager
    # Show rich progress bar
    # Handle interruption gracefully
    pass

@cli.command()
@click.pass_context
@click.option('--rpc-port', default=8332, help='RPC server port')
@click.option('--p2p-port', default=8333, help='P2P network port')
def start(ctx, rpc_port, p2p_port):
    """Start the Bitcoin node"""
    # Check if synced
    # Start node
    # Run until interrupted
    pass

@cli.command()
@click.pass_context
def status(ctx):
    """Show node status"""
    # Display blockchain height, peers, mempool size
    pass

@cli.command()
@click.argument('address')
def getbalance(address):
    """Get balance for address"""
    pass

if __name__ == '__main__':
    cli()

Use rich for beautiful progress bars and formatting.
Add proper signal handling (SIGINT, SIGTERM).
```

---

## Phase 6: Python Node Core (Weeks 15-18)

### Module 6.1: Transaction Validation

**File:** `python/bitcoin_node/validation.py`

**Cursor Prompt:**
```
Implement Python transaction validator:

from typing import Tuple, List
from .database import BlockchainDatabase
from .types import Transaction, Block
from .script import ScriptInterpreter

class TransactionValidator:
    """Validates transactions for mempool and new blocks"""
    
    def __init__(self, db: BlockchainDatabase):
        self.db = db
        self.script_interpreter = ScriptInterpreter()
        
    def validate_transaction(self, tx: Transaction, height: int) -> Tuple[bool, str]:
        """
        Validate transaction.
        
        Returns:
            (is_valid, error_message)
        """
        # 1. Check structure
        if not self._check_structure(tx):
            return False, "Invalid structure"
        
        # 2. Check inputs exist
        total_input = 0
        for tx_in in tx.inputs:
            utxo = self.db.get_utxo(tx_in.prev_txid, tx_in.prev_vout)
            if not utxo:
                return False, f"Input not found: {tx_in.prev_txid.hex()}:{tx_in.prev_vout}"
            
            # 3. Verify signatures
            if not self._verify_input_signature(tx, tx_in, utxo):
                return False, "Invalid signature"
            
            total_input += utxo['amount']
        
        # 4. Check amounts
        total_output = sum(out.amount for out in tx.outputs)
        if total_input < total_output:
            return False, "Outputs exceed inputs"
        
        # 5. Check fee
        fee = total_input - total_output
        if fee < self._calculate_min_fee(tx):
            return False, "Fee too low"
        
        return True, ""
    
    def _verify_input_signature(self, tx: Transaction, tx_in: TxIn, utxo: dict) -> bool:
        """Verify signature for one input"""
        return self.script_interpreter.verify(
            tx_in.script_sig,
            utxo['script_pubkey'],
            tx,
            tx_in.index
        )
    
    def _calculate_min_fee(self, tx: Transaction) -> int:
        """Calculate minimum relay fee (1 sat/vbyte)"""
        return len(tx.serialize())

Implement script interpreter using existing Bitcoin libraries (python-bitcoinlib).
Add support for all standard script types.
Test with real mainnet transactions.
```

### Module 6.2: Block Validation

**File:** `python/bitcoin_node/validation.py` (continued)

**Cursor Prompt:**
```
Add block validator to validation.py:

class BlockValidator:
    """Validates new blocks"""
    
    def __init__(self, db: BlockchainDatabase):
        self.db = db
        self.tx_validator = TransactionValidator(db)
    
    def validate_block(self, block: Block) -> Tuple[bool, str]:
        """
        Validate a new block completely.
        
        Returns:
            (is_valid, error_message)
        """
        # 1. Get previous block
        prev_block = self.db.get_block(block.prev_blockhash)
        if not prev_block:
            return False, "Previous block not found"
        
        # 2. Validate header
        if not self._validate_header(block, prev_block):
            return False, "Invalid header"
        
        # 3. Verify merkle root
        if not self._verify_merkle_root(block):
            return False, "Invalid merkle root"
        
        # 4. Validate all transactions
        total_fees = 0
        for i, tx in enumerate(block.transactions):
            if i == 0:  # Coinbase
                if not self._validate_coinbase(tx, prev_block.height + 1):
                    return False, "Invalid coinbase"
            else:
                valid, error = self.tx_validator.validate_transaction(
                    tx, prev_block.height + 1
                )
                if not valid:
                    return False, f"Transaction {i} invalid: {error}"
                
                # Calculate fee
                fee = self._calculate_tx_fee(tx)
                total_fees += fee
        
        # 5. Verify coinbase amount
        if not self._verify_coinbase_amount(block.transactions[0], 
                                           prev_block.height + 1, 
                                           total_fees):
            return False, "Coinbase amount invalid"
        
        return True, ""
    
    def apply_block(self, block: Block) -> None:
        """Apply block to database (update UTXO set)"""
        spent = []
        created = []
        
        # Collect spent and created UTXOs
        for tx in block.transactions:
            # Spent outputs (except coinbase)
            if not tx.is_coinbase:
                for tx_in in tx.inputs:
                    spent.append((tx_in.prev_txid, tx_in.prev_vout))
            
            # Created outputs
            for i, tx_out in enumerate(tx.outputs):
                created.append({
                    'txid': tx.txid(),
                    'vout': i,
                    'amount': tx_out.amount,
                    'script_pubkey': tx_out.script_pubkey,
                    'height': block.height
                })
        
        # Atomic update
        self.db.update_utxo_set(spent, created)
        self.db.store_block(block)
    
    def _verify_merkle_root(self, block: Block) -> bool:
        """Verify block's merkle root"""
        txids = [tx.txid() for tx in block.transactions]
        calculated_root = self._calculate_merkle_root(txids)
        return calculated_root == block.merkle_root
    
    def _calculate_merkle_root(self, txids: List[bytes]) -> bytes:
        """Calculate merkle root from transaction IDs"""
        # Implement Bitcoin's merkle tree algorithm
        pass
    
    def _calculate_block_subsidy(self, height: int) -> int:
        """Calculate block subsidy (50 BTC halving every 210000 blocks)"""
        halvings = height // 210000
        if halvings >= 64:
            return 0
        return 50 * 100_000_000 >> halvings

Add comprehensive tests with real blocks.
Test edge cases (reorgs, invalid blocks, etc.).
```

---

## Phase 7: Python P2P Network (Weeks 18-21)

### Module 7.1: P2P Message Types

**File:** `python/bitcoin_node/p2p/messages.py`

**Cursor Prompt:**
```
Implement Bitcoin P2P message types in Python:

from dataclasses import dataclass
from typing import List, Optional
import struct
import hashlib

MAGIC_MAINNET = 0xD9B4BEF9
MAGIC_TESTNET = 0x0709110B
MAGIC_REGTEST = 0xDAB5BFFA

@dataclass
class NetworkMessage:
    """Base Bitcoin network message"""
    command: str
    payload: bytes
    
    def serialize(self, magic: int = MAGIC_MAINNET) -> bytes:
        """Serialize message to bytes"""
        # Magic (4 bytes)
        # Command (12 bytes, null-padded)
        # Payload length (4 bytes)
        # Checksum (4 bytes, first 4 bytes of double SHA256)
        # Payload
        pass
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'NetworkMessage':
        """Deserialize from bytes"""
        pass
    
    def checksum(self) -> bytes:
        """Calculate message checksum"""
        return hashlib.sha256(hashlib.sha256(self.payload).digest()).digest()[:4]

@dataclass
class VersionMessage:
    version: int = 70015
    services: int = 0
    timestamp: int = 0
    addr_recv: str = ""
    addr_from: str = ""
    nonce: int = 0
    user_agent: str = "/bitcoin-hybrid:0.1.0/"
    start_height: int = 0
    relay: bool = True
    
    def to_network_message(self) -> NetworkMessage:
        """Convert to network message"""
        pass
    
    @classmethod
    def from_payload(cls, payload: bytes) -> 'VersionMessage':
        """Parse from payload"""
        pass

@dataclass
class InvMessage:
    """Inventory message (announces blocks/transactions)"""
    inventory: List[tuple[int, bytes]]  # (type, hash) pairs
    # type: 1=tx, 2=block, 3=filtered_block, 4=compact_block
    
    def to_network_message(self) -> NetworkMessage:
        pass
    
    @classmethod
    def from_payload(cls, payload: bytes) -> 'InvMessage':
        pass

@dataclass
class GetDataMessage:
    """Request blocks/transactions"""
    inventory: List[tuple[int, bytes]]
    
    def to_network_message(self) -> NetworkMessage:
        pass

@dataclass
class BlockMessage:
    """Block delivery"""
    block: 'Block'
    
    def to_network_message(self) -> NetworkMessage:
        pass
    
    @classmethod
    def from_payload(cls, payload: bytes) -> 'BlockMessage':
        pass

@dataclass
class TxMessage:
    """Transaction delivery"""
    transaction: 'Transaction'
    
    def to_network_message(self) -> NetworkMessage:
        pass

@dataclass
class GetHeadersMessage:
    """Request block headers"""
    version: int = 70015
    locator_hashes: List[bytes] = None
    hash_stop: bytes = b'\x00' * 32
    
    def to_network_message(self) -> NetworkMessage:
        pass

@dataclass
class HeadersMessage:
    """Block headers delivery"""
    headers: List['BlockHeader']
    
    def to_network_message(self) -> NetworkMessage:
        pass
    
    @classmethod
    def from_payload(cls, payload: bytes) -> 'HeadersMessage':
        pass

@dataclass
class PingMessage:
    nonce: int
    
    def to_network_message(self) -> NetworkMessage:
        pass

@dataclass
class PongMessage:
    nonce: int
    
    def to_network_message(self) -> NetworkMessage:
        pass

Implement serialization/deserialization for all message types.
Add validation methods.
Test with real Bitcoin network messages.
```

### Module 7.2: Peer Connection

**File:** `python/bitcoin_node/p2p/peer.py`

**Cursor Prompt:**
```
Implement peer connection management with asyncio:

import asyncio
from typing import Optional, Callable
from enum import Enum
import time
import logging
from .messages import *

logger = logging.getLogger(__name__)

class PeerState(Enum):
    DISCONNECTED = 0
    CONNECTING = 1
    CONNECTED = 2
    HANDSHAKING = 3
    READY = 4

class Peer:
    """Manages connection to a single Bitcoin peer"""
    
    def __init__(self, host: str, port: int, network: str = "mainnet"):
        self.host = host
        self.port = port
        self.network = network
        self.state = PeerState.DISCONNECTED
        
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        
        self.version: Optional[int] = None
        self.services: int = 0
        self.user_agent: str = ""
        self.start_height: int = 0
        
        self.last_ping: float = 0
        self.latency: float = 0
        self.score: int = 100  # Reputation score
        
        self.message_handlers: dict[str, Callable] = {}
    
    async def connect(self, start_height: int = 0) -> bool:
        """Connect to peer and complete handshake"""
        try:
            logger.info(f"Connecting to {self.host}:{self.port}")
            self.state = PeerState.CONNECTING
            
            # Establish TCP connection
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=10.0
            )
            
            self.state = PeerState.CONNECTED
            
            # Perform handshake
            await self._handshake(start_height)
            
            self.state = PeerState.READY
            logger.info(f"Connected to {self.host}:{self.port} - {self.user_agent}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to {self.host}:{self.port}: {e}")
            await self.disconnect()
            return False
    
    async def _handshake(self, start_height: int):
        """Perform version handshake"""
        # Send version
        version_msg = VersionMessage(
            timestamp=int(time.time()),
            addr_recv=f"{self.host}:{self.port}",
            addr_from="0.0.0.0:8333",
            nonce=self._generate_nonce(),
            start_height=start_height
        )
        
        await self.send_message(version_msg.to_network_message())
        
        # Receive version
        msg = await self.receive_message()
        if msg.command != "version":
            raise Exception(f"Expected version, got {msg.command}")
        
        version = VersionMessage.from_payload(msg.payload)
        self.version = version.version
        self.services = version.services
        self.user_agent = version.user_agent
        self.start_height = version.start_height
        
        # Send verack
        await self.send_message(NetworkMessage("verack", b""))
        
        # Receive verack
        msg = await self.receive_message()
        if msg.command != "verack":
            raise Exception(f"Expected verack, got {msg.command}")
    
    async def send_message(self, msg: NetworkMessage):
        """Send a message to peer"""
        magic = {
            "mainnet": MAGIC_MAINNET,
            "testnet": MAGIC_TESTNET,
            "regtest": MAGIC_REGTEST
        }[self.network]
        
        data = msg.serialize(magic)
        self.writer.write(data)
        await self.writer.drain()
        
        logger.debug(f"Sent {msg.command} to {self.host}:{self.port}")
    
    async def receive_message(self) -> NetworkMessage:
        """Receive a message from peer"""
        # Read header (24 bytes)
        header = await asyncio.wait_for(
            self.reader.readexactly(24),
            timeout=30.0
        )
        
        magic, command, length, checksum = struct.unpack('<I12sI4s', header)
        command = command.rstrip(b'\x00').decode('ascii')
        
        # Read payload
        payload = b''
        if length > 0:
            payload = await asyncio.wait_for(
                self.reader.readexactly(length),
                timeout=30.0
            )
        
        # Verify checksum
        expected_checksum = hashlib.sha256(
            hashlib.sha256(payload).digest()
        ).digest()[:4]
        
        if checksum != expected_checksum:
            raise Exception(f"Checksum mismatch for {command}")
        
        logger.debug(f"Received {command} from {self.host}:{self.port}")
        return NetworkMessage(command, payload)
    
    async def listen(self):
        """Listen for messages and dispatch to handlers"""
        try:
            while self.state == PeerState.READY:
                msg = await self.receive_message()
                
                # Handle ping/pong automatically
                if msg.command == "ping":
                    ping = PingMessage.from_payload(msg.payload)
                    pong = PongMessage(ping.nonce)
                    await self.send_message(pong.to_network_message())
                    continue
                
                if msg.command == "pong":
                    pong = PongMessage.from_payload(msg.payload)
                    self.latency = time.time() - self.last_ping
                    continue
                
                # Dispatch to handler
                if msg.command in self.message_handlers:
                    await self.message_handlers[msg.command](msg)
                    
        except asyncio.CancelledError:
            logger.info(f"Peer {self.host}:{self.port} listener cancelled")
        except Exception as e:
            logger.error(f"Error in peer {self.host}:{self.port} listener: {e}")
            await self.disconnect()
    
    def register_handler(self, command: str, handler: Callable):
        """Register message handler"""
        self.message_handlers[command] = handler
    
    async def ping(self):
        """Send ping to peer"""
        nonce = self._generate_nonce()
        self.last_ping = time.time()
        ping = PingMessage(nonce)
        await self.send_message(ping.to_network_message())
    
    async def disconnect(self):
        """Disconnect from peer"""
        self.state = PeerState.DISCONNECTED
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
    
    def _generate_nonce(self) -> int:
        """Generate random nonce"""
        import random
        return random.randint(0, 2**64 - 1)
    
    def adjust_score(self, delta: int):
        """Adjust peer reputation score"""
        self.score = max(0, min(100, self.score + delta))
        if self.score == 0:
            logger.warning(f"Peer {self.host}:{self.port} banned (score=0)")

Implement proper error handling and timeouts.
Add connection retry logic.
Test with real Bitcoin nodes.
```

### Module 7.3: Peer Manager

**File:** `python/bitcoin_node/p2p/peer_manager.py`

**Cursor Prompt:**
```
Implement peer discovery and connection management:

import asyncio
import socket
import random
from typing import List, Dict, Set, Optional
import logging
from .peer import Peer, PeerState

logger = logging.getLogger(__name__)

# DNS seeds for mainnet
DNS_SEEDS_MAINNET = [
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "dnsseed.bitcoin.dashjr.org",
    "seed.bitcoinstats.com",
    "seed.bitcoin.jonasschnelli.ch",
    "seed.btc.petertodd.org",
]

class PeerManager:
    """Manages peer connections and discovery"""
    
    def __init__(self, network: str = "mainnet", max_peers: int = 8):
        self.network = network
        self.max_peers = max_peers
        
        self.peers: Dict[str, Peer] = {}  # addr -> Peer
        self.known_addrs: Set[str] = set()
        self.banned_addrs: Dict[str, float] = {}  # addr -> unban_time
        
        self.running = False
    
    async def start(self, start_height: int = 0):
        """Start peer manager"""
        self.running = True
        
        # Discover peers from DNS seeds
        await self.discover_peers()
        
        # Connect to initial peers
        await self.connect_to_peers(start_height)
        
        # Start maintenance task
        asyncio.create_task(self.maintain_connections(start_height))
    
    async def stop(self):
        """Stop peer manager and disconnect all peers"""
        self.running = False
        
        # Disconnect all peers
        for peer in list(self.peers.values()):
            await peer.disconnect()
    
    async def discover_peers(self):
        """Discover peers from DNS seeds"""
        logger.info("Discovering peers from DNS seeds...")
        
        seeds = DNS_SEEDS_MAINNET if self.network == "mainnet" else []
        
        for seed in seeds:
            try:
                # Resolve DNS seed
                addrs = socket.getaddrinfo(seed, 8333, socket.AF_INET)
                
                for addr_info in addrs:
                    ip = addr_info[4][0]
                    addr = f"{ip}:8333"
                    self.known_addrs.add(addr)
                    
                logger.info(f"Discovered {len(addrs)} peers from {seed}")
                
            except Exception as e:
                logger.warning(f"Failed to resolve {seed}: {e}")
        
        logger.info(f"Total known peers: {len(self.known_addrs)}")
    
    async def connect_to_peers(self, start_height: int = 0):
        """Connect to peers up to max_peers"""
        while len(self.peers) < self.max_peers and self.known_addrs:
            # Pick random peer
            addr = random.choice(list(self.known_addrs - set(self.peers.keys())))
            
            # Check if banned
            if addr in self.banned_addrs:
                if time.time() < self.banned_addrs[addr]:
                    continue
                else:
                    del self.banned_addrs[addr]
            
            # Try to connect
            host, port = addr.split(':')
            peer = Peer(host, int(port), self.network)
            
            if await peer.connect(start_height):
                self.peers[addr] = peer
                # Start listening for messages
                asyncio.create_task(peer.listen())
            else:
                # Failed to connect, remove from known addrs
                self.known_addrs.discard(addr)
    
    async def maintain_connections(self, start_height: int):
        """Maintain peer connections"""
        while self.running:
            # Remove disconnected peers
            for addr, peer in list(self.peers.items()):
                if peer.state == PeerState.DISCONNECTED:
                    del self.peers[addr]
                    logger.info(f"Removed disconnected peer {addr}")
            
            # Connect to more peers if needed
            if len(self.peers) < self.max_peers:
                await self.connect_to_peers(start_height)
            
            # Ping all peers
            for peer in self.peers.values():
                await peer.ping()
            
            # Wait before next maintenance
            await asyncio.sleep(30)
    
    def get_best_peer(self) -> Optional[Peer]:
        """Get peer with lowest latency"""
        ready_peers = [p for p in self.peers.values() 
                      if p.state == PeerState.READY]
        
        if not ready_peers:
            return None
        
        return min(ready_peers, key=lambda p: p.latency if p.latency > 0 else 999)
    
    def get_all_ready_peers(self) -> List[Peer]:
        """Get all ready peers"""
        return [p for p in self.peers.values() 
                if p.state == PeerState.READY]
    
    async def broadcast(self, msg):
        """Broadcast message to all peers"""
        for peer in self.get_all_ready_peers():
            try:
                await peer.send_message(msg)
            except Exception as e:
                logger.error(f"Failed to broadcast to {peer.host}: {e}")
    
    def ban_peer(self, addr: str, duration: int = 3600):
        """Ban a peer temporarily"""
        self.banned_addrs[addr] = time.time() + duration
        
        if addr in self.peers:
            asyncio.create_task(self.peers[addr].disconnect())
            del self.peers[addr]
        
        logger.warning(f"Banned peer {addr} for {duration} seconds")

Add peer scoring and banning logic.
Implement exponential backoff for reconnections.
Test with real network.
```

### Module 7.4: Block Synchronization

**File:** `python/bitcoin_node/p2p/block_sync.py`

**Cursor Prompt:**
```
Implement ongoing block synchronization (after initial Rust sync):

import asyncio
import logging
from typing import Dict, Set
from ..database import BlockchainDatabase
from ..validation import BlockValidator
from .peer_manager import PeerManager
from .messages import *

logger = logging.getLogger(__name__)

class BlockSync:
    """Synchronizes new blocks from network"""
    
    def __init__(self, 
                 db: BlockchainDatabase,
                 validator: BlockValidator,
                 peer_manager: PeerManager):
        self.db = db
        self.validator = validator
        self.peer_manager = peer_manager
        
        self.requested_blocks: Dict[bytes, float] = {}  # hash -> request_time
        self.received_blocks: Dict[bytes, Block] = {}
        
        self.running = False
    
    async def start(self):
        """Start block synchronization"""
        self.running = True
        
        # Register message handlers
        for peer in self.peer_manager.get_all_ready_peers():
            peer.register_handler("inv", self.handle_inv)
            peer.register_handler("block", self.handle_block)
        
        # Start sync task
        asyncio.create_task(self.sync_loop())
    
    async def stop(self):
        """Stop block synchronization"""
        self.running = False
    
    async def sync_loop(self):
        """Main synchronization loop"""
        while self.running:
            try:
                # Check if we're behind
                best_hash, best_height = self.db.get_best_block()
                
                # Get peer with highest block
                best_peer = self._get_peer_with_highest_block()
                if best_peer and best_peer.start_height > best_height:
                    logger.info(f"Behind by {best_peer.start_height - best_height} blocks")
                    await self._catch_up(best_peer, best_height)
                
                # Handle timeouts
                await self._handle_timeouts()
                
            except Exception as e:
                logger.error(f"Error in sync loop: {e}")
            
            await asyncio.sleep(10)
    
    async def handle_inv(self, msg: NetworkMessage):
        """Handle inventory announcement"""
        inv = InvMessage.from_payload(msg.payload)
        
        # Request blocks we don't have
        to_request = []
        for inv_type, inv_hash in inv.inventory:
            if inv_type == 2:  # Block
                if not self.db.get_block(inv_hash):
                    to_request.append((inv_type, inv_hash))
                    self.requested_blocks[inv_hash] = time.time()
        
        if to_request:
            # Send getdata
            getdata = GetDataMessage(to_request)
            # Get peer that sent this inv
            peer = self.peer_manager.get_best_peer()
            await peer.send_message(getdata.to_network_message())
            
            logger.info(f"Requested {len(to_request)} blocks")
    
    async def handle_block(self, msg: NetworkMessage):
        """Handle block delivery"""
        block_msg = BlockMessage.from_payload(msg.payload)
        block = block_msg.block
        block_hash = block.hash()
        
        # Remove from requested
        if block_hash in self.requested_blocks:
            del self.requested_blocks[block_hash]
        
        # Validate block
        valid, error = self.validator.validate_block(block)
        
        if valid:
            # Apply to database
            self.validator.apply_block(block)
            logger.info(f"✓ New block {block.height}: {block_hash.hex()[:16]}...")
            
            # Broadcast to other peers
            inv = InvMessage([(2, block_hash)])
            await self.peer_manager.broadcast(inv.to_network_message())
        else:
            logger.warning(f"✗ Invalid block: {error}")
            # TODO: Ban peer that sent invalid block
    
    async def _catch_up(self, peer: Peer, our_height: int):
        """Request blocks to catch up"""
        # Build locator
        locator = self._build_locator(our_height)
        
        # Request headers
        getheaders = GetHeadersMessage(locator_hashes=locator)
        await peer.send_message(getheaders.to_network_message())
        
        # Wait for headers response (handled separately)
        # Then request blocks
    
    def _build_locator(self, height: int) -> List[bytes]:
        """Build block locator (exponential spacing)"""
        locator = []
        step = 1
        
        while height > 0:
            block = self.db.get_block_by_height(height)
            if block:
                locator.append(block.hash())
            
            if len(locator) > 10:
                step *= 2
            
            height -= step
        
        # Always include genesis
        genesis = self.db.get_block_by_height(0)
        if genesis:
            locator.append(genesis.hash())
        
        return locator
    
    def _get_peer_with_highest_block(self) -> Optional[Peer]:
        """Get peer with highest block height"""
        peers = self.peer_manager.get_all_ready_peers()
        if not peers:
            return None
        return max(peers, key=lambda p: p.start_height)
    
    async def _handle_timeouts(self):
        """Re-request blocks that timed out"""
        now = time.time()
        timeout = 30.0
        
        timed_out = [
            block_hash for block_hash, request_time in self.requested_blocks.items()
            if now - request_time > timeout
        ]
        
        for block_hash in timed_out:
            logger.warning(f"Block request timed out: {block_hash.hex()[:16]}")
            del self.requested_blocks[block_hash]
            
            # Re-request from different peer
            peer = self.peer_manager.get_best_peer()
            if peer:
                getdata = GetDataMessage([(2, block_hash)])
                await peer.send_message(getdata.to_network_message())
                self.requested_blocks[block_hash] = now

Implement proper error handling.
Add reorg detection and handling.
Test with testnet.
```

### Module 7.5: Mempool Management

**File:** `python/bitcoin_node/mempool.py`

**Cursor Prompt:**
```
Implement transaction mempool:

from typing import Dict, List, Set, Optional
from dataclasses import dataclass
import time
import logging
from .types import Transaction, OutPoint
from .validation import TransactionValidator

logger = logging.getLogger(__name__)

@dataclass
class MempoolEntry:
    """Entry in the mempool"""
    tx: Transaction
    fee: int
    fee_rate: float  # sat/vbyte
    size: int
    time_added: float
    height_added: int

class Mempool:
    """Unconfirmed transaction pool"""
    
    def __init__(self, 
                 validator: TransactionValidator,
                 max_size: int = 300_000_000):  # 300 MB
        self.validator = validator
        self.max_size = max_size
        
        self.transactions: Dict[bytes, MempoolEntry] = {}  # txid -> entry
        self.spent_outputs: Set[OutPoint] = set()
        
        # Sorted by fee rate (for mining)
        self.by_fee_rate: List[bytes] = []  # txids sorted by fee rate
        
        # Tracking
        self.current_size = 0  # bytes
    
    def add_transaction(self, tx: Transaction, height: int) -> tuple[bool, str]:
        """
        Add transaction to mempool.
        
        Returns:
            (success, error_message)
        """
        txid = tx.txid()
        
        # Check if already in mempool
        if txid in self.transactions:
            return False, "Already in mempool"
        
        # Validate transaction
        valid, error = self.validator.validate_transaction(tx, height)
        if not valid:
            return False, error
        
        # Check for conflicts (double spends)
        for tx_in in tx.inputs:
            outpoint = (tx_in.prev_txid, tx_in.prev_vout)
            if outpoint in self.spent_outputs:
                return False, "Double spend detected"
        
        # Check mempool size
        tx_size = len(tx.serialize())
        if self.current_size + tx_size > self.max_size:
            # Evict lowest fee rate transactions
            self._evict_low_fee_txs(tx_size)
        
        # Calculate fee
        total_input = sum(
            self.validator.db.get_utxo(tx_in.prev_txid, tx_in.prev_vout)['amount']
            for tx_in in tx.inputs
        )
        total_output = sum(out.amount for out in tx.outputs)
        fee = total_input - total_output
        fee_rate = fee / tx_size if tx_size > 0 else 0
        
        # Add to mempool
        entry = MempoolEntry(
            tx=tx,
            fee=fee,
            fee_rate=fee_rate,
            size=tx_size,
            time_added=time.time(),
            height_added=height
        )
        
        self.transactions[txid] = entry
        self.current_size += tx_size
        
        # Track spent outputs
        for tx_in in tx.inputs:
            self.spent_outputs.add((tx_in.prev_txid, tx_in.prev_vout))
        
        # Insert sorted by fee rate
        self._insert_sorted_by_fee_rate(txid, fee_rate)
        
        logger.info(f"Added transaction {txid.hex()[:16]}... to mempool (fee: {fee}, rate: {fee_rate:.2f} sat/vbyte)")
        return True, ""
    
    def remove_transaction(self, txid: bytes):
        """Remove transaction from mempool"""
        if txid not in self.transactions:
            return
        
        entry = self.transactions[txid]
        self.current_size -= entry.size
        
        # Remove spent outputs
        for tx_in in entry.tx.inputs:
            self.spent_outputs.discard((tx_in.prev_txid, tx_in.prev_vout))
        
        # Remove from sorted list
        if txid in self.by_fee_rate:
            self.by_fee_rate.remove(txid)
        
        del self.transactions[txid]
        logger.debug(f"Removed transaction {txid.hex()[:16]}... from mempool")
    
    def remove_block_transactions(self, block: 'Block'):
        """Remove transactions from mempool that are in a block"""
        for tx in block.transactions:
            if not tx.is_coinbase:
                txid = tx.txid()
                self.remove_transaction(txid)
    
    def get_transaction(self, txid: bytes) -> Optional[Transaction]:
        """Get transaction from mempool"""
        entry = self.transactions.get(txid)
        return entry.tx if entry else None
    
    def get_all_transactions(self) -> List[Transaction]:
        """Get all transactions in mempool"""
        return [entry.tx for entry in self.transactions.values()]
    
    def get_transactions_by_fee_rate(self, limit: Optional[int] = None) -> List[Transaction]:
        """Get transactions sorted by fee rate (highest first)"""
        txids = self.by_fee_rate[-limit:] if limit else self.by_fee_rate
        return [self.transactions[txid].tx for txid in reversed(txids)]
    
    def get_mempool_info(self) -> dict:
        """Get mempool statistics"""
        return {
            'size': len(self.transactions),
            'bytes': self.current_size,
            'max_size': self.max_size,
            'min_fee_rate': min((entry.fee_rate for entry in self.transactions.values()), default=0),
            'max_fee_rate': max((entry.fee_rate for entry in self.transactions.values()), default=0),
        }
    
    def _insert_sorted_by_fee_rate(self, txid: bytes, fee_rate: float):
        """Insert txid into sorted list by fee rate"""
        # Binary search and insert
        left, right = 0, len(self.by_fee_rate)
        while left < right:
            mid = (left + right) // 2
            mid_entry = self.transactions[self.by_fee_rate[mid]]
            if mid_entry.fee_rate < fee_rate:
                left = mid + 1
            else:
                right = mid
        self.by_fee_rate.insert(left, txid)
    
    def _evict_low_fee_txs(self, needed_space: int):
        """Evict lowest fee rate transactions to free space"""
        freed = 0
        while self.by_fee_rate and freed < needed_space:
            txid = self.by_fee_rate[0]  # Lowest fee rate
            entry = self.transactions[txid]
            self.remove_transaction(txid)
            freed += entry.size
        
        logger.info(f"Evicted transactions to free {freed} bytes")

Add comprehensive tests.
Test edge cases (full mempool, duplicate transactions, etc.).
```

---

## Phase 8: Python RPC Server (Weeks 21-23)

### Module 8.1: RPC Server Framework

**File:** `python/bitcoin_node/rpc.py`

**Cursor Prompt:**
```
Implement JSON-RPC server using FastAPI:

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from typing import Dict, Any, List, Optional
import json
import logging
from pydantic import BaseModel

logger = logging.getLogger(__name__)

class JSONRPCRequest(BaseModel):
    jsonrpc: str = "2.0"
    method: str
    params: List[Any] = []
    id: Optional[int] = None

class JSONRPCResponse(BaseModel):
    jsonrpc: str = "2.0"
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None
    id: Optional[int] = None

class RPCServer:
    """Bitcoin JSON-RPC server"""
    
    def __init__(self, node: 'BitcoinNode', port: int = 8332):
        self.node = node
        self.port = port
        self.app = FastAPI(title="Bitcoin Hybrid Node RPC")
        
        # Register RPC methods
        self._register_methods()
    
    def _register_methods(self):
        """Register all RPC methods"""
        @self.app.post("/")
        async def handle_rpc(request: JSONRPCRequest) -> JSONRPCResponse:
            try:
                method = getattr(self, f"rpc_{request.method}", None)
                if not method:
                    return JSONRPCResponse(
                        error={"code": -32601, "message": f"Method not found: {request.method}"},
                        id=request.id
                    )
                
                result = await method(*request.params)
                return JSONRPCResponse(result=result, id=request.id)
                
            except Exception as e:
                logger.error(f"RPC error: {e}", exc_info=True)
                return JSONRPCResponse(
                    error={"code": -32603, "message": str(e)},
                    id=request.id
                )
    
    async def start(self):
        """Start RPC server"""
        import uvicorn
        config = uvicorn.Config(self.app, host="127.0.0.1", port=self.port)
        server = uvicorn.Server(config)
        await server.serve()
    
    # RPC Methods (implement below)
    async def rpc_getblockchaininfo(self) -> Dict[str, Any]:
        """Return blockchain information"""
        best_hash, best_height = self.node.db.get_best_block()
        
        return {
            "chain": self.node.network,
            "blocks": best_height,
            "headers": best_height,
            "bestblockhash": best_hash.hex(),
            "difficulty": self.node.get_current_difficulty(),
            "mediantime": self.node.get_median_time(),
            "verificationprogress": 1.0 if self.node.is_synced() else 0.0,
            "chainwork": self.node.get_chainwork(),
            "pruned": False,
            "softforks": {},
        }
    
    async def rpc_getblockcount(self) -> int:
        """Return block count"""
        _, height = self.node.db.get_best_block()
        return height
    
    async def rpc_getbestblockhash(self) -> str:
        """Return best block hash"""
        hash, _ = self.node.db.get_best_block()
        return hash.hex()
    
    async def rpc_getblockhash(self, height: int) -> str:
        """Return block hash at height"""
        block = self.node.db.get_block_by_height(height)
        if not block:
            raise HTTPException(status_code=404, detail="Block not found")
        return block.hash().hex()
    
    async def rpc_getblock(self, blockhash: str, verbosity: int = 1) -> Dict[str, Any]:
        """Return block information"""
        try:
            block_hash = bytes.fromhex(blockhash)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid block hash")
        
        block = self.node.db.get_block(block_hash)
        if not block:
            raise HTTPException(status_code=404, detail="Block not found")
        
        if verbosity == 0:
            return block.serialize().hex()
        elif verbosity == 1:
            return {
                "hash": block.hash().hex(),
                "confirmations": self.node.get_confirmations(block.height),
                "height": block.height,
                "version": block.version,
                "merkleroot": block.merkle_root.hex(),
                "time": block.timestamp,
                "mediantime": block.timestamp,
                "nonce": block.nonce,
                "bits": hex(block.bits),
                "difficulty": self.node.get_difficulty(block.bits),
                "chainwork": self.node.get_chainwork_at_height(block.height),
                "nTx": len(block.transactions),
                "previousblockhash": block.prev_blockhash.hex(),
                "nextblockhash": None,  # TODO: implement
                "tx": [tx.txid().hex() for tx in block.transactions],
            }
        else:  # verbosity == 2
            # Include full transaction data
            return {
                **self.rpc_getblock(blockhash, 1),
                "tx": [self._tx_to_dict(tx) for tx in block.transactions],
            }
    
    async def rpc_getrawtransaction(self, txid: str, verbose: bool = False, blockhash: Optional[str] = None) -> Any:
        """Return transaction"""
        try:
            tx_hash = bytes.fromhex(txid)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid transaction ID")
        
        # Try mempool first
        tx = self.node.mempool.get_transaction(tx_hash)
        if tx:
            if verbose:
                return self._tx_to_dict(tx)
            return tx.serialize().hex()
        
        # Try blockchain
        tx = self.node.db.get_transaction(tx_hash, blockhash)
        if not tx:
            raise HTTPException(status_code=404, detail="Transaction not found")
        
        if verbose:
            return self._tx_to_dict(tx)
        return tx.serialize().hex()
    
    async def rpc_getmempoolinfo(self) -> Dict[str, Any]:
        """Return mempool information"""
        info = self.node.mempool.get_mempool_info()
        return {
            "size": info['size'],
            "bytes": info['bytes'],
            "usage": info['bytes'],
            "maxmempool": info['max_size'],
            "mempoolminfee": info['min_fee_rate'] / 1e8,  # Convert to BTC
            "minrelaytxfee": 0.00001,  # 1 sat/vbyte
        }
    
    async def rpc_sendrawtransaction(self, hexstring: str, maxfeerate: Optional[float] = None) -> str:
        """Broadcast transaction"""
        try:
            tx_data = bytes.fromhex(hexstring)
            tx = Transaction.deserialize(tx_data)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid transaction: {e}")
        
        # Add to mempool
        _, height = self.node.db.get_best_block()
        success, error = self.node.mempool.add_transaction(tx, height)
        
        if not success:
            raise HTTPException(status_code=400, detail=error)
        
        # Broadcast to peers
        await self.node.peer_manager.broadcast_transaction(tx)
        
        return tx.txid().hex()
    
    async def rpc_getnetworkinfo(self) -> Dict[str, Any]:
        """Return network information"""
        peers = self.node.peer_manager.get_all_ready_peers()
        return {
            "version": 240000,  # Bitcoin Core compatible version
            "subversion": "/bitcoin-hybrid:0.1.0/",
            "protocolversion": 70015,
            "connections": len(peers),
            "networkactive": True,
            "relayfee": 0.00001,
        }
    
    def _tx_to_dict(self, tx: Transaction) -> Dict[str, Any]:
        """Convert transaction to dictionary"""
        return {
            "txid": tx.txid().hex(),
            "hash": tx.wtxid().hex() if hasattr(tx, 'wtxid') else tx.txid().hex(),
            "version": tx.version,
            "size": len(tx.serialize()),
            "vsize": tx.vsize() if hasattr(tx, 'vsize') else len(tx.serialize()),
            "weight": tx.weight() if hasattr(tx, 'weight') else len(tx.serialize()) * 4,
            "locktime": tx.locktime,
            "vin": [self._vin_to_dict(vin) for vin in tx.inputs],
            "vout": [self._vout_to_dict(vout, i) for i, vout in enumerate(tx.outputs)],
        }
    
    def _vin_to_dict(self, vin: TxIn) -> Dict[str, Any]:
        """Convert input to dictionary"""
        return {
            "txid": vin.prev_txid.hex(),
            "vout": vin.prev_vout,
            "scriptSig": {
                "asm": "",  # TODO: disassemble script
                "hex": vin.script_sig.hex(),
            },
            "sequence": vin.sequence,
        }
    
    def _vout_to_dict(self, vout: TxOut, n: int) -> Dict[str, Any]:
        """Convert output to dictionary"""
        return {
            "value": vout.amount / 100_000_000,  # Convert satoshis to BTC
            "n": n,
            "scriptPubKey": {
                "asm": "",  # TODO: disassemble script
                "hex": vout.script_pubkey.hex(),
                "type": self._get_script_type(vout.script_pubkey),
            },
        }
    
    def _get_script_type(self, script: bytes) -> str:
        """Determine script type"""
        # Simplified - use script validator
        from .validate import identify_script_type
        script_type = identify_script_type(script)
        type_map = {
            "p2pkh": "pubkeyhash",
            "p2sh": "scripthash",
            "p2wpkh": "witness_v0_keyhash",
            "p2wsh": "witness_v0_scripthash",
            "p2pk": "pubkey",
        }
        return type_map.get(script_type.lower(), "nonstandard")

Implement authentication (username/password).
Add rate limiting.
Test compatibility with Bitcoin Core RPC clients.
```

---

## Phase 9: Python Node Orchestration (Weeks 23-25)

### Module 9.1: Main Node Class

**File:** `python/bitcoin_node/node.py`

**Cursor Prompt:**
```
Create main Bitcoin node class that orchestrates all components:

import asyncio
import logging
from typing import Optional
from .database import BlockchainDatabase
from .validation import BlockValidator, TransactionValidator
from .mempool import Mempool
from .p2p.peer_manager import PeerManager
from .p2p.block_sync import BlockSync
from .rpc import RPCServer
from .sync import SyncManager

logger = logging.getLogger(__name__)

class BitcoinNode:
    """Main Bitcoin full node"""
    
    def __init__(self, data_dir: str, network: str = "mainnet"):
        self.data_dir = data_dir
        self.network = network
        
        # Core components
        self.db: Optional[BlockchainDatabase] = None
        self.validator: Optional[BlockValidator] = None
        self.tx_validator: Optional[TransactionValidator] = None
        self.mempool: Optional[Mempool] = None
        
        # Network components
        self.peer_manager: Optional[PeerManager] = None
        self.block_sync: Optional[BlockSync] = None
        
        # RPC server
        self.rpc_server: Optional[RPCServer] = None
        
        # Sync manager
        self.sync_manager: Optional[SyncManager] = None
        
        # State
        self.running = False
        self.synced = False
    
    async def start(self, rpc_port: int = 8332, p2p_port: int = 8333):
        """Start the Bitcoin node"""
        logger.info(f"Starting Bitcoin Hybrid Node ({self.network})")
        
        # Initialize database
        self.db = BlockchainDatabase(self.data_dir)
        
        # Initialize validators
        self.tx_validator = TransactionValidator(self.db)
        self.validator = BlockValidator(self.db)
        
        # Initialize mempool
        self.mempool = Mempool(self.tx_validator)
        
        # Check if blockchain is synced
        self.synced = self._check_synced()
        
        if not self.synced:
            logger.warning("Blockchain not fully synced. Run 'sync' command first.")
            # Could auto-start sync here if desired
            return
        
        # Initialize peer manager
        _, best_height = self.db.get_best_block()
        self.peer_manager = PeerManager(self.network, max_peers=8)
        await self.peer_manager.start(best_height)
        
        # Initialize block sync
        self.block_sync = BlockSync(self.db, self.validator, self.peer_manager)
        await self.block_sync.start()
        
        # Start RPC server
        self.rpc_server = RPCServer(self, rpc_port)
        asyncio.create_task(self.rpc_server.start())
        
        # Register message handlers
        self._register_handlers()
        
        self.running = True
        logger.info("Bitcoin node started successfully")
        
        # Main loop
        await self._main_loop()
    
    async def stop(self):
        """Stop the Bitcoin node"""
        logger.info("Stopping Bitcoin node...")
        self.running = False
        
        if self.block_sync:
            await self.block_sync.stop()
        
        if self.peer_manager:
            await self.peer_manager.stop()
        
        logger.info("Bitcoin node stopped")
    
    async def _main_loop(self):
        """Main node loop"""
        while self.running:
            try:
                # Periodic tasks
                await self._periodic_tasks()
                
                # Sleep
                await asyncio.sleep(60)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}", exc_info=True)
                await asyncio.sleep(10)
    
    async def _periodic_tasks(self):
        """Periodic maintenance tasks"""
        # Check sync status
        if not self.synced:
            self.synced = self._check_synced()
            if self.synced:
                logger.info("Blockchain is now fully synced")
        
        # Log statistics
        if self.db:
            best_hash, best_height = self.db.get_best_block()
            peer_count = len(self.peer_manager.get_all_ready_peers()) if self.peer_manager else 0
            mempool_size = len(self.mempool.transactions) if self.mempool else 0
            
            logger.info(
                f"Height: {best_height}, "
                f"Peers: {peer_count}, "
                f"Mempool: {mempool_size} txs"
            )
    
    def _check_synced(self) -> bool:
        """Check if blockchain is synced"""
        # Simplified - in production, check against network
        if not self.db:
            return False
        
        # Check if we have blocks
        _, height = self.db.get_best_block()
        return height > 0
    
    def _register_handlers(self):
        """Register message handlers with peers"""
        if not self.peer_manager:
            return
        
        def handle_tx(msg):
            """Handle incoming transaction"""
            tx_msg = TxMessage.from_payload(msg.payload)
            tx = tx_msg.transaction
            
            # Add to mempool
            _, height = self.db.get_best_block()
            success, error = self.mempool.add_transaction(tx, height)
            
            if success:
                logger.info(f"Added transaction {tx.txid().hex()[:16]}... to mempool")
            else:
                logger.debug(f"Rejected transaction: {error}")
        
        # Register with all peers
        for peer in self.peer_manager.get_all_ready_peers():
            peer.register_handler("tx", handle_tx)
    
    def get_current_difficulty(self) -> float:
        """Get current difficulty"""
        # TODO: implement
        return 1.0
    
    def get_median_time(self) -> int:
        """Get median time"""
        # TODO: implement
        return 0
    
    def get_chainwork(self) -> str:
        """Get chain work (hex)"""
        # TODO: implement
        return "0"
    
    def get_confirmations(self, height: int) -> int:
        """Get confirmations for block at height"""
        _, best_height = self.db.get_best_block()
        return max(0, best_height - height + 1)
    
    def get_difficulty(self, bits: int) -> float:
        """Get difficulty from bits"""
        # TODO: implement
        return 1.0
    
    def get_chainwork_at_height(self, height: int) -> str:
        """Get chain work at height"""
        # TODO: implement
        return "0"

Add proper error handling and graceful shutdown.
Implement signal handlers (SIGINT, SIGTERM).
Add configuration file support.
```

---

## Phase 10: Testing & Documentation (Weeks 25-27)

### Module 10.1: Integration Tests

**File:** `tests/integration/test_node.py`

**Cursor Prompt:**
```
Create comprehensive integration tests:

import pytest
import asyncio
import tempfile
import shutil
from bitcoin_node.node import BitcoinNode

@pytest.fixture
def temp_data_dir():
    """Create temporary data directory"""
    tmpdir = tempfile.mkdtemp()
    yield tmpdir
    shutil.rmtree(tmpdir)

@pytest.fixture
def node(temp_data_dir):
    """Create test node"""
    return BitcoinNode(temp_data_dir, network="regtest")

@pytest.mark.asyncio
async def test_node_startup(node):
    """Test node startup"""
    # Test that node can start (with empty chain)
    # Should handle gracefully
    pass

@pytest.mark.asyncio
async def test_block_sync(node):
    """Test block synchronization"""
    # Mock peer manager
    # Test block reception and validation
    pass

@pytest.mark.asyncio
async def test_mempool_operations(node):
    """Test mempool operations"""
    # Create test transactions
    # Test add/remove from mempool
    pass

@pytest.mark.asyncio
async def test_rpc_endpoints(node):
    """Test RPC endpoints"""
    # Test all RPC methods
    # Verify responses match Bitcoin Core format
    pass

Add tests for:
- Block validation
- Transaction validation
- Mempool eviction
- Peer management
- Error handling
- Reorg handling
```

### Module 10.2: Documentation

**File:** `docs/README.md`

**Cursor Prompt:**
```
Create comprehensive documentation:

# Bitcoin Hybrid Node Documentation

## Overview
Bitcoin Hybrid Node is a Bitcoin full node implementation with:
- Rust-powered fast initial sync
- Python-based ongoing operations
- Bitcoin Core compatible RPC API

## Installation
[Installation instructions]

## Configuration
[Configuration file format]

## Usage
[Command-line usage]

## Architecture
[Architecture overview]

## API Reference
[RPC API documentation]

## Development
[Development setup and guidelines]

## Testing
[Testing instructions]

## Contributing
[Contributing guidelines]
```

---

## Phase 11: Production Readiness (Weeks 27-30)

### Module 11.1: Performance Optimization

**Tasks:**
- Profile Rust sync performance
- Optimize database queries
- Add connection pooling
- Optimize memory usage
- Add caching layers

### Module 11.2: Security Hardening

**Tasks:**
- RPC authentication
- Input validation
- Rate limiting
- SQL injection prevention (N/A - using RocksDB)
- Buffer overflow prevention
- Secure key storage

### Module 11.3: Monitoring & Logging

**Tasks:**
- Structured logging
- Metrics collection
- Health checks
- Alert system
- Performance monitoring

### Module 11.4: Deployment

**Tasks:**
- Docker containerization
- Systemd service files
- CI/CD pipeline
- Release process
- Documentation updates

---

## Summary

This plan provides a comprehensive roadmap for building a Bitcoin full node with:
- **Rust** for fast initial blockchain synchronization
- **Python** for flexible node operations, P2P networking, and RPC
- **Bitcoin Core compatibility** for RPC API
- **Production-ready** architecture with proper error handling, testing, and documentation

**Estimated Timeline:** 6-9 months for full implementation

**Key Milestones:**
1. Week 2: Project setup complete
2. Week 6: Storage layer complete
3. Week 10: Block validation complete
4. Week 13: Initial sync complete
5. Week 18: Python node core complete
6. Week 23: RPC server complete
7. Week 27: Testing complete
8. Week 30: Production ready

Good luck with your Bitcoin full node implementation!

