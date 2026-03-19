---
name: bitcoin-core-reference
description: Bitcoin Core source code reference map. Contains file paths for every subsystem in the reference implementation. Use when fixing gaps or implementing features to match Bitcoin Core behavior exactly.
---

# Bitcoin Core Reference Implementation

The Bitcoin Core reference source code is available at: `/home/max/hashhog/bitcoin/src/`

**IMPORTANT**: Before implementing any consensus, P2P, or policy fix, ALWAYS read the corresponding Bitcoin Core source file first. Match the exact behavior, edge cases, and error handling.

## Key Source Files by Subsystem

### Consensus & Validation
| File | Purpose |
|------|---------|
| `validation.cpp/h` | Core block/tx validation, `ConnectBlock`, `CheckBlock`, `AcceptBlock` |
| `consensus/tx_verify.cpp/h` | `CheckTransaction`, `GetTransactionSigOpCost`, sequence lock checks |
| `consensus/merkle.cpp/h` | Merkle root computation |
| `consensus/params.h` | `Consensus::Params` — deployment heights, pow params |
| `pow.cpp/h` | `GetNextWorkRequired`, `CalculateNextWorkRequired`, `CheckProofOfWork` |
| `versionbits.cpp/h` | BIP9 soft fork deployment state machine |
| `deploymentstatus.cpp/h` | `DeploymentActiveAt`, `DeploymentActiveAfter` |
| `arith_uint256.cpp/h` | 256-bit arithmetic for chainwork and target |

### Script Engine
| File | Purpose |
|------|---------|
| `script/interpreter.cpp/h` | `EvalScript`, `VerifyScript`, `ExecuteWitnessScript` — the script VM |
| `script/script.cpp/h` | `CScript` class, opcode definitions, `IsPayToScriptHash` |
| `script/sigcache.cpp/h` | Signature verification cache |
| `script/sign.cpp/h` | Transaction signing, `SignatureHash` |
| `script/descriptor.cpp/h` | Output descriptors (BIP380-386) |
| `script/miniscript.cpp/h` | Miniscript composition language |

### P2P Networking
| File | Purpose |
|------|---------|
| `net.cpp/h` | Socket management, `CConnman`, connection lifecycle |
| `net_processing.cpp/h` | Message processing, `PeerManagerImpl`, `Misbehaving` |
| `addrman.cpp/h` | Address manager with bucketed storage |
| `banman.cpp/h` | Peer banning/discouragement |
| `headerssync.cpp/h` | Header sync anti-DoS (PRESYNC/REDOWNLOAD) |
| `bip324.cpp/h` | V2 encrypted P2P transport |
| `blockencodings.cpp/h` | BIP152 compact blocks |
| `txrequest.cpp/h` | Transaction download scheduler |

### Mempool & Policy
| File | Purpose |
|------|---------|
| `txmempool.cpp/h` | `CTxMemPool`, ancestor/descendant tracking, eviction |
| `txgraph.cpp/h` | Cluster mempool linearization |
| `policy/rbf.cpp/h` | Replace-by-fee rules |
| `policy/packages.cpp/h` | Package relay validation |
| `policy/truc_policy.cpp/h` | v3/TRUC topological restrictions |
| `policy/ephemeral_policy.cpp/h` | Ephemeral anchor forwarding |
| `policy/policy.cpp/h` | Standardness checks, dust threshold |
| `policy/fees/block_policy_estimator.cpp` | Fee rate estimation |

### Mining
| File | Purpose |
|------|---------|
| `node/miner.cpp/h` | `BlockAssembler`, `CreateNewBlock`, `addChunks` |
| `node/mini_miner.cpp/h` | Lightweight miner for fee estimation |
| `rpc/mining.cpp` | Mining RPCs: `getblocktemplate`, `submitblock`, `generateblock` |

### Storage & Database
| File | Purpose |
|------|---------|
| `txdb.cpp/h` | `CBlockTreeDB`, `CCoinsViewDB` — LevelDB wrappers |
| `coins.cpp/h` | `CCoinsViewCache`, UTXO set abstraction |
| `flatfile.cpp/h` | `FlatFileSeq` — blk*.dat and rev*.dat management |
| `node/blockstorage.cpp/h` | Block read/write, file management, pruning |
| `undo.h` | `CTxUndo`, `CBlockUndo` — undo data for reorgs |
| `node/mempool_persist.cpp/h` | Mempool save/load |

### Wallet
| File | Purpose |
|------|---------|
| `wallet/wallet.cpp/h` | Main wallet class, `CWallet` |
| `wallet/spend.cpp/h` | Coin selection, transaction creation |
| `wallet/coinselection.cpp/h` | BnB, Knapsack, SRD, CoinGrinder algorithms |
| `wallet/scriptpubkeyman.cpp/h` | Key management, descriptors |
| `wallet/rpc/*.cpp` | Wallet RPCs |

### RPC
| File | Purpose |
|------|---------|
| `rpc/blockchain.cpp` | `getblock`, `getblockchaininfo`, `gettxoutsetinfo`, etc. |
| `rpc/rawtransaction.cpp` | `getrawtransaction`, `sendrawtransaction`, `decoderawtransaction` |
| `rpc/mempool.cpp` | `getrawmempool`, `getmempoolentry`, `testmempoolaccept` |
| `rpc/net.cpp` | `getpeerinfo`, `addnode`, `getnetworkinfo` |
| `rpc/mining.cpp` | `getblocktemplate`, `submitblock`, `getmininginfo` |
| `rpc/fees.cpp` | `estimatesmartfee` |
| `rpc/signmessage.cpp` | `verifymessage` |
| `httprpc.cpp` | HTTP server, batch requests |
| `rest.cpp` | REST API |

### Indexes
| File | Purpose |
|------|---------|
| `index/txindex.cpp/h` | Transaction index |
| `index/blockfilterindex.cpp/h` | BIP157/158 compact block filter index |
| `index/coinstatsindex.cpp/h` | UTXO set statistics index |

### Cryptography
| File | Purpose |
|------|---------|
| `crypto/sha256.cpp/h` | SHA-256 with hardware acceleration |
| `crypto/ripemd160.cpp/h` | RIPEMD-160 |
| `crypto/chacha20.cpp/h` | ChaCha20 stream cipher |
| `crypto/poly1305.cpp/h` | Poly1305 MAC |
| `crypto/hkdf_sha256_32.cpp/h` | HKDF key derivation |
| `crypto/siphash.cpp/h` | SipHash for compact blocks |
| `key.cpp/h` | `CKey`, `CPubKey` — secp256k1 key management |
| `pubkey.cpp/h` | Public key operations |

### Advanced
| File | Purpose |
|------|---------|
| `node/txreconciliation.cpp/h` | BIP330 Erlay set reconciliation |
| `node/minisketchwrapper.cpp/h` | Minisketch bindings for Erlay |
| `psbt.cpp/h` | PSBT (BIP174/370) |
| `signet.cpp/h` | Signet chain support |
| `blockfilter.cpp/h` | Compact block filters (BIP157/158) |

## Key Patterns to Match

### Script Verification Flags
Bitcoin Core sets flags cumulatively by block height in `GetBlockScriptFlags()` (validation.cpp):
- Pre-P2SH: no flags
- BIP16: `SCRIPT_VERIFY_P2SH`
- BIP66: add `SCRIPT_VERIFY_DERSIG`
- BIP65: add `SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY`
- CSV: add `SCRIPT_VERIFY_CHECKSEQUENCEVERIFY`
- SegWit: add `SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_NULLFAIL | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE`
- Taproot: add `SCRIPT_VERIFY_TAPROOT`

**Critical**: `NULLFAIL` and `WITNESS_PUBKEYTYPE` are consensus flags activated with SegWit, not policy-only.

### Witness Cleanstack
Bitcoin Core enforces cleanstack INSIDE `ExecuteWitnessScript` (interpreter.cpp) — the stack must have exactly 1 element after witness script execution. This is NOT gated by the `SCRIPT_VERIFY_CLEANSTACK` flag — it's always enforced for witness programs.

### P2SH Push-Only
Bitcoin Core unconditionally requires scriptSig to be push-only for P2SH scripts (interpreter.cpp line ~2059). This is NOT gated by `SCRIPT_VERIFY_SIGPUSHONLY`.

### Misbehaving Peers
`Misbehaving(peer, score, message)` in net_processing.cpp accumulates a score. At 100, the peer is flagged for disconnection. Key scores:
- Invalid block: 100 (immediate disconnect)
- Invalid transaction: 100
- Invalid headers: 100
- Unrequested data: 20

### Block Template Construction
Bitcoin Core's `BlockAssembler::CreateNewBlock` (miner.cpp):
1. Creates coinbase with `nLockTime = nHeight - 1` (anti-fee-sniping)
2. Coinbase input sequence = `CTxIn::SEQUENCE_FINAL - 1` (0xFFFFFFFE)
3. Uses `addChunks` with cluster linearization for optimal fee extraction
4. Validates template with `TestBlockValidity`
5. Computes block version via `ComputeBlockVersion` (BIP9 signaling)
