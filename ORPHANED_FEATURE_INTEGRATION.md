# Orphaned Feature Integration Guide

Six roadmap features have working implementations and passing tests but are **not wired into the running node**. This document provides step-by-step integration instructions for each, written as cursor prompts you can paste directly.

---

## Status Summary

| Feature | Module | What's Missing |
|---------|--------|----------------|
| C.1 HD Keys | `wallet.py` | No RPC to create HD wallet or derive addresses from seed |
| C.2 Encrypted Wallet | `wallet.py` | No `encryptwallet` / `walletpassphrase` / `walletlock` RPCs |
| C.3 PSBT | `psbt.py` | No `createpsbt` / `combinepsbt` / `finalizepsbt` / `decodepsbt` RPCs |
| D.1 v2 Transport | `transport_v2.py` | `Peer` always uses v1 plaintext; `V2Transport` never instantiated |
| D.2 Block Pruning | `pruning.py` | `BlockPruner` operates on dummy files; not called by node or storage |
| D.4 ZMQ | `zmq_publisher.py` | `ZMQPublisher` never instantiated; node never calls `notify_block`/`notify_transaction` |

---

## C.1 — HD Keys: Add RPC Endpoints

**Where to integrate:** `src/ouroboros/rpc.py`

The `HDKey` class and `Wallet.init_hd()` work correctly but no RPC exposes them. Bitcoin Core has `sethdseed` and returns HD metadata in `getwalletinfo`.

### Prompt

```
In src/ouroboros/rpc.py, add two new RPC methods:

1. `rpc_sethdseed(self, seed_hex: str = None)` that:
   - If seed_hex is provided, calls `self.node.wallet.init_hd(bytes.fromhex(seed_hex))`
   - If not provided, generates a random 32-byte seed and passes it to init_hd
   - Returns {"xprv": <xprv_string>, "message": "HD wallet initialized"}

2. Update the existing `rpc_getwalletinfo` to include HD metadata:
   - Add "hd": true/false based on wallet.is_hd
   - Add "hd_next_index": wallet._hd_next_index when HD is enabled
   - Add "hd_master_xpub": wallet.get_hd_master().serialize_xpub() when HD

Import HDKey at the top of rpc.py if needed. Don't modify any existing tests, just add the new RPC methods.
```

---

## C.2 — Encrypted Wallet: Add RPC Endpoints

**Where to integrate:** `src/ouroboros/rpc.py`

Bitcoin Core exposes `encryptwallet`, `walletpassphrase`, `walletpassphrase`, and `walletlock`. Our `Wallet` class already has `encrypt()`, `unlock()`, `lock()`, and `change_passphrase()`.

### Prompt

```
In src/ouroboros/rpc.py, add these RPC methods for wallet encryption:

1. `rpc_encryptwallet(self, passphrase: str)`:
   - Call self.node.wallet.encrypt(passphrase)
   - Return "Wallet encrypted successfully. Restart recommended."
   - Raise RPC error -15 if wallet is already encrypted

2. `rpc_walletpassphrase(self, passphrase: str, timeout: int = 60)`:
   - Call self.node.wallet.unlock(passphrase)
   - Return True on success
   - Raise RPC error -14 on wrong passphrase (catch ValueError)
   - Raise RPC error -15 if wallet is not encrypted

3. `rpc_walletlock(self)`:
   - Call self.node.wallet.lock()
   - Return True
   - Raise RPC error -15 if wallet is not encrypted/unlocked

4. `rpc_walletpassphrasechange(self, old_passphrase: str, new_passphrase: str)`:
   - Call self.node.wallet.change_passphrase(old_passphrase, new_passphrase)
   - Return True on success

Update rpc_getwalletinfo to include "encrypted": wallet.is_encrypted and "locked": wallet.is_locked.
```

---

## C.3 — PSBT: Add RPC Endpoints

**Where to integrate:** `src/ouroboros/rpc.py`

The `PSBT` class supports serialize/deserialize/combine/finalize/extract/decode. Bitcoin Core exposes these as separate RPCs.

### Prompt

```
In src/ouroboros/rpc.py, add PSBT RPC methods. Import PSBT from ouroboros.psbt at the top.

1. `rpc_decodepsbt(self, psbt_base64: str)`:
   - base64-decode the string, call PSBT.deserialize(), then return psbt.decode()

2. `rpc_combinepsbt(self, psbts: List[str])`:
   - Deserialize each base64 PSBT, call combined = first.combine(second) for each
   - Return base64-encoded combined.serialize()

3. `rpc_finalizepsbt(self, psbt_base64: str, extract: bool = True)`:
   - Deserialize, call psbt.finalize()
   - If extract is True and all inputs are finalized, call psbt.extract_transaction()
     and return {"hex": tx.serialize_with_witness().hex(), "complete": True}
   - Otherwise return {"psbt": base64(psbt.serialize()), "complete": False}

4. `rpc_createpsbt(self, inputs: List[Dict], outputs: List[Dict], locktime: int = 0)`:
   - Build a Transaction from the inputs [{"txid": hex, "vout": int}] and
     outputs [{"address": str, "amount": sat_int}]
   - Use address_to_script_pubkey for output scripts
   - Return base64-encoded PSBT.from_transaction(tx).serialize()

Use import base64 at the top. Handle errors with appropriate RPC error codes.
```

---

## D.1 — v2 Transport: Wire Into Peer Connections

**Where to integrate:** `src/ouroboros/peer.py`

The `V2Handshake` and `V2Transport` classes implement the full BIP 324 key exchange and ChaCha20-Poly1305 AEAD encryption. But `Peer.send_message()` and `Peer.receive_message()` always use plaintext v1 framing.

### Prompt

```
In src/ouroboros/peer.py, add optional v2 transport support:

1. Add a `transport_version` parameter to Peer.__init__ (default=1).
   Add self._v2_transport: Optional[V2Transport] = None

2. Add a method `async def _negotiate_v2(self)` that:
   - Creates a V2Handshake(initiator=True)
   - Sends the 64-byte local_pubkey_bytes over the raw socket
   - Reads 64 bytes from the peer (remote pubkey)
   - Calls handshake.receive_remote_pubkey(remote_bytes)
   - Creates self._v2_transport = V2Transport.from_handshake(handshake)
   - Log success

3. In the connect() method, after TCP connection but before version handshake,
   if self.transport_version == 2, call await self._negotiate_v2().
   Wrap in try/except — on failure, log a warning and fall back to v1.

4. In send_message(): if self._v2_transport is not None, encrypt the
   serialized message bytes with self._v2_transport.encrypt_message(data)
   before writing to the socket.

5. In receive_message(): if self._v2_transport is not None, read raw bytes
   and decrypt with self._v2_transport.decrypt_message(data), skipping
   decoy packets (is_decoy=True).

Import V2Handshake, V2Transport from ouroboros.transport_v2.
```

---

## D.2 — Block Pruning: Connect to Real Storage

**Where to integrate:** `src/ouroboros/node.py`, `src/ouroboros/pruning.py`

The current `BlockPruner` operates on dummy `.dat` files. It needs to:
1. Work with the real block storage (Rust backend)
2. Be configurable via `prune=<MB>` in the config
3. Run periodically from the node's main loop

### Prompt

```
Integrate block pruning into the node:

1. In src/ouroboros/node.py:
   - Import BlockPruner from ouroboros.pruning
   - In __init__, add self.pruner: Optional[BlockPruner] = None
   - In start(), after database init, check if self.config.get('prune') is set.
     If so, create self.pruner = BlockPruner(
       data_dir=self.data_dir,
       target_size_mb=int(self.config['prune']),
       keep_blocks=288
     )
   - In _periodic_tasks(), if self.pruner is not None, call:
     _, best_height = self.db.get_best_block()
     removed = self.pruner.prune_to_target(current_height=best_height)
     if removed > 0: logger.info(f"Pruned {removed} old block files")

2. In src/ouroboros/pruning.py, update BlockPruner to use the actual blocks
   directory at {data_dir}/blocks/ rather than requiring it to pre-exist.
   Make sure prune_blocks() and prune_to_target() handle the case where
   the blocks directory doesn't exist yet (return 0, don't crash).

Note: Full integration with the Rust storage layer would require exposing
a prune API from PyBlockchainDB. For now, operating on the block .dat files
in the data directory is sufficient.
```

---

## D.4 — ZMQ Notifications: Wire Into Node Event System

**Where to integrate:** `src/ouroboros/node.py`, `src/ouroboros/mempool.py`, `src/ouroboros/block_sync.py`

The `ZMQPublisher` is fully implemented but the node never instantiates it or calls `notify_block()` / `notify_transaction()`.

### Prompt

```
Wire ZMQ notifications into the node:

1. In src/ouroboros/node.py:
   - Import ZMQPublisher from ouroboros.zmq_publisher
   - In __init__, add self.zmq_publisher: Optional[ZMQPublisher] = None
   - In start(), after RPC server init, check if config has a zmq endpoint:
     zmq_endpoint = self.config.get('zmqpubhashblock') or self.config.get('zmq_endpoint')
     If set:
       self.zmq_publisher = ZMQPublisher(endpoint=zmq_endpoint)
       await self.zmq_publisher.start()
   - In stop(), if self.zmq_publisher: await self.zmq_publisher.stop()

2. In the _register_handlers() method in node.py, in the handle_tx handler,
   after a successful mempool.add_transaction(), call:
     if self.zmq_publisher:
       self.zmq_publisher.notify_transaction(tx)

3. In src/ouroboros/block_sync.py (or wherever new blocks are accepted),
   after a block is validated and stored, add:
     if hasattr(self, '_zmq_publisher') and self._zmq_publisher:
       self._zmq_publisher.notify_block(block)
   
   Alternatively, add a set_zmq_publisher(pub) method to BlockSync and
   call it from node.py after creating the ZMQPublisher. This avoids
   modifying BlockSync's constructor.

The ZMQPublisher gracefully no-ops if not started, so these calls are
safe even when ZMQ is not configured.
```

---

## Integration Order

Recommended order (easiest to hardest):

1. **D.4 ZMQ** — Simplest: just instantiate + call two methods
2. **C.2 Encrypted Wallet RPCs** — Thin RPC wrappers around existing methods
3. **C.1 HD Keys RPCs** — Two new RPCs + getwalletinfo update
4. **C.3 PSBT RPCs** — Four new RPCs with some serialization glue
5. **D.2 Block Pruning** — Node integration + config parsing
6. **D.1 v2 Transport** — Most complex: modifies the core send/receive path

---

## Verification

After each integration, run the full test suite:

```bash
python3 -m pytest tests/test_integration.py -v --tb=short
```

All 163 existing tests should continue to pass. New integration tests can be added to verify the RPC endpoints respond correctly.
