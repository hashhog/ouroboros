# Bitcoin Full Node in Erlang – Implementation Guide

A phased implementation guide for a Bitcoin P2P full node in Erlang, synthesizing Ouroboros (Rust/Python), Bitcoin Core (C++), and lessons learned from building and debugging Ouroboros on testnet4.

**References:**
- Ouroboros: `../ferrous-utils/sync/`, `../src/ouroboros/`
- Bitcoin Core: `../bitcoin/src/`
- Sync analysis: `../SYNC_ANALYSIS_20260213.md`, `../BLOCK_SYNC_DEBUGGING_GUIDE.md`
- Verification: `../TESTNET4_VERIFICATION_GUIDE.md`, `../scripts/compare_block_hashes.py`

---

## 1. Strategy Overview

### 1.1 Phased Approach

1. **Headers-first sync** – Download all block headers, validate PoW and chain link, store height→hash.
2. **Block sync** – Fill queue with missing heights, request blocks from peers in parallel.
3. **Peer management** – Maintain N outbound connections, re-queue on disconnect, handle desync.

### 1.2 Key Lessons from Ouroboros

| Lesson | Ouroboros experience | Erlang implication |
|--------|----------------------|--------------------|
| **PoW hash order** | Must use little-endian (internal) for target comparison; `from_big_endian` was wrong | Use Bitcoin internal byte order for PoW; display hex reverses bytes |
| **Per-peer cap** | 16 blocks in-flight per peer; 128 total overloads few peers → timeouts | Cap requests per peer; don't overload one slow peer |
| **Avoid failed peer** | When block times out, don't re-assign to same peer; breaks retry loop | Track (height → failed_peer); exclude on re-queue |
| **Testnet4 stalls** | Both Ouroboros and Bitcoin Core stall around block 50k on testnet4 | Expect bursts and stalls; network characteristic, not implementation bug |
| **Desync recovery** | PayloadSizeExceeded, InvalidMagic → blacklist; optional magic-byte resync | Implement PEQUOD_TRY_RESYNC; scan for magic before disconnect |
| **Large blocks** | 120–180s timeout for blocks; some blocks are multi-MB | Configurable block receive timeout; don't assume fast delivery |
| **Diagnostic mode** | `OUROBOROS_SYNC_DIAG=1` logs peer count, in-flight, queue every 60s | Add similar for debugging peer exhaustion |

### 1.3 Bitcoin Core Source Map

| Component | Bitcoin Core path | Ouroboros equivalent |
|-----------|-------------------|----------------------|
| Message header | `protocol.h` CMessageHeader, `protocol.cpp` | `messages.rs` |
| Version/Verack | `net.cpp` V1TransportDeserializer, `net_processing.cpp` | `peer.rs`, `messages.rs` |
| GetHeaders/Headers | `net_processing.cpp`, `protocol.h` NetMsgType | `header_sync.rs`, `messages.rs` |
| GetData/Block | `net_processing.cpp` ProcessGetData, ProcessBlock | `block_sync.rs`, `messages.rs` |
| Peer connection | `net.cpp` CNode, V1Transport | `peer.rs`, `peer_manager.rs` |
| Chain params | `kernel/chainparams.cpp` | `chain_params.rs` |
| PoW validation | `pow.cpp` CheckProofOfWork | `validate/pow.rs` |
| Block storage | `node/blockstorage.cpp`, LevelDB | `storage/db.rs` RocksDB |

---

## 2. Architecture

### 2.1 Erlang Supervision Tree

```
pequod_sup
├── pequod_chain_sup
│   ├── pequod_db              % Blocks, block_index (height→hash), meta
│   └── pequod_chainstate       % Best block, tip
├── pequod_peer_sup
│   ├── pequod_peer_manager     % Seeds, drain_peers, maintain N connections
│   └── pequod_peer_worker_1..N % gen_statem per connection
├── pequod_header_sync          % Headers-first coordinator
└── pequod_block_sync           % Block download coordinator
```

### 2.2 Block Sync Flow (from Ouroboros)

1. Fill queue with heights 0..tip (skip existing).
2. Assign up to `max_in_flight` (e.g. 32) to peers, max 16 per peer.
3. Per-peer gen_statem: receive block → send to coordinator.
4. Coordinator: store block, remove from in-flight, assign next.
5. Timeout: re-queue, record failed peer, assign to different peer.
6. Peer disconnect: re-queue all in-flight for that peer.

---

## 3. Protocol Specification (P2P Messages)

### 3.1 Message Frame (24-byte header)

| Field | Size | Endian | Notes |
|-------|------|--------|-------|
| Magic | 4 | LE | Network ID |
| Command | 12 | — | Null-padded ASCII |
| Payload size | 4 | LE | Max 4MB (sanity), 32MB (protocol) |
| Checksum | 4 | LE | First 4 bytes of SHA256(SHA256(payload)) |

**Reference:** `bitcoin/src/protocol.h` CMessageHeader, `ouroboros/ferrous-utils/sync/src/network/messages.rs`.

### 3.2 Core Messages (minimum for sync)

| Command | Direction | Purpose |
|---------|-----------|---------|
| version | Both | Handshake |
| verack | Both | Connection ready |
| getheaders | Out | Request headers from locator |
| headers | In | Block headers (up to 2000) |
| getdata | Out | Request blocks by inventory |
| block | In | Full block |
| inv | Both | Inventory announcement |
| ping/pong | Both | Keepalive |

### 3.3 Network Parameters (Testnet4)

**Reference:** `bitcoin/src/kernel/chainparams.cpp` (lines 347–383).

```erlang
% Magic bytes (LE): 0x1c, 0x16, 0x3f, 0x28 → 0x283f161c as 32-bit LE
-define(MAGIC_TESTNET4, <<16#1c, 16#16, 16#3f, 16#28>>).
-define(MAGIC_MAINNET,  <<16#f9, 16#be, 16#b4, 16#d9>>).
-define(MAGIC_TESTNET,  <<16#0b, 16#11, 16#09, 16#07>>).
-define(PORT_TESTNET4,  48333).
-define(PORT_MAINNET,   8333).
-define(PROTOCOL_VERSION, 70015).
```

### 3.4 Genesis Block (Testnet4)

**Reference:** `bitcoin/src/kernel/chainparams.cpp` line 356–361.

```erlang
% Genesis timestamp
-define(GENESIS_TIMESTAMP_TESTNET4, 1714777860).

% Genesis hash (internal/LE, 32 bytes) – from ouroboros chain_params.rs
% Display format: reverse bytes, then hex
-define(GENESIS_HASH_TESTNET4,
    <<16#43, 16#f0, 16#8b, 16#da, 16#b0, 16#50, 16#e3, 16#5b,
      16#56, 16#7c, 16#86, 16#4b, 16#91, 16#f4, 16#7f, 16#50,
      16#ae, 16#72, 16#5a, 16#e2, 16#de, 16#53, 16#bc, 16#fb,
      16#ba, 16#f2, 16#84, 16#da, 16#00, 16#00, 16#00, 16#00>>).
```

### 3.5 Seeds (Testnet4)

**Reference:** `bitcoin/src/kernel/chainparams.cpp` vSeeds, `contrib/seeds/`.

DNS: `seed.testnet4.bitcoin.sprovoost.nl`, `seed.testnet4.wiz.biz`

Hardcoded IPv4 (from Ouroboros runs): `51.158.61.33`, `35.201.167.154`, `103.165.192.211`, `103.99.170.202`, `54.76.27.166`, `168.119.150.247`, `103.99.168.213`, `158.220.90.103`, `209.146.50.203`, `18.189.156.102`, `208.73.202.78`, `103.165.192.210`.

---

## 4. Implementation Phases

### Phase 1: Project Skeleton and Message Serialization

**Goal:** Erlang app with message header encode/decode and checksum.

**Deliverables:** Rebar3 `pequod`, `pequod_protocol`, `pequod_checksum`, unit tests.

### Phase 2: TCP Connection and Version Handshake

**Goal:** Connect, version/verack handshake, peer in `ready` state.

**Deliverables:** `pequod_peer` gen_statem, version/verack serialization.

### Phase 3: Header Sync (Headers-First)

**Goal:** Download all headers via getheaders/headers, validate, store.

**Deliverables:** `pequod_getheaders`, `pequod_headers`, `pequod_header_sync`, PoW validation.

**Note:** Sequential (2000/request); each batch depends on previous. Ouroboros: ~1,200 headers/s.

### Phase 4: Block Sync and Storage

**Goal:** Download blocks in parallel, validate minimally, store.

**Deliverables:** `pequod_getdata`, block parse, `pequod_block_sync`, storage backend.

**Note:** Per-peer cap 16, max in-flight 32–64, timeout 120s. Avoid re-assigning to failed peer.

### Phase 5: Peer Manager and Robustness

**Goal:** Maintain peers, handle disconnect, desync recovery.

**Deliverables:** `pequod_peer_manager`, seeds, re-queue on disconnect, blacklist, optional resync.

### Phase 6: Verification Against Bitcoin Core

**Goal:** Compare block hashes at sampled heights.

**Deliverables:** Script or manual step using `../scripts/compare_block_hashes.py` pattern (Bitcoin Core + Pequod data dirs).

---

## 5. Cursor Prompts (Copy-Paste Ready)

### Prompt 5.1: Project Skeleton and Protocol

```
Create a Rebar3 Erlang application "pequod" in the pequod directory:

1. rebar.config: app pequod, deps []
2. src/pequod_app.erl, src/pequod_sup.erl – basic supervision
3. src/pequod_protocol.erl:
   - get_magic(testnet4) -> <<16#1c, 16#16, 16#3f, 16#28>>
   - encode_header(Magic, Command, Payload) -> binary()  % 24 bytes: magic(4) + command(12 null-pad) + size(4) + checksum(4)
   - decode_header(Binary) -> {ok, Magic, Command, Size, Checksum} | {error, Reason}
   - Checksum = first 4 bytes of crypto:hash(sha256, crypto:hash(sha256, Payload))
4. Reference: ../bitcoin/src/protocol.h CMessageHeader, ../ferrous-utils/sync/src/network/messages.rs
5. Unit test: encode/decode round-trip
```

### Prompt 5.2: Version and Verack

```
Add Bitcoin P2P handshake messages to pequod:

1. src/pequod_version.erl:
   - version_message(Version, Services, Timestamp, AddrRecv, AddrFrom, UserAgent, StartHeight, Relay) -> binary()
   - Fields LE: version(4), services(8), timestamp(8), addr_recv(26), addr_from(26), nonce(8), varint(user_agent_len), user_agent, start_height(4), relay(1) for 70001+
2. verack: empty payload (24-byte header only, size 0)
3. Handshake: send version -> receive version -> send verack -> receive verack -> ready
4. Ref: ../bitcoin/src/protocol.h, ../ferrous-utils/sync/src/network/messages.rs VersionMessage
```

### Prompt 5.3: Peer Connection gen_statem

```
Create src/pequod_peer.erl gen_statem for a single Bitcoin P2P connection:

1. States: connecting | version_sent | handshaking | ready | closed
2. On start: gen_tcp:connect, send version, → version_sent
3. On version: send verack, wait verack, → ready
4. In ready: handle message frames: read 24-byte header (pequod_protocol:decode_header), read Payload, verify checksum, dispatch by command
5. Use {active, once} to avoid mailbox overflow on large blocks
6. On TCP error/closed: → closed, notify parent (peer_manager)
7. Ref: ../ferrous-utils/sync/src/network/peer.rs
```

### Prompt 5.4: GetHeaders and Headers

```
Add header sync messages:

1. src/pequod_getheaders.erl:
   - encode(Version, LocatorHashes, HashStop) -> binary()
   - Format: version(4) + varint(count) + count*32 + hash_stop(32)
2. src/pequod_headers.erl:
   - parse(Binary) -> {ok, [Header80Bytes]}
   - varint(count) + count * (80-byte header + varint tx_count=0)
3. Ref: ../bitcoin/src/protocol.h GETHEADERS/HEADERS, ../ferrous-utils/sync/src/network/header_sync.rs
```

### Prompt 5.5: Header Sync Coordinator

```
Create src/pequod_header_sync.erl:

1. gen_server: get peer from pequod_peer_manager, send getheaders with locator [genesis_hash], hash_stop=0
2. On headers: validate each (PoW, prev_hash chain, timestamp), store in pequod_db
3. If count=2000: locator = last few hashes, getheaders again
4. PoW: hash must be <= target from bits. Use little-endian for hash comparison (ref: ../ferrous-utils/sync/src/validate/pow.rs – from_little_endian)
5. Ref: ../ferrous-utils/sync/src/network/header_sync.rs
```

### Prompt 5.6: Block Sync with Per-Peer Cap

```
Add block download:

1. src/pequod_getdata.erl: encode([{type, hash}]) where type=2 for block
2. src/pequod_block.erl: parse(Binary) -> {ok, #{header => <<80>>, txs => [TxBin]}}
3. src/pequod_block_sync.erl gen_server:
   - Queue of heights to fetch
   - Assign up to max_in_flight (32) to peers, max 16 per peer
   - On block: validate (hash, prev), store, remove from in-flight
   - On timeout: re-queue, record failed peer for that height, assign to different peer
   - On peer disconnect: re-queue all in-flight for that peer
4. Config: PEQUOD_MAX_IN_FLIGHT, PEQUOD_IN_FLIGHT_TIMEOUT_SECS, PEQUOD_BLOCK_RECEIVE_TIMEOUT_SECS
5. Ref: ../ferrous-utils/sync/src/network/block_sync.rs
```

### Prompt 5.7: Peer Manager and Seeds

```
Create src/pequod_peer_manager.erl:

1. gen_server: maintain list of connected peers (pequod_peer Pids)
2. Seeds: DNS (seed.testnet4.bitcoin.sprovoost.nl:48333, seed.testnet4.wiz.biz:48333) or hardcoded IPv4 from ../pequod/BITCOIN_ERLANG_IMPLEMENTATION_GUIDE.md
3. drain_peers/0 -> [{Addr, Pid}] for ready peers
4. maintain_connections/0: ensure >= N (e.g. 8) connections
5. On peer exit: remove, blacklist for T sec on desync (PEQUOD_DESYNC_BLACKLIST_SECS)
6. Ref: ../ferrous-utils/sync/src/network/peer_manager.rs
```

### Prompt 5.8: Desync Recovery

```
Handle stream desync (InvalidMagic, PayloadSizeExceeded):

1. Payload size sanity: if Size > 4*1024*1024, treat as desync
2. On invalid magic: if PEQUOD_TRY_RESYNC=1, scan buffer for 4-byte magic before disconnect
3. Blacklist peer on desync; shorter blacklist = faster recovery (PEQUOD_DESYNC_BLACKLIST_SECS=30)
4. Ref: ../BLOCK_SYNC_DEBUGGING_GUIDE.md, ../ferrous-utils/sync/src/network/peer.rs
```

### Prompt 5.9: Storage Backend

```
Add src/pequod_db.erl:

1. ETS or dets: blocks (hash->block), block_index (height->hash), meta (best_hash, best_height)
2. API: put_block/2, get_block/1, get_block_hash_by_height/1, get_best_block/0, set_best_block/2
3. Optional: RocksDB via erlang-rocksdb
4. Ref: ../ferrous-utils/sync/src/storage/
```

### Prompt 5.10: Main Sync and CLI

```
Create src/pequod_sync.erl and CLI:

1. sync(Network) -> start peer_manager, header_sync, block_sync, loop until done
2. CLI: pequod sync testnet4 --data-dir .pequod-testnet4
3. Progress logging: blocks received, rate, ETA (cap at 999h when speed near 0)
4. PEQUOD_SYNC_DIAG=1: log peer count, in-flight, queue every 60s
```

---

## 6. Verification Strategy

### 6.1 Correctness

1. Sync Pequod on testnet4.
2. Sync Bitcoin Core on testnet4 (or use existing).
3. Compare block hashes at heights 0, 1000, 10000, 50000, 100000, tip.
4. Pequod must expose `get_block_hash_by_height/1`; normalize to display hex (reverse bytes, hex).

### 6.2 Speed Comparison

- Ouroboros and Bitcoin Core both stall around 50k on testnet4; expect similar for Pequod.
- Target: Pequod within ~2–5× of Bitcoin Core. Measure with timing logs.

### 6.3 Diagnostic Env Vars (from Ouroboros)

| Variable | Default | Purpose |
|----------|---------|---------|
| PEQUOD_MAX_IN_FLIGHT | 32 | Max concurrent block requests |
| PEQUOD_IN_FLIGHT_TIMEOUT_SECS | 120 | Re-queue timeout |
| PEQUOD_BLOCK_RECEIVE_TIMEOUT_SECS | 180 | Per-block receive timeout |
| PEQUOD_DESYNC_BLACKLIST_SECS | 30 | Blacklist duration on desync |
| PEQUOD_TRY_RESYNC | 0 | 1 = scan for magic before disconnect |
| PEQUOD_SYNC_DIAG | 0 | 1 = log peer/in-flight/queue every 60s |

---

## 7. Implementation Order

1. **5.1** – Skeleton, protocol header
2. **5.2** – Version/Verack
3. **5.3** – Peer gen_statem, handshake
4. **5.4** – GetHeaders, Headers
5. **5.5** – Header sync
6. **5.9** – Storage (ETS first)
7. **5.6** – Block sync (with per-peer cap, avoid failed peer)
8. **5.7** – Peer manager
9. **5.8** – Desync handling
10. **5.10** – Main sync, CLI, diagnostics

---

## 8. Erlang-Specific Notes

- **Binaries:** `<<Magic:4/binary, Command:12/binary, Size:32/little, Checksum:4/binary>>` for header.
- **Active mode:** Use `{active, once}`; read header then payload for large blocks.
- **Supervision:** Restart peers on crash; peer_manager respawns.
- **Logging:** logger; avoid per-block debug logs.
- **Config:** `application:get_env(pequod, network, testnet4)`.

---

## 9. Testnet4 Quick Reference

| Item | Value |
|------|-------|
| Port | 48333 |
| Magic | <<16#1c, 16#16, 16#3f, 16#28>> (LE) |
| Protocol version | 70015 |
| Genesis timestamp | 1714777860 |
| Headers per request | 2000 (Bitcoin max) |
| Block sanity size | 4 MB |
| Seeds | seed.testnet4.bitcoin.sprovoost.nl, seed.testnet4.wiz.biz |

---

## 10. Ouroboros Documents to Cross-Reference

| Document | Use |
|----------|-----|
| SYNC_ANALYSIS_20260213.md | Bottlenecks, tuning, per-peer cap |
| BLOCK_SYNC_DEBUGGING_GUIDE.md | Env vars, common issues, debugging steps |
| GAPS_AND_FIXES_GUIDE.md | PoW validation, SegWit, chainwork |
| TESTNET4_VERIFICATION_GUIDE.md | Correctness comparison workflow |
| scripts/compare_block_hashes.py | Block hash comparison logic |
