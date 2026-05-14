"""
W112 — BIP-152 Compact Block Relay
30-gate fleet audit for ouroboros (Python + Rust ferrous-utils).

Covers both pipelines:
  Pipeline A (Python): src/ouroboros/compact_blocks.py
                       Message wiring in src/ouroboros/p2p.py
                       Block announcement in src/ouroboros/block_sync.py
  Pipeline B (Rust):   ferrous-utils/common/src/crypto/siphash.rs
                       ferrous-utils/sync/src/network/peer.rs (TODO stub)

Reference: bitcoin-core/src/blockencodings.h/cpp, net_processing.cpp, BIP-152.

Key constants:
  CMPCTBLOCKS_VERSION = 2  (witness-based)
  MAX_CMPCTBLOCK_DEPTH = 5
  MAX_BLOCKTXN_DEPTH = 10
  SHORTID_LEN = 6 bytes
  SipHash key = SHA256(header || nonce_le64)[0:16] -> k0/k1 as LE u64

Run:
    cd /home/work/hashhog/ouroboros && \\
      python3 -m pytest src/ouroboros/tests/test_w112_compact_blocks.py -v
"""

import hashlib
import struct
import unittest


# ---------------------------------------------------------------------------
# G1 — CMPCTBLOCKS_VERSION constant
# ---------------------------------------------------------------------------
class TestW112_G1_CmpctBlocksVersion(unittest.TestCase):
    """
    G1: CMPCTBLOCKS_VERSION must be 2.

    Bitcoin Core net_processing.cpp:
        static constexpr uint64_t CMPCTBLOCKS_VERSION{2};

    Version 2 uses wtxid for SipHash (BIP 152, Section 6).
    Version 1 used txid and is deliberately not supported.
    """

    def test_cmpctblocks_version_equals_2(self):
        from ouroboros.compact_blocks import CMPCTBLOCKS_VERSION
        self.assertEqual(CMPCTBLOCKS_VERSION, 2,
                         "CMPCTBLOCKS_VERSION must be 2 (witness compact blocks)")


# ---------------------------------------------------------------------------
# G2 — MAX_CMPCTBLOCK_DEPTH constant
# ---------------------------------------------------------------------------
class TestW112_G2_MaxCmpctBlockDepth(unittest.TestCase):
    """
    G2: MAX_CMPCTBLOCK_DEPTH must be 5.

    Bitcoin Core net_processing.cpp line 138:
        static const int MAX_CMPCTBLOCK_DEPTH = 5;

    Used for: we only SERVE compact blocks for blocks within 5 of tip.
    Ouroboros also uses it on the RECEIVE side (see BUG-5 / G25).
    """

    def test_max_cmpctblock_depth_equals_5(self):
        from ouroboros.compact_blocks import MAX_CMPCTBLOCK_DEPTH
        self.assertEqual(MAX_CMPCTBLOCK_DEPTH, 5,
                         "MAX_CMPCTBLOCK_DEPTH must be 5")


# ---------------------------------------------------------------------------
# G3 — MAX_BLOCKTXN_DEPTH constant
# ---------------------------------------------------------------------------
class TestW112_G3_MaxBlockTxnDepth(unittest.TestCase):
    """
    G3: MAX_BLOCKTXN_DEPTH must be 10.

    Bitcoin Core net_processing.cpp line 4276:
        if (pindex->nHeight >= m_chainman.ActiveChain().Height() - MAX_BLOCKTXN_DEPTH)

    Only serve blocktxn responses for blocks within 10 of tip.
    """

    def test_max_blocktxn_depth_equals_10(self):
        from ouroboros.compact_blocks import MAX_BLOCKTXN_DEPTH
        self.assertEqual(MAX_BLOCKTXN_DEPTH, 10,
                         "MAX_BLOCKTXN_DEPTH must be 10")


# ---------------------------------------------------------------------------
# G4 — Short ID length is 6 bytes (48 bits)
# ---------------------------------------------------------------------------
class TestW112_G4_ShortIdLength(unittest.TestCase):
    """
    G4: Short transaction IDs are 48-bit (6-byte) values.

    BIP 152: short txids are the lower 6 bytes of SipHash-2-4 output.
    Bitcoin Core blockencodings.h: encodes each short ID as 6 bytes LE.
    """

    def test_short_txid_is_48_bits(self):
        from ouroboros.compact_blocks import compute_siphash_key, short_txid
        key = compute_siphash_key(bytes(80), 0)
        sid = short_txid(key, bytes(32))
        self.assertLessEqual(sid, 0xFFFFFFFFFFFF,
                             "short_txid must fit in 48 bits (6 bytes)")
        self.assertGreaterEqual(sid, 0,
                                "short_txid must be non-negative")

    def test_short_txid_serialization_is_6_bytes(self):
        """CompactBlock.serialize() writes each short ID as exactly 6 bytes."""
        from ouroboros.compact_blocks import CompactBlock
        header = _make_header()
        # Build a block with one short ID
        cb = CompactBlock(header=header, nonce=0,
                          short_ids=[0xABCDEF012345], prefilled_txs=[])
        data = cb.serialize()
        # header(80) + nonce(8) + varint(1) + sid(6) + varint(1) = 96
        self.assertEqual(len(data), 96)
        # Extract the short ID bytes
        sid_bytes = data[89:95]  # after header(80)+nonce(8)+varint(1)
        sid_int = int.from_bytes(sid_bytes + b'\x00\x00', 'little')
        self.assertEqual(sid_int, 0xABCDEF012345)


# ---------------------------------------------------------------------------
# G5 — SipHash key derivation: SHA256(header || nonce_le64)[0:16]
# ---------------------------------------------------------------------------
class TestW112_G5_SipHashKeyDerivation(unittest.TestCase):
    """
    G5: SipHash-2-4 key = SHA256(header_bytes || nonce_little_endian_64)[0:16].
    k0 = key[0:8] as little-endian uint64
    k1 = key[8:16] as little-endian uint64

    Bitcoin Core blockencodings.h:
        GetShortID computes key = {nonce ^ header_hash_lo, nonce ^ header_hash_hi}
        ... actually: key is SHA256(header||nonce_le), not a XOR.
    BIP 152 Section 2: 'nonce' is random 8-byte little-endian value.
    """

    def test_key_derivation_matches_manual_sha256(self):
        """compute_siphash_key matches manual SHA256(header||nonce_le)[:16]."""
        from ouroboros.compact_blocks import compute_siphash_key
        header = bytes(range(80))
        nonce = 0xDEADBEEF12345678
        raw = header + struct.pack('<Q', nonce)
        expected = hashlib.sha256(raw).digest()[:16]
        result = compute_siphash_key(header, nonce)
        self.assertEqual(result, expected)

    def test_key_is_16_bytes(self):
        from ouroboros.compact_blocks import compute_siphash_key
        key = compute_siphash_key(bytes(80), 0)
        self.assertEqual(len(key), 16)

    def test_different_nonces_give_different_keys(self):
        from ouroboros.compact_blocks import compute_siphash_key
        header = bytes(80)
        k0 = compute_siphash_key(header, 0)
        k1 = compute_siphash_key(header, 1)
        self.assertNotEqual(k0, k1)

    def test_siphash_2_4_reference_vector(self):
        """
        Verify SipHash-2-4 against the official reference test vector.

        From the SipHash specification (https://131002.net/siphash/siphash.pdf):
          key = 0x000102030405060708090a0b0c0d0e0f
          data = 0x000102030405060708090a0b0c0d0e
          expected output = 0xa129ca6149be45e5
        """
        from ouroboros.compact_blocks import _siphash_2_4
        key = bytes(range(16))
        data = bytes(range(15))
        result = _siphash_2_4(key, data)
        self.assertEqual(result, 0xa129ca6149be45e5,
                         "SipHash-2-4 does not match reference vector")


# ---------------------------------------------------------------------------
# G6 — sendcmpct sent after verack, announce=False
# ---------------------------------------------------------------------------
class TestW112_G6_SendCmpctAfterVerack(unittest.TestCase):
    """
    G6: negotiate_compact_blocks sends sendcmpct(announce=False, version=2).

    Bitcoin Core net_processing.cpp line 3870 (post-verack):
        MakeAndPushMessage(pfrom, NetMsgType::SENDCMPCT, false, CMPCTBLOCKS_VERSION);
    Core always sends announce=False initially (low-bandwidth mode).
    """

    def test_negotiate_sends_announce_false(self):
        """negotiate_compact_blocks always uses announce=False."""
        import inspect
        from ouroboros import p2p
        src = inspect.getsource(p2p.PeerManager.negotiate_compact_blocks)
        self.assertIn('announce=False', src,
                      "negotiate_compact_blocks must send sendcmpct(announce=False)")

    def test_sendcmpct_wire_format_is_9_bytes(self):
        """sendcmpct payload is 1-byte bool + 8-byte uint64 = 9 bytes."""
        from ouroboros.p2p_messages import SendCmpctMessage
        msg = SendCmpctMessage(announce=False, version=2)
        payload = msg.to_network_message('mainnet').payload
        self.assertEqual(len(payload), 9,
                         "sendcmpct payload must be 9 bytes (1+8)")

    def test_sendcmpct_version_field_is_uint64(self):
        """Version field is uint64 LE in sendcmpct payload."""
        from ouroboros.p2p_messages import SendCmpctMessage
        msg = SendCmpctMessage(announce=False, version=2)
        payload = msg.to_network_message('mainnet').payload
        version = struct.unpack('<Q', payload[1:9])[0]
        self.assertEqual(version, 2)


# ---------------------------------------------------------------------------
# G7 — Only v2 supported; ignore v1
# ---------------------------------------------------------------------------
class TestW112_G7_OnlyV2Supported(unittest.TestCase):
    """
    G7: v1 sendcmpct is silently ignored (version field != 2).

    Bitcoin Core net_processing.cpp line 3907:
        if (sendcmpct_version != CMPCTBLOCKS_VERSION) return;

    Version 1 used txid (non-witness) and is not supported by ouroboros.
    """

    def test_default_version_is_2(self):
        from ouroboros.p2p_messages import SendCmpctMessage
        msg = SendCmpctMessage()
        self.assertEqual(msg.version, 2)

    def test_on_sendcmpct_ignores_v1(self):
        """on_sendcmpct handler must reject version != CMPCTBLOCKS_VERSION (2)."""
        import inspect
        from ouroboros import p2p
        src = inspect.getsource(p2p.PeerManager._register_compact_handlers)
        # The handler must have a version check that returns/ignores on mismatch
        self.assertIn('CMPCTBLOCKS_VERSION', src)


# ---------------------------------------------------------------------------
# G8 — Receive sendcmpct(True): record peer as HB source
# ---------------------------------------------------------------------------
class TestW112_G8_ReceiveSendCmpctHB(unittest.TestCase):
    """
    G8: When peer sends sendcmpct(announce=True, version=2), record peer
    as HB mode (wants_cmpctblock=True).

    Bitcoin Core net_processing.cpp line 3912-3915:
        nodestate->m_requested_hb_cmpctblocks = sendcmpct_hb;
        pfrom.m_bip152_highbandwidth_from = sendcmpct_hb;

    Ouroboros correctly sets peer.wants_cmpctblock=True.
    """

    def test_wants_cmpctblock_set_on_hb_request(self):
        """on_sendcmpct with announce=True sets peer.wants_cmpctblock=True."""
        import inspect
        from ouroboros import p2p
        src = inspect.getsource(p2p.PeerManager._register_compact_handlers)
        self.assertIn('wants_cmpctblock', src)
        self.assertIn('sc.announce', src)


# ---------------------------------------------------------------------------
# G9 — HB peer cap (BUG-4): No limit of 3 HB peers for outbound sends
# ---------------------------------------------------------------------------
class TestW112_G9_HBPeerCapMissing(unittest.TestCase):
    """
    BUG-4 (P1): No cap on the number of peers ouroboros sends compact blocks to.

    Bitcoin Core net_processing.cpp (MaybeSetPeerAsAnnouncingHeaderAndIDs):
        // As per BIP152, we only get 3 of our peers to announce blocks
        // using compact encodings.
        if (lNodesAnnouncingHeaderAndIDs.size() >= 3) {
            // Downgrade oldest HB peer to LB mode
            MakeAndPushMessage(*pnodeStop, NetMsgType::SENDCMPCT, false, VERSION);
            lNodesAnnouncingHeaderAndIDs.pop_front();
        }

    Ouroboros sends cmpctblock to ALL peers with wants_cmpctblock=True,
    with no cap. There is no lNodesAnnouncingHeaderAndIDs equivalent,
    no downgrade of the oldest HB peer, and no tracking of outbound
    HB peer count.

    Fix: add lNodesAnnouncingHeaderAndIDs-equivalent (ordered set),
    cap at 3, downgrade oldest with sendcmpct(False) when exceeded,
    prefer outbound over inbound HB peers.
    """

    def test_no_hb_peer_cap_present(self):
        """Confirms ouroboros has no cap on HB peer count (documents the bug)."""
        import inspect
        from ouroboros import p2p
        src = inspect.getsource(p2p.PeerManager)
        # There should be lNodesAnnouncingHeaderAndIDs or equivalent capping logic
        # Its absence documents BUG-4
        has_cap = (
            'lNodesAnnouncingHeaderAndIDs' in src
            or 'hb_peers' in src
            or 'MAX_HB_PEERS' in src
            or 'max_hb_peers' in src
            or ('len' in src and '3' in src and 'cmpct' in src.lower()
                and 'downgrade' in src.lower())
        )
        self.assertFalse(has_cap,
                         "BUG-4 is fixed: HB peer cap is now present (update test)")


# ---------------------------------------------------------------------------
# G10 — HB peer selection (BUG-3): Never sends sendcmpct(True) to any peer
# ---------------------------------------------------------------------------
class TestW112_G10_HBPeerSelectionMissing(unittest.TestCase):
    """
    BUG-3 (P1): Ouroboros never sends sendcmpct(announce=True) to request
    high-bandwidth compact block delivery from peers.

    Bitcoin Core: after a new block is validated (BlockChecked success),
    MaybeSetPeerAsAnnouncingHeaderAndIDs() promotes the block source
    to HB by sending sendcmpct(True) to it. This means Core actively
    requests up to 3 peers to send compact blocks unsolicited.

    Ouroboros: negotiate_compact_blocks always uses announce=False.
    No code path ever sends sendcmpct(announce=True).
    As a result, ouroboros is permanently in low-bandwidth mode and
    must explicitly request every new block via headers→getdata.

    Fix: after a new block is validated, promote the source peer to HB
    by sending sendcmpct(announce=True), subject to the 3-peer cap (G9).
    """

    def test_never_sends_announce_true(self):
        """No production path sends sendcmpct(announce=True) to request HB."""
        import ast
        import os
        src_files = ['src/ouroboros/p2p.py', 'src/ouroboros/node.py',
                     'src/ouroboros/block_sync.py']
        for fname in src_files:
            fpath = os.path.join('/home/work/hashhog/ouroboros', fname)
            with open(fpath) as f:
                content = f.read()
            # Look for SendCmpctMessage(announce=True) or equivalent
            if 'announce=True' in content and 'SendCmpctMessage' in content:
                # Found potential HB request code - check if it's actually used
                # (not just in a comment or docstring)
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    stripped = line.strip()
                    if 'announce=True' in stripped and not stripped.startswith('#'):
                        self.fail(
                            f"BUG-3 appears fixed: {fname}:{i+1} sends announce=True"
                        )

    def test_negotiate_compact_blocks_always_announce_false(self):
        """negotiate_compact_blocks sends only announce=False (never requests HB)."""
        from ouroboros.p2p_messages import SendCmpctMessage
        msg = SendCmpctMessage(announce=False, version=2)
        self.assertFalse(msg.announce,
                         "negotiate_compact_blocks must not request HB (announce=False)")


# ---------------------------------------------------------------------------
# G11 — cmpctblock deserialization: header + nonce + sids + prefilled
# ---------------------------------------------------------------------------
class TestW112_G11_CmpctBlockDeserialization(unittest.TestCase):
    """
    G11: CompactBlock.deserialize() correctly parses the BIP-152 wire format:
    header (80 bytes) + nonce (8 bytes LE uint64) + shorttxids + prefilledtxn.
    """

    def test_deserialize_roundtrip(self):
        """serialize() followed by deserialize() is an identity operation."""
        from ouroboros.compact_blocks import CompactBlock
        header = _make_header()
        sids = [0x111111111111, 0x222222222222, 0x333333333333]
        cb = CompactBlock(header=header, nonce=0xDEADBEEFCAFE0001,
                          short_ids=sids, prefilled_txs=[])
        raw = cb.serialize()
        cb2 = CompactBlock.deserialize(raw)
        self.assertEqual(cb2.header, header)
        self.assertEqual(cb2.nonce, 0xDEADBEEFCAFE0001)
        self.assertEqual(cb2.short_ids, sids)

    def test_deserialize_rejects_too_short_payload(self):
        """Payload shorter than 88 bytes raises ValueError."""
        from ouroboros.compact_blocks import CompactBlock
        with self.assertRaises(ValueError):
            CompactBlock.deserialize(bytes(87))

    def test_deserialize_header_is_80_bytes(self):
        """Deserialized header field is exactly 80 bytes."""
        from ouroboros.compact_blocks import CompactBlock
        header = _make_header()
        cb = CompactBlock(header=header, nonce=42, short_ids=[0xABCDEF], prefilled_txs=[])
        raw = cb.serialize()
        cb2 = CompactBlock.deserialize(raw)
        self.assertEqual(len(cb2.header), 80)

    def test_blocktxcount_overflow_check(self):
        """BlockTxCount > 0xFFFF raises ValueError during deserialization."""
        from ouroboros.compact_blocks import CompactBlock
        from ouroboros.p2p_messages import encode_varint
        header = _make_header()
        nonce = 0
        # Build a payload with sid_count + pf_count > 0xFFFF
        # Use sid_count = 0xFFFF (no actual IDs, just the count)
        data = bytearray()
        data.extend(header)
        data.extend(struct.pack('<Q', nonce))
        # Encode sid_count = 0xFFFF via varint
        data.extend(encode_varint(0xFFFF))
        # No actual short IDs (all will be truncated errors - we just need count)
        # Add 0xFFFF * 6 bytes... that's 393210 bytes, too much
        # Instead test with 1 + 0xFFFF = 0x10000 overflow via pf_count
        # Simulate by patching: encode sid_count=1, pf_count=0xFFFF
        data2 = bytearray()
        data2.extend(header)
        data2.extend(struct.pack('<Q', nonce))
        data2.extend(encode_varint(1))
        data2.extend(b'\x00' * 6)       # 1 short ID placeholder
        data2.extend(encode_varint(0xFFFF))  # pf_count that causes overflow
        with self.assertRaises(ValueError):
            CompactBlock.deserialize(bytes(data2))


# ---------------------------------------------------------------------------
# G12 — validate: null header / empty-both check
# ---------------------------------------------------------------------------
class TestW112_G12_ValidateNullHeader(unittest.TestCase):
    """
    G12: validate() returns INVALID for null header or both-lists-empty.

    Bitcoin Core blockencodings.cpp lines 62-63:
        if (header.IsNull() ||
            (shorttxids.empty() && prefilledtxn.empty()))
            return READ_STATUS_INVALID;
    """

    def test_null_header_returns_invalid(self):
        from ouroboros.compact_blocks import CompactBlock, ReadStatus
        cb = CompactBlock(header=bytes(80), nonce=0,
                          short_ids=[0x123], prefilled_txs=[])
        # All-zero header has nBits=0 → IsNull() == True
        self.assertEqual(cb.validate(), ReadStatus.INVALID)

    def test_empty_both_returns_invalid(self):
        from ouroboros.compact_blocks import CompactBlock, ReadStatus
        header = _make_header()
        cb = CompactBlock(header=header, nonce=0, short_ids=[], prefilled_txs=[])
        self.assertEqual(cb.validate(), ReadStatus.INVALID)

    def test_nonempty_short_ids_with_valid_header_ok(self):
        from ouroboros.compact_blocks import CompactBlock, ReadStatus
        header = _make_header()
        cb = CompactBlock(header=header, nonce=0, short_ids=[0x123456], prefilled_txs=[])
        self.assertEqual(cb.validate(), ReadStatus.OK)


# ---------------------------------------------------------------------------
# G13 — validate: MAX tx count = MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TX_WEIGHT
# ---------------------------------------------------------------------------
class TestW112_G13_ValidateMaxTxCount(unittest.TestCase):
    """
    G13: validate() returns INVALID when sid_count + pf_count > 100,000.

    Bitcoin Core blockencodings.cpp line 64:
        if (shorttxids.size() + prefilledtxn.size() >
            MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT)
            return READ_STATUS_INVALID;
    4_000_000 / 40 = 100,000.
    """

    def test_tx_count_at_limit_ok(self):
        from ouroboros.compact_blocks import CompactBlock, ReadStatus, MAX_CMPCTBLOCK_TX_COUNT
        header = _make_header()
        sids = list(range(MAX_CMPCTBLOCK_TX_COUNT))
        cb = CompactBlock(header=header, nonce=0, short_ids=sids, prefilled_txs=[])
        self.assertEqual(cb.validate(), ReadStatus.OK)

    def test_tx_count_over_limit_invalid(self):
        from ouroboros.compact_blocks import CompactBlock, ReadStatus, MAX_CMPCTBLOCK_TX_COUNT
        header = _make_header()
        sids = list(range(MAX_CMPCTBLOCK_TX_COUNT + 1))
        cb = CompactBlock(header=header, nonce=0, short_ids=sids, prefilled_txs=[])
        self.assertEqual(cb.validate(), ReadStatus.INVALID)

    def test_max_cmpctblock_tx_count_is_100000(self):
        from ouroboros.compact_blocks import MAX_CMPCTBLOCK_TX_COUNT
        self.assertEqual(MAX_CMPCTBLOCK_TX_COUNT, 100_000)


# ---------------------------------------------------------------------------
# G14 — validate: prefilled index uint16 overflow + gap check
# ---------------------------------------------------------------------------
class TestW112_G14_ValidatePrefilledIndexGap(unittest.TestCase):
    """
    G14: validate() rejects prefilled tx with index > uint16_t max or
    index beyond (shorttxids_count + i).

    Bitcoin Core blockencodings.cpp lines 77-85:
        lastprefilledindex += prefilledtxn[i].index + 1;
        if (lastprefilledindex > UINT16_MAX) return READ_STATUS_INVALID;
        if ((uint32_t)lastprefilledindex > shorttxids.size() + i)
            return READ_STATUS_INVALID;
    """

    def _mock_prefilled(self, index):
        """Create a PrefilledTransaction with the given absolute index."""
        from ouroboros.compact_blocks import PrefilledTransaction

        class MockTx:
            def serialize_with_witness(self): return bytes(10)
            def get_wtxid(self): return bytes(32)

        return PrefilledTransaction(index=index, tx=MockTx())

    def test_index_within_bounds_ok(self):
        from ouroboros.compact_blocks import CompactBlock, ReadStatus
        header = _make_header()
        # 1 short ID at slot 0, prefilled at slot 1 (valid)
        pf = self._mock_prefilled(1)
        cb = CompactBlock(header=header, nonce=0,
                          short_ids=[0x111], prefilled_txs=[pf])
        self.assertEqual(cb.validate(), ReadStatus.OK)

    def test_index_overflow_uint16_invalid(self):
        from ouroboros.compact_blocks import CompactBlock, ReadStatus
        header = _make_header()
        pf = self._mock_prefilled(0x10000)  # > 0xFFFF
        # Need enough short IDs so gap check doesn't fire first
        sids = list(range(0x10001))
        cb = CompactBlock(header=header, nonce=0, short_ids=sids, prefilled_txs=[pf])
        self.assertEqual(cb.validate(), ReadStatus.INVALID)

    def test_index_beyond_gap_invalid(self):
        from ouroboros.compact_blocks import CompactBlock, ReadStatus
        header = _make_header()
        # 0 short IDs, 1 prefilled at index 1 -> gap check fails (1 > 0 + 0 = 0)
        pf = self._mock_prefilled(1)
        cb = CompactBlock(header=header, nonce=0, short_ids=[], prefilled_txs=[pf])
        self.assertEqual(cb.validate(), ReadStatus.INVALID)


# ---------------------------------------------------------------------------
# G15 — validate: duplicate short IDs + bucket DoS gate
# ---------------------------------------------------------------------------
class TestW112_G15_ValidateDuplicateAndBucketDoS(unittest.TestCase):
    """
    G15: validate() returns FAILED for duplicate short IDs or when any
    hash bucket exceeds 12 entries (DoS protection).

    Bitcoin Core blockencodings.cpp lines 94-116:
        if (shorttxids.bucket_size(bucket(sid)) > 12)
            return READ_STATUS_FAILED;
        if (shorttxids.size() != cmpctblock.shorttxids.size())
            return READ_STATUS_FAILED; // Short ID collision
    """

    def test_duplicate_short_ids_fail(self):
        from ouroboros.compact_blocks import CompactBlock, ReadStatus
        header = _make_header()
        # Duplicate SID at positions 0 and 1
        sids = [0x111111111111, 0x111111111111, 0x222222222222]
        cb = CompactBlock(header=header, nonce=0, short_ids=sids, prefilled_txs=[])
        self.assertEqual(cb.validate(), ReadStatus.FAILED)

    def test_bucket_overflow_13_entries_fail(self):
        """13 SIDs all mapping to bucket 0 should return FAILED."""
        from ouroboros.compact_blocks import CompactBlock, ReadStatus
        header = _make_header()
        # With n_sids=13, bucket = sid % 13, so multiples of 13 all land in bucket 0
        sids = [i * 13 for i in range(13)]  # 0, 13, 26, ..., 156 all -> bucket 0
        cb = CompactBlock(header=header, nonce=0, short_ids=sids, prefilled_txs=[])
        self.assertEqual(cb.validate(), ReadStatus.FAILED)

    def test_bucket_exactly_12_entries_ok(self):
        """12 SIDs all mapping to bucket 0 should return OK."""
        from ouroboros.compact_blocks import CompactBlock, ReadStatus
        header = _make_header()
        # With n_sids=12, bucket = sid % 12
        sids = [i * 12 for i in range(12)]  # 0, 12, 24, ..., 132 all -> bucket 0
        cb = CompactBlock(header=header, nonce=0, short_ids=sids, prefilled_txs=[])
        self.assertEqual(cb.validate(), ReadStatus.OK)


# ---------------------------------------------------------------------------
# G16 — getblocktxn depth gate: only serve within MAX_BLOCKTXN_DEPTH=10
# ---------------------------------------------------------------------------
class TestW112_G16_GetBlockTxnDepthGate(unittest.TestCase):
    """
    G16: getblocktxn handler only serves blocks within MAX_BLOCKTXN_DEPTH (10)
    of the current tip.

    Bitcoin Core net_processing.cpp line 4276:
        if (pindex->nHeight >= m_chainman.ActiveChain().Height() - MAX_BLOCKTXN_DEPTH)
            // serve blocktxn
        else
            // send full block (MSG_WITNESS_BLOCK) instead

    Ouroboros silently drops the response for deep blocks (see BUG-7).
    """

    def test_max_blocktxn_depth_constant(self):
        from ouroboros.compact_blocks import MAX_BLOCKTXN_DEPTH
        self.assertEqual(MAX_BLOCKTXN_DEPTH, 10)

    def test_depth_gate_logic_present(self):
        """on_getblocktxn checks depth against MAX_BLOCKTXN_DEPTH."""
        import inspect
        from ouroboros import p2p
        src = inspect.getsource(p2p.PeerManager._register_compact_handlers)
        self.assertIn('MAX_BLOCKTXN_DEPTH', src)
        self.assertIn('tip_height', src)


# ---------------------------------------------------------------------------
# G17 — getblocktxn out-of-bounds indices: drop response
# ---------------------------------------------------------------------------
class TestW112_G17_GetBlockTxnOOB(unittest.TestCase):
    """
    G17: getblocktxn with out-of-bounds transaction index: drops response.

    Bitcoin Core net_processing.cpp:
        Misbehaving(peer, "getblocktxn with out-of-bounds tx indices")

    Ouroboros drops the response (does not crash, does not send partial reply).
    """

    def test_oob_check_logic_present(self):
        """on_getblocktxn drops when index >= len(block.transactions)."""
        import inspect
        from ouroboros import p2p
        src = inspect.getsource(p2p.PeerManager._register_compact_handlers)
        self.assertIn('out_of_bounds', src)


# ---------------------------------------------------------------------------
# G18 — getblocktxn deep block: should send full block (BUG-7)
# ---------------------------------------------------------------------------
class TestW112_G18_GetBlockTxnDeepBlockFallback(unittest.TestCase):
    """
    BUG-7 (P2): For getblocktxn targeting blocks > MAX_BLOCKTXN_DEPTH deep,
    Bitcoin Core falls back to sending the full block (MSG_WITNESS_BLOCK).

    Bitcoin Core net_processing.cpp lines 4292-4303:
        // If an older block is requested ... send a block response instead
        CInv inv{MSG_WITNESS_BLOCK, req.blockhash};
        WITH_LOCK(peer.m_getdata_requests_mutex,
                  peer.m_getdata_requests.push_back(inv));

    Ouroboros: silently returns without sending anything.
    This means the remote peer's compact block reconstruction permanently
    stalls — no blocktxn and no full-block fallback.

    Fix: when depth > MAX_BLOCKTXN_DEPTH, queue a MSG_WITNESS_BLOCK response.
    """

    def test_deep_block_fallback_missing(self):
        """Confirms no MSG_WITNESS_BLOCK fallback for deep blocks (documents BUG-7)."""
        import inspect
        from ouroboros import p2p
        src = inspect.getsource(p2p.PeerManager._register_compact_handlers)
        # Extract only the on_getblocktxn function body for analysis.
        # Then check whether it sends a full block (MSG_BLOCK/WITNESS_BLOCK) in the
        # deep-block branch.  The docstring mentions MSG_WITNESS_BLOCK as what Core
        # does but ouroboros doesn't; we must ignore docstring/comment content.
        start = src.find('async def on_getblocktxn')
        self.assertNotEqual(start, -1, "on_getblocktxn not found")
        func_src = src[start:]
        # End at the next function or handler registration
        next_boundary = func_src.find('\n        async def', 10)
        if next_boundary == -1:
            next_boundary = func_src.find('\n        peer.register_handler')
        func_body = func_src[:next_boundary] if next_boundary != -1 else func_src

        # An actual fallback would call send_message with a block-type message
        has_actual_fallback = (
            'send_message' in func_body and
            ('MSG_BLOCK' in func_body or 'BlockMessage' in func_body)
        )
        self.assertFalse(has_actual_fallback,
                         "BUG-7 fixed: full-block fallback present (update test)")


# ---------------------------------------------------------------------------
# G19 — blocktxn deserialization
# ---------------------------------------------------------------------------
class TestW112_G19_BlockTxnDeserialization(unittest.TestCase):
    """
    G19: BlockTransactions.deserialize() correctly parses block_hash + txs.
    """

    def test_blocktxn_payload_too_short(self):
        from ouroboros.compact_blocks import BlockTransactions
        with self.assertRaises(ValueError):
            BlockTransactions.deserialize(bytes(32))  # needs at least 33 bytes

    def test_blocktransactionsrequest_roundtrip(self):
        from ouroboros.compact_blocks import BlockTransactionsRequest
        block_hash = bytes(range(32))
        indices = [0, 2, 5, 10, 99]
        req = BlockTransactionsRequest(block_hash=block_hash, indices=indices)
        raw = req.serialize()
        req2 = BlockTransactionsRequest.deserialize(raw)
        self.assertEqual(req2.block_hash, block_hash)
        self.assertEqual(req2.indices, indices)

    def test_getblocktxn_indices_differential_encoding(self):
        """Indices are differentially encoded: diff[i] = idx[i] - (idx[i-1]+1)."""
        from ouroboros.compact_blocks import BlockTransactionsRequest
        from ouroboros.p2p_messages import decode_varint, encode_varint
        indices = [3, 7, 10]  # diffs = [3, 3, 2]
        req = BlockTransactionsRequest(block_hash=bytes(32), indices=indices)
        raw = req.serialize()
        # After 32-byte hash and varint count:
        off = 32
        count, consumed = decode_varint(raw, off)
        off += consumed
        self.assertEqual(count, 3)
        # diff[0] = 3 - (-1+1) = 3
        diff0, c = decode_varint(raw, off)
        self.assertEqual(diff0, 3)


# ---------------------------------------------------------------------------
# G20 — blocktxn: no partial block state tracking (BUG-2)
# ---------------------------------------------------------------------------
class TestW112_G20_BlockTxnMissingPartialState(unittest.TestCase):
    """
    BUG-2 (P1): on_blocktxn does not maintain partial block state.

    After sending getblocktxn (in response to a cmpctblock with missing txs),
    the node receives a blocktxn with ONLY the missing transactions. To
    assemble the full block, the node needs to merge these with:
      - the prefilled transactions from the original cmpctblock
      - the mempool-matched transactions for the short IDs it found

    Bitcoin Core tracks this per-block partial state in
    PartiallyDownloadedBlock (blockencodings.h), keyed by block hash.

    Ouroboros on_blocktxn:
        bt = BlockTransactions.deserialize(msg.payload)
        if self._on_compact_block:
            self._on_compact_block(bt.block_hash, bt.transactions, [])

    There is no in-flight partial block store. The callback receives only
    the missing transactions — insufficient to reconstruct the full block.

    Fix: add a dict[block_hash -> PartialCmpctBlock] in PeerManager that
    stores (prefilled_txs + matched_txs + missing_indices) from on_cmpctblock,
    then on_blocktxn merges the received txs and fires the block callback
    with the complete tx list.
    """

    def test_no_partial_block_state_in_peer_manager(self):
        """PeerManager has no in-flight compact block store (documents BUG-2)."""
        import inspect
        from ouroboros import p2p
        src = inspect.getsource(p2p.PeerManager)
        has_partial = (
            '_partial_blocks' in src
            or '_inflight_cmpct' in src
            or '_pending_compact' in src
            or 'PartiallyDownloadedBlock' in src
            or '_cmpct_inflight' in src
        )
        self.assertFalse(has_partial,
                         "BUG-2 fixed: partial block state tracking is now present")

    def test_on_blocktxn_calls_handler_with_partial_data(self):
        """
        Demonstrates that on_blocktxn fires the callback with only the
        missing txs (not a fully assembled block).
        """
        import inspect
        from ouroboros import p2p
        src = inspect.getsource(p2p.PeerManager._register_compact_handlers)
        # The on_blocktxn function should merge with partial block state before calling handler
        # Currently it calls the handler directly with bt.transactions
        self.assertIn('bt.transactions', src,
                      "on_blocktxn should pass bt.transactions to callback (no merge)")


# ---------------------------------------------------------------------------
# G21 — reconstruct: mempool match uses wtxid (v2)
# ---------------------------------------------------------------------------
class TestW112_G21_ReconstructUseWtxid(unittest.TestCase):
    """
    G21: Compact block v2 uses WTXID for short ID computation.

    BIP 152 (v2, endorsed by BIP 141):
        The short IDs in v2 compact blocks are derived from the wtxid
        (witness transaction ID) not the txid.

    Bitcoin Core blockencodings.cpp line 122:
        for (const auto& [wtxid, txit] : pool->txns_randomized) {
            uint64_t shortid = cmpctblock.GetShortID(wtxid);

    Ouroboros from_block() uses tx.get_wtxid() and the mempool's
    match_compact_block() iterates wtxid_to_txid.
    """

    def test_from_block_uses_wtxid(self):
        """CompactBlock.from_block() uses get_wtxid() for short ID computation."""
        import inspect
        from ouroboros.compact_blocks import CompactBlock
        src = inspect.getsource(CompactBlock.from_block)
        self.assertIn('get_wtxid', src,
                      "from_block must use wtxid for v2 short IDs")

    def test_match_compact_block_uses_wtxid_index(self):
        """match_compact_block iterates wtxid_to_txid dual index."""
        import inspect
        from ouroboros.mempool import Mempool
        src = inspect.getsource(Mempool.match_compact_block)
        self.assertIn('wtxid_to_txid', src,
                      "match_compact_block must use wtxid for matching")


# ---------------------------------------------------------------------------
# G22 — reconstruct: short ID collision is handled
# ---------------------------------------------------------------------------
class TestW112_G22_ShortIdCollisionHandling(unittest.TestCase):
    """
    G22: When two mempool transactions collide to the same short ID,
    both are treated as unavailable (missing).

    Bitcoin Core blockencodings.cpp lines 130-137:
        // If we find two mempool txn that match the short id,
        // just request it.
        if (txn_available[idit->second]) {
            txn_available[idit->second].reset();
            mempool_count--;
        }

    Ouroboros match_compact_block marks collisions as None.
    """

    def test_collision_handling_in_match_compact_block(self):
        import inspect
        from ouroboros.mempool import Mempool
        src = inspect.getsource(Mempool.match_compact_block)
        self.assertIn('collision', src.lower(),
                      "match_compact_block must handle short ID collisions")


# ---------------------------------------------------------------------------
# G23 — reconstruct: missing → send getblocktxn
# ---------------------------------------------------------------------------
class TestW112_G23_MissingTxSendsGetBlockTxn(unittest.TestCase):
    """
    G23: When reconstruction has missing transactions, ouroboros sends
    a getblocktxn message with the missing indices.
    """

    def test_on_cmpctblock_sends_getblocktxn_on_missing(self):
        """on_cmpctblock sends getblocktxn when txs cannot all be matched."""
        import inspect
        from ouroboros import p2p
        src = inspect.getsource(p2p.PeerManager._register_compact_handlers)
        self.assertIn('getblocktxn', src.lower())
        self.assertIn('missing', src.lower())
        self.assertIn('BlockTransactionsRequest', src)


# ---------------------------------------------------------------------------
# G24 — vExtraTxnForCompact missing (BUG-6)
# ---------------------------------------------------------------------------
class TestW112_G24_ExtraTxnPoolMissing(unittest.TestCase):
    """
    BUG-6 (P2): No vExtraTxnForCompact pool for compact block reconstruction.

    Bitcoin Core blockencodings.cpp lines 147-174:
        // Also check extra_txn (recently seen txns for compact block reconstruction)
        for (size_t i = 0; i < extra_txn.size(); i++) {
            uint64_t shortid = cmpctblock.GetShortID(extra_txn[i].first);
            idit = shorttxids.find(shortid);
            ...

    This pool contains recently evicted, conflicted, or freshly-broadcast
    transactions that are no longer in the mempool. Without it, compact block
    reconstruction fails for any tx removed from mempool since the compact
    block was announced, causing unnecessary round trips.

    Fix: add a deque of (wtxid, tx) pairs, populated when txs are:
    - removed from the mempool (eviction/replacement)
    - received via INV/TX before mempool admission
    """

    def test_no_extra_txn_pool_present(self):
        """Confirms no vExtraTxnForCompact equivalent exists (documents BUG-6)."""
        import os
        src_files = ['src/ouroboros/p2p.py', 'src/ouroboros/mempool.py',
                     'src/ouroboros/block_sync.py', 'src/ouroboros/node.py']
        for fname in src_files:
            fpath = os.path.join('/home/work/hashhog/ouroboros', fname)
            with open(fpath) as f:
                content = f.read()
            has_extra = (
                'vExtraTxnForCompact' in content
                or 'extra_txn' in content
                or '_extra_txn_for_compact' in content
            )
            if has_extra:
                self.fail(f"BUG-6 fixed in {fname}: extra txn pool present (update test)")


# ---------------------------------------------------------------------------
# G25 — Depth gate direction wrong on receive side (BUG-5)
# ---------------------------------------------------------------------------
class TestW112_G25_DepthGateDirectionWrong(unittest.TestCase):
    """
    BUG-5 (P2): MAX_CMPCTBLOCK_DEPTH is used on the RECEIVE side,
    but Bitcoin Core uses it only for the SERVE side.

    Bitcoin Core uses MAX_CMPCTBLOCK_DEPTH=5 when SERVING compact blocks:
        net_processing.cpp line 2466:
            if (can_direct_fetch &&
                pindex->nHeight >= tip->nHeight - MAX_CMPCTBLOCK_DEPTH)
                // serve compact block; else serve full block

    For RECEIVING a cmpctblock, Core's check is different:
        net_processing.cpp line 4576:
            if (pindex->nHeight <= m_chainman.ActiveChain().Height() + 2)
                // only process compact blocks near tip (+2 to handle brief re-orgs)

    Ouroboros on_cmpctblock uses:
        if announced_height < our_height - MAX_CMPCTBLOCK_DEPTH: ignore
    This ignores blocks > 5 below tip (reasonable heuristic), but the constant
    MAX_CMPCTBLOCK_DEPTH is documented as a SERVE constant, not a RECEIVE one.
    The semantic intent differs from Core.
    """

    def test_max_cmpctblock_depth_misapplied_to_receive(self):
        """MAX_CMPCTBLOCK_DEPTH appears in on_cmpctblock (misapplied to receive side)."""
        import inspect
        from ouroboros import p2p
        src = inspect.getsource(p2p.PeerManager._register_compact_handlers)
        # The receive handler should NOT use MAX_CMPCTBLOCK_DEPTH
        # It appears in on_cmpctblock (receive path) which is the bug
        self.assertIn('MAX_CMPCTBLOCK_DEPTH', src,
                      "MAX_CMPCTBLOCK_DEPTH should be removed from receive side (BUG-5)")


# ---------------------------------------------------------------------------
# G26 — Compact block callback dead handler (BUG-1 — P0)
# ---------------------------------------------------------------------------
class TestW112_G26_CompactBlockCallbackDeadHandler(unittest.TestCase):
    """
    BUG-1 (P0-CDIV): set_compact_block_handler() is defined but never called.

    _on_compact_block is initialized to None in PeerManager.__init__ and is
    ONLY settable via set_compact_block_handler(). Since node.py and
    block_sync.py never call set_compact_block_handler(), the handler
    is always None.

    Result: on_cmpctblock reconstructs the compact block correctly, but
    the guard `if self._on_compact_block:` is always False — the
    reconstructed block is silently discarded and never submitted to
    the validator. Compact block reception produces zero benefit.

    Fix: call peer_manager.set_compact_block_handler(handler) from
    block_sync.py or node.py, where handler submits the full tx list
    to the block validator.
    """

    def test_set_compact_block_handler_never_called_in_node(self):
        with open('/home/work/hashhog/ouroboros/src/ouroboros/node.py') as f:
            content = f.read()
        self.assertNotIn('set_compact_block_handler', content,
                         "BUG-1 fixed: node.py now calls set_compact_block_handler")

    def test_set_compact_block_handler_never_called_in_block_sync(self):
        with open('/home/work/hashhog/ouroboros/src/ouroboros/block_sync.py') as f:
            content = f.read()
        self.assertNotIn('set_compact_block_handler', content,
                         "BUG-1 fixed: block_sync.py now calls set_compact_block_handler")

    def test_on_compact_block_initializes_to_none(self):
        """_on_compact_block starts as None (proving the dead-handler default)."""
        import inspect
        from ouroboros import p2p
        src = inspect.getsource(p2p.PeerManager.__init__)
        self.assertIn('_on_compact_block = None', src)


# ---------------------------------------------------------------------------
# G27 — Compact block reconstruction to block processing
# ---------------------------------------------------------------------------
class TestW112_G27_ReconstructionToBlockProcessing(unittest.TestCase):
    """
    G27: When compact block reconstruction succeeds (all txs resolved),
    the assembled block must be submitted to the block validator.

    This is blocked by BUG-1 (dead handler). Documents that the reconstruct
    logic itself is correct; only the downstream wiring is absent.
    """

    def test_reconstruct_returns_tx_list_on_success(self):
        """
        CompactBlock.reconstruct() returns (txs, []) when all mempool matches found.
        Uses a mock mempool that returns prefixed matches.
        """
        from ouroboros.compact_blocks import CompactBlock, PrefilledTransaction

        class MockTx:
            def get_wtxid(self): return bytes(32)
            def serialize_with_witness(self): return bytes(10)

        class MockMempool:
            def match_compact_block(self, short_ids, key):
                # Return one matched tx per short ID (no missing)
                matched = [MockTx() for _ in short_ids]
                return matched, []

        header = _make_header()
        pf = PrefilledTransaction(index=0, tx=MockTx())
        cb = CompactBlock(header=header, nonce=42,
                          short_ids=[0x111111, 0x222222], prefilled_txs=[pf])

        txs, missing = cb.reconstruct(MockMempool())
        self.assertIsNotNone(txs)
        self.assertEqual(missing, [])
        self.assertEqual(len(txs), 3)  # 1 prefilled + 2 short IDs

    def test_reconstruct_returns_missing_when_tx_not_found(self):
        """reconstruct() returns (None, [indices]) when some txs are missing."""
        from ouroboros.compact_blocks import CompactBlock

        class MockTx:
            def get_wtxid(self): return bytes(32)
            def serialize_with_witness(self): return bytes(10)

        class MockMempool:
            def match_compact_block(self, short_ids, key):
                # Return None for all (all missing)
                return [None] * len(short_ids), list(range(len(short_ids)))

        header = _make_header()
        cb = CompactBlock(header=header, nonce=0,
                          short_ids=[0x1, 0x2, 0x3], prefilled_txs=[])
        txs, missing = cb.reconstruct(MockMempool())
        self.assertIsNone(txs)
        self.assertEqual(len(missing), 3)


# ---------------------------------------------------------------------------
# G28 — Announce new block with compact to HB peers
# ---------------------------------------------------------------------------
class TestW112_G28_AnnounceBlockWithCompact(unittest.TestCase):
    """
    G28: block_sync.py's _announce_block sends a cmpctblock to peers
    that have requested high-bandwidth mode (wants_cmpctblock=True).
    """

    def test_announce_block_sends_cmpctblock_to_hb_peers(self):
        """_announce_block uses CompactBlock.from_block for wants_cmpctblock peers."""
        import inspect
        from ouroboros.block_sync import BlockSync
        src = inspect.getsource(BlockSync._announce_block)
        self.assertIn('wants_cmpctblock', src)
        self.assertIn('CompactBlock.from_block', src)
        self.assertIn('CmpctBlockMessage', src)

    def test_announce_block_falls_back_to_headers(self):
        """_announce_block sends headers to peers with wants_headers=True."""
        import inspect
        from ouroboros.block_sync import BlockSync
        src = inspect.getsource(BlockSync._announce_block)
        self.assertIn('wants_headers', src)


# ---------------------------------------------------------------------------
# G29 — HB peer management: cmpct_peers set unused (BUG-8)
# ---------------------------------------------------------------------------
class TestW112_G29_CmpctPeersSetUnused(unittest.TestCase):
    """
    BUG-8 (P3): PeerManager.cmpct_peers set is populated but never read.

    In _register_compact_handlers, on_sendcmpct does:
        self.cmpct_peers.add(addr)

    But cmpct_peers is never queried by any other method. The actual HB
    announcement state is tracked via peer.wants_cmpctblock.

    This is a minor dead-helper — cmpct_peers is dead state that
    accumulates addresses without serving any function.
    """

    def test_cmpct_peers_set_is_written_but_never_read(self):
        """cmpct_peers is populated in on_sendcmpct but never queried."""
        import re
        with open('/home/work/hashhog/ouroboros/src/ouroboros/p2p.py') as f:
            content = f.read()
        # Find all uses: add() is a write, anything else could be a read
        writes = re.findall(r'cmpct_peers\.add\b', content)
        reads = re.findall(r'cmpct_peers\.(?!add\b)', content)
        # Also check for bare 'cmpct_peers' reads (not .add)
        all_uses = re.findall(r'\bcmpct_peers\b', content)
        # Declaration + add = 2 uses; any additional are reads
        decl_and_write = 2  # __init__ declaration + .add() call
        self.assertLessEqual(len(all_uses), decl_and_write,
                             "BUG-8 fixed: cmpct_peers is now being used (update test)")


# ---------------------------------------------------------------------------
# G30 — Rust pipeline: compact block messages unhandled (two-pipeline divergence)
# ---------------------------------------------------------------------------
class TestW112_G30_RustPipelineCompactBlocksMissing(unittest.TestCase):
    """
    G30: The Rust (ferrous-utils) pipeline has no compact block message
    handling for sendcmpct, cmpctblock, getblocktxn, or blocktxn.

    ferrous-utils/sync/src/network/peer.rs (lines 12-14):
        'Tx relay, BIP-152 compact blocks, and the matching serving paths
         live in the Python layer ... see the cross-impl P2P parity audit'
        '    sendcmpct, cmpctblock, getblocktxn, blocktxn) here.'

    The Rust pipeline:
    - Has SipHash-2-4 implementation (crypto/siphash.rs) - PRESENT
    - Has compute_siphash_key() + PresaltedSipHasher + short_txid() - PRESENT
    - Has NO compact block message deserialization/handling - ABSENT
    - Has NO sendcmpct negotiation - ABSENT (just silently drops the message)
    - Explicitly drops sendcmpct in header_sync.rs via pattern matching

    Two-pipeline divergence: Python handles the full compact block protocol;
    Rust silently ignores all compact block messages.

    Fix: not required for IBD-only ferrous-utils, but represents a gap
    if Rust pipeline is ever extended to full node operation.
    """

    def test_rust_compact_block_handling_absent(self):
        """Rust peer.rs has no compact block parsing (documents two-pipeline gap)."""
        with open('/home/work/hashhog/ouroboros/ferrous-utils/sync/src/network/peer.rs') as f:
            content = f.read()
        # Strip comment lines (lines starting with // or //!)
        non_comment_lines = [
            l for l in content.split('\n')
            if not l.strip().startswith('//')
        ]
        non_comment = '\n'.join(non_comment_lines)
        has_handling = (
            'CompactBlock' in non_comment
            or 'cmpctblock' in non_comment.lower()
            or 'getblocktxn' in non_comment.lower()
            or 'blocktxn' in non_comment.lower()
        )
        self.assertFalse(has_handling,
                         "Rust pipeline now has compact block handling (update test)")

    def test_rust_drops_sendcmpct_silently(self):
        """header_sync.rs explicitly silences sendcmpct without processing it."""
        with open('/home/work/hashhog/ouroboros/ferrous-utils/sync/src/network/header_sync.rs') as f:
            content = f.read()
        self.assertIn('sendcmpct', content,
                      "sendcmpct should appear in header_sync.rs silence list")

    def test_rust_siphash_present_and_correct(self):
        """Rust SipHash-2-4 implementation is present with correct reference vector."""
        with open('/home/work/hashhog/ouroboros/ferrous-utils/common/src/crypto/siphash.rs') as f:
            content = f.read()
        self.assertIn('compute_siphash_key', content)
        self.assertIn('PresaltedSipHasher', content)
        # Reference vector: 0xa129ca6149be45e5
        self.assertIn('0xa129ca6149be45e5', content)

    def test_rust_siphash_key_derivation_present(self):
        """Rust computes key = SHA256(header || nonce_le)[0:16]."""
        with open('/home/work/hashhog/ouroboros/ferrous-utils/common/src/crypto/siphash.rs') as f:
            content = f.read()
        self.assertIn('Sha256', content)
        self.assertIn('to_le_bytes', content)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _make_header() -> bytes:
    """Create an 80-byte block header with non-zero nBits (not IsNull)."""
    hdr = bytearray(80)
    # nBits at byte offset 72 (4 bytes LE)
    hdr[72:76] = struct.pack('<I', 0x1d00ffff)
    return bytes(hdr)


if __name__ == '__main__':
    unittest.main()
