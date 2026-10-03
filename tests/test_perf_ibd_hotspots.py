"""Equivalence pins for the IBD hot-path perf changes (perf/ibd-hotspots).

Every change here claims "same verdict, less work".  Each test pins BOTH
halves: the result is identical to the pre-change (eager / full-block) path,
AND the expensive call the change removed is really gone — a perf fix whose
fast path is never taken would pass an equivalence-only test.

  1. prev-block header lookup  (validation.validate_block, database.get_block_header)
  2. sync_loop tip/parent probe (block_sync.sync_loop, _check_tip_parent_height)
  3. BIP68 flag-first / reuse / memo (TransactionValidator.check_sequence_locks)
  4. in-place tx parsing        (Block.deserialize, TxMessage.from_payload(start))
  5. linear Transaction.serialize
  6. one backfill getheaders in flight + stale-reply drop (#3)
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import time
from unittest.mock import MagicMock

import pytest

from ouroboros.database import Block, BlockchainDatabase, Transaction, TxIn, TxOut
from ouroboros.p2p_messages import TxMessage, encode_varint
from ouroboros.validation import BlockValidator, MissingAncestorHeaderError, TransactionValidator


def _sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _header(prev: bytes, ts: int, bits: int = 0x1D00FFFF, version: int = 0x20000000,
            nonce: int = 7) -> bytes:
    return (
        version.to_bytes(4, "little", signed=True) + prev + bytes(range(32))
        + ts.to_bytes(4, "little") + bits.to_bytes(4, "little")
        + nonce.to_bytes(4, "little")
    )


# ---------------------------------------------------------------------------
# 1. get_block_header == header fields of get_block, without the body read
# ---------------------------------------------------------------------------


class _PyBlockLike:
    """What the Rust ``PyBlock`` exposes (note: NO ``height``)."""

    def __init__(self, header: bytes):
        self.version = int.from_bytes(header[0:4], "little", signed=True)
        self.prev_blockhash = header[4:36]
        self.merkle_root = header[36:68]
        self.timestamp = int.from_bytes(header[68:72], "little")
        self.bits = int.from_bytes(header[72:76], "little")
        self.nonce = int.from_bytes(header[76:80], "little")
        self.transactions = []
        self.hash = _sha256d(header)


class _FakeRustDBNoBytes:
    """Stored bodies keyed by hash; counts full-block reads (old extension:
    no ``get_block_bytes``)."""

    def __init__(self):
        self.bodies: dict[bytes, bytes] = {}
        self.full_reads = 0
        self.byte_reads = 0

    def store(self, header: bytes) -> bytes:
        h = _sha256d(header)
        self.bodies[h] = header + b"\x01" + b"\x00" * 60  # header + fake tx bytes
        return h

    def get_block(self, h):
        self.full_reads += 1
        body = self.bodies.get(bytes(h))
        return None if body is None else _PyBlockLike(body[:80])

    def has_block_hash(self, h):
        return bytes(h) in self.bodies

    def get_best_block(self):
        return (bytes(32), 0)


class _FakeRustDB(_FakeRustDBNoBytes):
    def get_block_bytes(self, h):
        self.byte_reads += 1
        return self.bodies.get(bytes(h))


def _db_over(fake) -> BlockchainDatabase:
    db = BlockchainDatabase.__new__(BlockchainDatabase)
    db._db = fake
    db._data_dir = "/nonexistent"
    db._cached_tip = None
    db._tip_bits = 0
    db._tip_timestamp = 0
    db._recent_timestamps = []
    db._cached_chainwork = 0
    from collections import OrderedDict
    db._chainwork_cache = OrderedDict()
    db._header_cache = OrderedDict()
    return db


def _fields(b: Block):
    return (b.version, bytes(b.prev_blockhash), bytes(b.merkle_root), b.timestamp,
            b.bits, b.nonce, bytes(b.hash), b.height)


@pytest.mark.parametrize("with_bytes", [True, False])
def test_get_block_header_matches_get_block_fields(with_bytes):
    fake = _FakeRustDB() if with_bytes else _FakeRustDBNoBytes()
    db = _db_over(fake)
    headers = [_header(bytes([i]) * 32, 1_600_000_000 + i, version=v)
               for i, v in enumerate([1, 2, 0x20000000, -1, 0x3FFFFFFF])]
    hashes = [fake.store(h) for h in headers]
    for h in hashes:
        full = db.get_block(h)
        hdr = db.get_block_header(h)
        assert _fields(hdr) == _fields(full)
        assert hdr.height is None and full.height is None
        assert hdr.transactions == []
    missing = bytes([0xAB]) * 32
    assert db.get_block(missing) is None
    assert db.get_block_header(missing) is None


def test_get_block_header_cache_hit_needs_no_body_read_but_rechecks_presence():
    fake = _FakeRustDB()
    db = _db_over(fake)
    hdr = _header(bytes(32), 1_700_000_000)
    h = fake.store(hdr)
    db._remember_header(hdr)  # what connect_block_from_bytes does
    fake.full_reads = fake.byte_reads = 0
    got = db.get_block_header(h)
    assert got is not None and got.bits == 0x1D00FFFF
    assert fake.full_reads == 0 and fake.byte_reads == 0  # served from the cache
    # Body gone (pruned) -> None, exactly like get_block, despite the cache.
    del fake.bodies[h]
    assert db.get_block(h) is None
    assert db.get_block_header(h) is None


def test_header_cache_is_bounded():
    from ouroboros import database as dbmod
    db = _db_over(_FakeRustDB())
    for i in range(dbmod._HEADER_CACHE_MAX + 50):
        db._remember_header(_header(bytes(32), i))
    assert len(db._header_cache) == dbmod._HEADER_CACHE_MAX


def test_validator_routes_prev_lookup_through_header_path_only_for_real_db():
    fake = _FakeRustDB()
    db = _db_over(fake)
    h = fake.store(_header(bytes(32), 1_700_000_000))
    v = BlockValidator(db, "mainnet")
    fake.full_reads = 0
    assert v._lookup_header_block(h).timestamp == 1_700_000_000
    assert fake.full_reads == 0
    # A test that patches get_block on the instance keeps control.
    sentinel = Block(1, bytes(32), bytes(32), 5, 6, 7, [], bytes(32))
    db.get_block = lambda _h: sentinel
    assert v._lookup_header_block(h) is sentinel
    # Mocks / fakes always go through get_block.
    m = MagicMock()
    m.get_block.return_value = sentinel
    assert BlockValidator(m, "mainnet")._lookup_header_block(h) is sentinel
    spec = MagicMock(spec=BlockchainDatabase)
    spec.get_block.return_value = sentinel
    assert BlockValidator(spec, "mainnet")._lookup_header_block(h) is sentinel


# ---------------------------------------------------------------------------
# 2. sync_loop tip/parent probe: no body reads, never re-drives a reorg
# ---------------------------------------------------------------------------


def _old_reorg_probe_fires(db, best_hash, best_height) -> bool:
    """The pre-change sync_loop condition, verbatim in effect."""
    current_block = db.get_block(best_hash)
    if current_block:
        prev_block = db.get_block(current_block.prev_blockhash)
        if prev_block and prev_block.height and best_height:
            if prev_block.height < best_height - 1:
                return True
    return False


def test_old_reorg_probe_was_unreachable_and_new_probe_reads_no_bodies():
    from ouroboros.block_sync import BlockSync

    fake = _FakeRustDB()
    db = _db_over(fake)
    heights: dict[bytes, int] = {}
    prev = bytes(32)
    chain = []
    for i in range(20):
        hdr = _header(prev, 1_600_000_000 + i)
        h = fake.store(hdr)
        db._remember_header(hdr)
        heights[h] = 100 + i
        chain.append(h)
        prev = h
    fake.get_block_metadata_by_hash = lambda hh: (
        (heights[bytes(hh)], bytes(32), 0, 0) if bytes(hh) in heights else None
    )
    bs = BlockSync.__new__(BlockSync)
    bs.db = db
    for i, h in enumerate(chain[1:], start=1):
        # Consistent index: neither path flags anything.
        assert _old_reorg_probe_fires(db, h, 100 + i) is False
        fake.full_reads = fake.byte_reads = 0
        assert bs._check_tip_parent_height(h, 100 + i) is True
        assert fake.full_reads == 0 and fake.byte_reads == 0
    # Inconsistent index (parent 5 below the tip): the old path STILL cannot
    # fire (PyBlock has no height) — the new probe reports it, and only logs.
    tip = chain[-1]
    assert _old_reorg_probe_fires(db, tip, 100 + 19 + 5) is False
    assert bs._check_tip_parent_height(tip, 100 + 19 + 5) is False
    # Mock DBs (unit-test BlockSyncs) are "no evidence", never an exception.
    bs.db = MagicMock()
    assert bs._check_tip_parent_height(tip, 500) is True


def test_real_pyblock_has_no_height_attribute():
    """The fact the dead-branch finding rests on (skip without the extension)."""
    from tests._real_sync import load_real_sync
    real = load_real_sync()
    if real is None:
        pytest.skip("compiled sync extension not built")
    assert hasattr(real, "PyBlock") and not hasattr(real.PyBlock, "height")


# ---------------------------------------------------------------------------
# 3. BIP68: flag-first, reuse resolved coins, memoised MTP — same verdicts
# ---------------------------------------------------------------------------

DISABLE = 1 << 31
TYPE = 1 << 22


def _old_check_sequence_locks(v, tx, block_height, block_mtp, network, intra):
    """Pre-change eager path (master aae2bc4), reproduced for the diff."""
    from ouroboros.validation import bip68_version_active
    from sync import check_sequence_locks as rust_csl
    from sync import is_bip68_active

    if not bip68_version_active(tx.version):
        return True
    enforce = is_bip68_active(block_height, network)
    if not enforce:
        return True
    infos = []
    for inp in tx.inputs:
        utxo = v.db.get_utxo(inp.prev_txid, inp.prev_vout)
        if utxo is None and intra:
            utxo = intra.get((inp.prev_txid, inp.prev_vout))
        if utxo is None:
            return False
        uh = utxo.get("height")
        if uh is None:
            infos.append((inp.sequence | DISABLE, 0, 0))
            continue
        mtp = v.db.get_median_time_past(max(uh - 1, 0))
        if mtp is None:
            mtp = 0
        infos.append((inp.sequence, uh, mtp))
    return rust_csl(tx.version, infos, block_height, block_mtp, enforce)


class _CoinDB:
    def __init__(self, coins, mtps):
        self.coins = coins
        self.mtps = mtps
        self.utxo_calls = 0
        self.mtp_calls: list[int] = []

    def get_utxo(self, txid, vout):
        self.utxo_calls += 1
        return self.coins.get((txid, vout))

    def get_utxo_batch(self, outpoints):
        return [self.coins.get((t, o)) for t, o in outpoints]

    def get_median_time_past(self, h):
        self.mtp_calls.append(h)
        return self.mtps.get(h)


def _rand_seq(rng):
    kind = rng.randrange(6)
    lock = rng.randrange(0, 70)
    if kind == 0:
        return 0xFFFFFFFF
    if kind == 1:
        return 0xFFFFFFFD
    if kind == 2:
        return DISABLE | TYPE | lock          # disabled time lock
    if kind == 3:
        return lock                            # height lock
    if kind == 4:
        return TYPE | lock                     # time lock
    return rng.getrandbits(32)


@pytest.fixture(params=["stub", "real"])
def sync_impl(request):
    """Run under conftest's stub AND the compiled Rust calculate/evaluate."""
    if request.param == "stub":
        yield "stub"
        return
    from tests._real_sync import load_real_sync, real_sync_installed
    real = load_real_sync()
    if real is None:
        pytest.skip("compiled sync extension not built")
    with real_sync_installed(real):
        yield "real"


def test_bip68_new_path_is_verdict_identical_to_the_eager_path(sync_impl):
    rng = random.Random(0xB1768)
    base_h = 700_000
    checked = fired = missing = 0
    for trial in range(3000):
        coins, intra, inputs = {}, {}, []
        n_in = rng.randrange(1, 6)
        for j in range(n_in):
            txid = rng.getrandbits(256).to_bytes(32, "little")
            coin_h = None if rng.random() < 0.05 else base_h - rng.randrange(0, 80)
            coin = {"value": 1000, "script_pubkey": b"\x51", "height": coin_h,
                    "is_coinbase": False}
            where = rng.random()
            if where < 0.1:
                intra[(txid, j)] = coin        # created earlier in the block
            elif where < 0.97:
                coins[(txid, j)] = coin
            # else: missing everywhere
            inputs.append(TxIn(prev_txid=txid, prev_vout=j, script_sig=b"",
                               sequence=_rand_seq(rng)))
        mtps = {h: 1_600_000_000 + h * 600 for h in range(base_h - 100, base_h + 1)
                if rng.random() > 0.1}                       # some MTPs unknown
        version = rng.choice([1, 2, 2, 2, 3, 0xFFFFFFFF])
        tx = Transaction(txid=bytes(32), version=version, locktime=0,
                         inputs=inputs, outputs=[TxOut(value=1, script_pubkey=b"")])
        block_h = base_h + rng.randrange(1, 60)
        block_mtp = 1_600_000_000 + (base_h + rng.randrange(-30, 30)) * 600

        old_db = _CoinDB(coins, mtps)
        old = _old_check_sequence_locks(TransactionValidator(old_db), tx, block_h,
                                        block_mtp, "mainnet", intra)
        # The eager path's ``mtp = 0`` for an unknown coin MTP was the
        # fail-OPEN this suite now forbids: an ENFORCED time lock whose coin
        # MTP is unknown must raise MissingAncestorHeaderError (fail closed),
        # in input order, after any earlier missing-coin ``False``.
        from ouroboros.validation import bip68_version_active
        expected = old
        if bip68_version_active(version):
            for i in inputs:
                c = coins.get((i.prev_txid, i.prev_vout)) or intra.get((i.prev_txid, i.prev_vout))
                if c is None:
                    break
                if (c["height"] is not None and not (i.sequence & DISABLE)
                        and (i.sequence & TYPE)
                        and mtps.get(max(c["height"] - 1, 0)) is None):
                    expected = "MISSING"
                    break

        def _run(fn):
            try:
                return fn()
            except MissingAncestorHeaderError:
                return "MISSING"

        # (a) no hint — the non-block callers
        new_db = _CoinDB(coins, mtps)
        new_a = _run(lambda: TransactionValidator(new_db).check_sequence_locks(
            tx, block_h, block_mtp, network="mainnet", intra_block_utxos=intra))
        # (b) validate_transaction's hint + a shared per-block memo
        resolved = [coins.get((i.prev_txid, i.prev_vout))
                    or intra.get((i.prev_txid, i.prev_vout)) for i in inputs]
        hint_db = _CoinDB(coins, mtps)
        memo: dict = {}
        new_b = _run(lambda: TransactionValidator(hint_db).check_sequence_locks(
            tx, block_h, block_mtp, network="mainnet", intra_block_utxos=intra,
            input_utxos=resolved, mtp_cache=memo))
        assert expected == new_a == new_b, (trial, version, [hex(i.sequence) for i in inputs])
        checked += 1
        fired += (expected is False)
        missing += (expected == "MISSING")
        if expected == "MISSING":
            continue
        # Work actually removed: no per-input UTXO re-read with the hint, and
        # an MTP only for an enforced TIME lock, each height at most once.
        assert hint_db.utxo_calls == 0
        assert len(hint_db.mtp_calls) == len(set(hint_db.mtp_calls))
        from ouroboros.validation import bip68_version_active
        if bip68_version_active(version) and all(r is not None for r in resolved):
            wanted = {max(r["height"] - 1, 0) for i, r in zip(inputs, resolved)
                      if r["height"] is not None and not (i.sequence & DISABLE)
                      and (i.sequence & TYPE)}
            assert set(hint_db.mtp_calls) == wanted
    assert checked == 3000 and 0 < fired < checked  # both verdicts exercised
    assert 0 < missing  # the fail-closed branch is exercised too


def test_bip68_all_disabled_v2_tx_reads_no_mtp():
    pytest.importorskip("sync")
    txid = bytes([9]) * 32
    coin = {"value": 5, "script_pubkey": b"", "height": 700_000, "is_coinbase": False}
    db = _CoinDB({(txid, 0): coin}, {})
    tx = Transaction(txid=bytes(32), version=2, locktime=0,
                     inputs=[TxIn(txid, 0, b"", 0xFFFFFFFD)],
                     outputs=[TxOut(1, b"")])
    assert TransactionValidator(db).check_sequence_locks(
        tx, 700_010, 0, network="mainnet", input_utxos=[coin])
    assert db.mtp_calls == [] and db.utxo_calls == 0


def test_bip68_coinbase_tx_without_hint_matches_eager_path():
    """A coinbase has a null prevout: both paths find no coin and return False."""
    pytest.importorskip("sync")
    cb = Transaction(txid=bytes(32), version=2, locktime=0,
                     inputs=[TxIn(bytes(32), 0xFFFFFFFF, b"\x03abc", 0)],
                     outputs=[TxOut(50, b"")])
    db = _CoinDB({}, {})
    assert _old_check_sequence_locks(TransactionValidator(db), cb, 700_000, 0,
                                     "mainnet", None) is False
    assert TransactionValidator(_CoinDB({}, {})).check_sequence_locks(
        cb, 700_000, 0, network="mainnet") is False


def test_bip68_misaligned_hint_falls_back_to_lookups():
    pytest.importorskip("sync")
    txid = bytes([3]) * 32
    coin = {"value": 5, "script_pubkey": b"", "height": 700_000, "is_coinbase": False}
    db = _CoinDB({(txid, 0): coin}, {})
    tx = Transaction(txid=bytes(32), version=2, locktime=0,
                     inputs=[TxIn(txid, 0, b"", 50)], outputs=[TxOut(1, b"")])
    # height lock of 50 at depth 10 -> locked; a wrong-length hint is ignored
    assert TransactionValidator(db).check_sequence_locks(
        tx, 700_010, 0, network="mainnet", input_utxos=[coin, coin]) is False
    assert db.utxo_calls == 1


# ---------------------------------------------------------------------------
# 4. In-place tx parsing == parsing a copied tail
# ---------------------------------------------------------------------------


def _rand_tx_bytes(rng, segwit: bool) -> bytes:
    n_in = rng.randrange(1, 4)
    n_out = rng.randrange(1, 4)
    out = bytearray(rng.choice([1, 2, 0xFFFFFFFF]).to_bytes(4, "little"))
    if segwit:
        out += b"\x00\x01"
    out += encode_varint(n_in)
    for _ in range(n_in):
        out += rng.getrandbits(256).to_bytes(32, "little")
        out += rng.getrandbits(32).to_bytes(4, "little")
        ss = rng.randbytes(rng.choice([0, 1, 107, 300]))
        out += encode_varint(len(ss)) + ss
        out += rng.getrandbits(32).to_bytes(4, "little")
    out += encode_varint(n_out)
    for _ in range(n_out):
        out += rng.getrandbits(50).to_bytes(8, "little")
        spk = rng.randbytes(rng.choice([22, 25, 34, 260]))
        out += encode_varint(len(spk)) + spk
    if segwit:
        for _ in range(n_in):
            items = [rng.randbytes(rng.choice([0, 33, 72])) for _ in range(rng.randrange(1, 3))]
            out += encode_varint(len(items))
            for it in items:
                out += encode_varint(len(it)) + it
    out += rng.getrandbits(32).to_bytes(4, "little")
    return bytes(out)


def _tx_fields(t: Transaction):
    return (t.txid, t.version, t.locktime, t.has_witness,
            [(i.prev_txid, i.prev_vout, i.script_sig, i.sequence, i.witness) for i in t.inputs],
            [(o.value, o.script_pubkey) for o in t.outputs])


def test_in_place_tx_parse_equals_tail_copy_parse_and_block_deserialize():
    rng = random.Random(4242)
    txs = [_rand_tx_bytes(rng, segwit=(k % 3 != 0)) for k in range(60)]
    data = _header(bytes(32), 1_650_000_000) + encode_varint(len(txs)) + b"".join(txs)
    off = 80 + len(encode_varint(len(txs)))
    for raw in txs:
        a = TxMessage.from_payload(data[off:])
        b = TxMessage.from_payload(data, off)
        assert a.bytes_consumed == b.bytes_consumed == len(raw)
        assert _tx_fields(a.transaction) == _tx_fields(b.transaction)
        assert type(b.transaction.inputs[0].script_sig) is bytes
        off += len(raw)
    blk = Block.deserialize(data)
    assert [t.txid for t in blk.transactions] == [
        TxMessage.from_payload(r).transaction.txid for r in txs
    ]
    assert blk.hash == _sha256d(data[:80])


@pytest.mark.parametrize("cut", [81, 83, 120, 300, -5, -1])
def test_truncated_block_raises_the_same_error(cut):
    rng = random.Random(cut & 0xFFFF)
    txs = [_rand_tx_bytes(rng, segwit=True) for _ in range(3)]
    data = _header(bytes(32), 1) + encode_varint(3) + b"".join(txs)
    data = data[:cut]
    off = 81
    try:
        TxMessage.from_payload(data[off:])
        old = None
    except ValueError as e:
        old = str(e)
    try:
        TxMessage.from_payload(data, off)
        new = None
    except ValueError as e:
        new = str(e)
    assert old == new


# ---------------------------------------------------------------------------
# 5. Transaction.serialize: same bytes as the old concatenating version
# ---------------------------------------------------------------------------


def _old_serialize(tx: Transaction) -> bytes:
    data = tx.version.to_bytes(4, "little")
    data += tx._encode_varint(len(tx.inputs))
    for i in tx.inputs:
        data += i.prev_txid + i.prev_vout.to_bytes(4, "little")
        data += tx._encode_varint(len(i.script_sig)) + i.script_sig
        data += i.sequence.to_bytes(4, "little")
    data += tx._encode_varint(len(tx.outputs))
    for o in tx.outputs:
        data += o.value.to_bytes(8, "little")
        data += tx._encode_varint(len(o.script_pubkey)) + o.script_pubkey
    data += tx.locktime.to_bytes(4, "little")
    return data


def test_serialize_bytes_unchanged():
    rng = random.Random(7)
    for k in range(200):
        tx = TxMessage.from_payload(_rand_tx_bytes(rng, segwit=bool(k % 2))).transaction
        new = tx.serialize()
        assert type(new) is bytes
        assert new == _old_serialize(tx)
    big = Transaction(bytes(32), 2, 0,
                      [TxIn(bytes([i % 256]) * 32, i, b"\x00" * 300, i) for i in range(700)],
                      [TxOut(i, b"\x51" * 40) for i in range(300)])
    assert big.serialize() == _old_serialize(big)


# ---------------------------------------------------------------------------
# 6. Header backfill: one getheaders in flight; stale replies are ours
# ---------------------------------------------------------------------------


class _Peer:
    def __init__(self):
        self.sent = []
        self.connected = True
        self.host = "127.0.0.1"
        self.port = 1

    async def send_message(self, m):
        self.sent.append(m)

    def is_connected(self):
        return self.connected


class _PM:
    network = "mainnet"

    def __init__(self, peers):
        self.peers = peers

    def get_all_ready_peers(self):
        return [p for p in self.peers if p.connected]


def _bs_with_backfill(peers):
    from ouroboros.block_sync import BlockSync
    from ouroboros.header_backfill import HeaderBackfill, block_hash

    # A 3-header synthetic range above a lower anchor.
    lower = bytes([0x11]) * 32
    hdrs, prev = [], lower
    for i in range(3):
        h = _header(prev, 1000 + i, bits=0x207FFFFF)
        hdrs.append(h)
        prev = block_hash(h)
    db = MagicMock()
    db.get_best_block.return_value = (bytes(32), 100)
    bs = BlockSync(db=db, validator=MagicMock(), peer_manager=_PM(peers))
    bs._header_backfill = HeaderBackfill(10, 12, prev, lower, "mainnet")
    return bs, hdrs


def test_backfill_request_is_not_resent_every_tick():
    p = _Peer()
    bs, hdrs = _bs_with_backfill([p])
    run = asyncio.run
    for _ in range(30):                       # 30 sync_loop ticks
        run(bs._request_backfill_headers())
    assert len(p.sent) == 1                   # was 30 before the fix
    # No reply within HEADERS_RESPONSE_TIME -> re-send once.
    bs._backfill_req_time -= bs._BACKFILL_RESPONSE_TIME + 1
    run(bs._request_backfill_headers())
    assert len(p.sent) == 2
    # Peer that held the request disconnected -> re-send to another at once.
    q = _Peer()
    bs.peer_manager.peers.append(q)
    p.connected = False
    run(bs._request_backfill_headers())
    assert len(q.sent) == 1
    # Walk advances -> the new position is requested immediately.
    assert run(bs._consume_backfill_headers(hdrs[:1], q)) is True
    assert len(q.sent) == 2


def test_stale_duplicate_backfill_reply_is_dropped_not_scored():
    p = _Peer()
    bs, hdrs = _bs_with_backfill([p])
    run = asyncio.run
    run(bs._request_backfill_headers())            # asks for successors of lower
    assert run(bs._consume_backfill_headers(hdrs[:2], p)) is True   # real reply
    # A second, duplicate answer to the SAME first request arrives late: it no
    # longer continues the walk, but it is ours — consumed, not unconnecting.
    assert bs._header_backfill.wants(hdrs[:2]) is False
    assert run(bs._consume_backfill_headers(hdrs[:2], p)) is True
    assert bs._header_backfill.progress() == (2, 3)  # untouched by the duplicate
    # An unrelated batch (not built on any backfill anchor) is NOT swallowed.
    other = [_header(bytes([0x77]) * 32, 5)]
    assert run(bs._consume_backfill_headers(other, p)) is False


def test_no_backfill_no_routing_change():
    from ouroboros.block_sync import BlockSync
    db = MagicMock()
    bs = BlockSync(db=db, validator=MagicMock(), peer_manager=_PM([]))
    assert bs._header_backfill is None and not bs._backfill_sent_anchors
    assert asyncio.run(bs._consume_backfill_headers([_header(bytes(32), 1)], None)) is False


# ---------------------------------------------------------------------------
# 4b. txid from the wire bytes == SHA256d(serialize()) (the old derivation)
# ---------------------------------------------------------------------------


def test_txid_from_wire_bytes_equals_reserialized_txid():
    rng = random.Random(99)
    for k in range(400):
        raw = _rand_tx_bytes(rng, segwit=bool(k % 2))
        tx = TxMessage.from_payload(raw).transaction
        assert tx.txid == _sha256d(tx.serialize())
        if not tx.has_witness:
            assert tx.txid == _sha256d(raw)
    # 0x00 NOT followed by flag 0x01: parsed as a legacy tx with zero inputs
    # (vin=0, vout=2) — the txid must still be the re-serialization's.
    out = (5).to_bytes(8, "little") + b"\x01\x51"
    odd = (2).to_bytes(4, "little") + b"\x00" + b"\x02" + out + out + bytes(4)
    t = TxMessage.from_payload(odd).transaction
    assert not t.has_witness and t.inputs == []
    assert t.txid == _sha256d(t.serialize()) == _sha256d(odd)
