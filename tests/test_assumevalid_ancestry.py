"""assumevalid follows Core's rules, not height alone.

Bug: below mainnet height 850000 (the last entry of the checkpoint table)
ouroboros skipped script checks for ANY block, by height alone
(``sync.can_skip_scripts_for_block``), on every path: the IBD drain, the
Python validator behind ``rpc.accept_block`` (submitblock and the P2P
side-branch reorg engine), and the reorg pre-flight.  Core skips only when
the block is an ancestor of the assumevalid block (mainnet 938343) and of a
best header with at least nMinimumChainWork, more than two weeks of work
below it (validation.cpp ``Chainstate::ConnectBlock``).

Two concrete ways a chain that is not the assumevalid chain reached the skip:

* a fork: fork headers are stored with PoW + difficulty checks only (no
  minimum-work gate) and a fork heavier than the ACTIVE TIP is reorged in
  through ``accept_block`` -> ``validate_block``, which skipped scripts by
  height.  During IBD the active tip is low, so this costs a few diff-1 blocks;
* a header-queue swap: a peer that passed the low-work PRESYNC walk is exempt
  from the minimum-work gate for its REDOWNLOAD, so it can then serve a
  different, cheap chain into the validated-header queue, and the drain
  skipped scripts for those blocks by height.

These tests pin the replacement: ``BlockSync._assumevalid_skip`` (the only
place a skip can be decided), the PRESYNC evidence it relies on, and the drain
routing.  The validator-level and submitblock pins are in
test_assumevalid_force_full_scripts.py and test_assumevalid_submitblock_path.py.
"""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

import pytest

import tests.conftest  # noqa: F401  (installs the sync stub before imports)
from ouroboros import block_sync as bs_mod
from ouroboros.block_sync import BlockSync

try:  # absent before the fix: tests that need it fail on an assertion
    from ouroboros import assumevalid as av
except ImportError:  # pragma: no cover - base commit only
    av = None

BITS = 0x1D00FFFF  # difficulty 1
AV_HEIGHT = 938_343
AV_HASH = bytes.fromhex(
    "00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac"
)[::-1]
PIN_10000 = bytes.fromhex(
    "0000000099c744455f58e6c6e98b671e1bf7f37346bfd4cf5d0274ad8ee660cb"
)[::-1]
TIP_HEIGHT = 999
TIP_HASH = b"\x10" * 32
MIN_WORK = 1 << 40


def _work(bits: int = BITS) -> int:
    return BlockSync._bits_to_work(bits)


def _fake_hash(height: int, salt: int = 0) -> bytes:
    return height.to_bytes(8, "little") + bytes([salt]) * 24


def _queue(
    n: int, *, pins: dict[int, bytes] | None = None, salt: int = 0,
    tip_height: int = TIP_HEIGHT,
):
    """A tip-anchored header queue for heights TIP_HEIGHT+1 .. TIP_HEIGHT+n.

    The decision reads hashes and bits only; continuity was already checked
    by handle_headers when the queue was built.
    """
    pins = pins or {}
    out, prev = [], TIP_HASH
    for i in range(n):
        h = tip_height + 1 + i
        bh = pins.get(h, _fake_hash(h, salt))
        out.append((bh, SimpleNamespace(prev_blockhash=prev, bits=BITS)))
        prev = bh
    return out


class _DB:
    def __init__(self, tip_cw: int = 1000 * _work()):
        self.tip = (TIP_HASH, TIP_HEIGHT)
        self.tip_cw = tip_cw

    def get_best_block(self):
        return self.tip

    def get_chainwork_by_height(self, h):
        return self.tip_cw if h == self.tip[1] else 0

    def get_block_bytes(self, h):
        return None


def _bs(network: str = "mainnet", db=None, validator=None) -> BlockSync:
    pm = SimpleNamespace(network=network, get_all_ready_peers=lambda: [])
    b = BlockSync(db=db or _DB(), validator=validator or SimpleNamespace(), peer_manager=pm)
    b._snapshot_offset_cache = 0
    return b


def _presync_proof(start_height: int = 1500, start_hash: bytes | None = None):
    return {
        "work": 940_000 * _work(),
        "bits": BITS,
        "height": 940_000,
        "start_height": start_height,
        "start_hash": start_hash if start_hash is not None else _fake_hash(start_height),
    }


@pytest.fixture(autouse=True)
def _min_work(monkeypatch):
    monkeypatch.setattr(
        bs_mod._sync_module, "get_minimum_chain_work",
        lambda network: f"{MIN_WORK:064x}", raising=False,
    )


def _skip(b: BlockSync, block_hash: bytes, height: int):
    fn = getattr(b, "_assumevalid_skip", None)
    assert fn is not None, "BlockSync has no assumevalid decision (height-only skip)"
    return fn(block_hash, height)


def _decide(b: BlockSync, height: int = TIP_HEIGHT + 1):
    return _skip(b, b._validated_headers[0][0], height)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
def test_mainnet_assumevalid_block_is_cores_default():
    assert av is not None, "no ouroboros.assumevalid module"
    p = av.params_for("mainnet")
    assert p.height == AV_HEIGHT and p.block_hash == AV_HASH
    assert p.pins[10000] == PIN_10000
    # Every pin is at or below the assumevalid block, no gap over 10,000.
    hs = list(p.pin_heights)
    assert hs[-1] == AV_HEIGHT and hs[0] == 10000
    assert all(b - a <= 10000 for a, b in zip(hs, hs[1:], strict=False))
    assert av.params_for("regtest") is None
    assert av.params_for("testnet4") is None


def test_pins_agree_with_the_correct_checkpoint_hashes():
    """Where the old checkpoint table holds the real chain's hash, the pin at
    the same height must agree (630000; 250000 and others are not 10k
    multiples).  Several old entries (478559, 556767, 740000, 850000) are
    not on Core's chain at all, which is why pins do not reuse them."""
    assert av is not None, "no ouroboros.assumevalid module"
    p = av.params_for("mainnet")
    assert p.pins[630000] == bytes.fromhex(
        "000000000000000000024bead8df69990852c202db0e0097c1a12ea637d7e96d"
    )[::-1]


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------
def test_control_assumevalid_chain_block_skips():
    """CONTROL: a block whose header chain reaches the pinned ancestor, with a
    PRESYNC-proven best header past the assumevalid block, skips scripts."""
    b = _bs()
    b._validated_headers = _queue(9001, pins={10000: PIN_10000})
    b._av_presync_proof = _presync_proof()
    assert _decide(b) == (True, "assumevalid")


def test_cheap_chain_in_the_header_queue_does_not_skip():
    """The REDOWNLOAD swap: a chain that is not the assumevalid chain sits in
    the validated-header queue (its hash at the pinned height is different).
    Height 1000 is far below 850000, so the old rule skipped its scripts."""
    b = _bs()
    b._validated_headers = _queue(9001)  # no real pin at 10000
    b._av_presync_proof = _presync_proof()
    assert _decide(b) == (False, "block not in assumevalid chain")
    # The old rule, for the record, said skip here.
    assert bs_mod._sync_module.can_skip_scripts_for_block(
        "mainnet", TIP_HEIGHT + 1, b._validated_headers[0][0]
    ) is True


def test_block_that_is_not_the_queue_head_does_not_skip():
    """Fork / submitblock blocks never reach the decision as the queue head."""
    b = _bs()
    b._validated_headers = _queue(9001, pins={10000: PIN_10000})
    b._av_presync_proof = _presync_proof()
    ok, reason = _skip(b, _fake_hash(TIP_HEIGHT + 1, salt=7), TIP_HEIGHT + 1)
    assert (ok, reason) == (False, "block not in best header chain")
    ok, reason = _skip(b, b._validated_headers[0][0], TIP_HEIGHT + 2)
    assert (ok, reason) == (False, "block not in best header chain")


def test_pin_beyond_the_header_window_does_not_skip():
    b = _bs()
    b._validated_headers = _queue(8999)  # ends at 9998, the pin is at 10000
    b._av_presync_proof = _presync_proof()
    assert _decide(b) == (False, "assumevalid chain not yet in headers")


def test_without_the_assumevalid_block_in_headers_does_not_skip():
    """Ancestry to a pin is proven but nothing shows the assumevalid block
    itself (no PRESYNC proof, the queue stops short of 938343)."""
    b = _bs()
    b._validated_headers = _queue(9001, pins={10000: PIN_10000})
    assert _decide(b) == (False, "assumevalid hash not in headers")


def test_best_header_below_minimum_chain_work_does_not_skip(monkeypatch):
    b = _bs()
    b._validated_headers = _queue(9001, pins={10000: PIN_10000})
    b._av_presync_proof = _presync_proof()
    monkeypatch.setattr(
        bs_mod._sync_module, "get_minimum_chain_work",
        lambda network: f"{(10**6) * _work():064x}",
    )
    assert _decide(b) == (False, "best header chainwork below minimumchainwork")


def test_block_within_two_weeks_of_best_header_does_not_skip():
    """Core's equivalent-time rule: at constant difficulty two weeks is 2016
    blocks; a best header exactly 2016 blocks past the block is too recent."""
    tip = 9989  # short queue (11 headers to the pin), so PRESYNC is best
    db = _DB()
    db.tip = (TIP_HASH, tip)
    b = _bs(db=db)
    b._validated_headers = _queue(11, pins={10000: PIN_10000}, tip_height=tip)
    block_cw = db.tip_cw + _work()
    proof = _presync_proof()
    proof["work"] = block_cw + 2016 * _work()
    b._av_presync_proof = proof
    assert _decide(b, tip + 1) == (False, "block too recent relative to best header")
    proof["work"] = block_cw + 2017 * _work()
    assert _decide(b, tip + 1) == (True, "assumevalid")


def test_queue_reaching_the_assumevalid_block_is_its_own_proof():
    """Near the assumevalid block the queue itself holds it: no PRESYNC proof
    needed, Core's in-headers test is met by the queue."""
    tip = AV_HEIGHT - 5000
    db = _DB(tip_cw=2 * MIN_WORK)
    db.tip = (TIP_HASH, tip)
    b = _bs(db=db)
    b._validated_headers = _queue(7000, pins={AV_HEIGHT: AV_HASH}, tip_height=tip)
    assert _decide(b, tip + 1) == (True, "assumevalid")
    # Same window, a different hash at 938343: not the assumevalid chain.
    b._validated_headers = _queue(7000, tip_height=tip)
    assert _decide(b, tip + 1) == (False, "block not in assumevalid chain")


def test_presync_proof_must_be_on_this_blocks_chain():
    """A PRESYNC walk that started above the pin only vouches for blocks
    whose header chain contains the walk's start header."""
    b = _bs()
    b._validated_headers = _queue(9001, pins={10000: PIN_10000})
    b._av_presync_proof = _presync_proof(start_height=10500, start_hash=b"\x77" * 32)
    assert _decide(b) == (False, "assumevalid hash not in headers")
    b._av_presync_proof = _presync_proof(
        start_height=9500, start_hash=b._validated_headers[9500 - TIP_HEIGHT - 1][0]
    )
    assert _decide(b) == (True, "assumevalid")


@pytest.mark.parametrize("height", [AV_HEIGHT + 1, 950_000])
def test_above_assumevalid_height_does_not_skip(height):
    b = _bs()
    b._validated_headers = _queue(1)
    ok, reason = _skip(b, b._validated_headers[0][0], height)
    assert (ok, reason) == (False, "block height above assumevalid height")


def test_assumevalid_zero_and_regtest_never_skip():
    b = _bs()
    b._validated_headers = _queue(9001, pins={10000: PIN_10000})
    b._av_presync_proof = _presync_proof()
    b.force_full_scripts = True
    assert _decide(b)[0] is False
    r = _bs(network="regtest")
    r._validated_headers = _queue(9001, pins={10000: PIN_10000})
    r._av_presync_proof = _presync_proof()
    assert _decide(r) == (False, "no assumevalid block for this network")


# ---------------------------------------------------------------------------
# PRESYNC evidence
# ---------------------------------------------------------------------------
def _peer():
    async def send_message(msg):
        return None
    return SimpleNamespace(
        host="203.0.113.5", port=8333, send_message=send_message,
        adjust_score=lambda d: None, note_block_height=lambda h: None,
    )


def _walk(b: BlockSync, start: int, n: int, hash_at) -> None:
    """Open a PRESYNC walk at *start* and feed it *n* headers."""
    peer = _peer()
    b._build_locator = lambda h: [TIP_HASH]

    async def run():
        await b._begin_lowwork_presync(
            2000, b"\x55" * 32, start, BITS, peer, 0, n * _work() // 2,
        )
        prev, hdrs, hashes = b"\x55" * 32, [], []
        for i in range(n):
            h = start + 1 + i
            hh = hash_at(h)
            hdrs.append(SimpleNamespace(prev_blockhash=prev, bits=BITS))
            hashes.append(hh)
            prev = hh
        await b._advance_lowwork_presync(hdrs, peer, hashes=hashes)

    asyncio.run(asyncio.wait_for(run(), 10.0))
    assert b._peer_key(peer) in b._lowwork_validated, "walk did not reach the bar"


def test_presync_through_the_assumevalid_block_is_recorded():
    b = _bs()
    _walk(b, AV_HEIGHT - 100, 200,
          lambda h: AV_HASH if h == AV_HEIGHT else _fake_hash(h))
    proof = getattr(b, "_av_presync_proof", "MISSING")
    assert isinstance(proof, dict), f"no PRESYNC assumevalid evidence: {proof!r}"
    assert proof["start_height"] == AV_HEIGHT - 100
    assert proof["height"] == AV_HEIGHT + 100


def test_presync_of_another_chain_proves_nothing():
    """The walk crosses nMinimumChainWork (so the peer is still exempted, as
    before) but its hash at 938343 is not the assumevalid block."""
    b = _bs()
    _walk(b, AV_HEIGHT - 100, 200, lambda h: _fake_hash(h))
    assert getattr(b, "_av_presync_proof", "MISSING") is None


def test_presync_that_misses_a_pin_proves_nothing():
    """Reaching the real assumevalid hash is not enough if an earlier pin on
    the walk did not match."""
    b = _bs()
    pins = av.params_for("mainnet").pins if av is not None else {}
    _walk(b, 929_000, AV_HEIGHT - 929_000 + 10,
          lambda h: AV_HASH if h == AV_HEIGHT else (
              _fake_hash(h, 9) if h == 930_000 else pins.get(h, _fake_hash(h))))
    assert getattr(b, "_av_presync_proof", "MISSING") is None
    b2 = _bs()
    _walk(b2, 929_000, AV_HEIGHT - 929_000 + 10,
          lambda h: pins.get(h, _fake_hash(h)))
    assert isinstance(getattr(b2, "_av_presync_proof", None), dict), (
        "CONTROL: the same walk with the real pin must be recorded"
    )


# ---------------------------------------------------------------------------
# Drain routing: who decides, and what the validators are told
# ---------------------------------------------------------------------------
def _coinbase_scriptsig(height: int) -> bytes:
    enc = height.to_bytes(4, "little").rstrip(b"\x00")
    if enc[-1] & 0x80:
        enc += b"\x00"
    return bytes([len(enc)]) + enc + b"\x00"


class _DrainDB(_DB):
    def __init__(self):
        super().__init__()
        self.rust_calls = 0

    def validate_block_from_bytes(self, raw, prev_height, skip_scripts, network):
        self.rust_calls += 1  # the no-script fast path


class _Validator:
    def __init__(self, db, hashes):
        self.db, self.hashes = db, hashes
        self.calls = []

    def validate_block(self, block, **kw):
        self.calls.append(kw)
        return True, ""

    def apply_block(self, block):
        self.db.tip = (self.hashes[id(block)], self.db.tip[1] + 1)


def _drain(queue, proof):
    async def run():
        db = _DrainDB()
        h1 = queue[0][0]
        cb = SimpleNamespace(inputs=[SimpleNamespace(script_sig=_coinbase_scriptsig(TIP_HEIGHT + 1))])
        b1 = SimpleNamespace(
            transactions=[cb], prev_blockhash=TIP_HASH, timestamp=int(time.time()),
            version=0x20000000, merkle_root=b"\x00" * 32, bits=BITS, nonce=0,
        )
        validator = _Validator(db, {id(b1): h1})
        b = _bs(db=db, validator=validator)
        b._prebase_headers_complete = True
        b.set_reorg_handler(SimpleNamespace(
            node=SimpleNamespace(), _attach_side_branch_block=None,
            _reorg_to_side_branch_tip=None, _side_branch_blocks={}))
        b._validated_headers = list(queue)
        b._av_presync_proof = proof
        b._buffer_put(h1, (b1, b"raw1"))
        n = await asyncio.wait_for(b._drain_block_buffer(), 5.0)
        for t in list(b._announce_tasks):
            t.cancel()
        return n, db, validator

    return asyncio.run(asyncio.wait_for(run(), 10.0))


def test_drain_checks_scripts_for_a_cheap_chain_below_the_old_cut():
    """The REDOWNLOAD swap end to end: the drain must not send a block on a
    chain that is not the assumevalid chain down the no-script Rust path."""
    n, db, validator = _drain(_queue(9001), _presync_proof())
    assert n == 1
    assert db.rust_calls == 0, (
        "a block off the assumevalid chain went down the no-script fast path "
        "(height-only skip below 850000)"
    )
    assert len(validator.calls) == 1
    assert validator.calls[0].get("assumed_valid", None) is False, validator.calls


def test_control_drain_skips_scripts_on_the_assumevalid_chain():
    """CONTROL: the same drain with the real pin in the queue still takes the
    no-script fast path, so IBD below the assumevalid block keeps its skip."""
    n, db, validator = _drain(_queue(9001, pins={10000: PIN_10000}), _presync_proof())
    assert n == 1
    assert db.rust_calls == 1 and validator.calls == []
