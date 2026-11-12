"""A witness-padded copy of an honest block is BLOCK_MUTATED, not invalid.

Finding (cffix-ouroboros-witness-malleation-before-limits): the witness is
not committed to by the block header's merkle root, so anyone relaying a block
can rewrite it.  ``BlockValidator.validate_block`` ran the witness-dependent
limits (block weight with witness bytes, P2WSH witness sigops) BEFORE the
witness-commitment check, so a peer that padded the witness of an honest block
got the block rejected as ``bad-blk-weight`` / ``bad-blk-sigops`` -- consensus
verdicts that mark the HEADER HASH failed (``_failed_blocks``) and
perm-rejected.  The node then refused the honest block and its chain when it
arrived intact from anyone else: a chain split driven by one relaying peer.

Bitcoin Core (src/validation.cpp): ``CheckBlock`` verifies the merkle root
before any size limit; ``ContextualCheckBlock`` runs ``CheckWitnessMalleation``
before the ``bad-blk-weight`` check; the witness sigop cost is only summed in
``ConnectBlock``, later still.  Malleation failures are ``BLOCK_MUTATED`` and
are never cached as invalid.

Every test builds REAL ``Block`` / ``Transaction`` objects and runs the real
validator (no stubbed checks except the DB).  The honest block is the control:
it passes ``validate_block``.  Each malleated copy keeps the honest header
hash (the witness is outside the txid merkle tree), so it names the same block.
"""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock

import pytest

import tests.conftest  # noqa: F401  (installs the sync stub before imports)

from ouroboros.database import Block, Transaction, TxIn, TxOut

NETWORK = "regtest"
HEIGHT = 200
PREV_HASH = b"\x11" * 32
PREV_TIME = 1_700_000_000
REGTEST_BITS = 0x207FFFFF

FUND_TXID = b"\x5a" * 32
FUND_VALUE = 1_000_000
WITNESS_SCRIPT = b"\x51"  # OP_TRUE: spendable with no signature
P2WSH_SPK = b"\x00\x20" + hashlib.sha256(WITNESS_SCRIPT).digest()


def _dsha(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _merkle(hashes: list[bytes]) -> bytes:
    level = list(hashes)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_dsha(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def _tx(inputs, outputs, *, witness: bool) -> Transaction:
    tx = Transaction(
        txid=b"", version=2, locktime=0, inputs=inputs, outputs=outputs,
        has_witness=witness,
    )
    tx.txid = _dsha(tx.serialize())
    return tx


def _bip34_push(height: int) -> bytes:
    # CScript() << nHeight: OP_1..OP_16 for 1..16, else a minimal push.
    if 1 <= height <= 16:
        return bytes([0x50 + height])
    n = height.to_bytes((height.bit_length() + 8) // 8, "little")
    return bytes([len(n)]) + n


def _build_block(
    spend_witness: list[bytes],
    commit_witness: list[bytes] | None = None,
    spend_spk: bytes = b"\x51",
) -> Block:
    """Coinbase + one P2WSH spend.  The coinbase commits to the wtxid tree
    built with ``commit_witness`` (default: the spend's own witness).
    ``spend_spk`` is the spend's output script (txid-committed)."""
    if commit_witness is None:
        commit_witness = spend_witness
    nonce = bytes(32)

    def _spend(w):
        return _tx(
            [TxIn(FUND_TXID, 0, b"", 0xFFFFFFFF, witness=list(w))],
            [TxOut(FUND_VALUE - 10_000, spend_spk)],
            witness=True,
        )

    committed_spend = _spend(commit_witness)
    witness_root = _merkle([bytes(32), committed_spend.get_wtxid()])
    commitment = _dsha(witness_root + nonce)
    coinbase = _tx(
        [TxIn(bytes(32), 0xFFFFFFFF, _bip34_push(HEIGHT) + b"\x00", 0xFFFFFFFF,
              witness=[nonce])],
        [TxOut(0, b"\x51"),
         TxOut(0, b"\x6a\x24\xaa\x21\xa9\xed" + commitment)],
        witness=True,
    )
    spend = _spend(spend_witness)
    txs = [coinbase, spend]
    merkle_root = _merkle([t.get_txid() for t in txs])
    header = (
        (4).to_bytes(4, "little") + PREV_HASH + merkle_root
        + (PREV_TIME + 600).to_bytes(4, "little")
        + REGTEST_BITS.to_bytes(4, "little") + (0).to_bytes(4, "little")
    )
    return Block(
        version=4, prev_blockhash=PREV_HASH, merkle_root=merkle_root,
        timestamp=PREV_TIME + 600, bits=REGTEST_BITS, nonce=0,
        transactions=txs, hash=_dsha(header), height=None,
    )


class _MemDB:
    """In-memory chainstate: the parent header and one P2WSH coin."""

    def __init__(self):
        self.prev = Block(
            version=4, prev_blockhash=b"\x22" * 32, merkle_root=bytes(32),
            timestamp=PREV_TIME, bits=REGTEST_BITS, nonce=0,
            transactions=[], hash=PREV_HASH, height=HEIGHT - 1,
        )
        self.coins = {
            (FUND_TXID, 0): {
                "txid": FUND_TXID, "vout": 0, "value": FUND_VALUE,
                "script_pubkey": P2WSH_SPK, "height": 100,
                "is_coinbase": False,
            }
        }

    def get_block(self, h):
        return self.prev if h == PREV_HASH else None

    def get_block_header(self, h):
        return self.get_block(h)

    def get_best_block(self):
        return PREV_HASH, HEIGHT - 1

    def get_median_time_past(self, height):
        return PREV_TIME - 600

    def get_block_hash_at_height(self, height):
        return None

    def get_utxo(self, txid, vout):
        return self.coins.get((bytes(txid), vout))

    def get_utxo_batch(self, outpoints):
        return [self.get_utxo(t, v) for t, v in outpoints]


def _validator():
    from ouroboros.validation import BlockValidator

    return BlockValidator(_MemDB(), network=NETWORK)


def _validate(block: Block) -> tuple[bool, str]:
    return _validator().validate_block(
        block, known_height=HEIGHT, skip_pow=True, force_check_scripts=True,
        current_time=PREV_TIME + 3600,
    )


HONEST_WITNESS = [WITNESS_SCRIPT]
# (a) witness[-1] = 4001 x OP_CHECKMULTISIG: 4001 * 20 = 80,020 witness
#     sigops > MAX_BLOCK_SIGOPS_COST (80,000).
SIGOP_WITNESS = [b"\xae" * 4001]
# (b) a junk witness item pushing the block past MAX_BLOCK_WEIGHT.
WEIGHT_WITNESS = [b"\x00" * 4_000_001, WITNESS_SCRIPT]


def test_control_honest_block_passes_validate_block():
    """CONTROL: the honest block is valid -- otherwise every assertion below
    could be satisfied by an unrelated early reject."""
    ok, err = _validate(_build_block(HONEST_WITNESS))
    assert (ok, err) == (True, "")


def test_malleated_copies_keep_the_honest_block_hash():
    honest = _build_block(HONEST_WITNESS)
    for w in (SIGOP_WITNESS, WEIGHT_WITNESS):
        copy = _build_block(w, commit_witness=HONEST_WITNESS)
        assert copy.hash == honest.hash
        assert copy.merkle_root == honest.merkle_root


@pytest.mark.parametrize(
    "padded", [SIGOP_WITNESS, WEIGHT_WITNESS], ids=["witness-sigops", "witness-weight"]
)
def test_witness_padded_copy_is_witness_merkle_mismatch_and_mutated(padded):
    from ouroboros.block_sync import classify_block_reject

    copy = _build_block(padded, commit_witness=HONEST_WITNESS)
    ok, err = _validate(copy)
    assert not ok
    assert err == "bad-witness-merkle-match", err
    assert classify_block_reject(err) == "mutated"


@pytest.mark.parametrize(
    "padded,token",
    [(SIGOP_WITNESS, "bad-blk-sigops"), (WEIGHT_WITNESS, "bad-blk-weight")],
    ids=["witness-sigops", "witness-weight"],
)
def test_control_committed_oversized_block_is_still_a_limit_verdict(padded, token):
    """NEGATIVE CONTROL for the reorder: when the coinbase DOES commit to the
    oversized witness (a block a miner really produced), the limits still
    reject it, as a consensus verdict.  The reorder must not let a genuinely
    overweight / oversigop block through."""
    from ouroboros.block_sync import classify_block_reject
    from ouroboros.rpc import bip22_result_string

    blk = _build_block(padded)  # commits to its own witness
    ok, err = _validate(blk)
    assert not ok
    assert classify_block_reject(err) != "mutated", err
    if token == "bad-blk-sigops":
        assert bip22_result_string(err) == token, err
        assert classify_block_reject(err) == "verdict"
    else:
        # The Python weight message carries no Core token yet (maps to the
        # generic "rejected"); only the rule that fired is asserted here.
        assert "weight" in err.lower(), err


# 20,001 x OP_CHECKSIG in a txid-committed output script: legacy sigop cost
# 80,004 > MAX_BLOCK_SIGOPS_COST.  Core rejects that in CheckBlock
# ("bad-blk-sigops", legacy count only), BEFORE CheckWitnessMalleation.
LEGACY_OVER_BUDGET_SPK = b"\xac" * 20_001
TAMPERED_WITNESS = [WITNESS_SCRIPT, b"\x00"]


def test_legacy_sigop_budget_beats_witness_tamper():
    """GUARD: a block over the LEGACY sigop budget is invalid whatever its
    witness says (the scripts are covered by the txid merkle root).  With
    the witness also tampered it must still be the bad-blk-sigops verdict,
    as in Core, not an uncached witness mismatch."""
    from ouroboros.block_sync import classify_block_reject
    from ouroboros.rpc import bip22_result_string

    blk = _build_block(TAMPERED_WITNESS, commit_witness=HONEST_WITNESS,
                       spend_spk=LEGACY_OVER_BUDGET_SPK)
    ok, err = _validate(blk)
    assert not ok
    assert bip22_result_string(err) == "bad-blk-sigops", err
    assert classify_block_reject(err) == "verdict"


@pytest.mark.parametrize(
    "rust_error,kind",
    [
        # Strings the Rust validate_block_from_bytes route raises (the FFI
        # prefixes "validate: ").  The malleation errors must classify as
        # mutated; SizeExceeded is a verdict -- which is why the Rust order
        # (merkle + witness commitment before the weight) matters.
        ("validate: BIP141: witness commitment mismatch", "mutated"),
        ("validate: BIP141: coinbase witness must be exactly one 32-byte item", "mutated"),
        ("validate: Invalid merkle root", "mutated"),
        ("validate: Block size exceeds limit", "verdict"),
    ],
)
def test_rust_route_error_strings_classify_like_core(rust_error, kind):
    from ouroboros.block_sync import classify_block_reject

    assert classify_block_reject(rust_error) == kind


# ---------------------------------------------------------------------------
# Through the P2P drain: the hash must not be cached as failed / perm-rejected
# ---------------------------------------------------------------------------


def _drain_bs(validator):
    from ouroboros.block_sync import BlockSync

    db = MagicMock()
    db.get_best_block.return_value = (PREV_HASH, HEIGHT - 1)
    pm = MagicMock()
    pm.misbehaving = MagicMock(return_value=True)
    bs = BlockSync(db=db, validator=validator, peer_manager=pm)
    bs._prebase_headers_complete = True
    return bs


def _stage(bs, block: Block, child_hash: bytes):
    h1 = MagicMock()
    h1.prev_blockhash = PREV_HASH
    h2 = MagicMock()
    h2.prev_blockhash = block.hash
    bs._validated_headers = [(block.hash, h1), (child_hash, h2)]
    bs._ibd_block_buffer[block.hash] = (block, block.serialize())
    bs.requested_blocks[block.hash] = 1.0
    bs._block_source_peer_addr[block.hash] = "127.0.0.2:5555"


def _skip_pow_validator():
    v = _validator()
    real = v.validate_block

    def _vb(block, **kw):
        kw.setdefault("skip_pow", True)
        kw.setdefault("current_time", PREV_TIME + 3600)
        return real(block, **kw)

    v.validate_block = _vb
    return v


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "padded", [SIGOP_WITNESS, WEIGHT_WITNESS], ids=["witness-sigops", "witness-weight"]
)
async def test_drain_witness_padded_copy_not_marked_failed(monkeypatch, padded):
    monkeypatch.setenv("OUROBOROS_DISABLE_RUST_VALIDATE", "1")
    bs = _drain_bs(_skip_pow_validator())
    copy = _build_block(padded, commit_witness=HONEST_WITNESS)
    _stage(bs, copy, b"\x77" * 32)

    await bs._drain_block_buffer_locked()

    assert copy.hash not in getattr(bs, "_failed_blocks", set())
    assert copy.hash not in bs._perm_rejected_blocks
    bs.db.connect_block_from_bytes.assert_not_called()


@pytest.mark.asyncio
async def test_drain_control_committed_oversigop_block_is_marked_failed(monkeypatch):
    """CONTROL: the same drain DOES mark a genuinely invalid block failed, so
    the absence above is the classification, not a drain that never decides."""
    monkeypatch.setenv("OUROBOROS_DISABLE_RUST_VALIDATE", "1")
    bs = _drain_bs(_skip_pow_validator())
    blk = _build_block(SIGOP_WITNESS)
    _stage(bs, blk, b"\x78" * 32)

    await bs._drain_block_buffer_locked()

    assert blk.hash in getattr(bs, "_failed_blocks", set())
    assert blk.hash in bs._perm_rejected_blocks


# ---------------------------------------------------------------------------
# submitblock side-branch store path (rpc._attach_side_branch_block)
# ---------------------------------------------------------------------------


def _side_branch_block(prev: bytes, height: int, spend_witness, commit_witness):
    """A PoW-solved regtest sibling: coinbase (BIP34 + witness commitment over
    ``commit_witness``) + one witness spend.  Side-branch storage runs only the
    context-free CheckBlock / ContextualCheckBlock set, so the spent outpoint
    need not exist."""
    import struct

    from tests._f0_chain import BASE_TIME, varint

    nonce = bytes(32)

    def _spend(w):
        return _tx(
            [TxIn(FUND_TXID, 0, b"", 0xFFFFFFFF, witness=list(w))],
            [TxOut(FUND_VALUE - 10_000, b"\x51")],
            witness=True,
        )

    witness_root = _merkle([bytes(32), _spend(commit_witness).get_wtxid()])
    coinbase = _tx(
        [TxIn(bytes(32), 0xFFFFFFFF, _bip34_push(height) + b"\xc7\xf1",
              0xFFFFFFFF, witness=[nonce])],
        [TxOut(0, b"\x51"),
         TxOut(0, b"\x6a\x24\xaa\x21\xa9\xed" + _dsha(witness_root + nonce))],
        witness=True,
    )
    txs = [coinbase, _spend(spend_witness)]
    root = _merkle([t.get_txid() for t in txs])
    ts = BASE_TIME + height * 600 + 13
    for n in range(4_000_000):
        header = (struct.pack("<i", 0x20000000) + prev + root
                  + struct.pack("<III", ts, REGTEST_BITS, n))
        h = _dsha(header)
        if h[31] < 0x7F:
            body = varint(len(txs)) + b"".join(t.serialize_with_witness() for t in txs)
            return header + body, h
    raise RuntimeError("could not solve regtest header")  # pragma: no cover


@pytest.fixture
def side_branch(tmp_path):
    """Production submitblock side-branch engine against the real Rust DB
    (same harness as test_submitblock_side_branch_inconclusive.py), with a
    real BlockValidator so the witness-commitment gate is live."""
    from tests._real_sync import real_sync_installed, real_sync_or_skip

    sync = real_sync_or_skip()
    with real_sync_installed(sync):
        from ouroboros.validation import BlockValidator
        from tests.test_invalidateblock_best_chain import TIP, _setup

        bdb, server, hashes = _setup(tmp_path)
        server.node.validator = BlockValidator(bdb, network="regtest")

        def attach(spend_witness, commit_witness):
            import asyncio

            raw, h = _side_branch_block(
                hashes[TIP - 1], TIP, spend_witness, commit_witness
            )
            res = asyncio.run(server._attach_side_branch_block(
                bdb, raw, h, hashes[TIP - 1], TIP))
            return res, h in server._side_branch_blocks

        yield attach


def test_side_branch_witness_padded_copy_is_witness_mismatch(side_branch):
    """The padded copy of a valid side-branch sibling is refused as the
    witness malleation it is (bad-witness-merkle-match), not bad-blk-weight,
    and is never stored."""
    res, stored = side_branch(WEIGHT_WITNESS, HONEST_WITNESS)
    assert res == "bad-witness-merkle-match", res
    assert not stored


def test_side_branch_control_honest_sibling_is_stored(side_branch):
    """CONTROL: the honest sibling passes every side-branch gate and is
    stored, so the reject above is the padding, not the harness."""
    res, stored = side_branch(HONEST_WITNESS, HONEST_WITNESS)
    assert res is None, res
    assert stored


def test_side_branch_control_committed_overweight_is_still_bad_blk_weight(side_branch):
    """NEGATIVE CONTROL: a sibling whose coinbase COMMITS to the overweight
    witness is still bad-blk-weight -- the reorder lets nothing oversized in."""
    res, stored = side_branch(WEIGHT_WITNESS, WEIGHT_WITNESS)
    assert res == "bad-blk-weight", res
    assert not stored


@pytest.mark.asyncio
async def test_drain_legacy_over_budget_with_tampered_witness_is_marked_failed(monkeypatch):
    """GUARD through the drain: the legacy-over-budget block with a tampered
    witness is a verdict -- marked failed and perm-rejected."""
    monkeypatch.setenv("OUROBOROS_DISABLE_RUST_VALIDATE", "1")
    bs = _drain_bs(_skip_pow_validator())
    blk = _build_block(TAMPERED_WITNESS, commit_witness=HONEST_WITNESS,
                       spend_spk=LEGACY_OVER_BUDGET_SPK)
    _stage(bs, blk, b"\x79" * 32)

    await bs._drain_block_buffer_locked()

    assert blk.hash in getattr(bs, "_failed_blocks", set())
    assert blk.hash in bs._perm_rejected_blocks

