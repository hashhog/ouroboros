"""getmempoolentry / verbose getrawmempool match Core v31.1 entryToJSON.

Core rpc/mempool.cpp entryToJSON, field by field:

* ``ancestorsize`` / ``descendantsize`` sum GetTxSize, the sigop-adjusted
  vsize, over the set including the tx (CalculateAncestorData /
  CalculateDescendantData); ouroboros summed stripped bytes.
* ``chunkweight`` / ``fees.chunk``: GetMainChunkFeerate, the tx's chunk in
  its cluster's optimal linearization, in modified fee and sigop-adjusted
  weight; ouroboros had neither.
* ``depends`` is a std::set of display hex (sorted); ``spentby`` is
  GetChildren, sorted by txid in uint256 (internal byte) order.
* ``bip125-replaceable``: IsRBFOptIn, the tx or an in-pool ancestor signals;
  ouroboros had no field.
* ``unbroadcast``: IsUnbroadcastTx, set by BroadcastTransaction
  (sendrawtransaction, the wallet), cleared when a peer fetches the tx or it
  leaves the pool; ouroboros always said false.
* ``height``: the tip when the tx entered.  InvalidateBlock re-adds each
  block's txs right after that block's DisconnectTip, so a tx confirmed at
  height h comes back with entry height h - 1; ouroboros gave every re-added
  tx the final tip.

The wallet test is the gettransaction ``details`` rows the same Core
regtest run exposes once getmempoolentry stops raising: Core skips the
change output of a tx the wallet funded and lists a payment to one of its
own addresses as both "send" and "receive".

Core v31.1 regtest rows: mempool, seed_mempool_reorg, seed_warden_e,
warden_a/b/c/d/e, warden_invalidated_submit, reorg, wallet.
"""

from __future__ import annotations

import asyncio
import itertools
import random
import struct
from types import SimpleNamespace

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

import pytest  # noqa: E402

from tests._f0_chain import COIN, FUNDING, dsha, varint  # noqa: E402
from tests.test_disconnect_pool_keeps_witness import (  # noqa: E402
    P2WSH,
    TIP,
    _segwit_block,
    _setup,
)

SIGNAL = 0xFFFFFFFD  # BIP125: nSequence <= this opts in
FINAL = 0xFFFFFFFE


@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(sync):
        yield


def _build(inputs, values, version=2):
    """(txid, legacy, wire) spending P2WSH(OP_TRUE) coins.

    *inputs*: [(prev_txid, vout, nSequence)], *values*: output amounts, each
    to P2WSH(OP_TRUE)."""
    ins = b"".join(t + struct.pack("<I", v) + b"\x00" + struct.pack("<I", seq)
                   for t, v, seq in inputs)
    outs = b"".join(struct.pack("<Q", val) + varint(len(P2WSH)) + P2WSH for val in values)
    body = varint(len(inputs)) + ins + varint(len(values)) + outs
    legacy = struct.pack("<I", version) + body + struct.pack("<I", 0)
    wit = b"\x01\x01\x51" * len(inputs)
    wire = struct.pack("<I", version) + b"\x00\x01" + body + wit + struct.pack("<I", 0)
    return dsha(legacy), legacy, wire


def _tx(wire):
    from ouroboros.p2p_messages import TxMessage
    return TxMessage.from_payload(wire, 0).transaction


def _add(mempool, wire):
    ok, err = mempool.add_transaction(_tx(wire), height=TIP)
    assert ok, err


def _entry(server, txid):
    return asyncio.run(server.rpc_getmempoolentry(txid[::-1].hex()))


def _fund(bdb, tag, value=FUNDING):
    txid = dsha(tag)
    bdb._db.add_utxo_raw(txid, 0, value, P2WSH, 1, False)
    return txid


def test_ancestor_and_descendant_sizes_are_vsize(tmp_path):
    bdb, _chain, _bs, server, mempool, fund = _setup(tmp_path)
    p, _l, pw = _build([(fund, 0, FINAL)], [FUNDING - 1_000])
    c, _l, cw = _build([(p, 0, FINAL)], [FUNDING - 3_000])
    _add(mempool, pw)
    _add(mempool, cw)
    vp, vc = mempool.transactions[p].vsize, mempool.transactions[c].vsize
    assert vp > mempool.transactions[p].size, "segwit: vsize must exceed stripped size"
    ep, ec = _entry(server, p), _entry(server, c)
    assert (ep["vsize"], ec["vsize"]) == (vp, vc)
    assert ep["ancestorsize"] == vp
    assert ep["descendantsize"] == vp + vc
    assert ec["ancestorsize"] == vp + vc
    assert ec["descendantsize"] == vc


def test_bip125_replaceable_is_inherited_from_ancestors(tmp_path):
    bdb, _chain, _bs, server, mempool, fund = _setup(tmp_path)
    other = _fund(bdb, b"other")
    p, _l, pw = _build([(fund, 0, SIGNAL)], [FUNDING - 1_000])
    c, _l, cw = _build([(p, 0, FINAL)], [FUNDING - 2_000])
    q, _l, qw = _build([(other, 0, FINAL)], [FUNDING - 1_000])
    for w in (pw, cw, qw):
        _add(mempool, w)
    assert _entry(server, p)["bip125-replaceable"] is True
    assert _entry(server, c)["bip125-replaceable"] is True, "parent signals"
    assert _entry(server, q)["bip125-replaceable"] is False


def test_bip125_replaceable_ignores_truc(tmp_path):
    """Core IsRBFOptIn checks nSequence only: a non-signalling v3 (TRUC) tx
    is replaceable by policy but reports bip125-replaceable false."""
    bdb, _chain, _bs, server, mempool, fund = _setup(tmp_path)
    t, _l, tw = _build([(fund, 0, FINAL)], [FUNDING - 1_000], version=3)
    _add(mempool, tw)
    assert mempool.is_rbf_opt_in(t), "TRUC is replaceable by policy"
    assert _entry(server, t)["bip125-replaceable"] is False


def test_chunk_is_the_cpfp_package(tmp_path):
    bdb, _chain, _bs, server, mempool, fund = _setup(tmp_path)
    other = _fund(bdb, b"other")
    p, _l, pw = _build([(fund, 0, FINAL)], [FUNDING - 1_000])
    c, _l, cw = _build([(p, 0, FINAL)], [FUNDING - 1_000 - 20_000])
    q, _l, qw = _build([(other, 0, FINAL)], [FUNDING - 5_000])
    for w in (pw, cw, qw):
        _add(mempool, w)
    wp = mempool.transactions[p].sigop_adjusted_weight
    wc = mempool.transactions[c].sigop_adjusted_weight
    for t in (p, c):
        e = _entry(server, t)
        assert e["chunkweight"] == wp + wc
        assert e["fees"]["chunk"] == pytest.approx(21_000 / 1e8)
    e = _entry(server, q)
    assert e["chunkweight"] == mempool.transactions[q].sigop_adjusted_weight
    assert e["fees"]["chunk"] == pytest.approx(5_000 / 1e8)


def test_chunk_uses_modified_fee_and_keeps_equal_feerates_apart(tmp_path):
    """A child at the parent's feerate is not merged into its chunk (Core
    merges only a strictly higher feerate); prioritisetransaction moves it."""
    bdb, _chain, _bs, server, mempool, fund = _setup(tmp_path)
    p, _l, pw = _build([(fund, 0, FINAL)], [FUNDING - 1_000])
    c, _l, cw = _build([(p, 0, FINAL)], [FUNDING - 2_000])
    _add(mempool, pw)
    _add(mempool, cw)
    w = mempool.transactions[p].sigop_adjusted_weight
    assert mempool.transactions[c].sigop_adjusted_weight == w
    assert (_entry(server, p)["chunkweight"], _entry(server, c)["chunkweight"]) == (w, w)
    assert _entry(server, c)["fees"]["chunk"] == pytest.approx(1_000 / 1e8)
    mempool.prioritise_transaction(c, 9_000)
    e = _entry(server, p)
    assert e["chunkweight"] == 2 * w
    assert e["fees"]["chunk"] == pytest.approx(11_000 / 1e8)


def test_chunk_of_a_star_matches_core_warden_e_shape(tmp_path):
    """warden_e: one parent, children of rising fee.  The best chunk is the
    parent plus every child that raises its feerate; the rest stand alone."""
    bdb, _chain, _bs, server, mempool, fund = _setup(tmp_path)
    n = 12
    each = (FUNDING - 10_000) // n
    p, _l, pw = _build([(fund, 0, FINAL)], [each] * n)
    _add(mempool, pw)
    kids = []
    for i in range(n):
        c, _l, cw = _build([(p, i, FINAL)], [each - (i + 1) * 1_000])
        _add(mempool, cw)
        kids.append(c)
    fee = {t: mempool.transactions[t].fee for t in [p, *kids]}
    wt = {t: mempool.transactions[t].sigop_adjusted_weight for t in fee}
    # Brute force: parent + the top-k children, best k.
    best = max(range(n + 1), key=lambda k: (
        (fee[p] + sum(fee[x] for x in kids[n - k:])) * 10**9
        // (wt[p] + sum(wt[x] for x in kids[n - k:]))))
    top = set(kids[n - best:])
    cf, cw_ = fee[p] + sum(fee[x] for x in top), wt[p] + sum(wt[x] for x in top)
    assert 0 < best < n, "fixture must split the star"
    for t in [p, *kids]:
        e = _entry(server, t)
        if t == p or t in top:
            assert (e["chunkweight"], round(e["fees"]["chunk"] * 1e8)) == (cw_, cf)
        else:
            assert (e["chunkweight"], round(e["fees"]["chunk"] * 1e8)) == (wt[t], fee[t])


def _closed(subset, parents):
    return all(parents[v] <= subset for v in subset)


def test_optimal_chunks_matches_brute_force_on_random_clusters():
    """Instrument for the chunker: on random DAGs of up to 7 txs every chunk
    is a highest-feerate closed subset of what is left, with no proper subset
    at that feerate."""
    from fractions import Fraction

    from ouroboros.mempool import optimal_chunks

    rng = random.Random(7)
    for _ in range(300):
        n = rng.randint(1, 7)
        ids = [bytes([i]) * 32 for i in range(n)]
        parents = {v: {u for u in ids[:i] if rng.random() < 0.4} for i, v in enumerate(ids)}
        fee = {v: rng.choice([0, 1, 2, 3, 5, 8, 13]) * 100 for v in ids}
        size = {v: rng.choice([1, 2, 3]) * 400 for v in ids}
        left = set(ids)
        for chunk, f, s in optimal_chunks(set(ids), fee, size, parents):
            assert chunk and chunk <= left
            assert (f, s) == (sum(fee[v] for v in chunk), sum(size[v] for v in chunk))
            par = {v: parents[v] & left for v in left}
            assert _closed(chunk, par)
            rates = {}
            for r in range(1, len(left) + 1):
                for sub in itertools.combinations(sorted(left), r):
                    sub = frozenset(sub)
                    if _closed(sub, par):
                        rate = Fraction(sum(fee[v] for v in sub), sum(size[v] for v in sub))
                        rates.setdefault(rate, []).append(sub)
            top = max(rates)
            assert Fraction(f, s) == top
            # No proper subset at that feerate: equal-feerate chunks stay
            # apart, so each tx's chunk is the same whichever comes first.
            assert not any(sub < chunk for sub in rates[top])
            left -= chunk
        assert not left


def test_depends_sorted_and_spentby_in_txid_order(tmp_path):
    bdb, _chain, _bs, server, mempool, fund = _setup(tmp_path)
    n = 4
    each = (FUNDING - 1_000) // n
    p, _l, pw = _build([(fund, 0, FINAL)], [each] * n)
    _add(mempool, pw)
    kids = {}
    for i in range(n - 1):
        c, _l, cw = _build([(p, i, FINAL)], [each - 1_000])
        kids[c] = cw
    # Admit the children in DESCENDING internal order, so insertion order is
    # the reverse of Core's.
    for c in sorted(kids, reverse=True):
        _add(mempool, kids[c])
    assert _entry(server, p)["spentby"] == [c[::-1].hex() for c in sorted(kids)]

    a, b = sorted(kids, key=lambda t: t[::-1].hex())[:2]
    # Spend the display-greater parent first.
    g, _l, gw = _build([(b, 0, FINAL), (a, 0, FINAL)], [2 * each - 4_000])
    _add(mempool, gw)
    assert _entry(server, g)["depends"] == sorted([a[::-1].hex(), b[::-1].hex()])


def test_unbroadcast_tracks_local_submission(tmp_path):
    bdb, _chain, _bs, server, mempool, fund = _setup(tmp_path)
    other = _fund(bdb, b"other")
    local, _l, lw = _build([(fund, 0, FINAL)], [FUNDING - 1_000])
    relayed, _l, rw = _build([(other, 0, FINAL)], [FUNDING - 1_000])
    assert asyncio.run(server.rpc_sendrawtransaction(lw.hex())) == local[::-1].hex()
    _add(mempool, rw)  # as if from a peer
    assert _entry(server, local)["unbroadcast"] is True
    assert _entry(server, relayed)["unbroadcast"] is False
    assert asyncio.run(server.rpc_getmempoolinfo())["unbroadcastcount"] == 1
    mempool.remove_unbroadcast(local)  # a peer getdata'd it
    assert _entry(server, local)["unbroadcast"] is False
    assert asyncio.run(server.rpc_getmempoolinfo())["unbroadcastcount"] == 0


def test_unbroadcast_dropped_when_the_tx_leaves_the_pool(tmp_path):
    bdb, _chain, _bs, server, mempool, fund = _setup(tmp_path)
    local, _l, lw = _build([(fund, 0, FINAL)], [FUNDING - 1_000])
    asyncio.run(server.rpc_sendrawtransaction(lw.hex()))
    assert local in mempool.unbroadcast_txids
    mempool.remove_transaction(local)
    assert local not in mempool.unbroadcast_txids


def test_invalidate_readds_each_block_at_its_own_tip(tmp_path):
    """warden_d: txs confirmed at h+1 and h+2, invalidate h+1.  Core re-adds
    the h+2 tx at tip h+1 and the h+1 tx at tip h."""
    bdb, chain, _bs, server, mempool, fund = _setup(tmp_path)
    t0, l0, w0 = _build([(fund, 0, FINAL)], [FUNDING - 10_000])
    t1, l1, w1 = _build([(t0, 0, FINAL)], [FUNDING - 20_000])
    raw0, h0 = _segwit_block(chain.tip_hash, TIP + 1, [(l0, w0)])
    bdb._db.connect_block_from_bytes(raw0, TIP + 1, "regtest")
    raw1, h1 = _segwit_block(h0, TIP + 2, [(l1, w1)])
    bdb._db.connect_block_from_bytes(raw1, TIP + 2, "regtest")
    assert bdb.get_best_block() == (h1, TIP + 2)
    asyncio.run(server.rpc_invalidateblock(h0[::-1].hex()))
    assert bdb.get_best_block()[1] == TIP
    assert _entry(server, t0)["height"] == TIP
    assert _entry(server, t1)["height"] == TIP + 1


def test_wallet_details_skip_change_and_list_self_payment_as_send(tmp_path):
    """Core gettransaction details for 1 BTC to the wallet's own second
    address from a 50 BTC coin: [receive 1, send -1]; the 49 BTC change is
    not listed.  ouroboros listed [receive 1, receive 49]."""
    from ouroboros.address import address_to_script_pubkey
    from ouroboros.wallet import Wallet

    wdir = tmp_path / "wallets" / "w"
    wdir.mkdir(parents=True)
    w = Wallet(data_dir=str(tmp_path), network="regtest", name="w", wallet_dir=str(wdir))
    w.init_hd(seed=bytes(range(32)))
    addr_a = asyncio.run(w.generate_new_address(address_type="bech32"))
    addr_b = asyncio.run(w.generate_new_address(address_type="bech32"))
    spk_a = address_to_script_pubkey(addr_a, w.network)

    fund_txid = b"\x33" * 32
    fund_tx = SimpleNamespace(
        inputs=[], outputs=[SimpleNamespace(value=50 * COIN, script_pubkey=spk_a)],
        is_coinbase=False, get_txid=lambda: fund_txid,
        serialize_with_witness=lambda: b"\x00",
    )
    w.scan_block_connect(SimpleNamespace(hash=b"\x01" * 32, timestamp=1, transactions=[fund_tx]), 101)

    class _DB:
        def get_best_block(self):
            return b"\x01" * 32, 101

        def list_unspent_by_address(self, addr, network):
            if addr != addr_a:
                return []
            return [{"txid": fund_txid[::-1].hex(), "vout": 0, "value": 50 * COIN,
                     "height": 101, "is_coinbase": False, "script_pubkey": spk_a.hex()}]

    w.db = _DB()
    raw = asyncio.run(w.send_transaction(addr_b, 1 * COIN, 2))
    tx = _tx(bytes.fromhex(raw))
    assert len(tx.outputs) == 2, "fixture must have a change output"
    w.scan_block_connect(SimpleNamespace(hash=b"\x02" * 32, timestamp=2, transactions=[tx]), 102)
    got = w.gettransaction_entry(tx.get_txid()[::-1].hex())
    details = sorted((d["category"], d["amount"]) for d in got["details"])
    assert details == [("receive", 1.0), ("send", -1.0)]
