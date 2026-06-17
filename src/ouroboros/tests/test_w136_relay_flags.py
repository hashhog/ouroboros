"""W136 — BIP-130 sendheaders + BIP-133 feefilter + BIP-339 wtxidrelay
(ouroboros).

DISCOVERY wave. 30 gates audited against
  bitcoin-core/src/net_processing.cpp
    - SENDHEADERS handler          @ 3896-3899
    - MaybeSendSendHeaders         @ 5519-5538
    - WTXIDRELAY handler           @ 3919-3939
    - WTXIDRELAY outbound          @ 3710-3712
    - FEEFILTER handler            @ 5035-5045
    - MaybeSendFeefilter           @ 5540-5580
    - Outbound INV feefilter check @ 6013, 6071
    - Pre-VERACK drop              @ 4010-4013
  bitcoin-core/src/policy/feerate.{cpp,h}
  bitcoin-core/src/policy/fees/block_policy_estimator.{cpp,h}
    - FeeFilterRounder            (MAX_FILTER_FEERATE=1e7,
                                   FEE_FILTER_SPACING=1.1)
  bitcoin-core/src/node/protocol_version.h
    - SENDHEADERS_VERSION = 70012
    - FEEFILTER_VERSION   = 70013
    - WTXID_RELAY_VERSION = 70016

Scope: P2P-only (Python `peer.py`, `p2p.py`, `node.py`, `p2p_messages.py`).
       Rust pipeline (`ferrous-utils/sync/src/network/`) has no relay-flag
       state and that is intentional — see G30 architectural guard.

This file contains one xfail per BUG-marked gate; xfails flip to XPASS the
moment a fix lands. PRESENT gates are plain asserts that pin Core-parity
wiring.

Reference: ouroboros/audit/w136_relay_flags.md.

NO production code changes. Only audit + xfail.
"""

from __future__ import annotations

import inspect
import re
import struct
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Path setup + sync module mock so ouroboros imports cleanly without the
# compiled Rust extension being present.
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[3]
FERROUS_UTILS = REPO_ROOT / "ferrous-utils"
SRC_OUROBOROS = REPO_ROOT / "src" / "ouroboros"

if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

if "sync" not in sys.modules:
    _mock_sync = types.ModuleType("sync")
    _mock_sync.PyBlockchainDB = MagicMock
    _mock_sync.PyBlock = MagicMock
    _mock_sync.PyUTXO = MagicMock
    _mock_sync.SyncEngine = MagicMock
    sys.modules["sync"] = _mock_sync


def _read_py(rel: str) -> str:
    p = SRC_OUROBOROS / rel
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


def _read_rust(rel: str) -> str:
    p = FERROUS_UTILS / rel
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


# ===========================================================================
# G1-G6 — Wire format & message types
# ===========================================================================


def test_w136_g1_sendheaders_empty_payload_command() -> None:
    """G1: `sendheaders` is an empty-payload BIP-130 command.

    Core: NetMsgType::SENDHEADERS, no payload.
    """
    from ouroboros.p2p_messages import SendHeadersMessage

    msg = SendHeadersMessage().to_network_message("mainnet")
    assert msg.command == "sendheaders"
    assert msg.payload == b""


@pytest.mark.xfail(
    reason="W136 BUG-7 (P1): FeeFilterMessage uses `<Q` (uint64) for both pack "
           "and unpack. Core serialises CAmount (int64_t) with `<q`. A "
           "malicious peer can send 0xff..ff and trigger BUG-1 (silent "
           "isolation).",
    strict=True,
)
def test_w136_g2_feefilter_payload_signed_int64() -> None:
    """G2: feefilter payload is 8-byte little-endian signed int64 (CAmount).

    Core: src/policy/feerate.h CAmount = int64_t.
    """
    from ouroboros.p2p_messages import FeeFilterMessage

    src = inspect.getsource(FeeFilterMessage)
    # Ensure the wire format uses signed `<q`, not unsigned `<Q`.
    assert "<q" in src and "<Q" not in src, (
        "FeeFilterMessage must use struct '<q' (int64) not '<Q' (uint64) "
        "to match Core CAmount semantics"
    )


def test_w136_g3_wtxidrelay_empty_payload_command() -> None:
    """G3: `wtxidrelay` is an empty-payload BIP-339 command."""
    from ouroboros.p2p_messages import WtxidRelayMessage

    msg = WtxidRelayMessage().to_network_message("mainnet")
    assert msg.command == "wtxidrelay"
    assert msg.payload == b""


def test_w136_g4_command_name_strings_match_core_constants() -> None:
    """G4: Command-name strings exactly equal Core's NetMsgType constants."""
    from ouroboros.p2p_messages import (
        FeeFilterMessage,
        SendHeadersMessage,
        WtxidRelayMessage,
    )

    assert SendHeadersMessage().to_network_message().command == "sendheaders"
    assert FeeFilterMessage(feerate=1000).to_network_message().command == "feefilter"
    assert WtxidRelayMessage().to_network_message().command == "wtxidrelay"


def test_w136_g5_message_magic_matches_network() -> None:
    """G5: Network magic on the three messages varies by network."""
    from ouroboros.p2p_messages import (
        FeeFilterMessage,
        SendHeadersMessage,
        WtxidRelayMessage,
        get_magic,
    )

    for cls in (SendHeadersMessage, WtxidRelayMessage):
        m_main = cls().to_network_message("mainnet")
        m_test = cls().to_network_message("testnet3")
        assert m_main.magic == get_magic("mainnet")
        assert m_test.magic == get_magic("testnet3")
        assert m_main.magic != m_test.magic
    ff_main = FeeFilterMessage(feerate=1000).to_network_message("mainnet")
    ff_test = FeeFilterMessage(feerate=1000).to_network_message("testnet3")
    assert ff_main.magic != ff_test.magic


def test_w136_g6_feefilter_payload_length_8_bytes() -> None:
    """G6: feefilter payload is exactly 8 bytes."""
    from ouroboros.p2p_messages import FeeFilterMessage

    msg = FeeFilterMessage(feerate=12345).to_network_message("mainnet")
    assert len(msg.payload) == 8
    # The round-trip should preserve the value for legal CAmounts.
    rt = FeeFilterMessage.from_payload(msg.payload)
    assert rt.feerate == 12345


# ===========================================================================
# G7-G11 — Outbound send timing
# ===========================================================================


@pytest.mark.xfail(
    reason="W136 BUG-2 (P1): peer.py:854 + peer.py:1408 send "
           "FeeFilterMessage(feerate=1000) hardcoded at post-VERACK. Core does "
           "NOT send a feefilter at handshake — relies on MaybeSendFeefilter "
           "tick (net_processing.cpp:5540-5580).",
    strict=True,
)
def test_w136_g7_feefilter_not_sent_at_handshake() -> None:
    """G7: feefilter is NOT sent immediately at post-VERACK.

    Core: `m_next_send_feefilter{0}` so the next msg-loop tick fires the
    actual current-mempool-min filter. Sending a hardcoded `1000` at
    handshake is an information-leak + bandwidth-waste + fingerprint.
    """
    src_peer = _read_py("peer.py")
    # Outer handshake and inbound handshake should not call FeeFilterMessage
    # with a literal value.
    assert "FeeFilterMessage(feerate=1000)" not in src_peer, (
        "FIX: remove hardcoded feefilter(1000) post-VERACK; rely on "
        "_broadcast_feefilter to send the real current_filter"
    )


def test_w136_g8_feefilter_gated_on_relay_txs() -> None:
    """G8: feefilter is sent only on full-relay (not block-relay-only) peers.

    Core: `MaybeSendFeefilter` returns early on `IsBlockOnlyConn()`.
    """
    src = _read_py("peer.py")
    # The handshake feature-negotiation block should gate feefilter on
    # `self.relay_txs`.  We expect a pattern of `if self.relay_txs:` BEFORE
    # the FeeFilterMessage send.
    assert "if self.relay_txs" in src
    # And the broadcast loop should skip block-relay-only peers.
    src_p2p = _read_py("p2p.py")
    assert "if not p.relay_txs" in src_p2p or "p.relay_txs" in src_p2p


@pytest.mark.xfail(
    reason="W136 BUG-9 (P1): peer.py:849/1400 sends sendheaders unconditionally "
           "post-VERACK. Core defers sendheaders until peer-best-known-block "
           "crosses MinimumChainWork (net_processing.cpp:5519-5538). Also "
           "BUG-10: no peer.sent_sendheaders dedupe latch.",
    strict=True,
)
def test_w136_g9_sendheaders_deferred_until_min_chain_work() -> None:
    """G9: sendheaders deferred until peer-best-known-block crosses
    MinimumChainWork (Core MaybeSendSendHeaders).
    """
    src = _read_py("peer.py")
    # We expect either (a) a MaybeSendSendHeaders-equivalent helper, or
    # (b) a guard on sendheaders that references chain-work / minimum-chain-work
    # / best-known-block.
    keywords = (
        "MinimumChainWork",
        "min_chain_work",
        "best_known_block",
        "MaybeSendSendHeaders",
        "maybe_send_sendheaders",
    )
    assert any(k in src for k in keywords), (
        "FIX: defer sendheaders until peer-best-known-block crosses "
        "MinimumChainWork; or add a MaybeSendSendHeaders-equivalent latch."
    )


def test_w136_g10_wtxidrelay_pre_verack_version_gated() -> None:
    """G10: wtxidrelay sent before VERACK, only if version >= 70016 && relay_txs.

    Core: net_processing.cpp:3710 — `greatest_common_version >=
    WTXID_RELAY_VERSION` (70016).
    """
    src = _read_py("peer.py")
    # We expect a conditional `if greatest_common_version >= 70016 and
    # self.relay_txs:` guarding the wtxidrelay send.
    assert "greatest_common_version >= 70016" in src
    # And both inbound and outbound handshakes do it (two occurrences).
    occurrences = src.count("WtxidRelayMessage().to_network_message")
    assert occurrences >= 2, (
        "Both inbound and outbound handshake paths must send wtxidrelay "
        "pre-VERACK if peer supports it."
    )


def test_w136_g11_outbound_feefilter_uses_real_mempool_min() -> None:
    """G11: outbound feefilter on maintenance tick uses real mempool min."""
    from ouroboros.p2p import PeerManager
    src = inspect.getsource(PeerManager._get_current_feefilter)
    # Must read the real mempool min, not return a hardcoded constant.
    assert "min_fee_rate" in src
    assert "get_mempool_info" in src or "_mempool" in src


# ===========================================================================
# G12-G16 — Inbound handler logic
# ===========================================================================


@pytest.mark.xfail(
    reason="W136 BUG-7 (P1): FeeFilterMessage.from_payload uses `<Q` (uint64) "
           "while Core serialises CAmount as int64_t with `<q`. Coupled with "
           "BUG-1, lets a peer send 0xff..ff and silently isolate us.",
    strict=True,
)
def test_w136_g12_feefilter_from_payload_signed() -> None:
    """G12: feefilter.from_payload deserialises 8 bytes as **signed** int64."""
    from ouroboros.p2p_messages import FeeFilterMessage

    src = inspect.getsource(FeeFilterMessage)
    assert "'<q'" in src or '"<q"' in src, (
        "FIX: deserialise feefilter payload as signed int64 ('<q')"
    )


def test_w136_g13_on_sendheaders_sets_wants_headers() -> None:
    """G13: on_sendheaders sets peer.wants_headers = True.

    Core: net_processing.cpp:3897 `peer.m_prefers_headers = true`.
    """
    from ouroboros.p2p import PeerManager
    src = inspect.getsource(PeerManager._register_compact_handlers)
    assert "peer.wants_headers = True" in src


@pytest.mark.xfail(
    reason="W136 BUG-1 (P0-CDIV): on_feefilter at p2p.py:2364 stores ff.feerate "
           "without MoneyRange-validating. A malicious peer can set "
           "peer_feefilter = 0xFFFFFFFFFFFFFFFF and PERMANENTLY suppress all "
           "outbound tx relay to us. Same universal shape as W117 BUG-1 / "
           "W120 BUG-3 (validate-before-store). Also BUG-6: no version-gate.",
    strict=True,
)
def test_w136_g14_on_feefilter_money_range_validates() -> None:
    """G14: on_feefilter MoneyRange-validates before storing.

    Core: net_processing.cpp:5038
        if (MoneyRange(newFeeFilter)) tx_relay->m_fee_filter_received = ...

    A peer that sends a value outside [0, MAX_MONEY] should be silently
    ignored (debug-log only).  ouroboros must do the same.
    """
    from ouroboros.p2p import PeerManager
    src = inspect.getsource(PeerManager._register_compact_handlers)
    # Find the on_feefilter handler body.
    handler_start = src.find("async def on_feefilter")
    assert handler_start != -1
    next_def = src.find("async def ", handler_start + 1)
    body = src[handler_start:next_def if next_def != -1 else len(src)]

    # Look for a MoneyRange-style check.
    needs = (
        "MoneyRange" in body
        or "MAX_MONEY" in body
        or "21_000_000" in body
        or "money_range" in body
    )
    assert needs, (
        "FIX (BUG-1 P0-CDIV): on_feefilter must MoneyRange-validate ff.feerate "
        "before assigning to peer.peer_feefilter (Core net_processing.cpp:5038)."
    )


@pytest.mark.xfail(
    reason="W136 BUG-3 (P1): node.py:971 compares `peer_feefilter > "
           "tx_feerate_per_kb` (per-kvB rounded compare). Core uses `tx.fee < "
           "filterrate.GetFee(tx.vsize)` — absolute-fee against "
           "filterrate-scaled vsize (net_processing.cpp:6013, 6071). Off-by-one "
           "at boundary vsizes.",
    strict=True,
)
def test_w136_g15_outbound_inv_uses_absolute_fee_check() -> None:
    """G15: outbound INV feefilter compare uses absolute-fee form.

    Core: `if (txinfo.fee < filterrate.GetFee(txinfo.vsize)) continue;`
    where `GetFee(vsize) = (sat_per_K * vsize) / 1000`.
    """
    src = _read_py("node.py")
    # Look for the absolute-fee compare shape:
    # `tx_fee < (peer.peer_feefilter * tx_vsize) // 1000`
    patterns = (
        "(peer.peer_feefilter * ",
        "(p.peer_feefilter * ",
        "* tx.vsize) // 1000",
        "* entry.vsize) // 1000",
        ".get_fee(",
        "GetFee(",
    )
    has_correct_form = any(p in src for p in patterns)
    assert has_correct_form, (
        "FIX: switch node.py outbound INV check to "
        "`tx.fee < (peer.peer_feefilter * tx.vsize) // 1000`"
    )


@pytest.mark.xfail(
    reason="W136 BUG-11 (P1): _maybe_send_feefilter (p2p.py:2018-2073) lacks "
           "Core's MAX_FILTER-recovery latch (net_processing.cpp:5558-5563). "
           "Post-IBD, if previous send was MAX_MONEY, next_send_time must be "
           "set to 0 so the real current filter is sent on the next tick.",
    strict=True,
)
def test_w136_g16_post_ibd_recovery_latch_present() -> None:
    """G16: When previous-sent filter was MAX_MONEY (IBD sentinel) and we are
    now NOT in IBD, force `next_feefilter_time = 0` to send the real filter
    immediately on the next tick.
    """
    from ouroboros.p2p import PeerManager
    src = inspect.getsource(PeerManager._maybe_send_feefilter)
    # Look for the recovery branch: an `if peer.feefilter_sent ==` against a
    # MAX_MONEY-sized sentinel that zeros `peer.next_feefilter_time`.
    has_recovery = (
        "feefilter_sent == MAX" in src
        or "feefilter_sent >= MAX_MONEY" in src
        or "next_feefilter_time = 0" in src
        and ("MAX_MONEY" in src or "MAX_FILTER" in src)
    )
    assert has_recovery, (
        "FIX: add Core's MAX_FILTER-recovery latch — if peer.feefilter_sent "
        "equals MAX_MONEY (or rounded-MAX_FILTER) and we exited IBD, set "
        "peer.next_feefilter_time = 0 so we re-send the real filter."
    )


# ===========================================================================
# G17-G22 — State tracking & misbehavior
# ===========================================================================


def test_w136_g17_wtxid_relay_only_set_pre_verack() -> None:
    """G17: peer.wtxid_relay is set only between VERSION and VERACK.

    Core: net_processing.cpp:3922-3925 — if `pfrom.fSuccessfullyConnected`
    when WTXIDRELAY arrives, disconnect.  ouroboros at peer.py:1679-1690
    correctly checks `not handshake_complete` and ignores otherwise.
    """
    src = _read_py("peer.py")
    # Look for the post-VERACK ignore branch.
    assert 'msg.command == "wtxidrelay"' in src
    assert "handshake_complete" in src
    # The peer.wtxid_relay = True assignment should be guarded by the
    # not-yet-completed handshake.
    occurrences = [m.start() for m in re.finditer(r"self\.wtxid_relay = True", src)]
    # We expect at least two of these — one in inbound handshake loop, one
    # in outbound handshake loop, and one in the listen-loop pre-handler
    # (under `if not handshake_complete`).
    assert len(occurrences) >= 2, (
        "wtxid_relay must be set at multiple pre-VERACK call sites"
    )


def test_w136_g18_feefilter_rounder_buckets() -> None:
    """G18: FeeFilterRounder uses 1.1x spacing up to 1e7.

    Core: src/policy/fees/block_policy_estimator.h:326-331
    MAX_FILTER_FEERATE=1e7, FEE_FILTER_SPACING=1.1.
    """
    from ouroboros.p2p import (
        FEE_FILTER_SPACING,
        MAX_FILTER_FEERATE,
        FeeFilterRounder,
    )

    assert FEE_FILTER_SPACING == pytest.approx(1.1)
    assert MAX_FILTER_FEERATE == pytest.approx(1e7)
    # Spot-check that the rounder maps 5000 to a bucket boundary or one
    # bucket below it.  Test that round() is monotonic-ish: rounding a
    # range of values stays bounded by the input.
    rounder = FeeFilterRounder()
    for v in (1000, 5000, 10_000, 100_000):
        r = rounder.round(v)
        # Rounding cannot exceed the input by more than one bucket.
        assert 0 <= r <= int(v * FEE_FILTER_SPACING) + 1


def test_w136_g19_hysteresis_expedite() -> None:
    """G19: hysteresis 3/4 vs 4/3 expedite if next_send too far away.

    Core: net_processing.cpp:5576-5578 expedites if currentFilter <
    3*m_fee_filter_sent/4 OR currentFilter > 4*m_fee_filter_sent/3.
    """
    from ouroboros.p2p import PeerManager
    src = inspect.getsource(PeerManager._maybe_send_feefilter)
    assert "(3 * peer.feefilter_sent) // 4" in src
    assert "(4 * peer.feefilter_sent) // 3" in src


def test_w136_g20_feefilter_poisson_interval() -> None:
    """G20: feefilter Poisson interval = ~10 min average."""
    from ouroboros.p2p import AVG_FEEFILTER_BROADCAST_INTERVAL

    assert AVG_FEEFILTER_BROADCAST_INTERVAL == pytest.approx(600.0)


def test_w136_g21_feefilter_max_change_delay() -> None:
    """G21: feefilter MAX_FEEFILTER_CHANGE_DELAY = 5 min."""
    from ouroboros.p2p import MAX_FEEFILTER_CHANGE_DELAY

    assert MAX_FEEFILTER_CHANGE_DELAY == pytest.approx(300.0)


def test_w136_g22_feefilter_max_money_in_ibd() -> None:
    """G22: feefilter set to MAX_MONEY during IBD.

    Core: net_processing.cpp:5552-5555 — in IBD, currentFilter = MAX_MONEY
    to suppress all tx announcements.
    """
    from ouroboros.p2p import PeerManager

    src = inspect.getsource(PeerManager._get_current_feefilter)
    assert "MAX_MONEY" in src
    assert "_in_ibd" in src


# ===========================================================================
# G23-G27 — Cross-cutting / divergences
# ===========================================================================


@pytest.mark.xfail(
    reason="W136 BUG-5 (P1): on_wtxidrelay handler at p2p.py:2370 is DEAD CODE. "
           "peer.py:1679-1690 short-circuits with `continue` before listen() "
           "dispatches to the registered handler.  Either remove the dead "
           "handler OR wire it to Core-parity-disconnect on post-VERACK "
           "wtxidrelay arrival (net_processing.cpp:3922-3925 sets "
           "pfrom.fDisconnect=true).",
    strict=True,
)
def test_w136_g23_on_wtxidrelay_handler_is_live_or_absent() -> None:
    """G23: The on_wtxidrelay handler registered in _register_compact_handlers
    must either (a) be removed (because peer.py absorbs the message before
    dispatch), OR (b) implement Core-parity-disconnect.
    """
    from ouroboros.p2p import PeerManager

    src = inspect.getsource(PeerManager._register_compact_handlers)
    has_handler = "async def on_wtxidrelay" in src

    if not has_handler:
        return  # branch (a): removed entirely; gate satisfied.

    # branch (b): handler exists, must implement Core-parity-disconnect.
    handler_start = src.find("async def on_wtxidrelay")
    next_def = src.find("async def ", handler_start + 1)
    body = src[handler_start:next_def if next_def != -1 else len(src)]
    must_have = (
        "peer.disconnect" in body
        or "fDisconnect" in body
        or "set_disconnect" in body
        or "misbehaving" in body
    )
    assert must_have, (
        "FIX: on_wtxidrelay must disconnect the peer (post-VERACK wtxidrelay "
        "is a BIP-339 violation per Core net_processing.cpp:3922-3925)."
    )


@pytest.mark.xfail(
    reason="W136 BUG-8 (P2): peer.py:1674 applies adjust_score(-10) for any "
           "non-handshake message pre-handshake. Core silently drops such "
           "messages (net_processing.cpp:4010-4013) with a debug log only — no "
           "misbehavior score.",
    strict=True,
)
def test_w136_g24_pre_verack_messages_not_scored() -> None:
    """G24: pre-VERACK non-handshake messages are dropped silently per Core."""
    src = _read_py("peer.py")
    # Find the pre-handshake filter block.
    listen_idx = src.find("async def listen")
    assert listen_idx != -1
    end = src.find("    async def ", listen_idx + 50)
    if end == -1:
        end = listen_idx + 4000
    listen_body = src[listen_idx:end]

    # The pre-handshake guard should NOT call adjust_score.
    assert "self.adjust_score" not in listen_body or (
        "if not self.handshake_complete" not in listen_body
    ), (
        "FIX: drop the adjust_score(-10) for non-handshake pre-VERACK "
        "messages — Core silently ignores them."
    )


def test_w136_g25_block_announce_precedence() -> None:
    """G25: block-announce precedence cmpctblock > headers > inv."""
    src = _read_py("block_sync.py")
    # Find _announce_block.
    idx = src.find("async def _announce_block")
    assert idx != -1
    next_def = src.find("async def ", idx + 1)
    body = src[idx:next_def if next_def != -1 else len(src)]
    # The cmpctblock branch must precede the wants_headers branch in source.
    cmpct = body.find("wants_cmpctblock")
    hdrs = body.find("wants_headers")
    inv = body.find("INV_TYPE_BLOCK")
    assert 0 < cmpct < hdrs < inv, (
        "Order must be: cmpctblock > headers > inv (matches Core "
        "net_processing.cpp:5892-5915)."
    )


def test_w136_g26_tx_inv_msg_wtx_iff_wtxid_relay() -> None:
    """G26: tx-INV uses MSG_WTX(5) iff peer.wtxid_relay else MSG_TX(1).

    Three call sites must all use this rule:
    - node.py per-tx INV announce
    - p2p.py TrickleQueue (per-peer batched)
    - p2p.py mempool-dump INV (BIP-35)
    """
    src_node = _read_py("node.py")
    src_p2p = _read_py("p2p.py")

    # node.py per-tx announce
    assert "getattr(p, \"wtxid_relay\", False)" in src_node
    assert "MSG_WTX" in src_node

    # p2p.py TrickleQueue
    assert "if self.wtxid_relay" in src_p2p
    assert "MSG_WTX" in src_p2p

    # p2p.py mempool-dump uses peer.services & NODE_WITNESS as proxy
    # (per BIP-35 + BIP-339 interaction — see audit doc).
    assert "MSG_WTX if (peer.services & NODE_WITNESS)" in src_p2p


def test_w136_g27_getdata_tx_accepts_wtx_type() -> None:
    """G27: GETDATA-tx with MSG_WTX(5) is matched against peer's wtxid_relay
    (already pinned by W121).  Verifies that the inv_type acceptance set
    includes MSG_WTX.
    """
    src = _read_py("block_sync.py")
    assert "MSG_WTX" in src
    # The on_inv handler should accept INV_TYPE_TX, MSG_WITNESS_TX, and MSG_WTX.
    assert "INV_TYPE_TX, MSG_WITNESS_TX, MSG_WTX" in src or (
        "INV_TYPE_TX" in src and "MSG_WITNESS_TX" in src and "MSG_WTX" in src
    )


# ===========================================================================
# G28-G30 — Wiring & two-pipeline guard
# ===========================================================================


@pytest.mark.xfail(
    reason="W136 BUG-14 (P1): rpc.py:6545 emits a 'minfeefilter' field BUT "
           "reads peer.fee_filter (no such attribute — typo for "
           "peer.peer_feefilter). getattr fallback returns 0 ⇒ field "
           "ALWAYS reports 0 sat/B. Cross-impl tooling (fleet-monitor / "
           "consensus-diff) misclassifies our peers as 'no filter'.",
    strict=True,
)
def test_w136_g28_getpeerinfo_minfeefilter_reads_correct_attr() -> None:
    """G28: getpeerinfo's minfeefilter field reads the correct peer attribute.

    Core rpc/net.cpp:235 emits the per-peer m_fee_filter_received under
    'minfeefilter'. ouroboros emits a 'minfeefilter' field BUT reads
    `peer.fee_filter` — which does not exist (peer.py defines
    `peer.peer_feefilter`).
    """
    src = _read_py("rpc.py")
    # Find rpc_getpeerinfo body.
    idx = src.find("def rpc_getpeerinfo")
    if idx == -1:
        idx = src.find("getpeerinfo")
    assert idx != -1
    body = src[idx:idx + 8000]
    # The field must be emitted AND the source attribute must be the real
    # one (`peer_feefilter`), not the typo (`fee_filter`).
    assert "minfeefilter" in body
    assert "peer_feefilter" in body or "fee_filter_received" in body, (
        "FIX: rpc.py:6545 reads peer.fee_filter but the actual peer attribute "
        "is peer.peer_feefilter. The minfeefilter field reports 0 forever."
    )


@pytest.mark.xfail(
    reason="W136 BUG-13 (P2): getpeerinfo lacks per-peer wtxid_relay surface. "
           "Core rpc/net.cpp emits service flags; ouroboros doesn't expose "
           "peer.wtxid_relay anywhere observable.",
    strict=True,
)
def test_w136_g29_getpeerinfo_wtxid_relay_field() -> None:
    """G29: getpeerinfo surfaces per-peer wtxid_relay."""
    src = _read_py("rpc.py")
    idx = src.find("def rpc_getpeerinfo")
    if idx == -1:
        idx = src.find("getpeerinfo")
    assert idx != -1
    body = src[idx:idx + 8000]
    assert "wtxid_relay" in body or "relaytxes_wtxid" in body, (
        "FIX: surface per-peer wtxid_relay in getpeerinfo response."
    )


def test_w136_getpeerinfo_inv_fields_and_no_startingheight() -> None:
    """getpeerinfo: last_inv_sequence + inv_to_send present in Core v31.99 wire
    order, and startingheight absent.

    Ported from rustoshi 077eb2f (add last_inv_sequence + inv_to_send) + 528045a
    (drop startingheight, removed in Core v31.99).  Core rpc/net.cpp:242-245
    pushes relaytxes -> last_inv_sequence -> inv_to_send -> lastsend; net.cpp
    no longer pushes startingheight (bip152_hb_from -> presynced_headers).

    Pure RPC response shape — never reachable from block/tx validation.
    """
    import asyncio

    from ouroboros.rpc import RPCServer

    class _StubPeer:
        id = 0
        address = "203.0.113.7:8333"
        services = 1
        relay_txs = True
        last_inv_sequence = 0
        inv_to_send = 0
        start_height = 654321  # would have populated the removed field

    class _StubPM:
        peers = [_StubPeer()]
        block_relay_peers: list = []
        inbound_peers: list = []

    class _StubNode:
        peer_manager = _StubPM()

    server = RPCServer(_StubNode())
    result = asyncio.run(server.rpc_getpeerinfo())
    assert len(result) == 1
    info = result[0]
    keys = list(info.keys())

    # Both new NUM fields present and numeric.
    assert "last_inv_sequence" in info, "last_inv_sequence missing (Core v31.99)"
    assert "inv_to_send" in info, "inv_to_send missing (Core v31.99)"
    assert isinstance(info["last_inv_sequence"], int)
    assert isinstance(info["inv_to_send"], int)

    # Exact Core wire order: relaytxes -> last_inv_sequence -> inv_to_send -> lastsend.
    i_relay = keys.index("relaytxes")
    i_lis = keys.index("last_inv_sequence")
    i_its = keys.index("inv_to_send")
    i_send = keys.index("lastsend")
    assert i_relay < i_lis < i_its < i_send, (
        f"getpeerinfo INV-field order wrong: {keys[i_relay:i_send + 1]}"
    )

    # startingheight removed in Core v31.99 — must be absent.
    assert "startingheight" not in info, (
        "startingheight must not be emitted (removed in Bitcoin Core v31.99)"
    )
    # bip152_hb_from -> presynced_headers contiguous (no startingheight between).
    i_hb = keys.index("bip152_hb_from")
    i_pre = keys.index("presynced_headers")
    assert keys[i_hb + 1] == "presynced_headers", (
        f"expected presynced_headers right after bip152_hb_from, got "
        f"{keys[i_hb + 1]!r}"
    )
    assert i_hb < i_pre


def test_w136_g30_two_pipeline_relay_flags_python_only() -> None:
    """G30 (architectural guard): relay flags are Python-only (active surface).

    Two-pipeline invariant: sendheaders / feefilter / wtxidrelay are
    negotiated and applied entirely in the Python pipeline. The Rust
    pipeline must contain no ACTIVE relay-flag code — only a passive
    silent-ignore allowlist in header_sync.rs is permitted.

    Future drift (e.g., moving relay-flag STATE into Rust, or making the
    Rust side react to feefilter values) trips this guard.
    """
    # --- Python pipeline OWNS the relay flags ---
    src_peer = _read_py("peer.py")
    src_p2p = _read_py("p2p.py")

    # peer.wtxid_relay, peer.wants_headers, peer.peer_feefilter all live in
    # peer.py and are referenced from p2p.py.
    assert "self.wtxid_relay" in src_peer
    assert "self.wants_headers" in src_peer
    assert "self.peer_feefilter" in src_peer

    # FeeFilterRounder is defined in p2p.py.
    assert "class FeeFilterRounder" in src_p2p

    # --- Rust pipeline must have NO ACTIVE relay-flag identifiers ---
    if not FERROUS_UTILS.exists():
        pytest.skip("ferrous-utils tree not present")

    # Active relay-flag identifiers (any of these in Rust means the Rust
    # pipeline has GROWN active relay-flag handling).
    ACTIVE_KEYWORDS = (
        "fee_filter_received",
        "m_fee_filter_sent",
        "m_prefers_headers",
        "m_wtxid_relay",
        "wants_headers",
        "peer_feefilter",
        "FeeFilterRounder",
        "FEEFILTER_BROADCAST_INTERVAL",
    )
    # Passive identifiers (just message-name strings in an allowlist).
    # These are permitted in non-acting silent-ignore allowlists; we don't
    # forbid them outright but we DO require the file to be in the
    # whitelist and the match count to be small.
    PASSIVE_WHITELIST_FILES = {
        # The HeaderSync silent-ignore allowlist at lines 427-435 is the
        # ONLY permitted touch of these strings in the Rust pipeline.
        "sync/src/network/header_sync.rs",
    }

    violations = []
    for rs in FERROUS_UTILS.rglob("*.rs"):
        # Exclude test trees.
        if any(part in {"tests", "examples", "benches"} for part in rs.parts):
            continue
        text = rs.read_text(encoding="utf-8", errors="replace")
        # No active keyword may appear anywhere.
        for kw in ACTIVE_KEYWORDS:
            if kw in text:
                violations.append(f"{rs}: active keyword {kw!r}")
        # Passive keywords may only appear in whitelisted files, and the
        # whitelisted file may contain them only as string-match literals
        # (no struct field, no method, no `let _ = feefilter...`).
        rel = str(rs.relative_to(FERROUS_UTILS))
        # Strip leading "./" if any
        rel = rel.lstrip("./")
        passive_lower = text.lower()
        for pkw in ("feefilter", "sendheaders", "wtxidrelay"):
            if pkw not in passive_lower:
                continue
            if rel not in PASSIVE_WHITELIST_FILES:
                violations.append(
                    f"{rs}: passive keyword {pkw!r} found OUTSIDE allowlist"
                )
                continue
            # Within the whitelisted file, all matches must be inside
            # a `matches!(...)` call (the silent-ignore allowlist) or a
            # comment (`//` line).  Anything else is active code.
            for ln_no, line in enumerate(text.splitlines(), start=1):
                ll = line.lower()
                if pkw not in ll:
                    continue
                stripped = ll.lstrip()
                if stripped.startswith("//"):
                    continue
                if "matches!" in ll:
                    continue
                violations.append(
                    f"{rs}:{ln_no}: {pkw!r} appears outside "
                    "matches!()/comment — active code, not passive ignore"
                )

    assert not violations, (
        "Two-pipeline-guard violation(s):\n"
        + "\n".join(f"  - {v}" for v in violations)
        + "\n\nRelay flags are a Python-only responsibility in ouroboros. "
        "The Rust pipeline may only contain the passive silent-ignore "
        "allowlist at ferrous-utils/sync/src/network/header_sync.rs:427-435."
    )


# ===========================================================================
# Trailer: BUG-12 contextual note (no test — documented divergence)
# ===========================================================================


def test_w136_bug12_random_rng_documented_divergence() -> None:
    """BUG-12 (P2): FeeFilterRounder.round uses python's `random.randint`
    rather than Core's FastRandomContext.  Documented divergence — no fix
    needed because Core itself uses a per-instance RNG (output depends on
    seed).  Network-observable behavior is statistically equivalent.

    This is an explicit no-op test pinning the contextual note.
    """
    from ouroboros.p2p import FeeFilterRounder

    src = inspect.getsource(FeeFilterRounder)
    # Should use Python's `random` module (not deterministic seed required).
    assert "random.randint" in src or "random." in src

    # Document the divergence: this is the only place the test acts as a
    # pin for an INTENTIONAL behavioural difference.  Any future fix that
    # tries to switch to a deterministic seed must update this test (and the
    # audit doc).
