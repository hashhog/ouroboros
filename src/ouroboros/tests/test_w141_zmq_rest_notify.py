"""W141 — ZMQ + REST + notification-scripts audit (ouroboros).

DISCOVERY wave: 30 gates audited against
  bitcoin-core/src/zmq/zmqnotificationinterface.cpp (213 lines:
    Create, Initialize, UpdatedBlockTip, TransactionAddedToMempool,
    TransactionRemovedFromMempool, BlockConnected, BlockDisconnected)
  bitcoin-core/src/zmq/zmqpublishnotifier.cpp (294 lines:
    CZMQAbstractPublishNotifier::Initialize/Shutdown/SendZmqMessage,
    the 5 MSG_* constants — hashblock, hashtx, rawblock, rawtx,
    sequence — and SendSequenceMsg)
  bitcoin-core/src/zmq/zmqabstractnotifier.h (DEFAULT_ZMQ_SNDHWM=1000)
  bitcoin-core/src/rest.cpp (1179 lines: 14 endpoint handlers,
    ParseDataFormat, CheckWarmup, uri_prefixes dispatch)
  bitcoin-core/src/init.cpp (-alertnotify, -blocknotify wiring)
  bitcoin-core/src/node/kernel_notifications.cpp (AlertNotify with
    SanitizeString + ShellEscape + runCommand)
  bitcoin-core/src/util/strencodings.{h,cpp} (SAFE_CHARS rules)
  bitcoin-core/src/common/system.cpp (runCommand wraps system(3))

Scope:
- ZMQ publisher (`zmq_notifier.py`, `zmq_publisher.py` legacy)
- REST interface (`rest.py`)
- Notification scripts (`-blocknotify`, `-alertnotify`,
  `-walletnotify`) — absent in ouroboros
- Shell-injection guard against future addition of notify scripts

Two-pipeline note: ZMQ + REST + notify-scripts are
**external-facing I/O**, Python-only. ferrous-utils (Rust) has
zero ZMQ / HTTP / Command::new surface. G28/G29/G30 codify this.

This file contains an xfail test per Core-divergent gate; xfails
flip to XPASS the moment a fix lands. PRESENT gates are plain
asserts that pin Core-parity wiring.

Reference: ouroboros/audit/w141_zmq_rest_notify.md.

NO production code changes. NO behavior changes. Only audit + xfail.
"""

from __future__ import annotations

import inspect
import re
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
CORE_SRC = REPO_ROOT.parent / "bitcoin-core" / "src"

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


def _read_core(rel: str) -> str:
    p = CORE_SRC / rel
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


# Lazy imports
def _zmqn():
    from ouroboros import zmq_notifier as m
    return m


def _zmqp():
    from ouroboros import zmq_publisher as m
    return m


# ============================================================================
# ZMQ subsystem (G1-G12)
# ============================================================================


def test_w141_g1_hashblock_topic_constant() -> None:
    """G1: `hashblock` topic constant (Core zmqpublishnotifier.cpp:33).

    PRESENT — zmq_notifier.py:87 pins TOPIC_HASH_BLOCK = b"hashblock".
    """
    z = _zmqn()
    assert z.ZMQNotifier.TOPIC_HASH_BLOCK == b"hashblock"


def test_w141_g2_hashtx_topic_constant() -> None:
    """G2: `hashtx` topic constant (Core zmqpublishnotifier.cpp:34).

    PRESENT for the constant. BUG-1 (P0-CDIV) flagged separately
    for the dead call-site at node.py:954.
    """
    z = _zmqn()
    assert z.ZMQNotifier.TOPIC_HASH_TX == b"hashtx"


def test_w141_g2_bug1_zmq_publisher_attribute_dead_call() -> None:
    """G2 BUG-1 (P0-CDIV): node.py:954 references self.zmq_publisher
    which is never initialized; mempool-accept ZMQ events silently drop.

    Pre-fix: node.py:954 reads `if self.zmq_publisher:` — always False.
    Post-fix: should be `self.zmq_notifier`.
    """
    src = _read_py("node.py")
    # The broken form must be removed; the correct form must appear.
    broken = "self.zmq_publisher.notify_transaction"
    correct = "self.zmq_notifier.notify_transaction"
    if broken in src:
        pytest.xfail(
            "W141 BUG-1 (P0-CDIV): node.py:~954 still references "
            "self.zmq_publisher (attribute never set). Mempool-accept "
            "ZMQ events are silently dropped. Fix: s/zmq_publisher/zmq_notifier/."
        )
    assert correct in src, (
        "BUG-1 closure verification: expected self.zmq_notifier.notify_transaction "
        "in node.py after fix."
    )


def test_w141_g2_bug2_set_zmq_notifier_method_mismatch() -> None:
    """G2 BUG-2 (P0-CDIV): node.py:519 calls set_zmq_notifier but
    block_sync.py:400 defines set_zmq_publisher. Any zmqpub* config
    crashes node startup with AttributeError.
    """
    node_src = _read_py("node.py")
    bs_src = _read_py("block_sync.py")

    # The crash form: node.py calls .set_zmq_notifier( and block_sync
    # does NOT define def set_zmq_notifier.
    node_calls_notifier = "set_zmq_notifier(" in node_src
    bs_defines_notifier = re.search(
        r"def\s+set_zmq_notifier\s*\(", bs_src
    ) is not None
    bs_defines_publisher = re.search(
        r"def\s+set_zmq_publisher\s*\(", bs_src
    ) is not None

    if node_calls_notifier and not bs_defines_notifier and bs_defines_publisher:
        pytest.xfail(
            "W141 BUG-2 (P0-CDIV): node.py:~519 calls "
            "self.block_sync.set_zmq_notifier(...) but block_sync.py:~400 "
            "only defines set_zmq_publisher. Any non-empty zmqpub* config "
            "raises AttributeError at startup, killing the node."
        )

    # Post-fix invariant: both names align OR the publisher alias is used.
    assert bs_defines_notifier or not node_calls_notifier, (
        "BUG-2 closure verification: either rename block_sync method to "
        "set_zmq_notifier OR call set_zmq_publisher from node.py."
    )


def test_w141_g3_rawblock_topic_constant() -> None:
    """G3: `rawblock` topic constant (Core zmqpublishnotifier.cpp:35).

    PRESENT — zmq_notifier.py:89 pins TOPIC_RAW_BLOCK = b"rawblock".
    """
    z = _zmqn()
    assert z.ZMQNotifier.TOPIC_RAW_BLOCK == b"rawblock"


def test_w141_g4_rawtx_topic_constant() -> None:
    """G4: `rawtx` topic constant (Core zmqpublishnotifier.cpp:36).

    PRESENT for the constant. BUG-1 (P0-CDIV) flagged separately.
    """
    z = _zmqn()
    assert z.ZMQNotifier.TOPIC_RAW_TX == b"rawtx"


def test_w141_g5_sequence_topic_constant_and_labels() -> None:
    """G5/G5b/G5c/G5d: `sequence` topic + 4 labels A/R/C/D
    (Core zmqpublishnotifier.cpp:37,256-293).

    PRESENT for constants. BUG-1 (mempool-accept feed dead),
    BUG-3 (no production call sites for disconnect/removal)
    flagged separately.
    """
    z = _zmqn()
    cls = z.ZMQNotifier
    assert cls.TOPIC_SEQUENCE == b"sequence"
    assert cls.LABEL_MEMPOOL_ACCEPT == ord("A")
    assert cls.LABEL_MEMPOOL_REMOVE == ord("R")
    assert cls.LABEL_BLOCK_CONNECT == ord("C")
    assert cls.LABEL_BLOCK_DISCONNECT == ord("D")


def test_w141_g5b_bug3_no_callsite_for_notify_block_disconnect() -> None:
    """G5b BUG-3 (P0-CDIV): zmq_notifier.notify_block_disconnect is
    defined but NEVER called outside the module itself.

    Core's BlockDisconnected hook
    (zmqnotificationinterface.cpp:198-211) fires NotifyBlockDisconnect
    on every reorg. Ouroboros never invokes this — `sequence`
    label 'D' is dead.
    """
    # Search all .py files in src/ouroboros for production call sites.
    callsites: list[str] = []
    for path in SRC_OUROBOROS.rglob("*.py"):
        # Skip the notifier module itself + the test file.
        if path.name in ("zmq_notifier.py", "zmq_publisher.py"):
            continue
        if "tests" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if "notify_block_disconnect" in text:
            callsites.append(str(path.relative_to(SRC_OUROBOROS)))

    if not callsites:
        pytest.xfail(
            "W141 BUG-3 (P0-CDIV): zmq_notifier.notify_block_disconnect "
            "has zero production call sites. Reorg-aware ZMQ subscribers "
            "(label 'D') will never receive disconnect events. Wire it "
            "into block_sync.py's disconnect path."
        )
    assert callsites, "expected at least one production call site for notify_block_disconnect"


def test_w141_g5d_bug3_no_callsite_for_notify_transaction_removed() -> None:
    """G5d BUG-3 (P0-CDIV): notify_transaction_removed never called.

    Core's TransactionRemovedFromMempool
    (zmqnotificationinterface.cpp:170-178) fires on every mempool
    eviction for any non-block-inclusion reason. Ouroboros never
    invokes this — `sequence` label 'R' is dead.
    """
    callsites: list[str] = []
    for path in SRC_OUROBOROS.rglob("*.py"):
        if path.name in ("zmq_notifier.py", "zmq_publisher.py"):
            continue
        if "tests" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if "notify_transaction_removed" in text:
            callsites.append(str(path.relative_to(SRC_OUROBOROS)))

    if not callsites:
        pytest.xfail(
            "W141 BUG-3 (P0-CDIV): zmq_notifier.notify_transaction_removed "
            "has zero production call sites. Eviction-aware ZMQ subscribers "
            "(label 'R') will never receive removal events. Wire it into "
            "mempool.py's eviction paths."
        )
    assert callsites, "expected at least one production call site for notify_transaction_removed"


def test_w141_g6_nsequence_le32_per_topic() -> None:
    """G6: nSequence is LE32 per-topic counter
    (Core zmqpublishnotifier.cpp:199-205).

    PRESENT — zmq_notifier.py:200-203 emits struct.pack("<I", seq).
    """
    src = _read_py("zmq_notifier.py")
    # Per-topic counters
    assert "_sequences: dict[bytes, int]" in src
    # LE32 packing
    assert 'struct.pack("<I"' in src or "struct.pack('<I'" in src


def test_w141_g7_tcp_keepalive_set() -> None:
    """G7: ZMQ_TCP_KEEPALIVE = 1 on bind
    (Core zmqpublishnotifier.cpp:121-127).

    PRESENT — zmq_notifier.py:150 calls setsockopt(zmq.TCP_KEEPALIVE, 1).
    """
    src = _read_py("zmq_notifier.py")
    assert "TCP_KEEPALIVE" in src


def test_w141_g8_bug6_ipv6_optin_missing() -> None:
    """G8 BUG-6 (P2): ZMQ_IPV6 opt-in for IPv6 addresses absent.

    Core (zmqpublishnotifier.cpp:82-93,130-135) parses the tcp://
    address, calls LookupHost, and explicitly sets ZMQ_IPV6 = 1 only
    for IPv6 addresses (some systems error if ZMQ_IPV6=1 with an IPv4
    bind).
    """
    src = _read_py("zmq_notifier.py")
    has_ipv6 = ("ZMQ_IPV6" in src) or (".IPV6" in src)
    if not has_ipv6:
        pytest.xfail(
            "W141 BUG-6 (P2): zmq_notifier.py never sets ZMQ_IPV6 — "
            "portability footgun on systems where pyzmq's default "
            "is wrong for the bind address family."
        )
    assert has_ipv6


def test_w141_g9_bug7_unix_to_ipc_rewrite_missing() -> None:
    """G9 BUG-7 (P1): `unix://` → `ipc://` address-scheme rewrite absent.

    Core (zmqnotificationinterface.cpp:62-64) transparently maps
    unix:// (common docs convention) to libzmq's ipc:// prefix.
    Ouroboros passes the endpoint through verbatim.
    """
    src = _read_py("zmq_notifier.py")
    # Look for any rewrite of unix:// to ipc://
    has_rewrite = ("unix://" in src and "ipc://" in src) or (
        re.search(r"unix:/+.*ipc:/+", src) is not None
    )
    if not has_rewrite:
        pytest.xfail(
            "W141 BUG-7 (P1): zmq_notifier.configure_endpoint passes "
            "the endpoint URL verbatim. Operators using -zmqpubhashblock="
            "unix:///path/to/sock get an obscure libzmq error. Add a "
            "prefix rewrite per Core zmqnotificationinterface.cpp:62-64."
        )
    assert has_rewrite


def test_w141_g10_default_sndhwm_1000() -> None:
    """G10: DEFAULT_ZMQ_SNDHWM = 1000
    (Core zmqabstractnotifier.h:22).

    PRESENT — zmq_notifier.py:148 sets SNDHWM = 1000.
    """
    src = _read_py("zmq_notifier.py")
    # Look for the literal 1000 in setsockopt context
    assert re.search(r"SNDHWM[^,]*,\s*1000\b", src), (
        "Expected setsockopt(SNDHWM, 1000) in zmq_notifier.py"
    )


def test_w141_g10b_bug5_per_topic_hwm_config_missing() -> None:
    """G10b BUG-5 (P1): per-topic <topic>hwm config option absent.

    Core (zmqnotificationinterface.cpp:69) reads
    gArgs.GetIntArg(arg + "hwm", DEFAULT_ZMQ_SNDHWM) per-topic so
    operators can tune `-zmqpubhashblockhwm=5000`. Ouroboros
    config.py:168-172 lacks these 5 keys.
    """
    config_src = _read_py("config.py")
    notifier_src = _read_py("zmq_notifier.py")

    has_hwm_config = any(
        f"zmqpub{topic}hwm" in config_src
        for topic in ("hashblock", "hashtx", "rawblock", "rawtx", "sequence")
    )
    # Look for the config being READ in zmq_notifier (the "if config" wire)
    has_hwm_read = "hwm" in notifier_src and "config" in notifier_src.lower()

    if not (has_hwm_config and has_hwm_read):
        pytest.xfail(
            "W141 BUG-5 (P1): per-topic zmqpub<topic>hwm config keys "
            "absent. Operators can't tune ZMQ HWM per-topic."
        )
    assert has_hwm_config


def test_w141_g11_bug4_notify_block_not_ibd_gated() -> None:
    """G11 BUG-4 (P0-CDIV): notify_block fires during IBD.

    Core's UpdatedBlockTip (zmqnotificationinterface.cpp:151-159)
    returns early if `fInitialDownload || pindexNew == pindexFork`.
    Ouroboros block_sync.py:1380 calls notify_block on every drained
    block including during IBD, flooding subscribers.
    """
    src = _read_py("block_sync.py")
    # Find the notify_block call and check for an IBD guard nearby.
    m = re.search(
        r"(.{200})self\._zmq_publisher\.notify_block\(block\)",
        src,
        re.S,
    )
    if not m:
        pytest.fail("notify_block call site not found in block_sync.py")
    context = m.group(1)
    # Look for an IBD-gating phrase in the 200 chars before the call.
    has_ibd_gate = bool(
        re.search(r"\b(?:in_ibd|is_ibd|initial_download|fInitialDownload)\b", context)
    )
    if not has_ibd_gate:
        pytest.xfail(
            "W141 BUG-4 (P0-CDIV): block_sync.py:~1380 notify_block call "
            "lacks an IBD gate; ZMQ subscribers are flooded during initial "
            "sync. Add `if not self.in_ibd:` guard before the call."
        )
    assert has_ibd_gate


def test_w141_g12_shutdown_linger_zero_and_term() -> None:
    """G12: stop() sets LINGER=0 + ctx.term to avoid socket leaks
    (Core zmqpublishnotifier.cpp:185-188 + zmqnotificationinterface.cpp:127).

    PRESENT — zmq_notifier.py:168 sets LINGER=0 + .term().
    Also pinned by W124 G28.
    """
    src = _read_py("zmq_notifier.py")
    assert "LINGER" in src
    assert ".term()" in src


# ============================================================================
# REST subsystem (G13-G24d)
# ============================================================================


def _rest():
    from ouroboros import rest as m
    return m


def test_w141_g13_rest_block_route_registered() -> None:
    """G13: /rest/block/<h>.<fmt> registered + handles all 3 formats.

    PARTIAL — handler exists (rest.py:258) but BUG-13 byte-order
    convention drift across endpoints flagged separately.
    """
    src = _read_py("rest.py")
    assert "/block/{blockhash:path}" in src
    assert "/block/notxdetails/{blockhash:path}" in src
    assert "rest_block" in src


def test_w141_g13_bug13_byte_order_convention_drift() -> None:
    """G13 BUG-13 (P1): cross-endpoint byte-order convention drift.

    rest_blockfilter (rest.py:706) reverses hash_be[::-1] for db lookup;
    rest_tx (rest.py:911) likewise. But rest_block (rest.py:302-310)
    passes user hex to db.get_block WITHOUT reversing.
    """
    src = _read_py("rest.py")
    # Look for a single helper that abstracts the convention.
    has_unified_helper = bool(
        re.search(
            r"def\s+_(?:parse_hash|hash_from_user|user_hash_to_internal)\s*\(",
            src,
        )
    )
    # Find call sites and tally those that do / don't reverse.
    reversed_sites = len(re.findall(r"bytes\.fromhex\([^)]*\)\[::-1\]", src))
    non_reversed_sites = len(
        re.findall(r"=\s*bytes\.fromhex\([^)]*\)\s*\n", src)
    )

    if not has_unified_helper and reversed_sites > 0 and non_reversed_sites > 0:
        pytest.xfail(
            "W141 BUG-13 (P1): rest.py mixes reversed and non-reversed "
            f"bytes.fromhex parses ({reversed_sites} reversed vs "
            f"{non_reversed_sites} non-reversed) without a single "
            "comment-pinned helper. Convention drift across endpoints."
        )
    assert has_unified_helper or non_reversed_sites == 0


def test_w141_g14_rest_block_notxdetails_route() -> None:
    """G14: /rest/block/notxdetails/<h>.<fmt> registered.

    PRESENT — rest.py:99 + handler at rest.py:278.
    """
    src = _read_py("rest.py")
    assert "notxdetails" in src
    assert "rest_block_notxdetails" in src


def test_w141_g15_rest_headers_route() -> None:
    """G15: /rest/headers/<h>.<fmt>?count=N registered.

    PRESENT — rest.py:113 + handler at rest.py:542.
    """
    src = _read_py("rest.py")
    assert "/headers/{path:path}" in src
    assert "MAX_REST_HEADERS_RESULTS = 2000" in src


def test_w141_g16_rest_tx_route() -> None:
    """G16: /rest/tx/<txid>.<fmt> registered.

    PRESENT — rest.py:139 + handler at rest.py:887.
    """
    src = _read_py("rest.py")
    assert "/tx/{txid:path}" in src
    assert "rest_tx" in src


def test_w141_g17_rest_blockfilter_route() -> None:
    """G17: /rest/blockfilter/<type>/<h>.<fmt> registered.

    PRESENT — rest.py:131 + handler at rest.py:667.
    """
    src = _read_py("rest.py")
    assert "/blockfilter/{path:path}" in src
    assert "BLOCK_FILTER_TYPES_BY_NAME" in src


def test_w141_g18_rest_blockfilter_headers_route() -> None:
    """G18: /rest/blockfilterheaders/<type>/... registered.

    PRESENT — rest.py:124 + handler at rest.py:747.
    """
    src = _read_py("rest.py")
    assert "/blockfilterheaders/{path:path}" in src
    assert "rest_blockfilter_headers" in src


def test_w141_g19_bug12_chaininfo_byte_order() -> None:
    """G19 BUG-12 (P0-CDIV): chaininfo bestblockhash byte-order wrong.

    Core (rest.cpp:716-738) emits getblockchaininfo's bestblockhash,
    which is display-order (uint256::GetHex). Ouroboros rest.py:1229
    emits `best_hash.hex()` — internal LE byte order.
    """
    src = _read_py("rest.py")
    # Find the chaininfo response builder.
    m = re.search(
        r'"bestblockhash":\s*(.+?)(?:,|\n|\})',
        src,
    )
    if not m:
        pytest.fail("chaininfo bestblockhash field not found in rest.py")
    expr = m.group(1)
    # Look for byte-reverse on the path.
    has_reverse = "[::-1]" in expr
    if not has_reverse:
        pytest.xfail(
            "W141 BUG-12 (P0-CDIV): rest.py rest_chaininfo emits "
            "bestblockhash in internal LE byte order; Core emits "
            "display-order. External consumers comparing REST vs RPC "
            "see disagreeing tips on the same node."
        )
    assert has_reverse


def test_w141_g20_bug12_getutxos_chaintip_byte_order() -> None:
    """G20 BUG-12 (P0-CDIV): getutxos chaintipHash byte-order wrong.

    Core (rest.cpp:1062) uses active_hash.GetHex() (display-order).
    Ouroboros rest.py:1080 uses best_hash.hex() (internal LE).
    """
    src = _read_py("rest.py")
    m = re.search(
        r'"chaintipHash":\s*(.+?)(?:,|\n|\})',
        src,
    )
    if not m:
        pytest.fail("chaintipHash field not found in rest.py")
    expr = m.group(1)
    has_reverse = "[::-1]" in expr
    if not has_reverse:
        pytest.xfail(
            "W141 BUG-12 (P0-CDIV): rest_getutxos chaintipHash in "
            "internal LE byte order; Core emits display-order."
        )
    assert has_reverse


def test_w141_g21_bug12_blockhashbyheight_byte_order() -> None:
    """G21 BUG-12 (P0-CDIV): blockhashbyheight result byte-order wrong.

    Core (rest.cpp:1125,1131) uses pblockindex->GetBlockHash().GetHex()
    in both hex and json forms (display-order). Ouroboros
    rest.py:1170,1176 use block_hash.hex() (internal LE).
    """
    src = _read_py("rest.py")
    # Look at the JSON form
    m = re.search(
        r'"blockhash":\s*(.+?)(?:,|\n|\})',
        src,
    )
    if not m:
        pytest.fail("blockhash field not found in rest.py")
    expr = m.group(1)
    has_reverse = "[::-1]" in expr
    if not has_reverse:
        pytest.xfail(
            "W141 BUG-12 (P0-CDIV): rest_blockhash_by_height emits "
            "blockhash in internal LE byte order; Core emits display-order."
        )
    assert has_reverse


def test_w141_g22_bug16_mempool_verbose_query_strict() -> None:
    """G22 BUG-16 (P2): /rest/mempool/contents verbose accepts any
    FastAPI-coerced bool, not just literal "true"/"false".

    Core (rest.cpp:800-820) enforces literal strings and returns 400
    on anything else.
    """
    src = _read_py("rest.py")
    # Look for explicit strict literal validation.
    has_strict_literal = bool(
        re.search(
            r'raw_verbose\s*not\s*in\s*\(\s*["\']true["\'],\s*["\']false["\']\)',
            src,
        )
    )
    if not has_strict_literal:
        pytest.xfail(
            "W141 BUG-16 (P2): rest_mempool_contents uses FastAPI bool "
            "coercion. Core requires literal 'true' or 'false' strings "
            "and returns 400 on anything else."
        )
    assert has_strict_literal


def test_w141_g23_bug9_blockpart_route_missing() -> None:
    """G23 BUG-9 (P1): /rest/blockpart/ route absent.

    Core (rest.cpp:481-498) exposes block-fragment fetch by
    offset+size. Ouroboros has no equivalent.
    """
    src = _read_py("rest.py")
    has_route = "/blockpart" in src or "rest_block_part" in src
    if not has_route:
        pytest.xfail(
            "W141 BUG-9 (P1): /rest/blockpart/ route absent. "
            "Light clients relying on this endpoint get 404."
        )
    assert has_route


def test_w141_g24_bug10_spenttxouts_route_missing() -> None:
    """G24 BUG-10 (P1): /rest/spenttxouts/ route absent.

    Core (rest.cpp:313-381) exposes per-block undo data
    (spent outputs). Ouroboros has no equivalent.
    """
    src = _read_py("rest.py")
    has_route = "/spenttxouts" in src or "rest_spent_txouts" in src
    if not has_route:
        pytest.xfail(
            "W141 BUG-10 (P1): /rest/spenttxouts/ route absent. "
            "Block explorers must reconstruct via getutxos per-input."
        )
    assert has_route


def test_w141_g24b_bug11_deploymentinfo_route_missing() -> None:
    """G24b BUG-11 (P2): /rest/deploymentinfo route absent.

    Core (rest.cpp:743-780) exposes getdeploymentinfo over REST.
    Ouroboros has no equivalent.
    """
    src = _read_py("rest.py")
    has_route = "/deploymentinfo" in src or "rest_deploymentinfo" in src
    if not has_route:
        pytest.xfail(
            "W141 BUG-11 (P2): /rest/deploymentinfo route absent."
        )
    assert has_route


def test_w141_g24c_bug14_rest_error_content_type() -> None:
    """G24c BUG-14 (P1): REST 4xx body should be `text/plain` + `\\r\\n`.

    Core's RESTERR (rest.cpp:71-76) emits:
        Content-Type: text/plain
        Body: message + "\\r\\n"

    Ouroboros uses FastAPI's HTTPException, which emits JSON envelope
    `{"detail": "..."}`.
    """
    src = _read_py("rest.py")
    # Look for a custom PlainTextResponse on error paths
    has_plain_text_error = bool(
        re.search(
            r'PlainTextResponse[^)]*status_code\s*=\s*[45]\d\d',
            src,
        )
    )
    # Or any indication of a RESTERR-equivalent helper
    has_resterr = "RESTERR" in src or "_rest_error" in src
    if not (has_plain_text_error or has_resterr):
        pytest.xfail(
            "W141 BUG-14 (P1): REST 4xx errors emit FastAPI JSON "
            "envelope; Core uses text/plain with trailing \\r\\n. "
            "Tooling parity break."
        )
    assert has_plain_text_error or has_resterr


def test_w141_g24d_bug15_rest_warmup_gate() -> None:
    """G24d BUG-15 (P1): REST warmup gate absent.

    Core (rest.cpp:171-177) calls CheckWarmup at every handler entry,
    returning HTTP 503 if RPCIsInWarmup. Ouroboros has no warmup gate.
    """
    src = _read_py("rest.py")
    has_warmup = bool(
        re.search(r"\bwarmup\b|RPCIsInWarmup|_check_warmup", src, re.I)
    )
    if not has_warmup:
        pytest.xfail(
            "W141 BUG-15 (P1): REST handlers have no warmup gate. "
            "Hitting REST during boot returns 500 not 503."
        )
    assert has_warmup


# ============================================================================
# Notification scripts subsystem (G25-G27)
# ============================================================================


def test_w141_g25_bug19_blocknotify_absent() -> None:
    """G25 BUG-19 (P1): -blocknotify=<cmd> argv support absent.

    Core (init.cpp:498,2008-2018) wires the option to fire a shell
    command on every new tip outside IBD, replacing %s with the
    block hash hex.
    """
    config_src = _read_py("config.py")
    cli_src = _read_py("cli.py")
    everything = config_src + cli_src
    has_blocknotify = "blocknotify" in everything
    if not has_blocknotify:
        pytest.xfail(
            "W141 BUG-19 (P1): -blocknotify argv option absent. "
            "Operators migrating from Core lose script-driven workflows. "
            "Closure MUST follow the Core sanitization model — see BUG-20."
        )
    assert has_blocknotify


def test_w141_g26_bug19_alertnotify_absent() -> None:
    """G26 BUG-19 (P1): -alertnotify=<cmd> argv support absent.

    Core (init.cpp:485 + kernel_notifications.cpp:30-47) wires
    -alertnotify to fire on every alert, replacing %s with the
    SanitizeString-cleaned + single-quote-wrapped alert message.
    """
    config_src = _read_py("config.py")
    cli_src = _read_py("cli.py")
    everything = config_src + cli_src
    has_alertnotify = "alertnotify" in everything
    if not has_alertnotify:
        pytest.xfail(
            "W141 BUG-19 (P1): -alertnotify argv option absent. "
            "Closure MUST sanitize the alert text per Core "
            "kernel_notifications.cpp:30-47 (SanitizeString + "
            "single-quote wrap + ShellEscape) — see BUG-20."
        )
    assert has_alertnotify


def test_w141_g27_bug19_walletnotify_absent() -> None:
    """G27 BUG-19 (P1): -walletnotify=<cmd> argv support absent.

    Core (wallet/init.cpp:75, wallet/wallet.cpp:1480/3069) fires
    a shell command on every wallet tx change, replacing %s with
    the txid, %w with the wallet name, %b with the block hash,
    %h with the block height.
    """
    config_src = _read_py("config.py")
    wallet_src = _read_py("wallet.py")
    cli_src = _read_py("cli.py")
    everything = config_src + wallet_src + cli_src
    has_walletnotify = "walletnotify" in everything
    if not has_walletnotify:
        pytest.xfail(
            "W141 BUG-19 (P1): -walletnotify argv option absent. "
            "Closure MUST sanitize the wallet name (%w) per Core "
            "(NB: Core's docstring at wallet/init.cpp:75 warns "
            "explicitly about shell-escaping the wallet name) — "
            "see BUG-20."
        )
    assert has_walletnotify


# ============================================================================
# Two-pipeline + shell-injection guards (G28-G30)
# ============================================================================


def test_w141_g28_two_pipeline_zmq_python_only() -> None:
    """G28 two-pipeline guard: ferrous-utils (Rust) must contain NO
    ZMQ bindings. ZMQ is external-facing I/O — owned by Python.

    Forbidden tokens: zmq (crate import), tmq, tokio_zmq, zeromq,
    libzmq-sys.
    """
    rust_root = REPO_ROOT / "ferrous-utils"
    if not rust_root.exists():
        pytest.skip("ferrous-utils submodule not populated; guard vacuous")

    forbidden = (
        "use zmq",
        "extern crate zmq",
        "use tmq",
        "use tokio_zmq",
        "use zeromq",
        "libzmq_sys",
        "libzmq-sys",
    )
    offenders: list[str] = []
    for path in rust_root.rglob("*.rs"):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for needle in forbidden:
            if needle in text:
                offenders.append(f"{path.relative_to(rust_root)}: {needle}")

    assert not offenders, (
        f"G28 two-pipeline guard: ferrous-utils must NOT contain ZMQ "
        f"bindings — they belong in the Python pipeline. Offenders: "
        f"{offenders[:5]}"
    )


def test_w141_g29_two_pipeline_rest_python_only() -> None:
    """G29 two-pipeline guard: ferrous-utils (Rust) must contain NO
    HTTP server / REST framework bindings.

    Forbidden tokens: actix_web, axum::Server, hyper::Server, warp,
    rocket, TcpListener, tokio::net::TcpListener.
    """
    rust_root = REPO_ROOT / "ferrous-utils"
    if not rust_root.exists():
        pytest.skip("ferrous-utils submodule not populated; guard vacuous")

    forbidden = (
        "use actix_web",
        "use axum",
        "use hyper::Server",
        "hyper::server",
        "use warp",
        "use rocket",
        "TcpListener",
        "tokio::net::TcpListener",
    )
    offenders: list[str] = []
    for path in rust_root.rglob("*.rs"):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for needle in forbidden:
            if needle in text:
                offenders.append(f"{path.relative_to(rust_root)}: {needle}")

    assert not offenders, (
        f"G29 two-pipeline guard: ferrous-utils must NOT contain HTTP "
        f"server / REST bindings — they belong in the Python pipeline. "
        f"Offenders: {offenders[:5]}"
    )


def test_w141_g30_no_shell_exec_with_user_input() -> None:
    """G30 pre-emptive shell-injection guard (BUG-20).

    When BUG-19 (-blocknotify / -alertnotify / -walletnotify) is
    eventually closed, a future contributor MUST NOT naively
    interpolate node-state strings into a shell-true subprocess
    invocation. Specifically forbidden patterns:

      - subprocess.run(..., shell=True, ...) with an argv that
        contains f"..." / .format(...) / %-interpolation of any
        node-state token.
      - subprocess.Popen(..., shell=True, ...) same.
      - os.system(...) with interpolated argv at all.

    Block-hash and txid hex are `[0-9a-f]{64}`-validated upstream
    so they CAN be %s-substituted directly per Core's contract
    (init.cpp:2013). Untrusted strings (alert text, wallet name
    %w) MUST go through SanitizeString-equivalent + ShellEscape.

    This guard catches any new shell-true subprocess in
    src/ouroboros/ whose argv string is built via interpolation.
    """
    rust_root = SRC_OUROBOROS
    if not rust_root.exists():
        pytest.skip("ouroboros src dir absent")

    # Patterns: subprocess.{run,Popen,call,check_call,check_output}
    # with shell=True AND an argv string that is interpolated.
    shell_call_re = re.compile(
        r"(?:subprocess|sp)\.(?:run|Popen|call|check_call|check_output)"
        r"\s*\(\s*(?P<argv>[^,)\n]+)[^)]*?shell\s*=\s*True",
        re.S,
    )
    os_system_re = re.compile(r"\bos\.system\s*\(\s*(?P<argv>[^)]+)\)")
    # Interpolation tokens in the argv
    interp_re = re.compile(r"f['\"]|\.format\(|\s%\s|%\s*\(\s*\w")

    offenders: list[str] = []
    for path in rust_root.rglob("*.py"):
        # Skip the test file itself + venv-y dirs
        if "tests" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for m in shell_call_re.finditer(text):
            argv = m.group("argv")
            if interp_re.search(argv):
                offenders.append(
                    f"{path.relative_to(SRC_OUROBOROS)}: shell=True with interpolated argv: {argv[:60]}"
                )
        for m in os_system_re.finditer(text):
            argv = m.group("argv")
            if interp_re.search(argv):
                offenders.append(
                    f"{path.relative_to(SRC_OUROBOROS)}: os.system with interpolated argv: {argv[:60]}"
                )

    assert not offenders, (
        "G30 shell-injection guard (W141 BUG-20 pre-emptive): "
        "any subprocess(shell=True) or os.system(...) call in "
        "src/ouroboros/ with an interpolated argv is FORBIDDEN. "
        "Future closures of BUG-19 (-blocknotify / -alertnotify / "
        "-walletnotify) MUST follow Core's SanitizeString + "
        "ShellEscape pattern from kernel_notifications.cpp:30-47. "
        f"Offenders: {offenders[:5]}"
    )


def test_w141_g30_no_rust_shell_exec() -> None:
    """G30 supplementary: ferrous-utils (Rust) must contain NO
    Command::new / std::process::Command / std::process::exit
    invocations. Shell exec belongs in Python.
    """
    rust_root = REPO_ROOT / "ferrous-utils"
    if not rust_root.exists():
        pytest.skip("ferrous-utils submodule not populated; guard vacuous")

    forbidden = (
        "Command::new",
        "std::process::Command",
        "use std::process::Command",
        "tokio::process::Command",
    )
    offenders: list[str] = []
    for path in rust_root.rglob("*.rs"):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for needle in forbidden:
            if needle in text:
                offenders.append(f"{path.relative_to(rust_root)}: {needle}")

    assert not offenders, (
        f"G30 two-pipeline guard: ferrous-utils must NOT shell out. "
        f"Offenders: {offenders[:5]}"
    )


# ============================================================================
# Sanity / smoke gates
# ============================================================================


def test_w141_smoke_zmq_notifier_importable() -> None:
    """Smoke: ouroboros.zmq_notifier must remain importable.

    Two-pipeline anchor — if this fails the test suite can't run any
    of the above gates.
    """
    z = _zmqn()
    assert z.ZMQNotifier is not None


def test_w141_smoke_rest_module_importable() -> None:
    """Smoke: ouroboros.rest must remain importable."""
    r = _rest()
    assert r.RESTInterface is not None
    assert r.MAX_REST_HEADERS_RESULTS == 2000
    assert r.MAX_GETUTXOS_OUTPOINTS == 15
