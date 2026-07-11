"""Outbound peer selection requires desirable service flags (Core parity).

Bitcoin Core's ``ThreadOpenConnections`` (net.cpp:2852) skips any addrman
candidate for which ``HasAllDesirableServiceFlags`` is false, i.e. peers that
do not advertise NODE_WITNESS together with NODE_NETWORK (or, near the tip, a
NODE_NETWORK_LIMITED substitute). Before this fix ouroboros' outbound selection
ignored service flags entirely, so the node drifted into a population dominated
by non-witness peers — which then silently dropped witness-block getdata and
wedged block-body delivery near the tip.

These tests pin the new behaviour:

  * ``has_all_desirable_service_flags`` matches Core's truth table.
  * ``select_for_connection(require_services=...)`` returns only witness-capable
    peers when such peers exist in addrman.
  * The requirement is a strong PREFERENCE with an unfiltered fallback, so a
    population containing no witness peers never starves outbound slots.

Reference: bitcoin-core/src/net.cpp:2852 (HasAllDesirableServiceFlags gate),
           bitcoin-core/src/net_processing.cpp:1752-1766
           (HasAllDesirableServiceFlags / GetDesirableServiceFlags).
"""

from __future__ import annotations

from ouroboros.addrman import (
    AddressManager,
    get_desirable_service_flags,
    has_all_desirable_service_flags,
)
from ouroboros.p2p_messages import (
    NODE_BLOOM,
    NODE_NETWORK,
    NODE_NETWORK_LIMITED,
    NODE_WITNESS,
)

FULL = NODE_NETWORK | NODE_WITNESS
DESIRED = NODE_NETWORK | NODE_WITNESS


# ---------------------------------------------------------------------------
# HasAllDesirableServiceFlags parity
# ---------------------------------------------------------------------------

def test_has_all_desirable_service_flags_truth_table():
    # Full node (NODE_NETWORK | NODE_WITNESS) — desirable.
    assert has_all_desirable_service_flags(NODE_NETWORK | NODE_WITNESS) is True
    # Witness but no network reachability — not desirable.
    assert has_all_desirable_service_flags(NODE_WITNESS) is False
    # Full block history but no witness — not desirable (the exact wedge cause).
    assert has_all_desirable_service_flags(NODE_NETWORK) is False
    # Unknown services (not yet learned) — never desirable; witness must be
    # advertised, exactly as in Core.
    assert has_all_desirable_service_flags(0) is False
    # Bloom + witness but no network — still not desirable.
    assert has_all_desirable_service_flags(NODE_BLOOM | NODE_WITNESS) is False


def test_network_limited_substitutes_only_near_tip():
    # BIP159 limited peer with witness is desirable ONLY when near the tip
    # (its 288-block window then covers what we need). Core:
    # GetDesirableServiceFlags substitutes NODE_NETWORK_LIMITED for NODE_NETWORK
    # when ApproximateBestBlockDepth() < 288.
    limited = NODE_NETWORK_LIMITED | NODE_WITNESS
    assert has_all_desirable_service_flags(limited, near_tip=True) is True
    assert has_all_desirable_service_flags(limited, near_tip=False) is False

    assert get_desirable_service_flags(limited, near_tip=True) == (
        NODE_NETWORK_LIMITED | NODE_WITNESS
    )
    assert get_desirable_service_flags(limited, near_tip=False) == (
        NODE_NETWORK | NODE_WITNESS
    )
    # A full peer always requires NODE_NETWORK | NODE_WITNESS regardless of tip.
    assert get_desirable_service_flags(FULL) == (NODE_NETWORK | NODE_WITNESS)


# ---------------------------------------------------------------------------
# select_for_connection preference
# ---------------------------------------------------------------------------

def _mixed_addrman() -> tuple[AddressManager, set[str], set[str]]:
    """Addrman with a mix of witness-capable and non-witness routable peers."""
    am = AddressManager(data_dir=None)
    source = "203.0.113.1:8333"

    witness = set()
    non_witness = set()

    # Witness-capable full nodes across distinct /8s (netgroup-diverse).
    for i, host in enumerate(["8.8.8.8", "9.9.9.9", "1.1.1.1", "4.4.4.4"]):
        assert am.add(host, 8333, services=FULL, source=source, timestamp=0.0)
        witness.add(f"{host}:8333")

    # Non-witness peers (NODE_NETWORK only) — the undesirable population.
    for host in ["12.34.56.78", "23.45.67.89", "34.56.78.90", "45.67.89.101"]:
        assert am.add(host, 8333, services=NODE_NETWORK, source=source, timestamp=0.0)
        non_witness.add(f"{host}:8333")

    return am, witness, non_witness


def test_select_prefers_witness_capable_peers():
    am, witness, non_witness = _mixed_addrman()

    picks = set()
    for _ in range(400):
        addr = am.select_for_connection(require_services=DESIRED)
        assert addr is not None
        picks.add(addr)

    # Every selection landed on a witness-capable peer; the non-witness
    # population was never chosen while witness peers were available.
    assert picks.issubset(witness), f"selected undesirable peers: {picks - witness}"
    assert picks & non_witness == set()


def test_no_requirement_selects_from_full_population():
    # Backwards compatibility: with require_services=0 (default) the old
    # unfiltered behaviour is preserved and non-witness peers are eligible.
    am, witness, non_witness = _mixed_addrman()
    picks = set()
    for _ in range(400):
        addr = am.select_for_connection()
        assert addr is not None
        picks.add(addr)
    # Both populations are reachable without a requirement.
    assert picks & non_witness, "unfiltered select never reached non-witness peers"


def test_fallback_does_not_starve_when_no_witness_peers():
    # A population with ONLY non-witness peers must still yield connections —
    # the requirement is a strong preference, not a hard filter, so we never
    # starve the live node's outbound slots.
    am = AddressManager(data_dir=None)
    source = "203.0.113.1:8333"
    non_witness = set()
    for host in ["12.34.56.78", "23.45.67.89", "34.56.78.90"]:
        assert am.add(host, 8333, services=NODE_NETWORK, source=source, timestamp=0.0)
        non_witness.add(f"{host}:8333")

    got = None
    for _ in range(50):
        got = am.select_for_connection(require_services=DESIRED)
        if got:
            break
    assert got in non_witness, "witness preference starved outbound selection"


def test_empty_addrman_returns_none():
    am = AddressManager(data_dir=None)
    assert am.select_for_connection(require_services=DESIRED) is None
