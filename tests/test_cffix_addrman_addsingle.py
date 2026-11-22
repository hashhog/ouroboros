"""AddressManager.add parity with Core's AddrManImpl::AddSingle.

Core (src/addrman.cpp, AddSingle):
  * an already-known address ORs the advertised services into the stored
    ones (``pinfo->nServices = ServiceFlags(pinfo->nServices | addr.nServices)``)
    before any early return, so gossip can add flags but never strip them;
  * an occupied new-table slot is only overwritten when the incumbent
    ``IsTerrible()`` or (incumbent nRefCount > 1 and the newcomer's
    nRefCount == 0). Otherwise the newcomer is dropped.

Before this fix ouroboros replaced services outright and always evicted the
slot's occupant, so a peer gossiping ``services=1`` could downgrade an honest
NODE_NETWORK|NODE_WITNESS entry out of full-service selection, and any
colliding gossip could displace a healthy address.
"""

import time

from ouroboros.addrman import AddressManager

NODE_NETWORK = 1
NODE_WITNESS = 1 << 3
FULL = NODE_NETWORK | NODE_WITNESS


def _force_collision(monkeypatch, am: AddressManager) -> None:
    """Map every address to new bucket 7, position 11."""
    monkeypatch.setattr(am, "_get_new_bucket", lambda addr, source_group: 7)
    monkeypatch.setattr(
        am, "_get_bucket_position", lambda addr, is_new, bucket: 11
    )


def test_readd_new_entry_keeps_witness_flag():
    am = AddressManager()
    now = time.time()
    assert am.add("1.2.3.4", 8333, services=FULL, timestamp=now, source="5.6.7.8")
    am.add("1.2.3.4", 8333, services=NODE_NETWORK, timestamp=now + 10,
           source="9.9.9.9")
    info = am.get_addr_info("1.2.3.4", 8333)
    assert info.services == FULL


def test_readd_ors_in_new_services():
    am = AddressManager()
    now = time.time()
    am.add("1.2.3.4", 8333, services=NODE_NETWORK, timestamp=now, source="5.6.7.8")
    am.add("1.2.3.4", 8333, services=NODE_WITNESS, timestamp=now, source="5.6.7.8")
    assert am.get_addr_info("1.2.3.4", 8333).services == FULL


def test_readd_tried_entry_ors_services():
    am = AddressManager()
    now = time.time()
    am.add("1.2.3.4", 8333, services=NODE_NETWORK, timestamp=now, source="5.6.7.8")
    am.mark_good("1.2.3.4", 8333)
    am.add("1.2.3.4", 8333, services=NODE_WITNESS, timestamp=now, source="5.6.7.8")
    info = am.get_addr_info("1.2.3.4", 8333)
    assert info.services == FULL


def test_collision_keeps_non_terrible_incumbent(monkeypatch):
    am = AddressManager()
    _force_collision(monkeypatch, am)
    now = time.time()
    assert am.add("1.2.3.4", 8333, services=FULL, timestamp=now, source="5.6.7.8")
    inserted = am.add("8.8.4.4", 8333, services=FULL, timestamp=now,
                      source="9.9.9.9")
    assert inserted is False
    assert am.get_addr_info("1.2.3.4", 8333) is not None
    # The rejected newcomer is not left dangling in the address map.
    assert am.get_addr_info("8.8.4.4", 8333) is None
    assert am.size() == 1
    assert am._new_buckets[7][11] == "1.2.3.4:8333"


def test_collision_evicts_terrible_incumbent(monkeypatch):
    # Negative control for the guard: a terrible incumbent (last seen beyond
    # the 30-day horizon) is still overwritten, as in Core.
    am = AddressManager()
    _force_collision(monkeypatch, am)
    now = time.time()
    am.add("1.2.3.4", 8333, services=FULL, timestamp=now - 40 * 86400,
           source="5.6.7.8")
    assert am._is_terrible(am.get_addr_info("1.2.3.4", 8333))
    assert am.add("8.8.4.4", 8333, services=FULL, timestamp=now,
                  source="9.9.9.9")
    assert am.get_addr_info("1.2.3.4", 8333) is None
    assert am._new_buckets[7][11] == "8.8.4.4:8333"
    assert am.size() == 1


def test_collision_evicts_multi_ref_incumbent(monkeypatch):
    # Core's second overwrite condition: incumbent nRefCount > 1 and the
    # newcomer nRefCount == 0. The incumbent loses one reference and stays
    # known through its other bucket.
    am = AddressManager()
    _force_collision(monkeypatch, am)
    now = time.time()
    am.add("1.2.3.4", 8333, services=FULL, timestamp=now, source="5.6.7.8")
    am.get_addr_info("1.2.3.4", 8333).ref_count = 2
    assert am.add("8.8.4.4", 8333, services=FULL, timestamp=now,
                  source="9.9.9.9")
    assert am._new_buckets[7][11] == "8.8.4.4:8333"
    assert am.get_addr_info("1.2.3.4", 8333).ref_count == 1
