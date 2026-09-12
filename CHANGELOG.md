# Changelog

## v1.0.2 — 2026-09-11

- 74403c5 docs: split the changelog — v1.0.1 shipped 2026-09-07, v1.0.2 is what is new since
- dea447e fix: gettxoutsetinfo hashed the set from a materialised list of every coin
- 9a70e19 docs: stall-class diagnosis — 70 CRITICALs are at-tip getdata to unservable peers
- fix: CheckProofOfWork target>powLimit on the header path; stall-clock no longer demotes honest tip peers; H1 getdata skips unservable peers and does not reset the in-flight timestamp


## v1.0.2 — 2026-09-11

Changes since `v1.0.1`:

- fix: gettxoutsetinfo hash_serialized_3 streams one txid group (was 85.8 GB at 875k)
- docs: stall-class diagnosis — 70 CRITICALs are at-tip getdata to unservable peers (`docs/STALL-CLASS-70-CRITICALS.md`)
- feat: getpeerinfo reports per-peer synced_headers/synced_blocks/inflight/presynced_headers from CNodeState-equivalent measurements instead of -1 stubs. Control: `pytest tests/test_per_peer_sync_fields.py`
- fix: header-sync CheckProofOfWork rejects target>powLimit (high-hash); stall-clock resets on empty/unconnecting headers; H1 never getdatas an unservable peer and does not reset the in-flight timestamp. Control: `pytest tests/test_stall_class_control.py`

## v1.0.1 — 2026-09-07

Changes since `v1.0.0`:

- 621ff72 docs: say the cited paths are private before the claims that rest on them
- c6086f9 fix: make importorskip("sync") able to skip, so those tests stop testing a mock
- 34b5875 fix: check proof of work before entering the low-work presync walk
- 0a6e42b fix: seed genesis from chainparams, and continue past the low-work gate
- bf0db78 fix: connect the first block above a snapshot base
- 66348f7 feat: HASHHOG_UNSAFE_SNAPSHOT_HEIGHT — accept an un-anchored UTXO snapshot
