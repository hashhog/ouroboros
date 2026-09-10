# Changelog

## v1.0.1 (unreleased)

Changes since `v1.0.0`:

- docs: stall-class diagnosis — 70 CRITICALs are at-tip getdata to unservable peers (`docs/STALL-CLASS-70-CRITICALS.md`); no fix until a failing control exists
- 621ff72 docs: say the cited paths are private before the claims that rest on them
- c6086f9 fix: make importorskip("sync") able to skip, so those tests stop testing a mock
- 34b5875 fix: check proof of work before entering the low-work presync walk
- 0a6e42b fix: seed genesis from chainparams, and continue past the low-work gate
- bf0db78 fix: connect the first block above a snapshot base
- 66348f7 feat: HASHHOG_UNSAFE_SNAPSHOT_HEIGHT — accept an un-anchored UTXO snapshot

