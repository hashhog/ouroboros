# Security Policy — ouroboros

ouroboros is a from-scratch Bitcoin full-node implementation in Python and Rust,
part of the [hashhog](https://github.com/hashhog) fleet of ten independent nodes that
cross-validate each other and Bitcoin Core.

## Project maturity — read this first

ouroboros is a pre-release node. Its consensus validation is exercised by the fleet's
cross-implementation differential harness against Bitcoin Core, but it has NOT
completed an independently verified `--assumevalid=0` genesis→tip validation on this
project's hardware (see `../CHARTER.md`). Treat it as a watchtower/validator run
*beside* Bitcoin Core, not as a standalone source of truth.

**It is NOT fund-capable.** Do not custody funds on it. There are no fund-grade
guarantees. Run from a pinned commit.

Release-signing key fingerprint: to be published with v1.0.0.

## Supported versions

| Version | Supported |
|---------|-----------|
| `v0.1.0-beta1` (pinned `6d87d1a`) | Beta — best-effort; no security SLA until the final `v0.1.0` |
| pre-release (`master`) | Best-effort |

## Reporting a vulnerability

**Please do NOT open a public GitHub issue** for anything in the consensus, P2P, or
wallet paths — a public report could put real Bitcoin nodes or funds at risk.

Report privately to the maintainer:

- **Email:** `max@dockyard.navy`  <!-- TODO(max): confirm or replace with a dedicated security alias -->

Include the affected path, a deterministic reproduction (a diff-test corpus entry,
regtest script, or malformed message), impact, and any suggested fix. We coordinate
a fix + disclosure timeline and credit you if you wish.

## In scope (highest priority)

- **Consensus divergence** — ouroboros accepting a block/tx Core rejects, or vice-versa.
- **Remotely-triggerable crashes / OOM / resource exhaustion** in the P2P or block/tx
  decode paths (Python asyncio networking and the Rust sync engine alike).
- **Wallet funds-safety** — silent wrong-key signing, a spend the node reports valid
  that the network rejects, un-recoverable backups, fee miscalculation stranding funds.
- **Chainstate corruption on crash.**

## Out of scope

- IBD/sync performance characteristics.
- Issues requiring an already-compromised host.

## Disclosure

Coordinated disclosure. Consensus fixes are verified with `../tools/verify-fix.sh` and
gated through the differential corpus before they are considered landed; a live
watchtower (`../tools/watchtower.sh`) alarms on any ouroboros-vs-Core divergence.
