# Security policy

ouroboros is an experimental, independent implementation of a Bitcoin full node. It is meant for research and testing. Do not use it to hold or move real funds.

## Supported versions

Only the latest `master` receives fixes. There are no long-term support releases and no response-time guarantee.

## Reporting a vulnerability

Please do not open a public GitHub issue for a problem in consensus, P2P or wallet code. A public report can put other nodes at risk before a fix exists.

Email the maintainer at `max@dockyard.navy` with:

- the affected component and commit,
- a reproduction: a regtest script, a block or transaction in hex, or a malformed P2P message,
- what happens and what you expected (ideally what Bitcoin Core does with the same input),
- a suggested fix, if you have one.

You will get an acknowledgement, a fix and disclosure timeline agreed with you, and credit if you want it.

## In scope

- Consensus divergence: ouroboros accepting a block or transaction that Bitcoin Core rejects, or rejecting one Core accepts.
- Remotely triggerable crashes, hangs, memory exhaustion or disk exhaustion through P2P messages, in the Python networking code or the Rust extension.
- Chainstate corruption after a crash or power loss.
- Wallet bugs that sign with the wrong key, produce a transaction the network rejects, compute a wrong fee, or lose keys.

## Out of scope

- Sync speed and resource use that is merely high.
- Attacks that need an already compromised host or access to the datadir.
- Exposing the metrics port to an untrusted network. The Prometheus exporter listens on port 9332 on all interfaces, has no authentication, and cannot be turned off; firewall it.

## Configuration to check

- The RPC server listens on `127.0.0.1` only. It uses the cookie in `<datadir>/.cookie` unless both `rpcuser` and `rpcpassword` are set in the config file. `GET /health`, `GET /getblockstats` and `GET /getblockfilter` on the RPC port answer without authentication.
- The P2P port listens on all interfaces by default. Use `--bind 127.0.0.1` or `--nolisten` to restrict it.

## Wallet caveats

The wallet has not been reviewed for custody. Wallet files live under `<datadir>/wallets/` and include the HD seed. They are not encrypted unless you call `encryptwallet`; protect the datadir accordingly. `dumpmnemonic` and `dumpprivkey` print secrets to anyone who can call the RPC.
