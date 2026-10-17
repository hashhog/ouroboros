# Status and how to check it

Each row of the status table in the [README](../README.md) can be checked with the commands on this page. Last updated 2026-10-17, against the `master` commit of that date. The commands assume the build from the README's quick start, with the virtualenv active.

## Test suite

```bash
git clone --depth 1 --branch v31.1 https://github.com/bitcoin/bitcoin.git bitcoin
python -m pytest
```

The clone puts Bitcoin Core's test vectors where `tests/test_script_vectors.py` and `tests/test_sighash_vectors.py` look for them (`bitcoin/src/test/data/`). On 2026-10-17 the suite ran in under two minutes, four times: each run had 3,953 passed, 4 failed, 83 skipped, 58 expected failures (`xfail`) and 1 unexpected pass. Three tests failed every time:

| Test | Failure |
|---|---|
| `tests/functional/test_submitpackage.py::TestSubmitPackageErrors::test_empty_package_rejected` | The test expects a different error message from the one the RPC now gives (`Array must contain between 1 and 25 transactions.`). |
| `tests/functional/test_submitpackage.py::TestSubmitPackageErrors::test_invalid_hex_rejected` | Same: the message is now `TX decode failed. Make sure the tx has at least one input.` |
| `tests/test_rerequest_loop.py::test_drain_pops_connected_header_before_yield` | A mock in the test returns a `MagicMock` where the code compares with a float. |

The fourth failure depends on how the suite is run. `tests/test_cli_daemon.py::test_pidfile_owned_by_live_process_raises` uses pytest's parent process as a "live" PID, so it fails when that parent has exited (for example `nohup python -m pytest &` from a shell that then ends). `tests/test_cli_daemon.py::test_sd_notify_sends_datagram` binds a Unix socket under pytest's temporary directory, so it fails with `AF_UNIX path too long` when `TMPDIR` is a long path.

Most tests run against a stand-in for the Rust extension that `tests/conftest.py` installs, so they test the Python code.

## Script interpreter

```bash
python -m pytest -s tests/test_script_vectors.py
python tests/test_sighash_vectors.py
```

The first prints `script_tests.json results: 1222 passed, 0 failed, 51 skipped, 0 parse errors`; the 51 skipped entries are the file's comment lines, so every vector runs. The second prints `PASSED : 500` and `All sighash test vectors passed.` Both use the Python interpreter, which is the default. `tests/native_script_differential.py` compares it with the Rust interpreter.

## UTXO set against Core, on regtest

This builds a chain on Bitcoin Core, lets ouroboros sync it over P2P, and compares the two UTXO-set hashes. `hash_serialized_3` covers every coin, so one wrong coin, amount or script changes it. You need Bitcoin Core's `bitcoind` and `bitcoin-cli` on your `PATH`; this was run with Core v31.1.

```bash
CORE=$(mktemp -d); NODE=$(mktemp -d)
bitcoind -regtest -datadir="$CORE" -port=18544 -rpcport=18543 -listen=1 -daemon
sleep 3
bitcoin-cli -regtest -datadir="$CORE" -rpcport=18543 generatetoaddress 200 bcrt1qlfglp2xalgefyyy8hdh3h6wg8ceqn006jdyp89
ouroboros --network regtest --data-dir "$NODE" start --rpc-port 18443 --p2p-port 18444 --connect 127.0.0.1:18544 &
sleep 20
bitcoin-cli -regtest -datadir="$CORE" -rpcport=18543 gettxoutsetinfo
curl -s --user "$(cat "$NODE/.cookie")" -d '{"method":"gettxoutsetinfo","params":[]}' http://127.0.0.1:18443/
```

Both report `"height": 200`, the same `bestblock`, and `"hash_serialized_3": "55a904f0ebf65d38b61e674ea2c411e0241cd7d311ad8c5f35c24c9eafbfe44f"`. The block hashes change from run to run because block times differ, but this UTXO hash does not: the chain holds only coinbase outputs to a fixed address, and their txids do not depend on the time.

To compare at a height below Core's tip, make Core step back first. Continuing with the nodes above:

```bash
curl -s --user "$(cat "$NODE/.cookie")" -d '{"method":"stop","params":[]}' http://127.0.0.1:18443/
NODE=$(mktemp -d)
bitcoin-cli -regtest -datadir="$CORE" -rpcport=18543 invalidateblock "$(bitcoin-cli -regtest -datadir="$CORE" -rpcport=18543 getblockhash 151)"
ouroboros --network regtest --data-dir "$NODE" start --rpc-port 18443 --p2p-port 18444 --connect 127.0.0.1:18544 &
sleep 20
bitcoin-cli -regtest -datadir="$CORE" -rpcport=18543 gettxoutsetinfo
curl -s --user "$(cat "$NODE/.cookie")" -d '{"method":"gettxoutsetinfo","params":[]}' http://127.0.0.1:18443/
curl -s --user "$(cat "$NODE/.cookie")" -d '{"method":"stop","params":[]}' http://127.0.0.1:18443/
bitcoin-cli -regtest -datadir="$CORE" -rpcport=18543 stop
```

Both nodes now stop at height 150 and report the same `hash_serialized_3`, `63e1130785ac5b59264e22149175cb6a304c1eea345700289ff2d25b52a29014`.

## UTXO set against Core, on mainnet

The same comparison works on mainnet with a fully synced Bitcoin Core. To check the README's height:

1. On Core, `invalidateblock` the block at height 958,795, so that Core's tip is 958,794 and it serves no later blocks. `gettxoutsetinfo` on Core then reports `hash_serialized_3` `29692050559b8f064a03af9cd605040e71d1d978fa22947c079cc7e5546e7af0` and `"txouts": 166180925`.
2. Start ouroboros on a fresh datadir with `--noassumevalid --connect <core-host>:8333`, so that every script is checked and every block comes from that Core node.
3. When ouroboros reaches height 958,794, call `gettxoutsetinfo` on it and compare.
4. `reconsiderblock` the same block on Core afterwards.

`--noassumevalid` matters: without it, scripts are not checked below height 850,000. A full pass this way takes a long time, because most of ouroboros' validation runs in Python.

The README's result was produced in pieces: the chain was cut into 48 ranges, each range was synced with scripts checked on a datadir loaded from a UTXO snapshot of the range's starting height (`ouroboros import-utxo`, with `HASHHOG_UNSAFE_SNAPSHOT_HEIGHT` for heights that are not built-in assumeUTXO points), and the UTXO hash at the end of each range was compared with Core's at that height. Core's `dumptxoutset` with `rollback=<height>` writes such a snapshot and prints its hash as `txoutset_hash`. `import-utxo` prints the hash it computes from the same file, so the two can be compared directly.

## RPC coverage

Start a regtest node as in the README's quick start, then:

```bash
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"help","params":[]}' http://127.0.0.1:18443/
```

`help` lists all 142 methods, one per line. [rpc.md](rpc.md) groups them and lists the known differences from Core.

## Known limitations

- The REST interface, ZMQ notifications and pruning exist in the code but cannot be turned on: no command-line option sets them, and the config-file keys for them are not read.
- The config file is only read from the `[rpc]`, `[p2p]`, `[network]`, `[logging]` and `[mainnet]` sections; `[DEFAULT]` and per-network sections such as `[regtest]` are ignored ([running.md](running.md#config-file)).
- `--rpc-port` and `--p2p-port` default to 8332 and 8333 on every network.
- `proxy`, `onion`, `i2psam`, `torcontrol` and `asmap` are parsed from the config file but not used, so Tor, I2P and ASMap bucketing cannot be enabled.
- The RPC server only listens on `127.0.0.1`.
- The Prometheus exporter always listens on port 9332 on all interfaces.
- `--reindex` prints a warning and does nothing else.
- `ouroboros status` cannot read the best block or mempool ([running.md](running.md#commands)).
- A hash given to `--assumevalid` is ignored; only `0` changes anything.
- `generateblock` and `generatetodescriptor` are not implemented; use `generatetoaddress` on regtest.
- After `import-utxo` on regtest the node does not sync past the snapshot height, because regtest has no built-in header for the snapshot's block.
- Initial block download is slow, because most validation runs in Python.
- Four tests in the suite fail (see above).
