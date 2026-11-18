#!/usr/bin/env python3
"""Record a Bitcoin Core v31.1 regtest chain for tests/test_index_header_fill.py.

Starts a throwaway bitcoind -regtest (no wallet, no listening socket), mines
120 blocks to OP_TRUE, then 5 blocks that each spend matured coinbases with
`generateblock` (so those blocks hold 2-4 transactions), and writes for every
height h in 0..tip:

    hash, block (getblock h 0), header_hex (getblockheader h false),
    header (getblockheader h true)

to core31_chain.json next to this script.  `getblockheader` is the reference
the test compares ouroboros' answer to.

Usage:  BITCOIND=<bitcoin-31.1>/bin/bitcoind python3 make_fixture.py <scratch-dir>
"""
import base64, hashlib, json, os, subprocess, sys, time, urllib.request

bitcoind = os.environ["BITCOIND"]
scratch = sys.argv[1]
os.makedirs(scratch, exist_ok=False)
PORT, RPC = 29_741, 29_742
proc = subprocess.Popen([bitcoind, "-regtest", f"-datadir={scratch}", f"-port={PORT}",
                         f"-rpcport={RPC}", "-listen=0", "-server", "-disablewallet",
                         "-rpcuser=u", "-rpcpassword=p", "-fallbackfee=0.0001"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
auth = base64.b64encode(b"u:p").decode()


def rpc(method, *params):
    req = urllib.request.Request(f"http://127.0.0.1:{RPC}/", json.dumps(
        {"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode(),
        {"Authorization": f"Basic {auth}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        out = json.loads(r.read())
    if out.get("error"):
        raise RuntimeError(out["error"])
    return out["result"]


try:
    for _ in range(100):
        try:
            rpc("getblockcount")
            break
        except Exception:
            time.sleep(0.2)
    version = rpc("getnetworkinfo")["subversion"]
    desc = rpc("getdescriptorinfo", "raw(51)")["descriptor"]
    rpc("generatetodescriptor", 120, desc)

    def spend(txid, vout, value_sat, n_out):
        # version 2, one input with an empty scriptSig (OP_TRUE needs none),
        # n_out OP_TRUE outputs, fee 1000 sat.
        each = (value_sat - 1000) // n_out
        tx = (2).to_bytes(4, "little") + b"\x01" + bytes.fromhex(txid)[::-1]
        tx += vout.to_bytes(4, "little") + b"\x00" + b"\xff\xff\xff\xff"
        tx += bytes([n_out]) + b"".join(each.to_bytes(8, "little") + b"\x01\x51" for _ in range(n_out))
        tx += b"\x00\x00\x00\x00"
        return tx.hex()

    h = 1
    for n_txs in (1, 2, 3, 1, 2):
        raws = []
        for _ in range(n_txs):
            cb = rpc("getblock", rpc("getblockhash", h), 2)["tx"][0]
            raws.append(spend(cb["txid"], 0, int(round(cb["vout"][0]["value"] * 1e8)), 2))
            h += 1
        rpc("generateblock", desc, raws)
    tip = rpc("getblockcount")
    chain = []
    for i in range(tip + 1):
        bh = rpc("getblockhash", i)
        chain.append({"height": i, "hash": bh, "block": rpc("getblock", bh, 0),
                      "header_hex": rpc("getblockheader", bh, False),
                      "header": rpc("getblockheader", bh, True)})
    out = {"core": version, "tip": tip, "chain": chain}
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "core31_chain.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=0, sort_keys=True)
        f.write("\n")
    print(f"{version} tip={tip} wrote {path}")
finally:
    try:
        rpc("stop")
    except Exception:
        pass
    proc.wait(timeout=60)
