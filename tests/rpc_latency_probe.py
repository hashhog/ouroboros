#!/usr/bin/env python3
"""RPC latency probe — measures getblockchaininfo response times."""

import base64
import json
import time
import urllib.request


def rpc_call(url, auth, method, params=None):
    payload = json.dumps({
        "jsonrpc": "1.0", "id": 1,
        "method": method, "params": params or []
    }).encode()
    req = urllib.request.Request(url, data=payload,
        headers={"Content-Type": "application/json"})
    cred = base64.b64encode(auth.encode()).decode()
    req.add_header("Authorization", f"Basic {cred}")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8359)
    parser.add_argument("--cookie", type=str, required=True)
    parser.add_argument("--calls", type=int, default=20)
    args = parser.parse_args()

    with open(args.cookie) as f:
        auth = f.read().strip()
    url = f"http://127.0.0.1:{args.port}/"

    latencies = []
    for i in range(args.calls):
        t0 = time.monotonic()
        try:
            rpc_call(url, auth, "getblockchaininfo")
            elapsed_ms = (time.monotonic() - t0) * 1000
            latencies.append(elapsed_ms)
            print(f"  call {i+1:3d}: {elapsed_ms:8.1f}ms")
        except Exception as e:
            elapsed_ms = (time.monotonic() - t0) * 1000
            print(f"  call {i+1:3d}: FAILED after {elapsed_ms:.0f}ms — {e}")

    if latencies:
        latencies.sort()
        p50 = latencies[len(latencies) // 2]
        p95_idx = int(len(latencies) * 0.95)
        p95 = latencies[min(p95_idx, len(latencies) - 1)]
        print(f"\n  n={len(latencies)}  p50={p50:.0f}ms  p95={p95:.0f}ms  "
              f"max={max(latencies):.0f}ms  min={min(latencies):.0f}ms")

if __name__ == "__main__":
    main()
