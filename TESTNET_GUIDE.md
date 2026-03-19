# Running Ouroboros on Bitcoin Testnet

Yes, you can run the node on testnet! Here's how:

## Available Test Networks

- **testnet** (testnet3): Classic Bitcoin testnet, port 18333
- **testnet4**: Newer testnet (BIP-94) with difficulty fixes, port 48333

## Quick Start

### Option 1: Using CLI with `--network` flag

```bash
# Sync testnet blockchain
python3 -m ouroboros.cli --network testnet sync

# Start node on testnet
python3 -m ouroboros.cli --network testnet start
```

### Testnet4

```bash
# Sync testnet4 (use separate data dir to avoid mixing with testnet3)
ouroboros --network testnet4 --data-dir ~/.ouroboros-testnet4 sync
ouroboros --network testnet4 --data-dir ~/.ouroboros-testnet4 start
```

If you have trouble connecting to peers (e.g. "No peers available"), try IPv4-only mode—many networks block or don't route IPv6:
```bash
OUROBOROS_PREFER_IPV4=1 ouroboros --network testnet4 --data-dir ~/.ouroboros-testnet4 sync
```

### Option 2: Using configuration file

Create `~/.ouroboros/ouroboros.conf`:

```ini
[network]
network=testnet

[rpc]
rpcport=18332

[p2p]
p2pport=18333
```

Then run:
```bash
python3 -m ouroboros.cli sync
python3 -m ouroboros.cli start
```

### Option 3: Using environment variables

```bash
export OUROBOROS_NETWORK=testnet
python3 -m ouroboros.cli sync
python3 -m ouroboros.cli start
```

## Testnet Default Ports

- **RPC Port**: 18332 (instead of 8332 for mainnet)
- **P2P Port**: 18333 (instead of 8333 for mainnet)

These are automatically set when you specify `--network testnet` or set `network=testnet` in config.

## Testnet Features

✅ **Supported Features:**
- Testnet peer discovery (uses testnet DNS seeds)
- Testnet magic bytes for P2P messages
- Testnet-specific ports
- Testnet blockchain sync
- All RPC methods work on testnet

## Example: Sync and Start Testnet Node

```bash
# 1. Sync testnet blockchain
python3 -m ouroboros.cli --network testnet --data-dir ~/.ouroboros-testnet sync

# 2. Start the node
python3 -m ouroboros.cli --network testnet --data-dir ~/.ouroboros-testnet start
```

## Testnet RPC Examples

Once running, you can use RPC on port 18332:

```bash
# Get blockchain info
curl -X POST http://localhost:18332/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}'

# Get block count
curl -X POST http://localhost:18332/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}'
```

## Separate Data Directory

It's recommended to use a separate data directory for testnet to avoid mixing with mainnet data:

```bash
python3 -m ouroboros.cli --network testnet --data-dir ~/.ouroboros-testnet sync
```

## Regtest Support

You can also run on regtest (local testing network):

```bash
python3 -m ouroboros.cli --network regtest sync
python3 -m ouroboros.cli --network regtest start
```

Regtest uses ports:
- RPC: 18443
- P2P: 18444

## Troubleshooting

### Port Already in Use

If you get "port already in use" errors, make sure:
1. No other Bitcoin node is running on those ports
2. You're using the correct ports for the network (testnet uses 18332/18333)

### Can't Connect to Peers

Testnet has fewer peers than mainnet. If you can't connect:
1. Wait a bit - peer discovery may take time
2. Check your firewall settings
3. Verify you're using `--network testnet` flag

### Wrong Network

If you see errors about magic bytes or network mismatches:
1. Make sure you're using `--network testnet` consistently
2. Check your config file has `network=testnet`
3. Clear the data directory if you switched networks

## Configuration Priority

Configuration is loaded in this order (highest priority first):
1. CLI arguments (`--network`, `--rpc-port`, etc.)
2. Environment variables (`OUROBOROS_NETWORK`, etc.)
3. Config file (`~/.ouroboros/ouroboros.conf`)
4. Default values
