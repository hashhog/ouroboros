#!/bin/bash
# Script to download Bitcoin test data for testing

set -e

TEST_DATA_DIR="ferrous-utils/sync/tests/data"
mkdir -p "$TEST_DATA_DIR"

echo "Downloading Bitcoin test data..."

# Download Bitcoin Core script test vectors
echo "Downloading script test vectors..."
curl -s -o "$TEST_DATA_DIR/script_tests.json" \
    https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/test/data/script_tests.json || {
    echo "Warning: Could not download script_tests.json"
    echo "You may need to download this manually from:"
    echo "https://github.com/bitcoin/bitcoin/blob/master/src/test/data/script_tests.json"
}

# Download Bitcoin Core base58 test vectors
echo "Downloading base58 test vectors..."
curl -s -o "$TEST_DATA_DIR/base58_keys_valid.json" \
    https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/test/data/base58_keys_valid.json || {
    echo "Warning: Could not download base58_keys_valid.json"
}

# Create directory for blocks
mkdir -p "$TEST_DATA_DIR/blocks"
mkdir -p "$TEST_DATA_DIR/headers"
mkdir -p "$TEST_DATA_DIR/transactions"

echo ""
echo "Test data download complete!"
echo ""
echo "Note: To download actual blocks, you'll need to:"
echo "1. Run Bitcoin Core on testnet"
echo "2. Use RPC calls to export blocks:"
echo "   bitcoin-cli getblock <hash> 0 > tests/data/blocks/block_<height>.hex"
echo ""
echo "Or use a block explorer API to download block data."

