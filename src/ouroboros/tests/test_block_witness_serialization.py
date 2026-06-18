"""BIP144 block witness-serialization regression.

Guards the fix for the P2P reorg-drop blocker's final gap: serving a block in
response to a ``MSG_WITNESS_BLOCK`` getdata MUST preserve the segwit witness
(the coinbase witness reserved value / nonce), or the requesting peer rejects
the block "bad-witness-nonce-size" when it runs CheckWitnessCommitment.

The Python ``Block`` round-trip strips witnesses via ``Block.serialize()``
(``get_block_bytes`` exists precisely because of that), so the getdata handler
must use the witness-preserving raw bytes or ``Block.serialize_with_witness()``.
This test pins ``serialize_with_witness`` round-tripping the coinbase nonce and
proves it differs from the stripped ``serialize``.
"""
from ouroboros.database import Block, Transaction, TxIn, TxOut


def _segwit_coinbase() -> Transaction:
    """A coinbase carrying a 32-byte witness reserved value (the nonce)."""
    nonce = bytes(32)  # Core's default coinbase witness reserved value
    cb_in = TxIn(
        prev_txid=bytes(32),
        prev_vout=0xFFFF_FFFF,
        script_sig=b"\x03\x01\x00\x00",  # BIP34-ish height push (content irrelevant here)
        sequence=0xFFFF_FFFF,
        witness=[nonce],
    )
    # A witness-commitment output (OP_RETURN 0x24 0xaa21a9ed || 32-byte commitment).
    commitment = b"\x6a\x24\xaa\x21\xa9\xed" + bytes(32)
    cb_out = TxOut(value=50_00000000, script_pubkey=commitment)
    return Transaction(
        txid=bytes(32),
        version=1,
        locktime=0,
        inputs=[cb_in],
        outputs=[cb_out],
        has_witness=True,
    )


def _block_with(coinbase: Transaction) -> Block:
    return Block(
        version=0x20000000,
        prev_blockhash=bytes(32),
        merkle_root=bytes(32),
        timestamp=1_700_000_000,
        bits=0x207FFFFF,
        nonce=0,
        transactions=[coinbase],
        hash=bytes(32),
    )


def test_serialize_with_witness_preserves_coinbase_nonce():
    block = _block_with(_segwit_coinbase())

    witness_bytes = block.serialize_with_witness()
    stripped_bytes = block.serialize()

    # The witness form must be strictly larger (marker+flag+witness stack) and
    # different from the stripped form.
    assert witness_bytes != stripped_bytes
    assert len(witness_bytes) > len(stripped_bytes)

    # Round-trip the witness bytes: the coinbase witness nonce survives.
    rt = Block.deserialize(witness_bytes)
    cb = rt.transactions[0]
    assert cb.has_witness is True
    wit = cb.inputs[0].witness or []
    assert len(wit) == 1, f"expected one witness item, got {len(wit)}"
    assert len(wit[0]) == 32, f"expected 32-byte nonce, got {len(wit[0])}"


def test_stripped_serialize_drops_witness():
    block = _block_with(_segwit_coinbase())

    # The stripped form deserializes to a coinbase with NO witness — this is
    # exactly the byte stream that triggered bad-witness-nonce-size when the
    # getdata handler served BlockMessage(block).serialize().
    rt = Block.deserialize(block.serialize())
    cb_in = rt.transactions[0].inputs[0]
    assert not cb_in.witness, "stripped serialize must not carry a witness nonce"


def test_witness_header_bytes_match_stripped_header():
    # Both serializations share an identical 80-byte header (the block hash is
    # header-only), so swapping in the witness body never changes the hash.
    block = _block_with(_segwit_coinbase())
    assert block.serialize_with_witness()[:80] == block.serialize()[:80]
