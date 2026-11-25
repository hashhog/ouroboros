"""BIP325 signet block solution: Core-identical extraction, clearing and parse.

Item cffix-ouroboros-signet-solution-parse (Claude Security scan
secscan2-ouroboros, finding B-F1, plus defect 0 found while validating it).

Core ``SignetTxs::Create`` (``src/signet.cpp``)::

    const int cidx = GetWitnessCommitmentIndex(block);
    if (cidx == NO_WITNESS_COMMITMENT) return std::nullopt;
    CScript& witness_commitment = modified_cb.vout.at(cidx).scriptPubKey;
    if (!FetchAndClearCommitmentSection(SIGNET_HEADER, witness_commitment,
                                        signet_solution)) {
        // no signet solution -- allow OP_TRUE as trivial block challenge
    } else {
        try {
            SpanReader v{signet_solution};
            v >> tx_spending.vin[0].scriptSig;
            v >> tx_spending.vin[0].scriptWitness.stack;
            if (!v.empty()) return std::nullopt; // extraneous data
        } catch (const std::exception&) {
            return std::nullopt; // parsing error
        }
    }

``CheckSignetBlockSolution`` returns false on ``nullopt`` and ``CheckBlock``
rejects with ``bad-signet-blksig``.  The rules pinned here:

1. a truncated / non-canonical CompactSize is a REJECT, never an exception;
2. bytes left over after the witness stack are a REJECT;
3. a solution with a scriptSig but no witness-stack count is a REJECT;
4. a witness item whose length overruns the solution is a REJECT;
5. defect 0: the modified-merkle / virtual-tx builders must not raise
   (``Transaction(..., is_coinbase=...)`` was a TypeError for every signet
   block above genesis);
6. commitment clearing is ``FetchAndClearCommitmentSection``: only the
   ``GetWitnessCommitmentIndex`` output is rewritten, every push is
   re-serialised minimally, only the first header-AND-data push is cut to
   the bare header, the walk stops where ``GetOp`` fails, and a script with
   no such push is left untouched;
7. real default-signet blocks 1..10 (Core ``feature_signet.py``) validate,
   and the same block with junk appended after its solution does not.

Rules 2-4 run under an OP_TRUE / P2WSH(OP_TRUE) challenge (Core's
``-signetchallenge=51`` style), the only way to make the signature itself
pass without the signet signer's key; the parse rules are independent of
the challenge.  Well-formed solutions under the same challenges are the
positive controls.
"""

from __future__ import annotations

import hashlib

import pytest

import ouroboros.validation as validation
from ouroboros.database import Block, Transaction, TxIn, TxOut
from ouroboros.validation import SIGNET_HEADER, BlockValidator

COMMITMENT_PREFIX = b"\x6a\x24" + bytes.fromhex("aa21a9ed")


def _push(data: bytes) -> bytes:
    assert len(data) <= 75
    return bytes([len(data)]) + data


def _dsha(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _commitment(tail: bytes = b"") -> bytes:
    return COMMITMENT_PREFIX + bytes(32) + tail


def _block_with_outputs(outputs: list[TxOut]) -> Block:
    coinbase = Transaction(
        txid=b"",
        version=2,
        locktime=0,
        inputs=[TxIn(prev_txid=bytes(32), prev_vout=0xFFFFFFFF,
                     script_sig=b"\x01\x01", sequence=0xFFFFFFFF,
                     witness=[bytes(32)])],
        outputs=outputs,
    )
    return Block(version=0x20000000, prev_blockhash=bytes(32),
                 merkle_root=bytes(32), timestamp=1_700_000_000,
                 bits=0x1E0377AE, nonce=0, transactions=[coinbase],
                 hash=bytes(32))


def _block(solution: bytes | None) -> Block:
    tail = b"" if solution is None else _push(SIGNET_HEADER + solution)
    return _block_with_outputs([TxOut(value=0, script_pubkey=b"\x51"),
                                TxOut(value=0, script_pubkey=_commitment(tail))])


def _validator() -> BlockValidator:
    v = BlockValidator.__new__(BlockValidator)
    v.network = "signet"
    return v


def _merkle(block: Block) -> bytes:
    return _validator()._compute_signet_merkle_root(block)


def _expected_merkle(block: Block, replace: dict[int, bytes]) -> bytes:
    """Merkle root of ``block`` with the coinbase outputs in ``replace``
    swapped for the given scripts: an independent model of Core's
    ComputeModifiedMerkleRoot (non-witness coinbase hash, other txids)."""
    cb = block.transactions[0]
    outs = [TxOut(value=o.value, script_pubkey=replace.get(i, o.script_pubkey))
            for i, o in enumerate(cb.outputs)]
    modified = Transaction(txid=b"", version=cb.version, locktime=cb.locktime,
                           inputs=cb.inputs, outputs=outs)
    txids = [_dsha(modified.serialize())]
    txids += [tx.get_txid() for tx in block.transactions[1:]]
    return _validator()._calculate_merkle_root(txids)


@pytest.fixture
def op_true_challenge(monkeypatch):
    monkeypatch.setattr(validation, "DEFAULT_SIGNET_CHALLENGE", b"\x51")


P2WSH_TRUE = b"\x00\x20" + hashlib.sha256(b"\x51").digest()


@pytest.fixture
def p2wsh_true_challenge(monkeypatch):
    monkeypatch.setattr(validation, "DEFAULT_SIGNET_CHALLENGE", P2WSH_TRUE)


# --- Rule 1: malformed CompactSize -> bad-signet-blksig, never an exception.
MALFORMED = {
    "truncated_fd": b"\xfd",                 # CompactSize<u16> with no body
    "noncanonical_fd": b"\xfd\x01\x00",      # 0xfd prefix encoding 1
    "truncated_fe": b"\xfe\x00\x00",         # CompactSize<u32> cut short
    "witness_count_truncated": b"\x00\xfd",  # scriptSig ok, stack count cut
}


@pytest.mark.parametrize("name", list(MALFORMED), ids=list(MALFORMED))
def test_malformed_solution_is_a_reject_not_an_exception(name):
    ok, err = _validator()._validate_signet_solution(_block(MALFORMED[name]), 1)
    assert ok is False
    assert err == "bad-signet-blksig"


# --- Rules 2 and 3 under an OP_TRUE challenge (the signature passes; only
# the parse decides).
PARSE_REJECTS = {
    "trailing_byte_after_stack": b"\x00\x00\xff",   # empty sig, 0 items, junk
    "no_witness_count": b"\x00",                     # scriptSig only
    "script_sig_overruns": b"\x05\x51",              # scriptSig says 5, has 1
}


@pytest.mark.parametrize("name", list(PARSE_REJECTS), ids=list(PARSE_REJECTS))
def test_unparseable_solution_is_rejected(name, op_true_challenge):
    ok, err = _validator()._validate_signet_solution(
        _block(PARSE_REJECTS[name]), 1)
    assert ok is False
    assert err == "bad-signet-blksig"


# --- Rules 2 and 4 with a witness item, under a P2WSH(OP_TRUE) challenge
# whose only valid solution is scriptSig "" + witness [OP_TRUE].
P2WSH_REJECTS = {
    "trailing_after_item": b"\x00\x01\x01\x51\x00",  # [0x51] then junk 00
    "item_len_overruns": b"\x00\x01\x05\x51",         # item says 5, has 1
    "item_missing": b"\x00\x02\x01\x51",              # count 2, one item
}
P2WSH_GOOD = b"\x00\x01\x01\x51"


@pytest.mark.parametrize("name", list(P2WSH_REJECTS), ids=list(P2WSH_REJECTS))
def test_unparseable_witness_solution_is_rejected(name, p2wsh_true_challenge):
    ok, err = _validator()._validate_signet_solution(
        _block(P2WSH_REJECTS[name]), 1)
    assert ok is False
    assert err == "bad-signet-blksig"


def test_positive_control_p2wsh_solution_accepted(p2wsh_true_challenge):
    ok, err = _validator()._validate_signet_solution(_block(P2WSH_GOOD), 1)
    assert ok is True, err


def test_negative_control_p2wsh_wrong_item_rejected(p2wsh_true_challenge):
    """The witness item decides: [0x52] does not hash to the program."""
    ok, err = _validator()._validate_signet_solution(
        _block(b"\x00\x01\x01\x52"), 1)
    assert ok is False
    assert err == "bad-signet-blksig"


def test_positive_control_wellformed_solution_accepted(op_true_challenge):
    """Instrument check: empty scriptSig + empty stack parses exactly and
    OP_TRUE accepts it, so the rejects above are decided by the parse."""
    ok, err = _validator()._validate_signet_solution(_block(b"\x00\x00"), 1)
    assert ok is True, err


def test_no_signet_push_is_an_empty_solution(op_true_challenge):
    """Core: no header+data push -> empty solution, OP_TRUE accepts."""
    ok, err = _validator()._validate_signet_solution(_block(None), 1)
    assert ok is True, err


def test_no_witness_commitment_is_a_reject():
    block = _block_with_outputs([TxOut(value=0, script_pubkey=b"\x51")])
    ok, err = _validator()._validate_signet_solution(block, 1)
    assert ok is False
    assert err == "bad-signet-blksig"


# --- Rule 5 (defect 0): a well-formed signet block reaches a verdict.
def test_wellformed_signet_block_reaches_a_verdict(op_true_challenge):
    ok, err = _validator()._validate_signet_solution(_block(b"\x00\x00"), 1)
    assert ok is True, err


def test_wellformed_signet_block_default_challenge_is_a_reject_not_a_crash():
    """With the real signet challenge an empty solution must fail the
    signature, proving the verify step runs at all."""
    ok, err = _validator()._validate_signet_solution(_block(b"\x00\x00"), 1)
    assert ok is False
    assert err == "bad-signet-blksig"


# --- Rule 6: commitment clearing is Core's FetchAndClearCommitmentSection.
def test_push_after_solution_is_covered_by_signed_message():
    plain = _block(b"\x00\x00")
    extra = _block(b"\x00\x00")
    cb_out = extra.transactions[0].outputs[1]
    extra.transactions[0].outputs[1] = TxOut(
        value=cb_out.value, script_pubkey=cb_out.script_pubkey + _push(b"xyz"))
    assert _merkle(plain) != _merkle(extra)


def test_bare_header_push_is_not_the_solution():
    """Core: a push counts only if it has the header AND some data, so the
    solution is taken from the later header+data push."""
    commitment = _commitment(_push(SIGNET_HEADER)
                             + _push(SIGNET_HEADER + b"\x00\x00"))
    assert BlockValidator._extract_signet_commitment(commitment) == b"\x00\x00"


CLEARING = {
    # tail after the 38-byte commitment -> Core's rewritten tail
    "solution_then_push": (
        _push(SIGNET_HEADER + b"\x00\x00") + _push(b"xyz"),
        b"\x04" + SIGNET_HEADER + b"\x03xyz"),
    "nonminimal_pushes_reserialised": (
        b"\x4c\x06" + SIGNET_HEADER + b"\x00\x00" + b"\x4c\x03xyz",
        b"\x04" + SIGNET_HEADER + b"\x03xyz"),
    "opcodes_kept": (
        _push(SIGNET_HEADER + b"\x00\x00") + b"\x00\x51\x4c\x00",
        # OP_0 and OP_1 re-emitted; empty PUSHDATA1 emits its opcode byte
        b"\x04" + SIGNET_HEADER + b"\x00\x51\x4c"),
    "second_header_push_untouched": (
        _push(SIGNET_HEADER + b"\x00\x00") + _push(SIGNET_HEADER + b"\x07"),
        b"\x04" + SIGNET_HEADER + b"\x05" + SIGNET_HEADER + b"\x07"),
    "walk_stops_at_truncated_op": (
        _push(SIGNET_HEADER + b"\x00\x00") + b"\x05ab",
        b"\x04" + SIGNET_HEADER),
}


@pytest.mark.parametrize("name", list(CLEARING), ids=list(CLEARING))
def test_commitment_clearing_matches_core(name):
    tail, cleared_tail = CLEARING[name]
    block = _block_with_outputs([
        TxOut(value=0, script_pubkey=b"\x51"),
        TxOut(value=0, script_pubkey=_commitment(tail)),
    ])
    expected = _expected_merkle(block, {1: _commitment(cleared_tail)})
    assert _merkle(block) == expected


def test_no_signet_push_leaves_script_untouched():
    """Core rewrites nothing when no header+data push exists: the modified
    merkle root is the plain coinbase-txid merkle root."""
    for tail in (b"", _push(SIGNET_HEADER), _push(b"xyz") + b"\x4c\x00"):
        block = _block_with_outputs([
            TxOut(value=0, script_pubkey=b"\x51"),
            TxOut(value=0, script_pubkey=_commitment(tail)),
        ])
        assert _merkle(block) == _expected_merkle(block, {}), tail.hex()


def test_only_the_last_commitment_output_is_cleared():
    """GetWitnessCommitmentIndex picks the LAST matching output; an earlier
    commitment-pattern output is not rewritten."""
    early = _commitment(_push(SIGNET_HEADER + b"\x00\x00") + _push(b"zz"))
    late = _commitment(_push(SIGNET_HEADER + b"\x00\x00"))
    block = _block_with_outputs([
        TxOut(value=0, script_pubkey=early),
        TxOut(value=0, script_pubkey=late),
    ])
    expected = _expected_merkle(block, {1: _commitment(b"\x04" + SIGNET_HEADER)})
    assert _merkle(block) == expected


# --- Rule 7: real default-signet blocks (Core test/functional/
# feature_signet.py ``signet_blocks``, heights 1..10 of the default signet,
# signed under the default 1-of-2 challenge).
DEFAULT_SIGNET_GENESIS = bytes.fromhex(
    "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6")[::-1]

SIGNET_BLOCKS = [
    "".join(parts) for parts in [
        (
            "00000020f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e9739881"
            "08000000f575c83235984e7dc4afc1f30944c170462e84437ab6f2d52e16878a"
            "79e4678bd1914d5fae77031eccf4070001010000000001010000000000000000"
            "000000000000000000000000000000000000000000000000ffffffff025151fe"
            "ffffff0200f2052a010000001600149243f727dd5343293eb83174324019ec16"
            "c2630f0000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa369"
            "53755c690689799962b48bebd836974e8cf94c4fecc7daa2490047304402205e"
            "423a8754336ca99dbe16509b877ef1bf98d008836c725005b3c787c41ebe4602"
            "2047246e4467ad7cc7f1ad98662afcaf14c115e0095a227c7b05c5182591c23e"
            "7e01000120000000000000000000000000000000000000000000000000000000"
            "000000000000000000"
        ),
        (
            "00000020533b53ded9bff4adc94101d32400a144c54edc5ed492a3b26c63b2d6"
            "86000000b38fef50592017cfafbcab88eb3d9cf50b2c801711cad8299495d26d"
            "f5e54812e7914d5fae77031ecfdd0b0001010000000001010000000000000000"
            "000000000000000000000000000000000000000000000000ffffffff025251fe"
            "ffffff0200f2052a01000000160014fd09839740f0e0b4fc6d5e2527e4022aa9"
            "b89dfa0000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa369"
            "53755c690689799962b48bebd836974e8cf94c4fecc7daa24900473044022031"
            "d64a1692cdad1fc0ced69838169fe19ae01be524d831b95fcf5ea4e6541c3c02"
            "204f9dea0801df8b4d0cd0857c62ab35c6c25cc47c930630dc7fe723531daa3e"
            "9b01000120000000000000000000000000000000000000000000000000000000"
            "000000000000000000"
        ),
        (
            "000000202960f3752f0bfa8858a3e333294aedc7808025e868c9dc03e71d88bb"
            "320000007765fcd3d5b4966beb338bba2675dc2cf2ad28d4ad1d83bdb6f286e7"
            "e27ac1f807924d5fae77031e81d60b0001010000000001010000000000000000"
            "000000000000000000000000000000000000000000000000ffffffff025351fe"
            "ffffff0200f2052a010000001600141e5fb426042692ae0e87c070e78c39307a"
            "5661c20000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa369"
            "53755c690689799962b48bebd836974e8cf94c4fecc7daa2490047304402205d"
            "e93694763a42954865bcf1540cb82958bc62d0ec4eee02070fb7937cd037f402"
            "2067f333753bce47b10bc25eb6e1f311482e994c862a7e0b2d41ab1c8679fd1b"
            "1101000120000000000000000000000000000000000000000000000000000000"
            "000000000000000000"
        ),
        (
            "00000020b06443a13ae1d3d50faef5ecad38c6818194dc46abca3e972e2aacda"
            "e800000069a5829097e80fee00ac49a56ea9f82d741a6af84d32b3bc455cf318"
            "71e2a8ac27924d5fae77031e9c91050001010000000001010000000000000000"
            "000000000000000000000000000000000000000000000000ffffffff025451fe"
            "ffffff0200f2052a0100000016001430db2f8225dcf7751361ab38735de08190"
            "318cb70000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa369"
            "53755c690689799962b48bebd836974e8cf94c4fecc7daa24900473044022009"
            "36f5f9872f6df5dd242026ad52241a68423f7f682e79169a8d85a374eab9b802"
            "202cd2979c48b321b3453e65e8f92460db3fca93cbea8539b450c959f4fbe630"
            "c601000120000000000000000000000000000000000000000000000000000000"
            "000000000000000000"
        ),
        (
            "000000207ed403758a4f228a1939418a155e2ebd4ae6b26e5ffd0ae433123f76"
            "94010000542e80b609c5bc58af5bdf492e26d4f60cd43a3966c2e063c50444c2"
            "9b3757a636924d5fae77031ee8601d0001010000000001010000000000000000"
            "000000000000000000000000000000000000000000000000ffffffff025551fe"
            "ffffff0200f2052a01000000160014edc207e014df34fa3885dff97d1129d356"
            "e1186a0000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa369"
            "53755c690689799962b48bebd836974e8cf94c4fecc7daa24900473044022021"
            "a3656609f85a66a2c5672ed9322c2158d57251040d2716ed202a1fe14f0c1202"
            "2057d68bc6611f7a9424a7e00bbf3e27e6ae6b096f60bac624a094bc97a59aa1"
            "ff01000120000000000000000000000000000000000000000000000000000000"
            "000000000000000000"
        ),
        (
            "000000205bea0a88d1422c3df08d766ad72df95084d0700e6f873b75dd4e986c"
            "7703000002b57516d33ed60c2bdd9f93d6d5614083324c837e68e5ba6e04287a"
            "7285633585924d5fae77031ed171960001010000000001010000000000000000"
            "000000000000000000000000000000000000000000000000ffffffff025651fe"
            "ffffff0200f2052a010000001600143ae612599cf96f2442ce572633e0251116"
            "eaa52f0000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa369"
            "53755c690689799962b48bebd836974e8cf94c4fecc7daa24900473044022059"
            "a7c54de76bfdbb1dd44c78ea2dbd2bb4e97f4abad38965f41e76433e56423c02"
            "2054bf17f04fe17415c0141f60eebd2b839200f574d8ad8d55a0917b92b0eb91"
            "3401000120000000000000000000000000000000000000000000000000000000"
            "000000000000000000"
        ),
        (
            "00000020daf3b60d374b19476461f97540498dcfa2eb7016238ec6b1d022f82f"
            "b60100007a7ae65b53cb988c2ec92d2384996713821d5645ffe61c9acea60da7"
            "5cd5edfa1a944d5fae77031e9dbb050001010000000001010000000000000000"
            "000000000000000000000000000000000000000000000000ffffffff025751fe"
            "ffffff0200f2052a01000000160014ef2dceae02e35f8137de76768ae3345d99"
            "ca68860000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa369"
            "53755c690689799962b48bebd836974e8cf94c4fecc7daa2490047304402202b"
            "3f946d6447f9bf17d00f3696cede7ee70b785495e5498274ee682a493befd502"
            "2045fc0bcf9332243168b5d35507175f9f374a8eba2336873885d12aada67ea5"
            "f601000120000000000000000000000000000000000000000000000000000000"
            "000000000000000000"
        ),
        (
            "00000020457cc5f3c2e1a5655bc20e20e48d33e1b7ea68786c614032b5c518f0"
            "b6000000541f36942d82c6e7248275ff15c8933487fbe1819c67a9ecc0f4b70b"
            "b7e6cf672a944d5fae77031e8f39860001010000000001010000000000000000"
            "000000000000000000000000000000000000000000000000ffffffff025851fe"
            "ffffff0200f2052a0100000016001472a27906947c06d034b38ba2fa13c6391a"
            "4832790000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa369"
            "53755c690689799962b48bebd836974e8cf94c4fecc7daa2490047304402202d"
            "62805ce60cbd60591f97f949b5ea5bd7e2307bcde343e6ea8394da92758e7202"
            "2053a25370b0aa20da100189b7899a8f8675a0fdc60e38ece6b8a4f98edd9456"
            "9e01000120000000000000000000000000000000000000000000000000000000"
            "000000000000000000"
        ),
        (
            "00000020a2eb61eb4f3831baa3a3363e1b42db4462663f756f07423e81ed3032"
            "2102000077224de7dea0f8d0ec22b1d2e2e255f0a987b96fe7200e1a2e6373f4"
            "8a2f5b7894954d5fae77031e36867e0001010000000001010000000000000000"
            "000000000000000000000000000000000000000000000000ffffffff025951fe"
            "ffffff0200f2052a01000000160014aa0ad9f26801258382e0734dceec03a4a7"
            "5f60240000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa369"
            "53755c690689799962b48bebd836974e8cf94c4fecc7daa2490047304402206f"
            "a0d59990eed369bd7375767c9a6c9369fae209152b8674e520da270605528c02"
            "20749eed3b12dbe3f583f505d21803e4aef59c8e24c5831951eafa4f15a8f92c"
            "4e01000120000000000000000000000000000000000000000000000000000000"
            "000000000000000000"
        ),
        (
            "00000020a868e8514be5e46dabd6a122132f423f36a43b716a40c394e2a8d063"
            "e1010000f4c6c717e99d800c699c25a2006a75a0c5c09f432a936f385e6fce13"
            "9cdbd1a5e9964d5fae77031e7d026e0001010000000001010000000000000000"
            "000000000000000000000000000000000000000000000000ffffffff025a51fe"
            "ffffff0200f2052a01000000160014aaa671c82b138e3b8f510cd801e5f2bd0a"
            "a305940000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa369"
            "53755c690689799962b48bebd836974e8cf94c4fecc7daa24900473044022042"
            "309f4c3c7a1a2ac8c24f890f962df1c0086cec10be0868087cfc427520cb2702"
            "201dafee8911c269b7e786e242045bb57cef3f5b0f177010c6159abae42f646c"
            "c501000120000000000000000000000000000000000000000000000000000000"
            "000000000000000000"
        ),
    ]
]


def _real_block(i: int) -> Block:
    return Block.deserialize(bytes.fromhex(SIGNET_BLOCKS[i]))


def test_real_blocks_parse_as_a_chain():
    """Instrument check: the fixtures deserialise, link from the default
    signet genesis, and their header merkle roots match the txids, so the
    block the validator sees is the block Core signed."""
    prev = DEFAULT_SIGNET_GENESIS
    for i in range(len(SIGNET_BLOCKS)):
        block = _real_block(i)
        assert block.prev_blockhash == prev, i
        txids = [tx.get_txid() for tx in block.transactions]
        assert _validator()._calculate_merkle_root(txids) == block.merkle_root
        prev = block.hash


@pytest.mark.parametrize("height", range(1, 11))
def test_real_default_signet_block_validates(height):
    ok, err = _validator()._validate_signet_solution(
        _real_block(height - 1), height)
    assert ok is True, err


def _with_commitment_tail(block: Block, extra: bytes) -> Block:
    cb = block.transactions[0]
    outs = list(cb.outputs)
    idx = max(i for i, o in enumerate(outs)
              if o.script_pubkey[:6] == COMMITMENT_PREFIX)
    outs[idx] = TxOut(value=outs[idx].value,
                      script_pubkey=outs[idx].script_pubkey + extra)
    cb.outputs = outs
    return block


def test_real_block_with_junk_push_after_solution_is_rejected():
    """The attack: append a push after a signed block's solution (and
    re-mine signet's low PoW).  Core's signed message covers it, so the
    signature no longer verifies."""
    block = _with_commitment_tail(_real_block(0), _push(b"\xde\xad"))
    ok, err = _validator()._validate_signet_solution(block, 1)
    assert ok is False
    assert err == "bad-signet-blksig"


def test_real_block_with_trailing_byte_in_solution_is_rejected():
    """Extend the solution push itself by one byte: the stack parse leaves
    a byte over, which Core rejects as extraneous data."""
    block = _real_block(0)
    cb = block.transactions[0]
    idx = max(i for i, o in enumerate(cb.outputs)
              if o.script_pubkey[:6] == COMMITMENT_PREFIX)
    spk = cb.outputs[idx].script_pubkey
    assert spk[38] == 0x4C  # PUSHDATA1 <len> header+solution, nothing after
    n = spk[39]
    assert len(spk) == 40 + n
    new_spk = spk[:38] + bytes([0x4C, n + 1]) + spk[40:] + b"\x00"
    outs = list(cb.outputs)
    outs[idx] = TxOut(value=outs[idx].value, script_pubkey=new_spk)
    cb.outputs = outs
    ok, err = _validator()._validate_signet_solution(block, 1)
    assert ok is False
    assert err == "bad-signet-blksig"


def test_real_block_with_flipped_signature_byte_is_rejected():
    """Negative control on the verify step with a real solution."""
    block = _real_block(0)
    cb = block.transactions[0]
    idx = max(i for i, o in enumerate(cb.outputs)
              if o.script_pubkey[:6] == COMMITMENT_PREFIX)
    spk = bytearray(cb.outputs[idx].script_pubkey)
    spk[60] ^= 0x01  # inside the DER signature's r value
    outs = list(cb.outputs)
    outs[idx] = TxOut(value=outs[idx].value, script_pubkey=bytes(spk))
    cb.outputs = outs
    ok, err = _validator()._validate_signet_solution(block, 1)
    assert ok is False
    assert err == "bad-signet-blksig"


def test_real_block_rejected_under_other_challenge(monkeypatch):
    """Core feature_signet.py: block 1 under the 2-of-2 variant of the
    default challenge is bad-signet-blksig."""
    two_of_two = b"\x52" + validation.DEFAULT_SIGNET_CHALLENGE[1:]
    monkeypatch.setattr(validation, "DEFAULT_SIGNET_CHALLENGE", two_of_two)
    ok, err = _validator()._validate_signet_solution(_real_block(0), 1)
    assert ok is False
    assert err == "bad-signet-blksig"


def test_system_fault_in_verify_is_not_a_reject(monkeypatch, op_true_challenge):
    """Gate 6: a MemoryError while verifying is a system fault, not
    bad-signet-blksig (which would mark a valid block invalid)."""
    def _boom(self, *args, **kwargs):
        raise MemoryError("simulated")
    monkeypatch.setattr(validation.ScriptInterpreter, "verify", _boom)
    with pytest.raises(MemoryError):
        _validator()._validate_signet_solution(_block(b"\x00\x00"), 1)
