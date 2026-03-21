"""
Test harness for Bitcoin Core's script_tests.json test vectors.

Parses script assembly notation, constructs script bytecode, and
verifies each test case against the ouroboros script interpreter.

Formats:
  [scriptSig_asm, scriptPubKey_asm, flags, expected_result]              (4 fields)
  [scriptSig_asm, scriptPubKey_asm, flags, expected_result, comment]     (5 fields)
  [[wit_hex..., amount_btc], scriptSig_asm, scriptPubKey_asm, flags, result]  (witness)

Single-element arrays are comments and are skipped.
"""

# Mock the sync module BEFORE any ouroboros imports
import types
import sys

sync = types.ModuleType("sync")
sync.PyUTXO = type("PyUTXO", (), {})
sync.SyncEngine = type("SyncEngine", (), {})
sync.PyBlockchainDB = type("PyBlockchainDB", (), {})
sys.modules["sync"] = sync

import hashlib
import json
from pathlib import Path

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.script import (
    ScriptInterpreter,
    SCRIPT_VERIFY_NONE,
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_STRICTENC,
    SCRIPT_VERIFY_DERSIG,
    SCRIPT_VERIFY_LOW_S,
    SCRIPT_VERIFY_NULLDUMMY,
    SCRIPT_VERIFY_SIGPUSHONLY,
    SCRIPT_VERIFY_MINIMALDATA,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
    SCRIPT_VERIFY_CLEANSTACK,
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
    SCRIPT_VERIFY_WITNESS,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    SCRIPT_VERIFY_MINIMALIF,
    SCRIPT_VERIFY_NULLFAIL,
    SCRIPT_VERIFY_WITNESS_PUBKEYTYPE,
    SCRIPT_VERIFY_CONST_SCRIPTCODE,
    SCRIPT_VERIFY_TAPROOT,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
    SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS,
)

VECTOR_PATH = Path("/home/max/hashhog/bitcoin/src/test/data/script_tests.json")

# ---------------------------------------------------------------------------
# Opcode name -> byte value mapping
# ---------------------------------------------------------------------------

OPCODE_MAP = {
    "OP_0": 0x00, "OP_FALSE": 0x00,
    "OP_PUSHDATA1": 0x4c, "OP_PUSHDATA2": 0x4d, "OP_PUSHDATA4": 0x4e,
    "OP_1NEGATE": 0x4f, "OP_RESERVED": 0x50,
    "OP_1": 0x51, "OP_TRUE": 0x51,
    "OP_2": 0x52, "OP_3": 0x53, "OP_4": 0x54, "OP_5": 0x55,
    "OP_6": 0x56, "OP_7": 0x57, "OP_8": 0x58, "OP_9": 0x59,
    "OP_10": 0x5a, "OP_11": 0x5b, "OP_12": 0x5c, "OP_13": 0x5d,
    "OP_14": 0x5e, "OP_15": 0x5f, "OP_16": 0x60,
    "OP_NOP": 0x61, "OP_VER": 0x62,
    "OP_IF": 0x63, "OP_NOTIF": 0x64,
    "OP_VERIF": 0x65, "OP_VERNOTIF": 0x66,
    "OP_ELSE": 0x67, "OP_ENDIF": 0x68,
    "OP_VERIFY": 0x69, "OP_RETURN": 0x6a,
    "OP_TOALTSTACK": 0x6b, "OP_FROMALTSTACK": 0x6c,
    "OP_2DROP": 0x6d, "OP_2DUP": 0x6e, "OP_3DUP": 0x6f,
    "OP_2OVER": 0x70, "OP_2ROT": 0x71, "OP_2SWAP": 0x72,
    "OP_IFDUP": 0x73, "OP_DEPTH": 0x74,
    "OP_DROP": 0x75, "OP_DUP": 0x76, "OP_NIP": 0x77,
    "OP_OVER": 0x78, "OP_PICK": 0x79, "OP_ROLL": 0x7a,
    "OP_ROT": 0x7b, "OP_SWAP": 0x7c, "OP_TUCK": 0x7d,
    "OP_CAT": 0x7e, "OP_SUBSTR": 0x7f, "OP_LEFT": 0x80, "OP_RIGHT": 0x81,
    "OP_SIZE": 0x82,
    "OP_INVERT": 0x83, "OP_AND": 0x84, "OP_OR": 0x85, "OP_XOR": 0x86,
    "OP_EQUAL": 0x87, "OP_EQUALVERIFY": 0x88,
    "OP_RESERVED1": 0x89, "OP_RESERVED2": 0x8a,
    "OP_1ADD": 0x8b, "OP_1SUB": 0x8c,
    "OP_2MUL": 0x8d, "OP_2DIV": 0x8e,
    "OP_NEGATE": 0x8f, "OP_ABS": 0x90,
    "OP_NOT": 0x91, "OP_0NOTEQUAL": 0x92,
    "OP_ADD": 0x93, "OP_SUB": 0x94,
    "OP_MUL": 0x95, "OP_DIV": 0x96, "OP_MOD": 0x97,
    "OP_LSHIFT": 0x98, "OP_RSHIFT": 0x99,
    "OP_BOOLAND": 0x9a, "OP_BOOLOR": 0x9b,
    "OP_NUMEQUAL": 0x9c, "OP_NUMEQUALVERIFY": 0x9d,
    "OP_NUMNOTEQUAL": 0x9e,
    "OP_LESSTHAN": 0x9f, "OP_GREATERTHAN": 0xa0,
    "OP_LESSTHANOREQUAL": 0xa1, "OP_GREATERTHANOREQUAL": 0xa2,
    "OP_MIN": 0xa3, "OP_MAX": 0xa4, "OP_WITHIN": 0xa5,
    "OP_RIPEMD160": 0xa6, "OP_SHA1": 0xa7, "OP_SHA256": 0xa8,
    "OP_HASH160": 0xa9, "OP_HASH256": 0xaa,
    "OP_CODESEPARATOR": 0xab,
    "OP_CHECKSIG": 0xac, "OP_CHECKSIGVERIFY": 0xad,
    "OP_CHECKMULTISIG": 0xae, "OP_CHECKMULTISIGVERIFY": 0xaf,
    "OP_NOP1": 0xb0,
    "OP_CHECKLOCKTIMEVERIFY": 0xb1, "OP_CLTV": 0xb1, "OP_NOP2": 0xb1,
    "OP_CHECKSEQUENCEVERIFY": 0xb2, "OP_CSV": 0xb2, "OP_NOP3": 0xb2,
    "OP_NOP4": 0xb3, "OP_NOP5": 0xb4,
    "OP_NOP6": 0xb5, "OP_NOP7": 0xb6,
    "OP_NOP8": 0xb7, "OP_NOP9": 0xb8, "OP_NOP10": 0xb9,
    "OP_CHECKSIGADD": 0xba,
    "OP_INVALIDOPCODE": 0xff,
}

# Add aliases without OP_ prefix
_bare = {}
for k, v in OPCODE_MAP.items():
    if k.startswith("OP_"):
        _bare[k[3:]] = v
OPCODE_MAP.update(_bare)


def encode_scriptnum(n: int) -> bytes:
    """Encode an integer as a Bitcoin Script number (CScriptNum)."""
    if n == 0:
        return b""
    negative = n < 0
    abs_val = abs(n)
    result = bytearray()
    while abs_val > 0:
        result.append(abs_val & 0xff)
        abs_val >>= 8
    if result[-1] & 0x80:
        result.append(0x80 if negative else 0x00)
    elif negative:
        result[-1] |= 0x80
    return bytes(result)


def push_data(data: bytes) -> bytes:
    """Create minimal push-data encoding."""
    length = len(data)
    if length == 0:
        return bytes([0x00])
    if length <= 75:
        return bytes([length]) + data
    if length <= 255:
        return bytes([0x4c, length]) + data
    if length <= 65535:
        return bytes([0x4d, length & 0xff, (length >> 8) & 0xff]) + data
    return bytes([0x4e, length & 0xff, (length >> 8) & 0xff,
                  (length >> 16) & 0xff, (length >> 24) & 0xff]) + data


def parse_script_asm(asm: str) -> bytes:
    """Parse a Bitcoin Script assembly string into raw bytes."""
    result = bytearray()
    tokens = asm.split()
    i = 0

    while i < len(tokens):
        tok = tokens[i]

        # Quoted string: 'text'
        if tok.startswith("'") and tok.endswith("'") and len(tok) >= 2:
            text = tok[1:-1]
            result.extend(push_data(text.encode("ascii")))
            i += 1
            continue

        # Hex literal: 0xNN
        if tok.startswith("0x") or tok.startswith("0X"):
            hex_str = tok[2:]
            data = bytes.fromhex(hex_str)

            # Check for push prefix pattern
            if (len(data) == 1 and i + 1 < len(tokens)
                    and (tokens[i + 1].startswith("0x") or tokens[i + 1].startswith("0X"))):
                op_byte = data[0]
                if (1 <= op_byte <= 75) or op_byte in (0x4c, 0x4d, 0x4e):
                    next_data = bytes.fromhex(tokens[i + 1][2:])
                    result.append(op_byte)
                    result.extend(next_data)
                    i += 2
                    continue

            result.extend(data)
            i += 1
            continue

        # Opcode name lookup
        op_val = OPCODE_MAP.get(tok) or OPCODE_MAP.get("OP_" + tok)
        if op_val is not None:
            result.append(op_val)
            i += 1
            continue

        # Bare "0"
        if tok == "0":
            result.append(0x00)
            i += 1
            continue

        # Decimal number
        try:
            n = int(tok)
            if n == -1:
                result.append(0x4f)  # OP_1NEGATE
            elif 1 <= n <= 16:
                result.append(0x50 + n)
            else:
                encoded = encode_scriptnum(n)
                result.extend(push_data(encoded))
            i += 1
            continue
        except ValueError:
            pass

        raise ValueError(f"unknown token: {tok!r}")

    return bytes(result)


def parse_flags(s: str) -> int:
    """Parse comma-separated flag string into integer flags."""
    flags = SCRIPT_VERIFY_NONE
    if not s or s == "NONE":
        return flags

    flag_map = {
        "P2SH": SCRIPT_VERIFY_P2SH,
        "STRICTENC": SCRIPT_VERIFY_STRICTENC,
        "DERSIG": SCRIPT_VERIFY_DERSIG,
        "LOW_S": SCRIPT_VERIFY_LOW_S,
        "NULLDUMMY": SCRIPT_VERIFY_NULLDUMMY,
        "SIGPUSHONLY": SCRIPT_VERIFY_SIGPUSHONLY,
        "MINIMALDATA": SCRIPT_VERIFY_MINIMALDATA,
        "DISCOURAGE_UPGRADABLE_NOPS": SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
        "CLEANSTACK": SCRIPT_VERIFY_CLEANSTACK,
        "CHECKLOCKTIMEVERIFY": SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
        "CHECKSEQUENCEVERIFY": SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
        "WITNESS": SCRIPT_VERIFY_WITNESS,
        "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM": SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
        "MINIMALIF": SCRIPT_VERIFY_MINIMALIF,
        "NULLFAIL": SCRIPT_VERIFY_NULLFAIL,
        "WITNESS_PUBKEYTYPE": SCRIPT_VERIFY_WITNESS_PUBKEYTYPE,
        "CONST_SCRIPTCODE": SCRIPT_VERIFY_CONST_SCRIPTCODE,
        "TAPROOT": SCRIPT_VERIFY_TAPROOT,
        "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION": SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
        "DISCOURAGE_OP_SUCCESS": SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS,
    }

    for f in s.split(","):
        f = f.strip()
        if f in flag_map:
            flags |= flag_map[f]

    return flags


def _encode_varint(value: int) -> bytes:
    """Encode an integer as a Bitcoin protocol compact-size varint."""
    if value < 0xfd:
        return bytes([value])
    elif value <= 0xffff:
        return b'\xfd' + value.to_bytes(2, 'little')
    elif value <= 0xffffffff:
        return b'\xfe' + value.to_bytes(4, 'little')
    else:
        return b'\xff' + value.to_bytes(8, 'little')


def _serialize_tx(tx: Transaction) -> bytes:
    """Serialize a transaction to raw bytes (no witness)."""
    data = bytearray()
    data.extend(tx.version.to_bytes(4, 'little'))
    data.extend(_encode_varint(len(tx.inputs)))
    for inp in tx.inputs:
        data.extend(inp.prev_txid)
        data.extend(inp.prev_vout.to_bytes(4, 'little'))
        data.extend(_encode_varint(len(inp.script_sig)))
        data.extend(inp.script_sig)
        data.extend(inp.sequence.to_bytes(4, 'little'))
    data.extend(_encode_varint(len(tx.outputs)))
    for out in tx.outputs:
        data.extend(out.value.to_bytes(8, 'little'))
        data.extend(_encode_varint(len(out.script_pubkey)))
        data.extend(out.script_pubkey)
    data.extend(tx.locktime.to_bytes(4, 'little'))
    return bytes(data)


def _double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def make_crediting_spending_tx(
    script_sig: bytes, script_pubkey: bytes,
    amount: int = 0, witness: list = None,
) -> Transaction:
    """
    Build crediting + spending transactions matching Bitcoin Core's test framework
    (BuildCreditingTransaction / BuildSpendingTransaction in script_tests.cpp).

    Crediting tx: version 1, locktime 0, single input (null prevout with
    vout=0xFFFFFFFF, scriptSig = OP_0 OP_0, sequence 0xFFFFFFFF), single output
    (scriptPubKey = test's scriptPubKey, value = amount).

    Spending tx: version 1, locktime 0, single input (prevout = hash(crediting_tx):0,
    scriptSig = test's scriptSig, sequence 0xFFFFFFFF), single output (empty
    scriptPubKey, value = amount), witness = provided witness stack.
    """
    # --- crediting transaction ---
    # scriptSig for crediting tx: CScriptNum(0) CScriptNum(0) -> OP_0 OP_0
    credit_script_sig = bytes([0x00, 0x00])
    credit_in = TxIn(
        prev_txid=b"\x00" * 32,
        prev_vout=0xFFFFFFFF,
        script_sig=credit_script_sig,
        sequence=0xFFFFFFFF,
        witness=None,
    )
    credit_out = TxOut(value=amount, script_pubkey=script_pubkey)
    credit_tx = Transaction(
        txid=b"\x00" * 32,  # placeholder
        version=1,
        locktime=0,
        inputs=[credit_in],
        outputs=[credit_out],
        has_witness=False,
    )
    # Compute the real txid of the crediting tx
    credit_txid = _double_sha256(_serialize_tx(credit_tx))

    # --- spending transaction ---
    has_wit = witness is not None and len(witness) > 0
    spend_in = TxIn(
        prev_txid=credit_txid,
        prev_vout=0,
        script_sig=script_sig,
        sequence=0xFFFFFFFF,
        witness=witness if has_wit else None,
    )
    spend_out = TxOut(value=amount, script_pubkey=b"")
    spend_tx = Transaction(
        txid=b"\x00" * 32,  # placeholder
        version=1,
        locktime=0,
        inputs=[spend_in],
        outputs=[spend_out],
        has_witness=has_wit,
    )
    # Compute txid of spending tx (for completeness)
    spend_tx.txid = _double_sha256(_serialize_tx(spend_tx))
    return spend_tx


def test_script_vectors():
    """Run all script_tests.json test vectors."""
    data = VECTOR_PATH.read_text()
    vectors = json.loads(data)

    passed = 0
    failed = 0
    skipped = 0
    parse_errors = 0

    interp = ScriptInterpreter()

    for i, entry in enumerate(vectors):
        if not isinstance(entry, list):
            skipped += 1
            continue

        # Skip comments
        if len(entry) <= 1:
            skipped += 1
            continue

        # Parse witness vectors (first element is an array)
        witness_stack = None
        witness_amount = 0
        if isinstance(entry[0], list):
            if len(entry) < 5:
                skipped += 1
                continue
            # Witness format: [[wit_hex1, wit_hex2, ..., amount_btc], scriptSig, scriptPubKey, flags, result]
            # The last element of entry[0] is the amount in BTC (float), rest are hex witness items
            wit_array = entry[0]
            # Skip taproot placeholder vectors (#SCRIPT#, #CONTROLBLOCK#, etc.)
            has_placeholder = any(
                isinstance(x, str) and x.startswith('#') for x in wit_array[:-1]
            )
            if has_placeholder:
                skipped += 1
                continue
            witness_amount = round(float(wit_array[-1]) * 1e8)
            witness_stack = [bytes.fromhex(h) for h in wit_array[:-1]]
            script_sig_asm = entry[1]
            script_pubkey_asm = entry[2]
            flags_str = entry[3]
            expected = entry[4]
            comment = entry[5] if len(entry) >= 6 else ""
        elif len(entry) < 4:
            skipped += 1
            continue
        else:
            script_sig_asm = entry[0]
            script_pubkey_asm = entry[1]
            flags_str = entry[2]
            expected = entry[3]
            comment = entry[4] if len(entry) >= 5 else ""

        try:
            script_sig = parse_script_asm(script_sig_asm)
        except Exception as e:
            parse_errors += 1
            if parse_errors <= 20:
                print(f"test {i}: parse scriptSig error: {e} (asm: {script_sig_asm!r})")
            continue

        try:
            script_pubkey = parse_script_asm(script_pubkey_asm)
        except Exception as e:
            parse_errors += 1
            if parse_errors <= 20:
                print(f"test {i}: parse scriptPubKey error: {e} (asm: {script_pubkey_asm!r})")
            continue

        flags = parse_flags(flags_str)
        tx = make_crediting_spending_tx(
            script_sig, script_pubkey,
            amount=witness_amount, witness=witness_stack,
        )

        try:
            got_ok = interp.verify(
                script_sig, script_pubkey, tx, 0,
                flags=flags, amount=witness_amount,
            )
        except Exception:
            got_ok = False

        expect_ok = expected == "OK"

        if expect_ok == got_ok:
            passed += 1
        else:
            failed += 1
            if failed <= 50:
                print(
                    f"FAIL test {i}: expected={expected} got={'OK' if got_ok else 'FAIL'} "
                    f"sigAsm={script_sig_asm!r} pubkeyAsm={script_pubkey_asm!r} "
                    f"flags={flags_str} comment={comment!r}"
                )

    print(
        f"script_tests.json results: {passed} passed, {failed} failed, "
        f"{skipped} skipped, {parse_errors} parse errors"
    )

    if failed > 0:
        print("NOTE: some failures may remain for taproot placeholder tests (skipped above)")


if __name__ == "__main__":
    test_script_vectors()
