"""
Bitcoin address decoding and script_pubkey derivation.

Supports P2PKH (1...), P2SH (3...), P2WPKH/P2WSH (bc1q.../tb1q...),
P2TR (bc1p.../tb1p... — Taproot, BIP 350 bech32m), and
P2A (Pay-to-Anchor — bc1pfeessrawgf... for CPFP anchors).
"""


# P2PKH: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
_P2PKH_PREFIX = bytes([0x76, 0xa9, 0x14])
_P2PKH_SUFFIX = bytes([0x88, 0xac])

# P2SH: OP_HASH160 <20-byte hash> OP_EQUAL
_P2SH_PREFIX = bytes([0xa9, 0x14])
_P2SH_SUFFIX = bytes([0x87])

# P2WPKH: OP_0 <20-byte hash>
_P2WPKH_PREFIX = bytes([0x00, 0x14])

# P2WSH: OP_0 <32-byte hash>
_P2WSH_PREFIX = bytes([0x00, 0x20])

# P2A (Pay-to-Anchor): OP_1 OP_PUSHBYTES_2 0x4e73
# This is a witness v1 program with a 2-byte program (0x4e73 = "Ns")
# P2A is anyone-can-spend and used for CPFP fee bumping in Lightning
_P2A_SCRIPT = bytes([0x51, 0x02, 0x4e, 0x73])
_P2A_PROGRAM = bytes([0x4e, 0x73])

# bech32m (BIP 350)
# The only difference from bech32 is the checksum constant:
#   bech32  → polymod == 1
#   bech32m → polymod == 0x2bc830a3
_BECH32M_CONST = 0x2bc830a3


def _decode_base58check(address: str) -> tuple[int, bytes]:
    import base58
    decoded = base58.b58decode_check(address)
    if len(decoded) < 2:
        raise ValueError("Invalid base58check address length")
    version = decoded[0]
    payload = bytes(decoded[1:])
    return version, payload


def _bech32m_polymod(values: list) -> int:
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32m_hrp_expand(hrp: str) -> list:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32m_verify_checksum(hrp: str, data: list) -> str:
    const = _bech32m_polymod(_bech32m_hrp_expand(hrp) + data)
    if const == 1:
        return "bech32"
    if const == _BECH32M_CONST:
        return "bech32m"
    return ""


def _bech32m_create_checksum(hrp: str, data: list, spec: str) -> list:
    const = 1 if spec == "bech32" else _BECH32M_CONST
    values = _bech32m_hrp_expand(hrp) + data
    polymod = _bech32m_polymod(values + [0] * 6) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32m_decode(address: str) -> tuple[str | None, int | None, list | None]:
    """Decode a bech32 or bech32m address."""
    if any(ord(c) < 33 or ord(c) > 126 for c in address):
        return None, None, None
    lower = address.lower()
    if address != lower and address != address.upper():
        return None, None, None
    address = lower
    pos = address.rfind("1")
    if pos < 1 or pos + 7 > len(address) or len(address) > 90:
        return None, None, None
    hrp = address[:pos]
    data_part = address[pos + 1:]
    data = []
    for c in data_part:
        idx = _BECH32_CHARSET.find(c)
        if idx < 0:
            return None, None, None
        data.append(idx)
    spec = _bech32m_verify_checksum(hrp, data)
    if not spec:
        return None, None, None
    witness_version = data[0]
    if witness_version == 0 and spec != "bech32":
        return None, None, None
    if witness_version != 0 and spec != "bech32m":
        return None, None, None
    return hrp, witness_version, data[1:-6]


def _bech32m_encode(hrp: str, witness_version: int, witness_program: bytes) -> str:
    import bech32 as _b32
    spec = "bech32" if witness_version == 0 else "bech32m"
    data_5bit = _b32.convertbits(witness_program, 8, 5)
    if data_5bit is None:
        raise ValueError("convertbits failed")
    combined = [witness_version] + data_5bit
    checksum = _bech32m_create_checksum(hrp, combined, spec)
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in combined + checksum)


def _decode_bech32(address: str) -> tuple[int, bytes]:
    import bech32
    hrp, witness_version, data_5bit = _bech32m_decode(address)
    if hrp is None or data_5bit is None or witness_version is None:
        raise ValueError("Invalid bech32/bech32m address")
    decoded = bech32.convertbits(data_5bit, 5, 8, False)
    if decoded is None or len(decoded) < 2 or len(decoded) > 40:
        raise ValueError("Invalid witness program length")
    if witness_version > 16:
        raise ValueError(f"Invalid witness version: {witness_version}")
    return witness_version, bytes(decoded)


def address_to_script_pubkey(address: str, network: str = "mainnet") -> bytes:
    """Decode a Bitcoin address and return the scriptPubKey bytes.

    Raises ValueError for invalid or unsupported addresses.
    """
    address = address.strip()
    if not address:
        raise ValueError("Empty address")

    # Bech32/Bech32m (SegWit)
    if address.lower().startswith(("bc1", "tb1", "bcrt1")):
        if network == "testnet" and not address.lower().startswith(("tb1", "bcrt1")):
            pass  # Allow bc1 on testnet for now (some addresses may still work)
        witness_version, witness_program = _decode_bech32(address)
        if witness_version == 0:
            if len(witness_program) == 20:
                return _P2WPKH_PREFIX + witness_program
            if len(witness_program) == 32:
                return _P2WSH_PREFIX + witness_program
        elif 1 <= witness_version <= 16:
            # Witness v1 = P2TR (BIP 341), v2-v16 reserved
            # scriptPubKey: OP_n <witness_program>
            # OP_1 = 0x51, OP_2 = 0x52, ... OP_16 = 0x60
            op_n = 0x50 + witness_version
            return bytes([op_n, len(witness_program)]) + witness_program
        raise ValueError(f"Unsupported SegWit version or program length: {witness_version}, {len(witness_program)}")

    # Base58Check (P2PKH and P2SH)
    version, payload = _decode_base58check(address)
    if len(payload) != 20:
        raise ValueError(f"Invalid payload length for legacy address: {len(payload)}")

    if version == 0x00:  # Mainnet P2PKH
        return _P2PKH_PREFIX + payload + _P2PKH_SUFFIX
    if version == 0x05:  # Mainnet P2SH
        return _P2SH_PREFIX + payload + _P2SH_SUFFIX
    if version == 0x6f:  # Testnet P2PKH
        return _P2PKH_PREFIX + payload + _P2PKH_SUFFIX
    if version == 0xc4:  # Testnet P2SH
        return _P2SH_PREFIX + payload + _P2SH_SUFFIX

    raise ValueError(f"Unsupported address version: {version}")


# =============================================================================
# Pay-to-Anchor (P2A) utilities
# =============================================================================

def anchor_to_address(network: str = "mainnet") -> str:
    """Return the P2A (Pay-to-Anchor) address for the given network.

    P2A is a standardized anyone-can-spend output for anchor outputs in
    Lightning and other protocols that need efficient CPFP fee bumping.

    The P2A script is: OP_1 OP_PUSHBYTES_2 0x4e73 (4 bytes)
    This is a witness v1 program with a 2-byte program (not Taproot).

    Returns:
        The bech32m-encoded P2A address for the network.

    Examples:
        mainnet: bc1pfeessrawgf...
        testnet: tb1pfeessrawgf...
        regtest: bcrt1pfeessrawgf...

    Reference: Bitcoin Core script/script.cpp, policy/policy.cpp
    """
    if network == "mainnet":
        hrp = "bc"
    elif network in ("testnet", "testnet3", "testnet4", "signet"):
        hrp = "tb"
    elif network == "regtest":
        hrp = "bcrt"
    else:
        raise ValueError(f"Unknown network: {network}")

    # Witness version 1, program = 0x4e73
    return _bech32m_encode(hrp, 1, _P2A_PROGRAM)


def p2a_script() -> bytes:
    """Return the P2A (Pay-to-Anchor) scriptPubKey.

    Returns the 4-byte scriptPubKey: OP_1 OP_PUSHBYTES_2 0x4e73
    """
    return _P2A_SCRIPT


def is_pay_to_anchor(script_pubkey: bytes) -> bool:
    """Check if a scriptPubKey is a Pay-to-Anchor (P2A) output.

    P2A pattern: OP_1 OP_PUSHBYTES_2 0x4e73 (4 bytes total)
    """
    return script_pubkey == _P2A_SCRIPT


def is_pay_to_anchor_program(version: int, program: bytes) -> bool:
    """Check if a witness program is P2A given version and program bytes."""
    return version == 1 and program == _P2A_PROGRAM
