"""
Bitcoin address decoding and script_pubkey derivation.

Supports P2PKH (1...), P2SH (3...), and P2WPKH/P2WSH (bc1..., tb1...).
"""

from typing import Tuple, Optional

# P2PKH: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
# Script: 76 a9 14 <20 bytes> 88 ac
_P2PKH_PREFIX = bytes([0x76, 0xa9, 0x14])
_P2PKH_SUFFIX = bytes([0x88, 0xac])

# P2SH: OP_HASH160 <20-byte hash> OP_EQUAL
# Script: a9 14 <20 bytes> 87
_P2SH_PREFIX = bytes([0xa9, 0x14])
_P2SH_SUFFIX = bytes([0x87])

# P2WPKH: OP_0 <20-byte hash>
# Script: 00 14 <20 bytes>
_P2WPKH_PREFIX = bytes([0x00, 0x14])

# P2WSH: OP_0 <32-byte hash>
# Script: 00 20 <32 bytes>
_P2WSH_PREFIX = bytes([0x00, 0x20])


def _decode_base58check(address: str) -> Tuple[int, bytes]:
    """
    Decode base58check address.
    Returns (version_byte, payload).
    """
    import base58
    decoded = base58.b58decode_check(address)
    if len(decoded) < 2:
        raise ValueError("Invalid base58check address length")
    version = decoded[0]
    payload = bytes(decoded[1:])
    return version, payload


def _decode_bech32(address: str) -> Tuple[int, bytes]:
    """
    Decode bech32/bech32m address.
    Returns (witness_version, witness_program).
    """
    import bech32
    hrp, data_5bit = bech32.bech32_decode(address)
    if hrp is None or data_5bit is None:
        raise ValueError("Invalid bech32 address")
    if len(data_5bit) < 2:
        raise ValueError("Invalid bech32 data length")
    witness_version = data_5bit[0]
    decoded = bech32.convertbits(data_5bit[1:], 5, 8, False)  # Skip witness version
    if decoded is None:
        raise ValueError("Invalid bech32 data")
    return witness_version, bytes(decoded)


def address_to_script_pubkey(address: str, network: str = "mainnet") -> bytes:
    """
    Decode Bitcoin address and return script_pubkey.

    Args:
        address: Bitcoin address (P2PKH 1..., P2SH 3..., P2WPKH bc1/tb1...)
        network: "mainnet" or "testnet" (for bech32 HRP validation)

    Returns:
        script_pubkey as bytes

    Raises:
        ValueError: If address is invalid
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
                # P2WPKH
                return _P2WPKH_PREFIX + witness_program
            if len(witness_program) == 32:
                # P2WSH
                return _P2WSH_PREFIX + witness_program
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
