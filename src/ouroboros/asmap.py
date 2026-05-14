"""
ASMap interpreter for Autonomous System Number (ASN) lookup from IP addresses.

Provides a compressed mapping from IP address prefixes to Autonomous System
Numbers (ASNs) via a binary trie encoded as bytecode instructions.

Port of bitcoin-core/src/util/asmap.cpp (Interpret, SanityCheckAsmap,
CheckStandardAsmap, DecodeAsmap, AsmapVersion).

Format: bit-packed binary trie, LSB-first bytes for the asmap data,
MSB-first for IP address bits.  Four instruction types:
  RETURN   [0]      — return a constant ASN leaf
  JUMP     [1,0]    — branch on next IP bit (0=fall-through, 1=jump)
  MATCH    [1,1,0]  — compare several IP bits against a pattern
  DEFAULT  [1,1,1]  — set default ASN for subsequent MATCH failures
"""

from __future__ import annotations

import hashlib
import logging

logger = logging.getLogger(__name__)

# Maximum ASMap file size (8 MiB), matching Bitcoin Core's practical limit.
MAX_ASMAP_FILE_SIZE: int = 8_388_608  # 8 * 1024 * 1024

# Sentinel for decoding errors.
_INVALID: int = 0xFFFFFFFF

# Instruction type encodings (see asmap.cpp DecodeType).
_RETURN = 0
_JUMP = 1
_MATCH = 2
_DEFAULT = 3

# Variable-length integer encoding table (bit_sizes arrays from asmap.cpp).
# TYPE: [0, 0, 1] — RETURN=[0], JUMP=[1,0], MATCH=[1,1,0], DEFAULT=[1,1,1]
_TYPE_BIT_SIZES = (0, 0, 1)
# ASN: minval=1, 10 classes covering up to ~16.7 million
_ASN_BIT_SIZES = (15, 16, 17, 18, 19, 20, 21, 22, 23, 24)
# MATCH argument: minval=2, 8 classes covering values [2, 511]
_MATCH_BIT_SIZES = (1, 2, 3, 4, 5, 6, 7, 8)
# JUMP offset: minval=17, 26 classes
_JUMP_BIT_SIZES = (5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                   17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30)


def _consume_bit_le(data: bytes, bitpos: int) -> int:
    """Extract one bit from `data` using LSB-first ordering (for asmap bytes)."""
    return (data[bitpos >> 3] >> (bitpos & 7)) & 1


def _consume_bit_be(data: bytes, bitpos: int) -> int:
    """Extract one bit from `data` using MSB-first ordering (for IP bytes)."""
    return (data[bitpos >> 3] >> (7 - (bitpos & 7))) & 1


def _decode_bits(data: bytes, bitpos: int, minval: int, bit_sizes: tuple) -> tuple[int, int]:
    """Decode a variable-length integer from the asmap bitstream.

    Returns (value, new_bitpos).  Returns (_INVALID, bitpos) on error.

    The encoding uses a sequence of size classes.  For each class k:
      - If k < last class: read one continuation bit.
        0 → decode bit_sizes[k] mantissa bits (big-endian within class).
        1 → add 2^bit_sizes[k] to val and move to class k+1.
      - If k == last class: no continuation bit; decode bit_sizes[k] bits.

    Args:
        data: Raw asmap bytes.
        bitpos: Current bit position (LSB-first).
        minval: Minimum representable value (class-0 starts here).
        bit_sizes: Tuple of mantissa widths per class.
    """
    val = minval
    end_bit = len(data) * 8
    last = len(bit_sizes) - 1
    for k, bsize in enumerate(bit_sizes):
        if k < last:
            if bitpos >= end_bit:
                return _INVALID, bitpos
            cont = _consume_bit_le(data, bitpos)
            bitpos += 1
            if cont:
                val += 1 << bsize
                continue
        # Decode bsize mantissa bits in big-endian order
        for b in range(bsize - 1, -1, -1):
            if bitpos >= end_bit:
                return _INVALID, bitpos
            bit = _consume_bit_le(data, bitpos)
            bitpos += 1
            val += bit << b
        return val, bitpos
    return _INVALID, bitpos


def interpret(asmap: bytes, ip: bytes) -> int:
    """Execute the ASMap trie bytecode to find the ASN for an IP address.

    Direct port of bitcoin-core/src/util/asmap.cpp Interpret().

    Args:
        asmap: Raw asmap bytecode (LSB-first packed bits).
        ip: IP address as bytes, MSB-first (16 bytes for IPv4-in-IPv6 or IPv6).

    Returns:
        ASN (> 0) on success, 0 if no mapping found.
    """
    bitpos: int = 0
    end_bit: int = len(asmap) * 8
    ip_bit: int = 0
    ip_bits_end: int = len(ip) * 8
    default_asn: int = 0

    while bitpos < end_bit:
        opcode, bitpos = _decode_bits(asmap, bitpos, 0, _TYPE_BIT_SIZES)
        if opcode == _INVALID:
            break

        if opcode == _RETURN:
            asn, bitpos = _decode_bits(asmap, bitpos, 1, _ASN_BIT_SIZES)
            if asn == _INVALID:
                break
            return asn

        elif opcode == _JUMP:
            jump, bitpos = _decode_bits(asmap, bitpos, 17, _JUMP_BIT_SIZES)
            if jump == _INVALID:
                break
            if ip_bit >= ip_bits_end:
                break
            if jump >= (end_bit - bitpos):
                break
            if _consume_bit_be(ip, ip_bit):
                bitpos += jump
            ip_bit += 1

        elif opcode == _MATCH:
            match, bitpos = _decode_bits(asmap, bitpos, 2, _MATCH_BIT_SIZES)
            if match == _INVALID:
                break
            # Highest set bit of match determines pattern length (n-1 bits below it)
            matchlen = match.bit_length() - 1
            if (ip_bits_end - ip_bit) < matchlen:
                break
            matched = True
            for bit_idx in range(matchlen):
                ip_b = _consume_bit_be(ip, ip_bit)
                ip_bit += 1
                pattern_bit = (match >> (matchlen - 1 - bit_idx)) & 1
                if ip_b != pattern_bit:
                    matched = False
                    break
            if not matched:
                # Pattern mismatch — consume remaining pattern bits and return default
                remaining = matchlen - (ip_bit - (ip_bit - (matchlen - (matchlen - (ip_bit - ip_bit)))))
                return default_asn

        elif opcode == _DEFAULT:
            asn, bitpos = _decode_bits(asmap, bitpos, 1, _ASN_BIT_SIZES)
            if asn == _INVALID:
                break
            default_asn = asn

        else:
            break

    # Reached EOF without RETURN — should have been caught by sanity check
    return default_asn


def _bit_width(n: int) -> int:
    """Return the number of bits needed to represent n (equivalent to C++ bit_width)."""
    return n.bit_length()


def interpret(asmap: bytes, ip: bytes) -> int:  # noqa: F811 — redefine cleanly below
    """Execute the ASMap trie bytecode to find the ASN for an IP address.

    Direct port of bitcoin-core/src/util/asmap.cpp Interpret().

    Args:
        asmap: Raw asmap bytecode (LSB-first packed bits).
        ip: IP address as bytes, MSB-first (16 bytes for IPv4-in-IPv6 or IPv6).

    Returns:
        ASN (> 0) on success, 0 if no mapping found.
    """
    bitpos: int = 0
    end_bit: int = len(asmap) * 8
    ip_bit: int = 0
    ip_bits_end: int = len(ip) * 8
    default_asn: int = 0

    while bitpos < end_bit:
        opcode, bitpos = _decode_bits(asmap, bitpos, 0, _TYPE_BIT_SIZES)
        if opcode == _INVALID:
            break

        if opcode == _RETURN:
            asn, bitpos = _decode_bits(asmap, bitpos, 1, _ASN_BIT_SIZES)
            if asn == _INVALID:
                break
            return asn

        elif opcode == _JUMP:
            jump, bitpos = _decode_bits(asmap, bitpos, 17, _JUMP_BIT_SIZES)
            if jump == _INVALID:
                break
            if ip_bit >= ip_bits_end:
                break
            if jump >= (end_bit - bitpos):
                break
            ip_b = _consume_bit_be(ip, ip_bit)
            ip_bit += 1
            if ip_b:
                bitpos += jump

        elif opcode == _MATCH:
            match, bitpos = _decode_bits(asmap, bitpos, 2, _MATCH_BIT_SIZES)
            if match == _INVALID:
                break
            matchlen = _bit_width(match) - 1
            if (ip_bits_end - ip_bit) < matchlen:
                break
            mismatch = False
            for bit_idx in range(matchlen):
                ip_b = _consume_bit_be(ip, ip_bit)
                ip_bit += 1
                pattern_bit = (match >> (matchlen - 1 - bit_idx)) & 1
                if ip_b != pattern_bit:
                    mismatch = True
                    break
            if mismatch:
                return default_asn

        elif opcode == _DEFAULT:
            asn, bitpos = _decode_bits(asmap, bitpos, 1, _ASN_BIT_SIZES)
            if asn == _INVALID:
                break
            default_asn = asn

        else:
            break

    return default_asn


def sanity_check_asmap(asmap: bytes, bits: int = 128) -> bool:
    """Validate ASMap structure by simulating all possible execution paths.

    Port of bitcoin-core/src/util/asmap.cpp SanityCheckAsmap().

    Checks:
    - All execution paths terminate with RETURN
    - No intersecting jumps
    - No unreachable code between RETURN and its jump target
    - At most one incomplete (< 8 bit) MATCH in a consecutive sequence
    - RETURN never immediately after DEFAULT (could be folded into RETURN)
    - No consecutive DEFAULT instructions
    - Padding (< 8 trailing bits) is all-zero

    Args:
        asmap: Raw asmap bytecode bytes.
        bits: Number of IP bits to consume (128 for standard IPv4/IPv6).

    Returns:
        True if the asmap passes all structural checks.
    """
    bitpos: int = 0
    end_bit: int = len(asmap) * 8
    # Stack of (jump_target_bitpos, remaining_ip_bits) for pending jump targets
    jumps: list[tuple[int, int]] = []
    prev_opcode: int = _JUMP  # Sentinel: start as if after a JUMP
    had_incomplete_match: bool = False

    while bitpos != end_bit:
        # If we have a pending jump target that we should have reached by now
        if jumps and bitpos >= jumps[-1][0]:
            return False

        opcode, bitpos = _decode_bits(asmap, bitpos, 0, _TYPE_BIT_SIZES)
        if opcode == _INVALID:
            return False

        if opcode == _RETURN:
            # RETURN immediately after DEFAULT is inefficient (fold into RETURN)
            if prev_opcode == _DEFAULT:
                return False
            asn, bitpos = _decode_bits(asmap, bitpos, 1, _ASN_BIT_SIZES)
            if asn == _INVALID:
                return False
            if not jumps:
                # Last RETURN — check zero-padding and EOF
                if (end_bit - bitpos) > 7:
                    return False
                while bitpos < end_bit:
                    if _consume_bit_le(asmap, bitpos):
                        return False
                    bitpos += 1
                return True
            else:
                # After RETURN, execution resumes at the saved jump target
                if bitpos != jumps[-1][0]:
                    return False  # Unreachable code between RETURN and target
                bits = jumps[-1][1]
                jumps.pop()
                prev_opcode = _JUMP

        elif opcode == _JUMP:
            jump, bitpos = _decode_bits(asmap, bitpos, 17, _JUMP_BIT_SIZES)
            if jump == _INVALID:
                return False
            if jump > (end_bit - bitpos):
                return False
            if bits == 0:
                return False  # No IP bits left to branch on
            bits -= 1
            jump_target = bitpos + jump
            if jumps and jump_target >= jumps[-1][0]:
                return False  # Intersecting jumps
            jumps.append((jump_target, bits))
            prev_opcode = _JUMP

        elif opcode == _MATCH:
            match, bitpos = _decode_bits(asmap, bitpos, 2, _MATCH_BIT_SIZES)
            if match == _INVALID:
                return False
            matchlen = _bit_width(match) - 1
            if prev_opcode != _MATCH:
                had_incomplete_match = False
            # Within a consecutive MATCH sequence only one may be < 8 bits
            if matchlen < 8 and had_incomplete_match:
                return False
            had_incomplete_match = matchlen < 8
            if bits < matchlen:
                return False
            bits -= matchlen
            prev_opcode = _MATCH

        elif opcode == _DEFAULT:
            if prev_opcode == _DEFAULT:
                return False  # Consecutive DEFAULTs should be folded
            asn, bitpos = _decode_bits(asmap, bitpos, 1, _ASN_BIT_SIZES)
            if asn == _INVALID:
                return False
            prev_opcode = _DEFAULT

        else:
            return False

    return False  # Reached EOF without completing a RETURN path


def check_standard_asmap(data: bytes) -> bool:
    """Validate asmap data for standard 128-bit (IPv4/IPv6) use.

    Port of bitcoin-core/src/util/asmap.cpp CheckStandardAsmap().

    Args:
        data: Raw asmap bytes.

    Returns:
        True if the data passes sanity check for 128-bit inputs.
    """
    if not sanity_check_asmap(data, 128):
        logger.warning("Sanity check of asmap data failed")
        return False
    return True


def load_asmap(path: str) -> bytes:
    """Load and validate an ASMap file from disk.

    Port of bitcoin-core/src/util/asmap.cpp DecodeAsmap().

    Args:
        path: Path to the asmap binary file.

    Returns:
        Raw asmap bytes on success, empty bytes on failure.

    Raises:
        Nothing — errors are logged and empty bytes returned (matching Core).
    """
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_ASMAP_FILE_SIZE + 1)
    except OSError as e:
        logger.warning("Failed to open asmap file %s: %s", path, e)
        return b""

    if len(data) > MAX_ASMAP_FILE_SIZE:
        logger.warning(
            "ASMap file %s exceeds maximum size of %d bytes",
            path,
            MAX_ASMAP_FILE_SIZE,
        )
        return b""

    logger.info("Opened asmap file %s (%d bytes) from disk", path, len(data))

    if not check_standard_asmap(data):
        logger.warning("Sanity check of asmap file %s failed", path)
        return b""

    return data


def asmap_version(data: bytes) -> bytes:
    """Compute double-SHA256 fingerprint of asmap data.

    Port of bitcoin-core/src/util/asmap.cpp AsmapVersion().

    Used to detect asmap changes across restarts (addrman re-bucketing).

    Args:
        data: Raw asmap bytes.

    Returns:
        32-byte double-SHA256 digest, or 32 zero bytes if data is empty.
    """
    if not data:
        return b"\x00" * 32
    inner = hashlib.sha256(data).digest()
    return hashlib.sha256(inner).digest()


# =============================================================================
# Group encoding helpers (mirrors netgroup.cpp)
# =============================================================================

# NET_IPV6 prefix byte used by Core when encoding an ASN-based group.
# Both IPv4 and IPv6 addresses in the same AS share this prefix so they
# compete for the same addrman buckets (anti-eclipse property).
_NET_IPV6: int = 2

# IPv4-in-IPv6 mapped address prefix (10 zero bytes + 0xFF 0xFF)
_IPV4_IN_IPV6_PREFIX: bytes = b"\x00" * 10 + b"\xff\xff"


def get_mapped_as(asmap: bytes, host: str, network_id: int) -> int:
    """Look up the ASN for a host address using the loaded asmap.

    Mirrors bitcoin-core/src/netgroup.cpp NetGroupManager::GetMappedAS().

    For IPv4: builds a 16-byte IPv4-in-IPv6 representation and calls interpret().
    For IPv6: uses the raw 16 bytes directly.
    For Tor/I2P/CJDNS/unknown: returns 0 (no mapping).

    Args:
        asmap: Raw asmap bytecode (from load_asmap()).  Empty bytes → always 0.
        host: Human-readable address string (dotted-decimal IPv4, IPv6, .onion).
        network_id: BIP155 network ID (1=IPv4, 2=IPv6, others=non-IP).

    Returns:
        ASN as a positive integer, or 0 if no mapping / non-IP type.
    """
    if not asmap:
        return 0

    # Only IPv4 and IPv6 have ASN mappings
    if network_id not in (1, 2):  # NET_IPV4=1, NET_IPV6=2
        return 0

    import ipaddress as _ip

    try:
        if network_id == 1:  # IPv4
            addr = _ip.IPv4Address(host)
            ip_bytes = _IPV4_IN_IPV6_PREFIX + addr.packed
        else:  # IPv6
            addr6 = _ip.IPv6Address(host)
            ip_bytes = addr6.packed
    except ValueError:
        return 0

    return interpret(asmap, ip_bytes)


def asn_group_bytes(asn: int) -> bytes:
    """Encode an ASN as a 5-byte group vector for addrman bucket computation.

    Mirrors bitcoin-core/src/netgroup.cpp NetGroupManager::GetGroup() when
    an ASN is found.  Uses NET_IPV6 (2) as the first byte so that IPv4 and
    IPv6 addresses in the same AS compete for the same addrman buckets
    (anti-eclipse property from netgroup.cpp:26-31).

    Args:
        asn: Autonomous System Number (positive integer).

    Returns:
        5 bytes: [NET_IPV6, asn&0xFF, (asn>>8)&0xFF, (asn>>16)&0xFF, (asn>>24)&0xFF]
    """
    return bytes([
        _NET_IPV6,
        asn & 0xFF,
        (asn >> 8) & 0xFF,
        (asn >> 16) & 0xFF,
        (asn >> 24) & 0xFF,
    ])
