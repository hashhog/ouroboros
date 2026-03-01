"""
Output descriptor parsing, validation, and address derivation.

Implements the Bitcoin output descriptor language (BIP 380–386):
  - ``wpkh(KEY)``       — BIP 84 native SegWit P2WPKH
  - ``pkh(KEY)``        — BIP 44 legacy P2PKH
  - ``tr(KEY)``         — BIP 86 taproot (key-path only)
  - ``sh(wpkh(KEY))``   — BIP 49 P2SH-wrapped SegWit
  - ``multi(M, KEY, ...)``  — bare multisig
  - ``wsh(multi(...))`` — P2WSH multisig

KEY may be:
  - A hex-encoded compressed public key (66 hex chars)
  - An xpub/tpub extended public key, optionally with a derivation suffix
  - An xprv/tprv extended private key (treated identically but flagged)
  - An origin prefix ``[fingerprint/path]`` before any key

Range descriptors use ``*`` as a wildcard index:
  ``wpkh(xpub.../0/*)`` derives addresses at index 0, 1, 2, …

Checksum: every canonical descriptor ends with ``#<8-char checksum>``
computed per the algorithm in BIP 380.

Reference:
  - BIP 380  https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki
  - BIP 381  https://github.com/bitcoin/bips/blob/master/bip-0381.mediawiki
  - BIP 386  https://github.com/bitcoin/bips/blob/master/bip-0386.mediawiki
"""

from __future__ import annotations

import hashlib
import hmac
import re
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple, Union

import base58
import bech32
from coincurve import PrivateKey, PublicKey

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SECP256K1_ORDER = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
)

# BIP 32 version bytes
_XPUB_MAINNET = 0x0488B21E
_XPRV_MAINNET = 0x0488ADE4
_XPUB_TESTNET = 0x043587CF
_XPRV_TESTNET = 0x04358394

_XPUB_VERSIONS = {_XPUB_MAINNET, _XPUB_TESTNET}
_XPRV_VERSIONS = {_XPRV_MAINNET, _XPRV_TESTNET}

# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def _hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _tagged_hash(tag: str, data: bytes) -> bytes:
    tag_hash = _sha256(tag.encode())
    return _sha256(tag_hash + tag_hash + data)


# ---------------------------------------------------------------------------
# BIP 380 descriptor checksum
# ---------------------------------------------------------------------------

_INPUT_CHARSET = (
    "0123456789()[],'/*abcdefgh@:$%{}"
    "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
    "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
)
_CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(c: int, val: int) -> int:
    c0 = c >> 35
    c = ((c & 0x7FFFFFFFF) << 5) ^ val
    if c0 & 1:
        c ^= 0xF5DEE51989
    if c0 & 2:
        c ^= 0xA9FDCA3312
    if c0 & 4:
        c ^= 0x1BAB10E32D
    if c0 & 8:
        c ^= 0x3706B1677A
    if c0 & 16:
        c ^= 0x644D626FFD
    return c


def descriptor_checksum(desc: str) -> str:
    """BIP 380 descriptor checksum for *desc* (must not include an existing ``#…`` suffix)."""
    c = 1
    cls = 0
    clscount = 0
    for ch in desc:
        pos = _INPUT_CHARSET.find(ch)
        if pos < 0:
            raise ValueError(f"Invalid character in descriptor: {ch!r}")
        c = _polymod(c, pos & 31)
        cls = cls * 3 + (pos >> 5)
        clscount += 1
        if clscount == 3:
            c = _polymod(c, cls)
            cls = 0
            clscount = 0
    if clscount > 0:
        c = _polymod(c, cls)
    for _ in range(8):
        c = _polymod(c, 0)
    c ^= 1
    return "".join(_CHECKSUM_CHARSET[(c >> (5 * (7 - i))) & 31] for i in range(8))


def add_checksum(desc: str) -> str:
    """Return *desc* with its ``#checksum`` appended."""
    if "#" in desc:
        desc = desc.split("#")[0]
    return f"{desc}#{descriptor_checksum(desc)}"


def verify_checksum(desc_with_checksum: str) -> bool:
    """Validate the ``#checksum`` suffix of a descriptor string."""
    if "#" not in desc_with_checksum:
        return False
    body, given = desc_with_checksum.rsplit("#", 1)
    if len(given) != 8:
        return False
    return descriptor_checksum(body) == given


# ---------------------------------------------------------------------------
# Extended public key (xpub / tpub) handling
# ---------------------------------------------------------------------------


@dataclass
class ExtendedPubKey:
    """BIP 32 extended *public* key (watch-only)."""

    public_key: bytes      # 33-byte compressed SEC
    chain_code: bytes      # 32 bytes
    depth: int = 0
    parent_fingerprint: bytes = b"\x00\x00\x00\x00"
    child_index: int = 0
    network: str = "mainnet"

    @property
    def fingerprint(self) -> bytes:
        return _hash160(self.public_key)[:4]

    # -- child derivation (public only — normal indices) -------------------

    def derive_child(self, index: int) -> "ExtendedPubKey":
        """Derive a normal (non-hardened) child extended public key."""
        if index & 0x80000000:
            raise ValueError("Cannot derive hardened child from public key")
        data = self.public_key + index.to_bytes(4, "big")
        I = hmac.new(self.chain_code, data, hashlib.sha512).digest()  # noqa: E741
        il = int.from_bytes(I[:32], "big")
        if il >= SECP256K1_ORDER:
            raise ValueError("Derived key out of range")
        # Point addition: child_pub = parse(IL) * G + parent_pub
        parent = PublicKey(self.public_key)
        child_pub = parent.add(I[:32])
        return ExtendedPubKey(
            public_key=child_pub.format(compressed=True),
            chain_code=I[32:],
            depth=self.depth + 1,
            parent_fingerprint=self.fingerprint,
            child_index=index,
            network=self.network,
        )

    def derive_path(self, path: str) -> "ExtendedPubKey":
        """Derive through a slash-separated path, e.g. ``"0/1/2"``."""
        node = self
        for part in path.split("/"):
            part = part.strip()
            if not part:
                continue
            if part.endswith("'") or part.endswith("h"):
                raise ValueError(
                    f"Cannot derive hardened child from xpub: {part}"
                )
            node = node.derive_child(int(part))
        return node

    # -- serialisation -----------------------------------------------------

    def serialize(self) -> str:
        """Base58check-encoded xpub / tpub string."""
        ver = _XPUB_MAINNET if self.network == "mainnet" else _XPUB_TESTNET
        payload = struct.pack(">I", ver)
        payload += bytes([self.depth])
        payload += self.parent_fingerprint
        payload += struct.pack(">I", self.child_index)
        payload += self.chain_code
        payload += self.public_key
        return base58.b58encode_check(payload).decode()

    @classmethod
    def deserialize(cls, encoded: str) -> "ExtendedPubKey":
        """Deserialise an xpub/tpub/xprv/tprv string; xprv keys are converted to their public half."""
        raw = base58.b58decode_check(encoded)
        if len(raw) != 78:
            raise ValueError("Invalid extended key length")
        ver = struct.unpack(">I", raw[:4])[0]
        depth = raw[4]
        parent_fp = raw[5:9]
        child_idx = struct.unpack(">I", raw[9:13])[0]
        chain_code = raw[13:45]

        if ver in _XPUB_VERSIONS:
            pub = bytes(raw[45:78])
            network = "mainnet" if ver == _XPUB_MAINNET else "testnet"
        elif ver in _XPRV_VERSIONS:
            if raw[45] != 0:
                raise ValueError("Invalid extended private key padding")
            priv = raw[46:78]
            pub = PublicKey.from_secret(priv).format(compressed=True)
            network = "mainnet" if ver == _XPRV_MAINNET else "testnet"
        else:
            raise ValueError(f"Unknown extended key version: 0x{ver:08x}")

        return cls(
            public_key=pub,
            chain_code=chain_code,
            depth=depth,
            parent_fingerprint=parent_fp,
            child_index=child_idx,
            network=network,
        )


# ---------------------------------------------------------------------------
# Key expression parsing
# ---------------------------------------------------------------------------

# Matches an origin like [d34db33f/44'/0'/0']
_ORIGIN_RE = re.compile(
    r"^\[([0-9a-fA-F]{8})"     # fingerprint (8 hex)
    r"(/[0-9'/h]+)*"           # derivation steps
    r"\]"
)


@dataclass
class KeyOrigin:
    """Optional key-origin information ``[fingerprint/path]``."""
    fingerprint: str   # 8 hex chars
    path: str          # e.g. "/44'/0'/0'"


@dataclass
class KeyExpression:
    """A parsed key expression inside a descriptor."""
    origin: Optional[KeyOrigin] = None
    # Exactly one of: hex pubkey *or* extended key
    hex_pubkey: Optional[bytes] = None          # 33-byte compressed
    ext_key: Optional[ExtendedPubKey] = None
    ext_key_str: str = ""                       # original xpub/tpub/xprv/tprv
    derivation_suffix: str = ""                 # e.g. "/0/*"
    is_range: bool = False                      # True when suffix contains *
    is_private: bool = False                    # True when xprv/tprv

    def derive_pubkey(self, index: int = 0) -> bytes:
        """Return the 33-byte compressed public key at *index*."""
        if self.hex_pubkey is not None:
            return self.hex_pubkey
        if self.ext_key is None:
            raise ValueError("No key material in expression")
        # Apply derivation suffix, substituting * → index
        suffix = self.derivation_suffix
        if suffix:
            path = suffix.replace("*", str(index))
            derived = self.ext_key.derive_path(path)
        else:
            derived = self.ext_key
        return derived.public_key

    def derive_range(self, start: int, count: int) -> List[bytes]:
        """Derive *count* public keys starting at *start*."""
        return [self.derive_pubkey(i) for i in range(start, start + count)]


def _parse_key_expression(raw: str) -> KeyExpression:
    """Parse a single KEY token from inside a descriptor."""
    expr = KeyExpression()

    s = raw.strip()

    # 1. Optional origin [fingerprint/path]
    m = _ORIGIN_RE.match(s)
    if m:
        origin_str = m.group(0)
        fp = m.group(1)
        path_part = origin_str[1 + 8:-1]  # everything between fp and ]
        expr.origin = KeyOrigin(fingerprint=fp, path=path_part)
        s = s[len(origin_str):]

    # 2. Determine key type
    if s.startswith(("xpub", "tpub", "xprv", "tprv")):
        # Extended key — find end (may have /0/* suffix)
        # The xpub/tpub base58 string ends at the first '/' that follows
        # a base58 character, or at end-of-string.
        slash_idx = None
        # base58check xpub is exactly 111 characters
        # but safer to find where base58 chars end
        for i, ch in enumerate(s):
            if ch == "/" and i > 4:
                slash_idx = i
                break
        if slash_idx is not None:
            ext_str = s[:slash_idx]
            suffix = s[slash_idx:]
            # Strip leading / from suffix for path derivation
            suffix_clean = suffix.lstrip("/")
            expr.derivation_suffix = suffix_clean
            expr.is_range = "*" in suffix
        else:
            ext_str = s
        expr.ext_key_str = ext_str
        expr.ext_key = ExtendedPubKey.deserialize(ext_str)
        expr.is_private = ext_str.startswith(("xprv", "tprv"))
    else:
        # Raw hex public key (compressed: 02/03 + 32 bytes = 66 hex)
        hex_clean = s.strip()
        if len(hex_clean) == 66:
            try:
                pubkey_bytes = bytes.fromhex(hex_clean)
                if pubkey_bytes[0] not in (0x02, 0x03):
                    raise ValueError(f"Not a compressed pubkey: {hex_clean}")
                expr.hex_pubkey = pubkey_bytes
            except ValueError:
                raise ValueError(f"Invalid hex public key: {hex_clean}")
        else:
            raise ValueError(f"Cannot parse key expression: {raw}")

    return expr


# ---------------------------------------------------------------------------
# Descriptor AST
# ---------------------------------------------------------------------------


@dataclass
class Descriptor:
    """Parsed output descriptor."""
    descriptor_type: str          # "wpkh", "pkh", "tr", "sh-wpkh", "multi", "wsh-multi"
    keys: List[KeyExpression] = field(default_factory=list)
    multisig_threshold: int = 0   # M in multi(M, ...)
    is_range: bool = False
    raw: str = ""                 # original canonical string (no checksum)

    # -- address / script derivation --------------------------------------

    def derive_address(self, index: int = 0, network: str = "mainnet") -> str:
        """Derive the address at *index* (relevant for range descriptors)."""
        if self.descriptor_type == "wpkh":
            pub = self.keys[0].derive_pubkey(index)
            return _pubkey_to_p2wpkh(pub, network)
        elif self.descriptor_type == "pkh":
            pub = self.keys[0].derive_pubkey(index)
            return _pubkey_to_p2pkh(pub, network)
        elif self.descriptor_type == "tr":
            pub = self.keys[0].derive_pubkey(index)
            return _pubkey_to_p2tr(pub, network)
        elif self.descriptor_type == "sh-wpkh":
            pub = self.keys[0].derive_pubkey(index)
            return _pubkey_to_p2sh_p2wpkh(pub, network)
        elif self.descriptor_type == "multi":
            pubs = [k.derive_pubkey(index) for k in self.keys]
            script = _make_multisig_script(self.multisig_threshold, pubs)
            # Bare multisig — address is P2SH of the script
            return _script_to_p2sh(script, network)
        elif self.descriptor_type == "wsh-multi":
            pubs = [k.derive_pubkey(index) for k in self.keys]
            script = _make_multisig_script(self.multisig_threshold, pubs)
            return _script_to_p2wsh(script, network)
        else:
            raise ValueError(f"Unknown descriptor type: {self.descriptor_type}")

    def derive_script_pubkey(self, index: int = 0) -> bytes:
        """Derive the scriptPubKey at *index*."""
        if self.descriptor_type == "wpkh":
            pub = self.keys[0].derive_pubkey(index)
            return b"\x00\x14" + _hash160(pub)
        elif self.descriptor_type == "pkh":
            pub = self.keys[0].derive_pubkey(index)
            h = _hash160(pub)
            return b"\x76\xa9\x14" + h + b"\x88\xac"
        elif self.descriptor_type == "tr":
            pub = self.keys[0].derive_pubkey(index)
            tweaked = _taproot_tweak_pubkey(pub)
            return b"\x51\x20" + tweaked
        elif self.descriptor_type == "sh-wpkh":
            pub = self.keys[0].derive_pubkey(index)
            redeem = b"\x00\x14" + _hash160(pub)
            return b"\xa9\x14" + _hash160(redeem) + b"\x87"
        elif self.descriptor_type == "multi":
            pubs = [k.derive_pubkey(index) for k in self.keys]
            script = _make_multisig_script(self.multisig_threshold, pubs)
            return b"\xa9\x14" + _hash160(script) + b"\x87"
        elif self.descriptor_type == "wsh-multi":
            pubs = [k.derive_pubkey(index) for k in self.keys]
            script = _make_multisig_script(self.multisig_threshold, pubs)
            return b"\x00\x20" + _sha256(script)
        else:
            raise ValueError(f"Unknown descriptor type: {self.descriptor_type}")

    def derive_addresses(
        self, start: int = 0, count: int = 20, network: str = "mainnet"
    ) -> List[str]:
        """Derive a range of addresses."""
        return [self.derive_address(i, network) for i in range(start, start + count)]


# ---------------------------------------------------------------------------
# Address helpers
# ---------------------------------------------------------------------------


def _pubkey_to_p2wpkh(pub: bytes, network: str) -> str:
    h160 = _hash160(pub)
    hrp = "bc" if network == "mainnet" else "tb"
    bits5 = bech32.convertbits(h160, 8, 5)
    return bech32.bech32_encode(hrp, [0] + bits5)


def _pubkey_to_p2pkh(pub: bytes, network: str) -> str:
    h160 = _hash160(pub)
    version = b"\x00" if network == "mainnet" else b"\x6f"
    return base58.b58encode_check(version + h160).decode()


def _pubkey_to_p2sh_p2wpkh(pub: bytes, network: str) -> str:
    h160 = _hash160(pub)
    redeem_script = b"\x00\x14" + h160
    script_hash = _hash160(redeem_script)
    version = b"\x05" if network == "mainnet" else b"\xc4"
    return base58.b58encode_check(version + script_hash).decode()


def _taproot_tweak_pubkey(pub: bytes) -> bytes:
    x_only = pub[1:]  # drop 02/03 prefix
    tweak = _tagged_hash("TapTweak", x_only)
    # Compute P + t*G
    pk = PublicKey(pub)
    tweaked = pk.add(tweak)
    return tweaked.format(compressed=True)[1:]  # x-only


def _pubkey_to_p2tr(pub: bytes, network: str) -> str:
    from ouroboros.address import _bech32m_encode
    tweaked_x = _taproot_tweak_pubkey(pub)
    hrp = "bc" if network == "mainnet" else "tb"
    return _bech32m_encode(hrp, 1, tweaked_x)


def _make_multisig_script(threshold: int, pubkeys: List[bytes]) -> bytes:
    if threshold < 1 or threshold > len(pubkeys):
        raise ValueError(
            f"Invalid multisig threshold: {threshold} of {len(pubkeys)}"
        )
    if len(pubkeys) > 20:
        raise ValueError(f"Too many multisig keys: {len(pubkeys)} (max 20)")
    # OP_M <key1> <key2> ... OP_N OP_CHECKMULTISIG
    op_m = 0x50 + threshold  # OP_1 = 0x51, OP_2 = 0x52, ...
    op_n = 0x50 + len(pubkeys)
    script = bytes([op_m])
    for pk in pubkeys:
        script += bytes([len(pk)]) + pk
    script += bytes([op_n, 0xAE])  # OP_CHECKMULTISIG
    return script


def _script_to_p2sh(script: bytes, network: str) -> str:
    script_hash = _hash160(script)
    version = b"\x05" if network == "mainnet" else b"\xc4"
    return base58.b58encode_check(version + script_hash).decode()


def _script_to_p2wsh(script: bytes, network: str) -> str:
    witness_program = _sha256(script)
    hrp = "bc" if network == "mainnet" else "tb"
    bits5 = bech32.convertbits(witness_program, 8, 5)
    return bech32.bech32_encode(hrp, [0] + bits5)


# ---------------------------------------------------------------------------
# Descriptor parser
# ---------------------------------------------------------------------------

def _find_matching_paren(s: str, start: int = 0) -> int:
    if s[start] != "(":
        raise ValueError(f"Expected '(' at position {start}")
    depth = 0
    for i in range(start, len(s)):
        if s[i] == "(":
            depth += 1
        elif s[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    raise ValueError("Unmatched parenthesis")


def parse_descriptor(desc_str: str) -> Descriptor:
    """
    Parse a descriptor string and return a :class:`Descriptor`.

    Accepts descriptors with or without a ``#checksum`` suffix.
    If a checksum is present it is validated.

    Supported forms::

        wpkh(KEY)
        pkh(KEY)
        tr(KEY)
        sh(wpkh(KEY))
        multi(M, KEY, KEY, ...)
        wsh(multi(M, KEY, KEY, ...))

    Raises ``ValueError`` on any parse or validation error.
    """
    s = desc_str.strip()

    # Strip and validate checksum
    if "#" in s:
        if not verify_checksum(s):
            raise ValueError(f"Invalid descriptor checksum: {s}")
        s = s.split("#")[0]

    canonical = s  # save the body for Descriptor.raw

    # -- sh(wpkh(KEY)) -----------------------------------------------------
    if s.startswith("sh(wpkh("):
        inner_start = s.index("wpkh(") + 5
        inner_end = _find_matching_paren(s, s.index("wpkh(") + 4)
        key_str = s[inner_start:inner_end]
        key = _parse_key_expression(key_str)
        return Descriptor(
            descriptor_type="sh-wpkh",
            keys=[key],
            is_range=key.is_range,
            raw=canonical,
        )

    # -- wsh(multi(M, KEY, ...)) ------------------------------------------
    if s.startswith("wsh(multi("):
        inner_start = s.index("multi(") + 6
        inner_end = _find_matching_paren(s, s.index("multi(") + 5)
        inner = s[inner_start:inner_end]
        return _parse_multi_inner(inner, "wsh-multi", canonical)

    # -- wpkh(KEY) --------------------------------------------------------
    if s.startswith("wpkh("):
        paren_open = 4
        paren_close = _find_matching_paren(s, paren_open)
        key_str = s[paren_open + 1:paren_close]
        key = _parse_key_expression(key_str)
        return Descriptor(
            descriptor_type="wpkh",
            keys=[key],
            is_range=key.is_range,
            raw=canonical,
        )

    # -- pkh(KEY) ---------------------------------------------------------
    if s.startswith("pkh("):
        paren_open = 3
        paren_close = _find_matching_paren(s, paren_open)
        key_str = s[paren_open + 1:paren_close]
        key = _parse_key_expression(key_str)
        return Descriptor(
            descriptor_type="pkh",
            keys=[key],
            is_range=key.is_range,
            raw=canonical,
        )

    # -- tr(KEY) ----------------------------------------------------------
    if s.startswith("tr("):
        paren_open = 2
        paren_close = _find_matching_paren(s, paren_open)
        key_str = s[paren_open + 1:paren_close]
        key = _parse_key_expression(key_str)
        return Descriptor(
            descriptor_type="tr",
            keys=[key],
            is_range=key.is_range,
            raw=canonical,
        )

    # -- multi(M, KEY, KEY, ...) ------------------------------------------
    if s.startswith("multi("):
        paren_open = 5
        paren_close = _find_matching_paren(s, paren_open)
        inner = s[paren_open + 1:paren_close]
        return _parse_multi_inner(inner, "multi", canonical)

    raise ValueError(f"Unsupported descriptor: {desc_str}")


def _parse_multi_inner(
    inner: str, dtype: str, canonical: str
) -> Descriptor:
    # Split by commas, but be careful about brackets in origins
    parts = _split_top_level_commas(inner)
    if len(parts) < 2:
        raise ValueError(f"multi() requires threshold + at least one key")
    threshold = int(parts[0].strip())
    keys = [_parse_key_expression(p) for p in parts[1:]]
    if threshold < 1 or threshold > len(keys):
        raise ValueError(
            f"Invalid multisig threshold {threshold} for {len(keys)} keys"
        )
    is_range = any(k.is_range for k in keys)
    return Descriptor(
        descriptor_type=dtype,
        keys=keys,
        multisig_threshold=threshold,
        is_range=is_range,
        raw=canonical,
    )


def _split_top_level_commas(s: str) -> List[str]:
    parts: List[str] = []
    depth = 0
    current: List[str] = []
    for ch in s:
        if ch in "([":
            depth += 1
            current.append(ch)
        elif ch in ")]":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current))
    return parts


# ---------------------------------------------------------------------------
# Descriptor entry for wallet storage
# ---------------------------------------------------------------------------


@dataclass
class DescriptorEntry:
    """A descriptor stored in the wallet, with metadata."""
    descriptor: Descriptor
    desc_string: str          # canonical string with checksum
    timestamp: int = 0        # import time (UNIX)
    active: bool = True       # whether to derive new addresses from it
    range_start: int = 0
    range_end: int = 1000     # default gap limit
    next_index: int = 0       # next unused derivation index
    internal: bool = False    # True for change descriptors
    label: str = ""

    def to_dict(self) -> Dict:
        """Serialise for JSON storage."""
        return {
            "desc": self.desc_string,
            "timestamp": self.timestamp,
            "active": self.active,
            "range": [self.range_start, self.range_end],
            "next_index": self.next_index,
            "internal": self.internal,
            "label": self.label,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "DescriptorEntry":
        """Deserialise from JSON storage."""
        desc_str = d["desc"]
        # Strip checksum for parsing, re-add after
        descriptor = parse_descriptor(desc_str)
        rng = d.get("range", [0, 1000])
        return cls(
            descriptor=descriptor,
            desc_string=desc_str if "#" in desc_str else add_checksum(desc_str),
            timestamp=d.get("timestamp", 0),
            active=d.get("active", True),
            range_start=rng[0] if isinstance(rng, list) else 0,
            range_end=rng[1] if isinstance(rng, list) and len(rng) > 1 else 1000,
            next_index=d.get("next_index", 0),
            internal=d.get("internal", False),
            label=d.get("label", ""),
        )
