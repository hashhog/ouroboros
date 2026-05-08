"""
Output descriptor parsing, validation, and address derivation.

Implements the Bitcoin output descriptor language (BIP 380–386):
  - ``pk(KEY)``         — bare P2PK (pay-to-pubkey)
  - ``pkh(KEY)``        — BIP 44 legacy P2PKH
  - ``wpkh(KEY)``       — BIP 84 native SegWit P2WPKH
  - ``tr(KEY)``         — BIP 86 taproot (key-path only)
  - ``tr(KEY, TREE)``   — BIP 386 taproot with script paths (including miniscript)
  - ``sh(wpkh(KEY))``   — BIP 49 P2SH-wrapped SegWit
  - ``multi(M, KEY, ...)``      — bare multisig (wrapped in P2SH)
  - ``sortedmulti(M, KEY, ...)`` — sorted multisig (keys sorted lexicographically)
  - ``wsh(multi(...))`` — P2WSH multisig
  - ``wsh(sortedmulti(...))`` — P2WSH sorted multisig
  - ``wsh(MINISCRIPT)`` — P2WSH with miniscript
  - ``sh(multi(...))``  — P2SH multisig
  - ``sh(wsh(multi(...)))`` — P2SH-P2WSH multisig
  - ``combo(KEY)``      — expands to P2PK, P2PKH, P2WPKH, P2SH-P2WPKH
  - ``addr(ADDRESS)``   — raw address (watch-only)
  - ``raw(HEX)``        — raw scriptPubKey hex

KEY may be:
  - A hex-encoded compressed public key (66 hex chars)
  - An xpub/tpub extended public key, optionally with a derivation suffix
  - An xprv/tprv extended private key (treated identically but flagged)
  - An origin prefix ``[fingerprint/path]`` before any key

MINISCRIPT:
  - Miniscript expressions can be used inside wsh() and in tr() script paths
  - Examples: wsh(and_v(pk(KEY),older(1000))), tr(KEY,pk(KEY2))

Range descriptors use ``*`` as a wildcard index:
  ``wpkh(xpub.../0/*)`` derives addresses at index 0, 1, 2, …

Checksum: every canonical descriptor ends with ``#<8-char checksum>``
computed per the algorithm in BIP 380.

Reference:
  - BIP 380  https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki
  - BIP 381  https://github.com/bitcoin/bips/blob/master/bip-0381.mediawiki
  - BIP 383  https://github.com/bitcoin/bips/blob/master/bip-0383.mediawiki
  - BIP 386  https://github.com/bitcoin/bips/blob/master/bip-0386.mediawiki
  - BIP 379  https://github.com/bitcoin/bips/blob/master/bip-0379.mediawiki (Miniscript)
"""

from __future__ import annotations

import hashlib
import hmac
import re
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ouroboros.miniscript import MiniscriptNode

import base58
import bech32
from coincurve import PublicKey

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

    def derive_child(self, index: int) -> ExtendedPubKey:
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

    def derive_path(self, path: str) -> ExtendedPubKey:
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
    def deserialize(cls, encoded: str) -> ExtendedPubKey:
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
    origin: KeyOrigin | None = None
    # Exactly one of: hex pubkey *or* extended key
    hex_pubkey: bytes | None = None          # 33-byte compressed
    ext_key: ExtendedPubKey | None = None
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

    def derive_range(self, start: int, count: int) -> list[bytes]:
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
                raise ValueError(f"Invalid hex public key: {hex_clean}") from None
        else:
            raise ValueError(f"Cannot parse key expression: {raw}")

    return expr


# ---------------------------------------------------------------------------
# Descriptor AST
# ---------------------------------------------------------------------------


@dataclass
class Descriptor:
    """Parsed output descriptor."""
    descriptor_type: str          # "pk", "pkh", "wpkh", "tr", "sh-wpkh", "multi",
                                  # "sortedmulti", "wsh-multi", "wsh-sortedmulti",
                                  # "wsh-miniscript", "tr-script", "sh-multi",
                                  # "sh-wsh-multi", "combo", "addr", "raw"
    keys: list[KeyExpression] = field(default_factory=list)
    multisig_threshold: int = 0   # M in multi(M, ...)
    is_range: bool = False
    raw: str = ""                 # original canonical string (no checksum)
    sorted_multi: bool = False    # True for sortedmulti() descriptors
    # For addr() and raw() descriptors
    address: str = ""             # address string for addr() descriptors
    script_hex: str = ""          # raw script hex for raw() descriptors
    # For miniscript descriptors
    miniscript_expr: str = ""     # miniscript expression string
    miniscript_node: MiniscriptNode | None = None  # parsed miniscript
    # For tr() with script paths
    tap_tree: list | None = None  # Taproot script tree

    # -- address / script derivation --------------------------------------

    def derive_address(self, index: int = 0, network: str = "mainnet") -> str:
        """Derive the address at *index* (relevant for range descriptors).

        For combo() descriptors, returns a list of addresses.
        """
        dtype = self.descriptor_type

        if dtype == "pk":
            # P2PK has no standard address; wrap in P2SH
            pub = self.keys[0].derive_pubkey(index)
            script = _make_p2pk_script(pub)
            return _script_to_p2sh(script, network)

        if dtype == "pkh":
            pub = self.keys[0].derive_pubkey(index)
            return _pubkey_to_p2pkh(pub, network)

        if dtype == "wpkh":
            pub = self.keys[0].derive_pubkey(index)
            return _pubkey_to_p2wpkh(pub, network)

        if dtype == "tr":
            pub = self.keys[0].derive_pubkey(index)
            return _pubkey_to_p2tr(pub, network)

        if dtype == "sh-wpkh":
            pub = self.keys[0].derive_pubkey(index)
            return _pubkey_to_p2sh_p2wpkh(pub, network)

        if dtype in ("multi", "sortedmulti"):
            pubs = [k.derive_pubkey(index) for k in self.keys]
            script = _make_multisig_script(
                self.multisig_threshold, pubs, self.sorted_multi
            )
            # Bare multisig — address is P2SH of the script
            return _script_to_p2sh(script, network)

        if dtype in ("wsh-multi", "wsh-sortedmulti"):
            pubs = [k.derive_pubkey(index) for k in self.keys]
            script = _make_multisig_script(
                self.multisig_threshold, pubs, self.sorted_multi
            )
            return _script_to_p2wsh(script, network)

        if dtype in ("sh-multi", "sh-sortedmulti"):
            pubs = [k.derive_pubkey(index) for k in self.keys]
            script = _make_multisig_script(
                self.multisig_threshold, pubs, self.sorted_multi
            )
            return _script_to_p2sh(script, network)

        if dtype in ("sh-wsh-multi", "sh-wsh-sortedmulti"):
            pubs = [k.derive_pubkey(index) for k in self.keys]
            script = _make_multisig_script(
                self.multisig_threshold, pubs, self.sorted_multi
            )
            # P2SH wrapping P2WSH
            witness_program = b"\x00\x20" + _sha256(script)
            return _script_to_p2sh(witness_program, network)

        if dtype == "wsh-miniscript":
            script = self._compile_miniscript(index)
            return _script_to_p2wsh(script, network)

        if dtype == "tr-script":
            pub = self.keys[0].derive_pubkey(index)
            tweaked = self._taproot_tweak_with_tree(pub, index)
            hrp = "bc" if network == "mainnet" else "tb"
            from ouroboros.address import _bech32m_encode
            return _bech32m_encode(hrp, 1, tweaked)

        if dtype == "addr":
            # addr() always returns the stored address
            return self.address

        if dtype == "raw":
            # raw() returns P2SH of the script
            script = bytes.fromhex(self.script_hex)
            return _script_to_p2sh(script, network)

        raise ValueError(f"Unknown descriptor type: {dtype}")

    def derive_script_pubkey(self, index: int = 0) -> bytes:
        """Derive the scriptPubKey at *index*."""
        dtype = self.descriptor_type

        if dtype == "pk":
            pub = self.keys[0].derive_pubkey(index)
            return _make_p2pk_script(pub)

        if dtype == "pkh":
            pub = self.keys[0].derive_pubkey(index)
            h = _hash160(pub)
            return b"\x76\xa9\x14" + h + b"\x88\xac"

        if dtype == "wpkh":
            pub = self.keys[0].derive_pubkey(index)
            return b"\x00\x14" + _hash160(pub)

        if dtype == "tr":
            pub = self.keys[0].derive_pubkey(index)
            tweaked = _taproot_tweak_pubkey(pub)
            return b"\x51\x20" + tweaked

        if dtype == "sh-wpkh":
            pub = self.keys[0].derive_pubkey(index)
            redeem = b"\x00\x14" + _hash160(pub)
            return b"\xa9\x14" + _hash160(redeem) + b"\x87"

        if dtype in ("multi", "sortedmulti"):
            pubs = [k.derive_pubkey(index) for k in self.keys]
            script = _make_multisig_script(
                self.multisig_threshold, pubs, self.sorted_multi
            )
            return b"\xa9\x14" + _hash160(script) + b"\x87"

        if dtype in ("wsh-multi", "wsh-sortedmulti"):
            pubs = [k.derive_pubkey(index) for k in self.keys]
            script = _make_multisig_script(
                self.multisig_threshold, pubs, self.sorted_multi
            )
            return b"\x00\x20" + _sha256(script)

        if dtype in ("sh-multi", "sh-sortedmulti"):
            pubs = [k.derive_pubkey(index) for k in self.keys]
            script = _make_multisig_script(
                self.multisig_threshold, pubs, self.sorted_multi
            )
            return b"\xa9\x14" + _hash160(script) + b"\x87"

        if dtype in ("sh-wsh-multi", "sh-wsh-sortedmulti"):
            pubs = [k.derive_pubkey(index) for k in self.keys]
            script = _make_multisig_script(
                self.multisig_threshold, pubs, self.sorted_multi
            )
            witness_program = b"\x00\x20" + _sha256(script)
            return b"\xa9\x14" + _hash160(witness_program) + b"\x87"

        if dtype == "wsh-miniscript":
            # Compile miniscript to get witness script
            script = self._compile_miniscript(index)
            return b"\x00\x20" + _sha256(script)

        if dtype == "tr-script":
            # Taproot with script paths
            pub = self.keys[0].derive_pubkey(index)
            tweaked = self._taproot_tweak_with_tree(pub, index)
            return b"\x51\x20" + tweaked

        if dtype == "addr":
            # addr() — decode address to scriptPubKey
            return _decode_address(self.address)

        if dtype == "raw":
            return bytes.fromhex(self.script_hex)

        raise ValueError(f"Unknown descriptor type: {dtype}")

    def derive_all_scripts(self, index: int = 0) -> list[bytes]:
        """For combo() descriptors, return all scriptPubKeys; otherwise a single-element list."""
        if self.descriptor_type != "combo":
            return [self.derive_script_pubkey(index)]

        # combo(KEY) expands to: P2PK, P2PKH, and if compressed: P2WPKH, P2SH-P2WPKH
        pub = self.keys[0].derive_pubkey(index)
        scripts: list[bytes] = []
        # P2PK
        scripts.append(_make_p2pk_script(pub))
        # P2PKH
        h = _hash160(pub)
        scripts.append(b"\x76\xa9\x14" + h + b"\x88\xac")
        # Compressed keys get segwit variants
        if pub[0] in (0x02, 0x03):
            # P2WPKH
            scripts.append(b"\x00\x14" + _hash160(pub))
            # P2SH-P2WPKH
            redeem = b"\x00\x14" + _hash160(pub)
            scripts.append(b"\xa9\x14" + _hash160(redeem) + b"\x87")
        return scripts

    def derive_all_addresses(self, index: int = 0, network: str = "mainnet") -> list[str]:
        """For combo() descriptors, return all addresses; otherwise a single-element list."""
        if self.descriptor_type != "combo":
            return [self.derive_address(index, network)]

        # combo(KEY) expands to: P2PK (as P2SH), P2PKH, and if compressed: P2WPKH, P2SH-P2WPKH
        pub = self.keys[0].derive_pubkey(index)
        addresses: list[str] = []
        # P2PK has no standard address; wrap in P2SH
        script = _make_p2pk_script(pub)
        addresses.append(_script_to_p2sh(script, network))
        # P2PKH
        addresses.append(_pubkey_to_p2pkh(pub, network))
        # Compressed keys get segwit variants
        if pub[0] in (0x02, 0x03):
            # P2WPKH
            addresses.append(_pubkey_to_p2wpkh(pub, network))
            # P2SH-P2WPKH
            addresses.append(_pubkey_to_p2sh_p2wpkh(pub, network))
        return addresses

    def derive_addresses(
        self, start: int = 0, count: int = 20, network: str = "mainnet"
    ) -> list[str]:
        """Derive a range of addresses."""
        return [self.derive_address(i, network) for i in range(start, start + count)]

    def _compile_miniscript(self, index: int = 0) -> bytes:
        """Compile miniscript expression to witness script."""
        from ouroboros.miniscript import (
            MiniscriptContext,
            compile_miniscript,
            parse_miniscript,
        )

        # Create key parser that resolves keys from our key expressions
        def key_parser(key_str: str) -> bytes:
            # Try to find matching key expression
            for key_expr in self.keys:
                if key_expr.hex_pubkey is not None:
                    if key_str.strip() == key_expr.hex_pubkey.hex():
                        return key_expr.hex_pubkey
                elif key_expr.ext_key_str:
                    # Check if it's an xpub reference
                    if key_str.strip().startswith(key_expr.ext_key_str[:10]):
                        return key_expr.derive_pubkey(index)
            # Try hex decode
            return bytes.fromhex(key_str.strip())

        ctx = MiniscriptContext.P2WSH
        if self.miniscript_node is not None:
            return compile_miniscript(self.miniscript_node, ctx)

        node = parse_miniscript(self.miniscript_expr, ctx, key_parser)
        return compile_miniscript(node, ctx)

    def _taproot_tweak_with_tree(self, pub: bytes, index: int = 0) -> bytes:
        """Compute taproot output key with script tree.

        Per BIP-341 the on-chain output key is::

            Q = lift_x(P) + tagged_hash("TapTweak", x_only(P) || merkle) * G

        i.e. the *internal* point must be lifted to even-Y before applying
        the tweak. The pre-W23 implementation called
        ``coincurve.PublicKey(pub).add(tweak)`` directly, which uses the
        actual parity of ``pub`` and produces a different ``Q`` whenever
        the internal Y is odd — silently corrupting every ``tr(KEY)`` /
        ``tr(KEY, TREE)`` address whose internal pubkey hits 0x03.

        Routes through ``derive_taproot_output_xonly`` so the
        even-Y normalization lives in exactly one place (shared with
        the wallet signing path in ``taproot.py``).
        """
        from ouroboros.taproot import derive_taproot_output_xonly

        if self.tap_tree is None:
            merkle_root: bytes | None = None
        else:
            merkle_root = self._compute_tap_tree_merkle(index)

        return derive_taproot_output_xonly(pub, merkle_root)

    def _compute_tap_tree_merkle(self, index: int = 0) -> bytes:
        """Compute merkle root of taproot script tree."""
        from ouroboros.miniscript import MiniscriptContext, compile_miniscript, parse_miniscript

        def leaf_hash(script: bytes, leaf_version: int = 0xc0) -> bytes:
            return _tagged_hash("TapLeaf", bytes([leaf_version]) + _compact_size(len(script)) + script)

        def branch_hash(left: bytes, right: bytes) -> bytes:
            # Sort lexicographically
            if left > right:
                left, right = right, left
            return _tagged_hash("TapBranch", left + right)

        def compute_tree(tree) -> bytes:
            if isinstance(tree, str):
                # It's a miniscript expression - compile it
                def key_parser(key_str: str) -> bytes:
                    for key_expr in self.keys:
                        if key_expr.hex_pubkey is not None:
                            if key_str.strip() == key_expr.hex_pubkey.hex():
                                return key_expr.hex_pubkey
                    return bytes.fromhex(key_str.strip())
                node = parse_miniscript(tree, MiniscriptContext.TAPSCRIPT, key_parser)
                script = compile_miniscript(node, MiniscriptContext.TAPSCRIPT)
                return leaf_hash(script)
            elif isinstance(tree, tuple) and len(tree) == 2:
                # It's a branch (left, right)
                left = compute_tree(tree[0])
                right = compute_tree(tree[1])
                return branch_hash(left, right)
            elif isinstance(tree, list) and len(tree) == 1:
                return compute_tree(tree[0])
            elif isinstance(tree, list) and len(tree) == 2:
                left = compute_tree(tree[0])
                right = compute_tree(tree[1])
                return branch_hash(left, right)
            else:
                raise ValueError(f"Invalid tap tree structure: {tree}")

        return compute_tree(self.tap_tree)

    def get_miniscript_satisfaction_size(self, index: int = 0) -> int | None:
        """Get the witness size needed to satisfy this miniscript descriptor."""
        if self.descriptor_type not in ("wsh-miniscript", "tr-script"):
            return None

        from ouroboros.miniscript import (
            MiniscriptContext,
            analyze_satisfaction,
            parse_miniscript,
        )

        ctx = (
            MiniscriptContext.TAPSCRIPT
            if self.descriptor_type == "tr-script"
            else MiniscriptContext.P2WSH
        )

        if self.miniscript_node is not None:
            info = analyze_satisfaction(self.miniscript_node)
        else:
            node = parse_miniscript(self.miniscript_expr, ctx)
            info = analyze_satisfaction(node)

        return info.sat_size


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
    """BIP-86 single-key taproot tweak.

    Per BIP-341 the internal point must be lifted to even-Y before
    adding ``t*G``. ``coincurve.PublicKey(pub).add(tweak)`` honors the
    actual parity of ``pub`` and silently returns the wrong ``Q``
    when ``pub`` is odd-Y (prefix 0x03). Route through
    ``derive_taproot_output_xonly`` for a single source of truth shared
    with the wallet/PSBT signing path.
    """
    from ouroboros.taproot import derive_taproot_output_xonly
    return derive_taproot_output_xonly(pub, None)


def _pubkey_to_p2tr(pub: bytes, network: str) -> str:
    from ouroboros.address import _bech32m_encode
    tweaked_x = _taproot_tweak_pubkey(pub)
    hrp = "bc" if network == "mainnet" else "tb"
    return _bech32m_encode(hrp, 1, tweaked_x)


def _make_multisig_script(
    threshold: int, pubkeys: list[bytes], sorted_keys: bool = False
) -> bytes:
    if threshold < 1 or threshold > len(pubkeys):
        raise ValueError(
            f"Invalid multisig threshold: {threshold} of {len(pubkeys)}"
        )
    if len(pubkeys) > 20:
        raise ValueError(f"Too many multisig keys: {len(pubkeys)} (max 20)")
    # For sortedmulti, sort keys lexicographically
    if sorted_keys:
        pubkeys = sorted(pubkeys)
    # OP_M <key1> <key2> ... OP_N OP_CHECKMULTISIG
    op_m = 0x50 + threshold  # OP_1 = 0x51, OP_2 = 0x52, ...
    op_n = 0x50 + len(pubkeys)
    script = bytes([op_m])
    for pk in pubkeys:
        script += bytes([len(pk)]) + pk
    script += bytes([op_n, 0xAE])  # OP_CHECKMULTISIG
    return script


def _make_p2pk_script(pub: bytes) -> bytes:
    """Create a P2PK scriptPubKey: <pubkey> OP_CHECKSIG."""
    return bytes([len(pub)]) + pub + bytes([0xAC])  # 0xAC = OP_CHECKSIG


def _compact_size(n: int) -> bytes:
    """Encode an integer as a Bitcoin compact size."""
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return b"\xfd" + n.to_bytes(2, "little")
    elif n <= 0xffffffff:
        return b"\xfe" + n.to_bytes(4, "little")
    else:
        return b"\xff" + n.to_bytes(8, "little")


def _decode_address(addr: str, network: str = "mainnet") -> bytes:
    """Decode a Bitcoin address and return its scriptPubKey.

    Supports: P2PKH (1.../m...), P2SH (3.../2...), P2WPKH (bc1q.../tb1q...),
    P2WSH (bc1q... 32-byte), P2TR (bc1p.../tb1p...).
    """
    # Bech32/Bech32m addresses
    if addr.lower().startswith(("bc1", "tb1")):
        hrp = "bc" if network == "mainnet" else "tb"
        try:
            # Try bech32 first
            decoded = bech32.bech32_decode(addr)
            if decoded[0] is not None:
                _, data = decoded
                if data is None or len(data) < 1:
                    raise ValueError(f"Invalid bech32 address: {addr}")
                witver = data[0]
                witprog = bytes(bech32.convertbits(data[1:], 5, 8, False))
                if witver == 0:
                    if len(witprog) == 20:
                        # P2WPKH
                        return b"\x00\x14" + witprog
                    elif len(witprog) == 32:
                        # P2WSH
                        return b"\x00\x20" + witprog
        except Exception:
            pass
        # Try bech32m for taproot
        try:
            from ouroboros.address import _bech32m_decode
            witver, witprog = _bech32m_decode(hrp, addr)
            if witver == 1 and len(witprog) == 32:
                # P2TR
                return b"\x51\x20" + witprog
        except Exception:
            pass
        raise ValueError(f"Invalid bech32/bech32m address: {addr}")

    # Base58Check addresses (P2PKH, P2SH)
    try:
        decoded = base58.b58decode_check(addr)
    except Exception:
        raise ValueError(f"Invalid base58 address: {addr}") from None

    if len(decoded) != 21:
        raise ValueError(f"Invalid address length: {addr}")

    version = decoded[0]
    h160 = decoded[1:]

    # P2PKH mainnet (0x00), testnet (0x6f)
    if version == 0x00 or version == 0x6F:
        return b"\x76\xa9\x14" + h160 + b"\x88\xac"
    # P2SH mainnet (0x05), testnet (0xc4)
    if version == 0x05 or version == 0xC4:
        return b"\xa9\x14" + h160 + b"\x87"

    raise ValueError(f"Unknown address version: {version}")


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

        pk(KEY)                    — bare P2PK
        pkh(KEY)                   — P2PKH
        wpkh(KEY)                  — P2WPKH
        tr(KEY)                    — P2TR (key-path only)
        sh(wpkh(KEY))              — P2SH-P2WPKH
        multi(M, KEY, ...)         — bare multisig (wrapped in P2SH)
        sortedmulti(M, KEY, ...)   — sorted multisig
        wsh(multi(M, KEY, ...))    — P2WSH multisig
        wsh(sortedmulti(...))      — P2WSH sorted multisig
        sh(multi(M, KEY, ...))     — P2SH multisig
        sh(wsh(multi(...)))        — P2SH-P2WSH multisig
        combo(KEY)                 — P2PK, P2PKH, P2WPKH, P2SH-P2WPKH
        addr(ADDRESS)              — raw address (watch-only)
        raw(HEX)                   — raw scriptPubKey hex

    Raises ``ValueError`` on any parse or validation error.
    """
    s = desc_str.strip()

    # Strip and validate checksum
    if "#" in s:
        if not verify_checksum(s):
            raise ValueError(f"Invalid descriptor checksum: {s}")
        s = s.split("#")[0]

    canonical = s  # save the body for Descriptor.raw

    # -- addr(ADDRESS) -----------------------------------------------------
    if s.startswith("addr("):
        paren_close = _find_matching_paren(s, 4)
        addr_str = s[5:paren_close].strip()
        # Validate address by attempting to decode it
        _decode_address(addr_str)
        return Descriptor(
            descriptor_type="addr",
            address=addr_str,
            is_range=False,
            raw=canonical,
        )

    # -- raw(HEX) ----------------------------------------------------------
    if s.startswith("raw("):
        paren_close = _find_matching_paren(s, 3)
        hex_str = s[4:paren_close].strip()
        # Validate hex
        try:
            bytes.fromhex(hex_str)
        except ValueError:
            raise ValueError(f"Invalid hex in raw(): {hex_str}") from None
        return Descriptor(
            descriptor_type="raw",
            script_hex=hex_str,
            is_range=False,
            raw=canonical,
        )

    # -- combo(KEY) --------------------------------------------------------
    if s.startswith("combo("):
        paren_close = _find_matching_paren(s, 5)
        key_str = s[6:paren_close]
        key = _parse_key_expression(key_str)
        return Descriptor(
            descriptor_type="combo",
            keys=[key],
            is_range=key.is_range,
            raw=canonical,
        )

    # -- sh(wsh(multi(M, KEY, ...))) or sh(wsh(sortedmulti(...))) ---------
    if s.startswith("sh(wsh(multi(") or s.startswith("sh(wsh(sortedmulti("):
        sorted_multi = "sortedmulti" in s
        if sorted_multi:
            inner_start = s.index("sortedmulti(") + 12
            inner_end = _find_matching_paren(s, s.index("sortedmulti(") + 11)
        else:
            inner_start = s.index("multi(") + 6
            inner_end = _find_matching_paren(s, s.index("multi(") + 5)
        inner = s[inner_start:inner_end]
        dtype = "sh-wsh-sortedmulti" if sorted_multi else "sh-wsh-multi"
        return _parse_multi_inner(inner, dtype, canonical, sorted_multi)

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

    # -- sh(multi(M, KEY, ...)) or sh(sortedmulti(...)) --------------------
    if s.startswith("sh(multi(") or s.startswith("sh(sortedmulti("):
        sorted_multi = "sortedmulti" in s
        if sorted_multi:
            inner_start = s.index("sortedmulti(") + 12
            inner_end = _find_matching_paren(s, s.index("sortedmulti(") + 11)
        else:
            inner_start = s.index("multi(") + 6
            inner_end = _find_matching_paren(s, s.index("multi(") + 5)
        inner = s[inner_start:inner_end]
        dtype = "sh-sortedmulti" if sorted_multi else "sh-multi"
        return _parse_multi_inner(inner, dtype, canonical, sorted_multi)

    # -- wsh(multi(M, KEY, ...)) or wsh(sortedmulti(...)) ------------------
    if s.startswith("wsh(multi(") or s.startswith("wsh(sortedmulti("):
        sorted_multi = "sortedmulti" in s
        if sorted_multi:
            inner_start = s.index("sortedmulti(") + 12
            inner_end = _find_matching_paren(s, s.index("sortedmulti(") + 11)
        else:
            inner_start = s.index("multi(") + 6
            inner_end = _find_matching_paren(s, s.index("multi(") + 5)
        inner = s[inner_start:inner_end]
        dtype = "wsh-sortedmulti" if sorted_multi else "wsh-multi"
        return _parse_multi_inner(inner, dtype, canonical, sorted_multi)

    # -- wsh(MINISCRIPT) ---------------------------------------------------
    if s.startswith("wsh("):
        paren_close = _find_matching_paren(s, 3)
        inner = s[4:paren_close]
        # Check if it's a known non-miniscript construct
        if not inner.startswith(("multi(", "sortedmulti(")):
            return _parse_wsh_miniscript(inner, canonical)

    # -- pk(KEY) -----------------------------------------------------------
    if s.startswith("pk("):
        paren_close = _find_matching_paren(s, 2)
        key_str = s[3:paren_close]
        key = _parse_key_expression(key_str)
        return Descriptor(
            descriptor_type="pk",
            keys=[key],
            is_range=key.is_range,
            raw=canonical,
        )

    # -- pkh(KEY) ---------------------------------------------------------
    if s.startswith("pkh("):
        paren_close = _find_matching_paren(s, 3)
        key_str = s[4:paren_close]
        key = _parse_key_expression(key_str)
        return Descriptor(
            descriptor_type="pkh",
            keys=[key],
            is_range=key.is_range,
            raw=canonical,
        )

    # -- wpkh(KEY) --------------------------------------------------------
    if s.startswith("wpkh("):
        paren_close = _find_matching_paren(s, 4)
        key_str = s[5:paren_close]
        key = _parse_key_expression(key_str)
        return Descriptor(
            descriptor_type="wpkh",
            keys=[key],
            is_range=key.is_range,
            raw=canonical,
        )

    # -- tr(KEY) or tr(KEY, TREE) ------------------------------------------
    if s.startswith("tr("):
        paren_close = _find_matching_paren(s, 2)
        inner = s[3:paren_close]
        # Check if there's a script tree (comma-separated)
        parts = _split_top_level_commas(inner)
        if len(parts) == 1:
            # Key-path only: tr(KEY)
            key = _parse_key_expression(parts[0])
            return Descriptor(
                descriptor_type="tr",
                keys=[key],
                is_range=key.is_range,
                raw=canonical,
            )
        elif len(parts) >= 2:
            # Script path: tr(KEY, TREE)
            key = _parse_key_expression(parts[0])
            tree_str = ",".join(parts[1:])
            tap_tree, extra_keys = _parse_tap_tree(tree_str)
            all_keys = [key] + extra_keys
            return Descriptor(
                descriptor_type="tr-script",
                keys=all_keys,
                is_range=key.is_range or any(k.is_range for k in extra_keys),
                raw=canonical,
                tap_tree=tap_tree,
            )
        else:
            raise ValueError(f"Invalid tr() descriptor: {s}")

    # -- sortedmulti(M, KEY, KEY, ...) ------------------------------------
    if s.startswith("sortedmulti("):
        paren_close = _find_matching_paren(s, 11)
        inner = s[12:paren_close]
        return _parse_multi_inner(inner, "sortedmulti", canonical, sorted_multi=True)

    # -- multi(M, KEY, KEY, ...) ------------------------------------------
    if s.startswith("multi("):
        paren_close = _find_matching_paren(s, 5)
        inner = s[6:paren_close]
        return _parse_multi_inner(inner, "multi", canonical, sorted_multi=False)

    raise ValueError(f"Unsupported descriptor: {desc_str}")


def _parse_multi_inner(
    inner: str, dtype: str, canonical: str, sorted_multi: bool = False
) -> Descriptor:
    """Parse the inner content of a multi() or sortedmulti() descriptor."""
    # Split by commas, but be careful about brackets in origins
    parts = _split_top_level_commas(inner)
    if len(parts) < 2:
        raise ValueError("multi() requires threshold + at least one key")
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
        sorted_multi=sorted_multi,
    )


def _split_top_level_commas(s: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in s:
        if ch in "([{":
            depth += 1
            current.append(ch)
        elif ch in ")]}":
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


def _parse_wsh_miniscript(miniscript_expr: str, canonical: str) -> Descriptor:
    """Parse a wsh(MINISCRIPT) descriptor."""
    from ouroboros.miniscript import MiniscriptContext, parse_miniscript

    # Extract keys from the miniscript expression
    keys = _extract_keys_from_miniscript(miniscript_expr)

    # Create key parser
    def key_parser(key_str: str) -> bytes:
        key_str = key_str.strip()
        # Try to parse as a key expression
        try:
            expr = _parse_key_expression(key_str)
            return expr.derive_pubkey(0)
        except ValueError:
            # Fall back to hex decode
            return bytes.fromhex(key_str)

    # Parse and validate the miniscript
    node = parse_miniscript(miniscript_expr, MiniscriptContext.P2WSH, key_parser)

    return Descriptor(
        descriptor_type="wsh-miniscript",
        keys=keys,
        is_range=any(k.is_range for k in keys),
        raw=canonical,
        miniscript_expr=miniscript_expr,
        miniscript_node=node,
    )


def _extract_keys_from_miniscript(expr: str) -> list[KeyExpression]:
    """Extract all key expressions from a miniscript string."""
    import re

    keys = []
    # Find all pk(), pkh(), pk_k(), pk_h() arguments
    for pattern in [
        r'pk\(([^)]+)\)',
        r'pkh\(([^)]+)\)',
        r'pk_k\(([^)]+)\)',
        r'pk_h\(([^)]+)\)',
    ]:
        for match in re.finditer(pattern, expr):
            key_str = match.group(1).strip()
            try:
                key = _parse_key_expression(key_str)
                keys.append(key)
            except ValueError:
                pass  # Skip invalid keys

    # Find all multi() and multi_a() keys
    multi_pattern = r'multi(?:_a)?\((\d+)([^)]+)\)'
    for match in re.finditer(multi_pattern, expr):
        keys_str = match.group(2)
        for key_str in keys_str.split(",")[1:]:  # Skip threshold
            key_str = key_str.strip()
            if key_str:
                try:
                    key = _parse_key_expression(key_str)
                    keys.append(key)
                except ValueError:
                    pass

    return keys


def _parse_tap_tree(tree_str: str) -> tuple[str | list, list[KeyExpression]]:
    """
    Parse a taproot script tree expression.

    Tree format:
      - Single script: "pk(KEY)" or any miniscript
      - Binary tree: "{left,right}" where left/right are scripts or subtrees

    Returns:
        Tuple of (parsed tree structure, list of keys found)
    """
    tree_str = tree_str.strip()
    all_keys: list[KeyExpression] = []

    def parse_node(s: str) -> str | list:
        s = s.strip()
        if s.startswith("{"):
            # It's a branch node
            if not s.endswith("}"):
                raise ValueError(f"Invalid tree node: {s}")
            inner = s[1:-1]
            parts = _split_top_level_commas(inner)
            if len(parts) != 2:
                raise ValueError(f"Branch must have exactly 2 children: {s}")
            left = parse_node(parts[0])
            right = parse_node(parts[1])
            return [left, right]
        else:
            # It's a leaf (miniscript expression)
            # Extract keys
            keys = _extract_keys_from_miniscript(s)
            all_keys.extend(keys)
            return s

    tree = parse_node(tree_str)
    return tree, all_keys


# ---------------------------------------------------------------------------
# getdescriptorinfo: analyze and add checksum to descriptor
# ---------------------------------------------------------------------------


def getdescriptorinfo(desc_str: str) -> dict:
    """
    Analyze a descriptor string and return information about it.

    This is equivalent to Bitcoin Core's ``getdescriptorinfo`` RPC.

    Args:
        desc_str: Descriptor string (with or without checksum)

    Returns:
        Dict containing:
        - descriptor: The descriptor with checksum added
        - checksum: The 8-character checksum
        - isrange: Whether the descriptor uses wildcards
        - issolvable: Whether we can sign for this descriptor
        - hasprivatekeys: Whether private keys are present

    Reference: Bitcoin Core rpc/misc.cpp getdescriptorinfo
    """
    # Strip existing checksum for parsing
    if "#" in desc_str:
        body = desc_str.split("#")[0]
    else:
        body = desc_str

    # Parse to validate and extract info
    descriptor = parse_descriptor(body)

    # Compute checksum
    checksum = descriptor_checksum(body)
    canonical = f"{body}#{checksum}"

    # Check if any keys are private
    has_private = any(k.is_private for k in descriptor.keys)

    # Check if solvable (we have key material)
    # addr() and raw() are not solvable (no signing info)
    is_solvable = descriptor.descriptor_type not in ("addr", "raw")

    return {
        "descriptor": canonical,
        "checksum": checksum,
        "isrange": descriptor.is_range,
        "issolvable": is_solvable,
        "hasprivatekeys": has_private,
    }


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

    def to_dict(self) -> dict:
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
    def from_dict(cls, d: dict) -> DescriptorEntry:
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
