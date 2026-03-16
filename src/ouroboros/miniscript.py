"""
Miniscript: a structured representation of Bitcoin Script for analysis and composition.

Miniscript enables:
  - Parsing miniscript expressions into an AST
  - Compiling miniscript to Bitcoin Script
  - Type checking (B, V, K, W with modifiers z, o, n, d, u, e, f, s, m, x)
  - Computing witness size for fee estimation
  - Constructing witnesses for satisfaction

Fragments:
  Basic:
    - pk_k(KEY)      — push pubkey
    - pk_h(KEY)      — OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY
    - older(n)       — <n> OP_CHECKSEQUENCEVERIFY
    - after(n)       — <n> OP_CHECKLOCKTIMEVERIFY
    - sha256(h)      — OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <h> OP_EQUAL
    - hash256(h)     — OP_SIZE 32 OP_EQUALVERIFY OP_HASH256 <h> OP_EQUAL
    - ripemd160(h)   — OP_SIZE 32 OP_EQUALVERIFY OP_RIPEMD160 <h> OP_EQUAL
    - hash160(h)     — OP_SIZE 32 OP_EQUALVERIFY OP_HASH160 <h> OP_EQUAL

  Combinators:
    - and_v(X, Y)    — [X] [Y]
    - and_b(X, Y)    — [X] [Y] OP_BOOLAND
    - or_b(X, Y)     — [X] [Y] OP_BOOLOR
    - or_c(X, Y)     — [X] OP_NOTIF [Y] OP_ENDIF
    - or_d(X, Y)     — [X] OP_IFDUP OP_NOTIF [Y] OP_ENDIF
    - or_i(X, Y)     — OP_IF [X] OP_ELSE [Y] OP_ENDIF
    - andor(X, Y, Z) — [X] OP_NOTIF [Z] OP_ELSE [Y] OP_ENDIF
    - thresh(k, X1, X2, ...) — [X1] [X2] OP_ADD ... [k] OP_EQUAL

  Wrappers:
    - a: X           — OP_TOALTSTACK [X] OP_FROMALTSTACK
    - s: X           — OP_SWAP [X]
    - c: X           — [X] OP_CHECKSIG
    - d: X           — OP_DUP OP_IF [X] OP_ENDIF
    - v: X           — [X] OP_VERIFY (or -VERIFY version of last opcode)
    - j: X           — OP_SIZE OP_0NOTEQUAL OP_IF [X] OP_ENDIF
    - n: X           — [X] OP_0NOTEQUAL

  Multisig:
    - multi(k, key1, ...) — [k] [keys...] [n] OP_CHECKMULTISIG (P2WSH only)
    - multi_a(k, key1, ...) — [key1] OP_CHECKSIG ... OP_CHECKSIGADD [k] OP_NUMEQUAL (Tapscript only)

Syntactic sugar:
    - pk(KEY)        — c:pk_k(KEY)
    - pkh(KEY)       — c:pk_h(KEY)
    - and_n(X, Y)    — andor(X, Y, 0)
    - t: X           — and_v(X, 1)
    - l: X           — or_i(0, X)
    - u: X           — or_i(X, 0)

Reference: Bitcoin Core script/miniscript.h, BIP 379 (proposed)
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Fragment types
# ---------------------------------------------------------------------------


class Fragment(Enum):
    """Miniscript node types (fragments)."""
    # Terminal fragments
    JUST_0 = auto()      # OP_0
    JUST_1 = auto()      # OP_1
    PK_K = auto()        # [key]
    PK_H = auto()        # OP_DUP OP_HASH160 [keyhash] OP_EQUALVERIFY
    OLDER = auto()       # [n] OP_CHECKSEQUENCEVERIFY
    AFTER = auto()       # [n] OP_CHECKLOCKTIMEVERIFY
    SHA256 = auto()      # OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 [hash] OP_EQUAL
    HASH256 = auto()     # OP_SIZE 32 OP_EQUALVERIFY OP_HASH256 [hash] OP_EQUAL
    RIPEMD160 = auto()   # OP_SIZE 32 OP_EQUALVERIFY OP_RIPEMD160 [hash] OP_EQUAL
    HASH160 = auto()     # OP_SIZE 32 OP_EQUALVERIFY OP_HASH160 [hash] OP_EQUAL

    # Wrapper fragments
    WRAP_A = auto()      # OP_TOALTSTACK [X] OP_FROMALTSTACK
    WRAP_S = auto()      # OP_SWAP [X]
    WRAP_C = auto()      # [X] OP_CHECKSIG
    WRAP_D = auto()      # OP_DUP OP_IF [X] OP_ENDIF
    WRAP_V = auto()      # [X] OP_VERIFY
    WRAP_J = auto()      # OP_SIZE OP_0NOTEQUAL OP_IF [X] OP_ENDIF
    WRAP_N = auto()      # [X] OP_0NOTEQUAL

    # Combinator fragments
    AND_V = auto()       # [X] [Y]
    AND_B = auto()       # [X] [Y] OP_BOOLAND
    OR_B = auto()        # [X] [Y] OP_BOOLOR
    OR_C = auto()        # [X] OP_NOTIF [Y] OP_ENDIF
    OR_D = auto()        # [X] OP_IFDUP OP_NOTIF [Y] OP_ENDIF
    OR_I = auto()        # OP_IF [X] OP_ELSE [Y] OP_ENDIF
    ANDOR = auto()       # [X] OP_NOTIF [Z] OP_ELSE [Y] OP_ENDIF
    THRESH = auto()      # [X1] ([Xn] OP_ADD)* [k] OP_EQUAL

    # Multisig
    MULTI = auto()       # [k] [keys...] [n] OP_CHECKMULTISIG (P2WSH only)
    MULTI_A = auto()     # [key1] OP_CHECKSIG ... OP_CHECKSIGADD [k] OP_NUMEQUAL (Tapscript)


class MiniscriptContext(Enum):
    """Script execution context."""
    P2WSH = auto()
    TAPSCRIPT = auto()


# ---------------------------------------------------------------------------
# Type system
# ---------------------------------------------------------------------------


class MiniscriptType:
    """
    Miniscript type: base types (B, V, K, W) with modifiers.

    Base types:
      B - Base: pushes 0/1 on stack for dissatisfy/satisfy
      V - Verify: pushes nothing, cannot be dissatisfied
      K - Key: pushes a pubkey, becomes B with OP_CHECKSIG
      W - Wrapped: takes input from one below top of stack

    Modifiers:
      z - Zero-arg: consumes 0 stack elements
      o - One-arg: consumes 1 stack element
      n - Nonzero: satisfaction never needs zero on top
      d - Dissatisfiable: easy dissatisfaction exists
      u - Unit: satisfaction pushes exactly 1
      e - Expression: non-malleable dissatisfaction
      f - Forced: dissatisfaction requires signature
      s - Safe: satisfaction requires signature
      m - Nonmalleable: non-malleable satisfaction exists
      x - Expensive verify: last opcode isn't EQUAL/CHECKSIG/CHECKMULTISIG
      g - Relative time timelock (CSV with time flag)
      h - Relative height timelock (CSV without time flag)
      i - Absolute time timelock (CLTV with time flag)
      j - Absolute height timelock (CLTV without time flag)
      k - No timelock mixing
    """

    # Bit positions for properties
    _B = 1 << 0
    _V = 1 << 1
    _K = 1 << 2
    _W = 1 << 3
    _z = 1 << 4
    _o = 1 << 5
    _n = 1 << 6
    _d = 1 << 7
    _u = 1 << 8
    _e = 1 << 9
    _f = 1 << 10
    _s = 1 << 11
    _m = 1 << 12
    _x = 1 << 13
    _g = 1 << 14
    _h = 1 << 15
    _i = 1 << 16
    _j = 1 << 17
    _k = 1 << 18

    _CHAR_TO_BIT = {
        'B': _B, 'V': _V, 'K': _K, 'W': _W,
        'z': _z, 'o': _o, 'n': _n, 'd': _d, 'u': _u,
        'e': _e, 'f': _f, 's': _s, 'm': _m, 'x': _x,
        'g': _g, 'h': _h, 'i': _i, 'j': _j, 'k': _k,
    }

    def __init__(self, flags: int = 0):
        self._flags = flags

    @classmethod
    def from_str(cls, s: str) -> "MiniscriptType":
        """Create type from string like 'Bzonudems'."""
        flags = 0
        for ch in s:
            if ch in cls._CHAR_TO_BIT:
                flags |= cls._CHAR_TO_BIT[ch]
        return cls(flags)

    def __or__(self, other: "MiniscriptType") -> "MiniscriptType":
        """Union of properties."""
        return MiniscriptType(self._flags | other._flags)

    def __and__(self, other: "MiniscriptType") -> "MiniscriptType":
        """Intersection of properties."""
        return MiniscriptType(self._flags & other._flags)

    def __contains__(self, prop: str) -> bool:
        """Check if type has all properties in string."""
        for ch in prop:
            if ch in self._CHAR_TO_BIT:
                if not (self._flags & self._CHAR_TO_BIT[ch]):
                    return False
        return True

    def has(self, prop: str) -> bool:
        """Check if type has all properties in string."""
        return prop in self

    def has_any(self, prop: str) -> bool:
        """Check if type has any property in string."""
        for ch in prop:
            if ch in self._CHAR_TO_BIT:
                if self._flags & self._CHAR_TO_BIT[ch]:
                    return True
        return False

    def when(self, cond: bool) -> "MiniscriptType":
        """Return empty type if cond is False, else self."""
        return MiniscriptType(self._flags if cond else 0)

    @property
    def is_B(self) -> bool:
        return bool(self._flags & self._B)

    @property
    def is_V(self) -> bool:
        return bool(self._flags & self._V)

    @property
    def is_K(self) -> bool:
        return bool(self._flags & self._K)

    @property
    def is_W(self) -> bool:
        return bool(self._flags & self._W)

    @property
    def is_valid(self) -> bool:
        """Check if exactly one base type is set."""
        base_count = sum([self.is_B, self.is_V, self.is_K, self.is_W])
        return base_count == 1

    def __repr__(self) -> str:
        parts = []
        for ch, bit in sorted(self._CHAR_TO_BIT.items(), key=lambda x: x[1]):
            if self._flags & bit:
                parts.append(ch)
        return f"Type({''.join(parts)})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, MiniscriptType):
            return self._flags == other._flags
        return False

    def __hash__(self) -> int:
        return hash(self._flags)


# Convenience type constructors
def _mst(s: str) -> MiniscriptType:
    """Create a MiniscriptType from a string."""
    return MiniscriptType.from_str(s)


# ---------------------------------------------------------------------------
# Miniscript Node
# ---------------------------------------------------------------------------


@dataclass
class MiniscriptNode:
    """A node in a miniscript expression tree."""
    fragment: Fragment
    subs: List["MiniscriptNode"] = field(default_factory=list)
    keys: List[bytes] = field(default_factory=list)  # Compressed pubkeys
    data: bytes = b""  # Hash preimages
    k: int = 0  # Threshold or timelock value
    _type: Optional[MiniscriptType] = field(default=None, repr=False)
    _ctx: MiniscriptContext = MiniscriptContext.P2WSH

    def get_type(self) -> MiniscriptType:
        """Compute and return the type of this node."""
        if self._type is not None:
            return self._type
        self._type = self._compute_type()
        return self._type

    def _compute_type(self) -> MiniscriptType:
        """Compute the type based on the fragment and subexpressions."""
        ctx = self._ctx
        is_tapscript = ctx == MiniscriptContext.TAPSCRIPT

        # Get types of subexpressions
        x = self.subs[0].get_type() if len(self.subs) > 0 else _mst("")
        y = self.subs[1].get_type() if len(self.subs) > 1 else _mst("")
        z = self.subs[2].get_type() if len(self.subs) > 2 else _mst("")

        # LOCKTIME_THRESHOLD = 500000000
        LOCKTIME_THRESHOLD = 500000000
        # Sequence time flag
        SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22

        frag = self.fragment

        if frag == Fragment.PK_K:
            return _mst("Konudemsxk")
        elif frag == Fragment.PK_H:
            return _mst("Knudemsxk")
        elif frag == Fragment.OLDER:
            time_flag = _mst("g").when(bool(self.k & SEQUENCE_LOCKTIME_TYPE_FLAG))
            height_flag = _mst("h").when(not bool(self.k & SEQUENCE_LOCKTIME_TYPE_FLAG))
            return time_flag | height_flag | _mst("Bzfmxk")
        elif frag == Fragment.AFTER:
            time_flag = _mst("i").when(self.k >= LOCKTIME_THRESHOLD)
            height_flag = _mst("j").when(self.k < LOCKTIME_THRESHOLD)
            return time_flag | height_flag | _mst("Bzfmxk")
        elif frag in (Fragment.SHA256, Fragment.RIPEMD160, Fragment.HASH256, Fragment.HASH160):
            return _mst("Bonudmk")
        elif frag == Fragment.JUST_1:
            return _mst("Bzufmxk")
        elif frag == Fragment.JUST_0:
            return _mst("Bzudemsxk")
        elif frag == Fragment.WRAP_A:
            return (
                _mst("W").when("B" in x) |
                (x & _mst("ghijk")) |
                (x & _mst("udfems")) |
                _mst("x")
            )
        elif frag == Fragment.WRAP_S:
            return (
                _mst("W").when("B" in x and "o" in x) |
                (x & _mst("ghijk")) |
                (x & _mst("udfemsx"))
            )
        elif frag == Fragment.WRAP_C:
            return (
                _mst("B").when("K" in x) |
                (x & _mst("ghijk")) |
                (x & _mst("ondfem")) |
                _mst("us")
            )
        elif frag == Fragment.WRAP_D:
            return (
                _mst("B").when("V" in x and "z" in x) |
                _mst("o").when("z" in x) |
                _mst("e").when("f" in x) |
                (x & _mst("ghijk")) |
                (x & _mst("ms")) |
                _mst("u").when(is_tapscript) |
                _mst("ndx")
            )
        elif frag == Fragment.WRAP_V:
            return (
                _mst("V").when("B" in x) |
                (x & _mst("ghijk")) |
                (x & _mst("zonms")) |
                _mst("fx")
            )
        elif frag == Fragment.WRAP_J:
            return (
                _mst("B").when("B" in x and "n" in x) |
                _mst("e").when("f" in x) |
                (x & _mst("ghijk")) |
                (x & _mst("oums")) |
                _mst("ndx")
            )
        elif frag == Fragment.WRAP_N:
            return (
                (x & _mst("ghijk")) |
                (x & _mst("Bzondfems")) |
                _mst("ux")
            )
        elif frag == Fragment.AND_V:
            return (
                (y & _mst("KVB")).when("V" in x) |
                (x & _mst("n")) | (y & _mst("n")).when("z" in x) |
                ((x | y) & _mst("o")).when("z" in x or "z" in y) |
                (x & y & _mst("mz")) |
                ((x | y) & _mst("s")) |
                _mst("f").when("f" in y or "s" in x) |
                (y & _mst("ux")) |
                ((x | y) & _mst("ghij")) |
                _mst("k").when(
                    "k" in x and "k" in y and not (
                        ("g" in x and "h" in y) or ("h" in x and "g" in y) or
                        ("i" in x and "j" in y) or ("j" in x and "i" in y)
                    )
                )
            )
        elif frag == Fragment.AND_B:
            return (
                (x & _mst("B")).when("W" in y) |
                ((x | y) & _mst("o")).when("z" in x or "z" in y) |
                (x & _mst("n")) | (y & _mst("n")).when("z" in x) |
                (x & y & _mst("e")).when("s" in x and "s" in y) |
                (x & y & _mst("dzm")) |
                _mst("f").when(("f" in x and "f" in y) or ("s" in x and "f" in x) or ("s" in y and "f" in y)) |
                ((x | y) & _mst("s")) |
                _mst("ux") |
                ((x | y) & _mst("ghij")) |
                _mst("k").when(
                    "k" in x and "k" in y and not (
                        ("g" in x and "h" in y) or ("h" in x and "g" in y) or
                        ("i" in x and "j" in y) or ("j" in x and "i" in y)
                    )
                )
            )
        elif frag == Fragment.OR_B:
            return (
                _mst("B").when("B" in x and "d" in x and "W" in y and "d" in y) |
                ((x | y) & _mst("o")).when("z" in x or "z" in y) |
                (x & y & _mst("m")).when(("s" in x or "s" in y) and "e" in x and "e" in y) |
                (x & y & _mst("zse")) |
                _mst("dux") |
                ((x | y) & _mst("ghij")) |
                (x & y & _mst("k"))
            )
        elif frag == Fragment.OR_D:
            return (
                (y & _mst("B")).when("B" in x and "d" in x and "u" in x) |
                (x & _mst("o")).when("z" in y) |
                (x & y & _mst("m")).when("e" in x and ("s" in x or "s" in y)) |
                (x & y & _mst("zs")) |
                (y & _mst("ufde")) |
                _mst("x") |
                ((x | y) & _mst("ghij")) |
                (x & y & _mst("k"))
            )
        elif frag == Fragment.OR_C:
            return (
                (y & _mst("V")).when("B" in x and "d" in x and "u" in x) |
                (x & _mst("o")).when("z" in y) |
                (x & y & _mst("m")).when("e" in x and ("s" in x or "s" in y)) |
                (x & y & _mst("zs")) |
                _mst("fx") |
                ((x | y) & _mst("ghij")) |
                (x & y & _mst("k"))
            )
        elif frag == Fragment.OR_I:
            return (
                (x & y & _mst("VBKufs")) |
                _mst("o").when("z" in x and "z" in y) |
                ((x | y) & _mst("e")).when("f" in x or "f" in y) |
                (x & y & _mst("m")).when("s" in x or "s" in y) |
                ((x | y) & _mst("d")) |
                _mst("x") |
                ((x | y) & _mst("ghij")) |
                (x & y & _mst("k"))
            )
        elif frag == Fragment.ANDOR:
            return (
                (y & z & _mst("BKV")).when("B" in x and "d" in x and "u" in x) |
                (x & y & z & _mst("z")) |
                ((x | (y & z)) & _mst("o")).when("z" in x or ("z" in y and "z" in z)) |
                (y & z & _mst("u")) |
                (z & _mst("f")).when("s" in x or "f" in y) |
                (z & _mst("d")) |
                (z & _mst("e")).when("s" in x or "f" in y) |
                (x & y & z & _mst("m")).when("e" in x and ("s" in x or "s" in y or "s" in z)) |
                (z & (x | y) & _mst("s")) |
                _mst("x") |
                ((x | y | z) & _mst("ghij")) |
                _mst("k").when(
                    "k" in x and "k" in y and "k" in z and not (
                        ("g" in x and "h" in y) or ("h" in x and "g" in y) or
                        ("i" in x and "j" in y) or ("j" in x and "i" in y)
                    )
                )
            )
        elif frag == Fragment.MULTI:
            return _mst("Bnudemsk")
        elif frag == Fragment.MULTI_A:
            return _mst("Budemsk")
        elif frag == Fragment.THRESH:
            # Complex type computation for thresh
            all_e = True
            all_m = True
            num_s = 0
            args = 0
            has_k = True
            acc_g = False
            acc_h = False
            acc_i = False
            acc_j = False

            for i, sub in enumerate(self.subs):
                t = sub.get_type()
                expected = "Bdu" if i == 0 else "Wdu"
                if not all(c in t for c in expected):
                    return _mst("")  # Invalid
                if "e" not in t:
                    all_e = False
                if "m" not in t:
                    all_m = False
                if "s" in t:
                    num_s += 1
                if "z" in t:
                    args += 0
                elif "o" in t:
                    args += 1
                else:
                    args += 2

                # Timelock conflict detection
                if "g" in t:
                    if acc_h and self.k > 1:
                        has_k = False
                    acc_g = True
                if "h" in t:
                    if acc_g and self.k > 1:
                        has_k = False
                    acc_h = True
                if "i" in t:
                    if acc_j and self.k > 1:
                        has_k = False
                    acc_i = True
                if "j" in t:
                    if acc_i and self.k > 1:
                        has_k = False
                    acc_j = True
                if "k" not in t:
                    has_k = False

            result = _mst("Bdu")
            if args == 0:
                result = result | _mst("z")
            elif args == 1:
                result = result | _mst("o")
            if all_e and num_s == len(self.subs):
                result = result | _mst("e")
            if all_e and all_m and num_s >= len(self.subs) - self.k:
                result = result | _mst("m")
            if num_s >= len(self.subs) - self.k + 1:
                result = result | _mst("s")
            if acc_g:
                result = result | _mst("g")
            if acc_h:
                result = result | _mst("h")
            if acc_i:
                result = result | _mst("i")
            if acc_j:
                result = result | _mst("j")
            if has_k:
                result = result | _mst("k")
            return result

        return _mst("")  # Unknown fragment

    def is_valid_type(self) -> bool:
        """Check if this node has a valid type."""
        return self.get_type().is_valid

    def to_script(self) -> bytes:
        """Compile this miniscript to Bitcoin Script."""
        return compile_miniscript(self, self._ctx)

    def __repr__(self) -> str:
        return f"MiniscriptNode({self.fragment.name})"


# ---------------------------------------------------------------------------
# Script compilation
# ---------------------------------------------------------------------------


def _push_int(n: int) -> bytes:
    """Encode an integer as a minimally-encoded script number push."""
    if n == 0:
        return b"\x00"  # OP_0
    elif 1 <= n <= 16:
        return bytes([0x50 + n])  # OP_1 through OP_16
    elif n == -1:
        return bytes([0x4f])  # OP_1NEGATE
    else:
        # CScriptNum encoding
        neg = n < 0
        abs_n = abs(n)
        result = []
        while abs_n:
            result.append(abs_n & 0xff)
            abs_n >>= 8
        if result[-1] & 0x80:
            result.append(0x80 if neg else 0x00)
        elif neg:
            result[-1] |= 0x80
        data = bytes(result)
        if len(data) == 1:
            return bytes([len(data)]) + data
        elif len(data) <= 75:
            return bytes([len(data)]) + data
        else:
            # For larger numbers
            return bytes([0x4c, len(data)]) + data


def _push_data(data: bytes) -> bytes:
    """Push data onto the stack."""
    if len(data) == 0:
        return b"\x00"  # OP_0
    elif len(data) <= 75:
        return bytes([len(data)]) + data
    elif len(data) <= 255:
        return bytes([0x4c, len(data)]) + data  # OP_PUSHDATA1
    elif len(data) <= 65535:
        return bytes([0x4d]) + len(data).to_bytes(2, "little") + data  # OP_PUSHDATA2
    else:
        return bytes([0x4e]) + len(data).to_bytes(4, "little") + data  # OP_PUSHDATA4


# Opcodes
OP_0 = 0x00
OP_1 = 0x51
OP_16 = 0x60
OP_DUP = 0x76
OP_SWAP = 0x7c
OP_TOALTSTACK = 0x6b
OP_FROMALTSTACK = 0x6c
OP_IF = 0x63
OP_NOTIF = 0x64
OP_ELSE = 0x67
OP_ENDIF = 0x68
OP_VERIFY = 0x69
OP_IFDUP = 0x73
OP_SIZE = 0x82
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_0NOTEQUAL = 0x92
OP_ADD = 0x93
OP_NUMEQUAL = 0x9c
OP_NUMEQUALVERIFY = 0x9d
OP_BOOLAND = 0x9a
OP_BOOLOR = 0x9b
OP_SHA256 = 0xa8
OP_HASH160 = 0xa9
OP_HASH256 = 0xaa
OP_RIPEMD160 = 0xa6
OP_CHECKSIG = 0xac
OP_CHECKSIGVERIFY = 0xad
OP_CHECKMULTISIG = 0xae
OP_CHECKMULTISIGVERIFY = 0xaf
OP_CHECKLOCKTIMEVERIFY = 0xb1
OP_CHECKSEQUENCEVERIFY = 0xb2
OP_CHECKSIGADD = 0xba


def compile_miniscript(node: MiniscriptNode, ctx: MiniscriptContext = MiniscriptContext.P2WSH, verify: bool = False) -> bytes:
    """
    Compile a miniscript AST to Bitcoin Script.

    Args:
        node: The miniscript node to compile
        ctx: Script context (P2WSH or TAPSCRIPT)
        verify: Whether the result is followed by OP_VERIFY

    Returns:
        The compiled Bitcoin Script as bytes
    """
    is_tapscript = ctx == MiniscriptContext.TAPSCRIPT
    frag = node.fragment

    # Determine verify status for children
    def child_verify(idx: int) -> bool:
        if frag == Fragment.WRAP_V:
            return True
        if frag == Fragment.WRAP_S and idx == 0:
            return verify
        if frag == Fragment.AND_V and idx == 1:
            return verify
        return False

    # Compile children
    subs = [compile_miniscript(sub, ctx, child_verify(i)) for i, sub in enumerate(node.subs)]

    if frag == Fragment.PK_K:
        return _push_data(node.keys[0])

    elif frag == Fragment.PK_H:
        keyhash = hashlib.new("ripemd160", hashlib.sha256(node.keys[0]).digest()).digest()
        return bytes([OP_DUP, OP_HASH160]) + _push_data(keyhash) + bytes([OP_EQUALVERIFY])

    elif frag == Fragment.OLDER:
        return _push_int(node.k) + bytes([OP_CHECKSEQUENCEVERIFY])

    elif frag == Fragment.AFTER:
        return _push_int(node.k) + bytes([OP_CHECKLOCKTIMEVERIFY])

    elif frag == Fragment.SHA256:
        eq_op = OP_EQUALVERIFY if verify else OP_EQUAL
        return bytes([OP_SIZE]) + _push_int(32) + bytes([OP_EQUALVERIFY, OP_SHA256]) + _push_data(node.data) + bytes([eq_op])

    elif frag == Fragment.HASH256:
        eq_op = OP_EQUALVERIFY if verify else OP_EQUAL
        return bytes([OP_SIZE]) + _push_int(32) + bytes([OP_EQUALVERIFY, OP_HASH256]) + _push_data(node.data) + bytes([eq_op])

    elif frag == Fragment.RIPEMD160:
        eq_op = OP_EQUALVERIFY if verify else OP_EQUAL
        return bytes([OP_SIZE]) + _push_int(32) + bytes([OP_EQUALVERIFY, OP_RIPEMD160]) + _push_data(node.data) + bytes([eq_op])

    elif frag == Fragment.HASH160:
        eq_op = OP_EQUALVERIFY if verify else OP_EQUAL
        return bytes([OP_SIZE]) + _push_int(32) + bytes([OP_EQUALVERIFY, OP_HASH160]) + _push_data(node.data) + bytes([eq_op])

    elif frag == Fragment.JUST_0:
        return bytes([OP_0])

    elif frag == Fragment.JUST_1:
        return bytes([OP_1])

    elif frag == Fragment.WRAP_A:
        return bytes([OP_TOALTSTACK]) + subs[0] + bytes([OP_FROMALTSTACK])

    elif frag == Fragment.WRAP_S:
        return bytes([OP_SWAP]) + subs[0]

    elif frag == Fragment.WRAP_C:
        checksig_op = OP_CHECKSIGVERIFY if verify else OP_CHECKSIG
        return subs[0] + bytes([checksig_op])

    elif frag == Fragment.WRAP_D:
        return bytes([OP_DUP, OP_IF]) + subs[0] + bytes([OP_ENDIF])

    elif frag == Fragment.WRAP_V:
        # Check if last opcode can be converted to VERIFY form
        sub_type = node.subs[0].get_type()
        if "x" in sub_type:
            # Expensive verify: needs explicit OP_VERIFY
            return subs[0] + bytes([OP_VERIFY])
        else:
            # Last opcode already has VERIFY form, sub was compiled with verify=True
            return subs[0]

    elif frag == Fragment.WRAP_J:
        return bytes([OP_SIZE, OP_0NOTEQUAL, OP_IF]) + subs[0] + bytes([OP_ENDIF])

    elif frag == Fragment.WRAP_N:
        return subs[0] + bytes([OP_0NOTEQUAL])

    elif frag == Fragment.AND_V:
        return subs[0] + subs[1]

    elif frag == Fragment.AND_B:
        return subs[0] + subs[1] + bytes([OP_BOOLAND])

    elif frag == Fragment.OR_B:
        return subs[0] + subs[1] + bytes([OP_BOOLOR])

    elif frag == Fragment.OR_C:
        return subs[0] + bytes([OP_NOTIF]) + subs[1] + bytes([OP_ENDIF])

    elif frag == Fragment.OR_D:
        return subs[0] + bytes([OP_IFDUP, OP_NOTIF]) + subs[1] + bytes([OP_ENDIF])

    elif frag == Fragment.OR_I:
        return bytes([OP_IF]) + subs[0] + bytes([OP_ELSE]) + subs[1] + bytes([OP_ENDIF])

    elif frag == Fragment.ANDOR:
        # [X] OP_NOTIF [Z] OP_ELSE [Y] OP_ENDIF
        return subs[0] + bytes([OP_NOTIF]) + subs[2] + bytes([OP_ELSE]) + subs[1] + bytes([OP_ENDIF])

    elif frag == Fragment.MULTI:
        # [k] [key1] [key2] ... [n] OP_CHECKMULTISIG
        assert not is_tapscript, "MULTI not allowed in Tapscript"
        script = _push_int(node.k)
        for key in node.keys:
            script += _push_data(key)
        script += _push_int(len(node.keys))
        script += bytes([OP_CHECKMULTISIGVERIFY if verify else OP_CHECKMULTISIG])
        return script

    elif frag == Fragment.MULTI_A:
        # [key1] OP_CHECKSIG [key2] OP_CHECKSIGADD ... [k] OP_NUMEQUAL
        assert is_tapscript, "MULTI_A only allowed in Tapscript"
        script = _push_data(node.keys[0]) + bytes([OP_CHECKSIG])
        for key in node.keys[1:]:
            script += _push_data(key) + bytes([OP_CHECKSIGADD])
        script += _push_int(node.k)
        script += bytes([OP_NUMEQUALVERIFY if verify else OP_NUMEQUAL])
        return script

    elif frag == Fragment.THRESH:
        # [X1] [X2] OP_ADD [X3] OP_ADD ... [k] OP_EQUAL
        script = subs[0]
        for sub in subs[1:]:
            script += sub + bytes([OP_ADD])
        script += _push_int(node.k)
        script += bytes([OP_EQUALVERIFY if verify else OP_EQUAL])
        return script

    raise ValueError(f"Unknown fragment: {frag}")


# ---------------------------------------------------------------------------
# Miniscript parser
# ---------------------------------------------------------------------------


def parse_miniscript(expr: str, ctx: MiniscriptContext = MiniscriptContext.P2WSH, key_parser: Optional[Callable[[str], bytes]] = None) -> MiniscriptNode:
    """
    Parse a miniscript expression string into a MiniscriptNode.

    Args:
        expr: The miniscript expression (e.g., "and_v(pk(KEY),older(1000))")
        ctx: Script context (P2WSH or TAPSCRIPT)
        key_parser: Optional function to parse key strings into pubkey bytes.
                    If None, keys are expected to be hex-encoded compressed pubkeys.

    Returns:
        The parsed MiniscriptNode
    """
    if key_parser is None:
        def key_parser(s: str) -> bytes:
            s = s.strip()
            if len(s) == 66:
                return bytes.fromhex(s)
            raise ValueError(f"Invalid key: {s}")

    expr = expr.strip()

    return _parse_miniscript_inner(expr, ctx, key_parser)


def _parse_miniscript_inner(expr: str, ctx: MiniscriptContext, key_parser: Callable[[str], bytes]) -> MiniscriptNode:
    """Internal recursive parser."""
    expr = expr.strip()

    # Handle wrappers (single-char prefixes): a:, s:, c:, d:, v:, j:, n:, t:, l:, u:
    wrappers = []
    while len(expr) > 1 and expr[1] == ':':
        wrapper = expr[0]
        if wrapper in "ascdvjn":
            wrappers.append(wrapper)
            expr = expr[2:]
        elif wrapper == 't':
            # t:X is and_v(X, 1)
            wrappers.append('t')
            expr = expr[2:]
        elif wrapper == 'l':
            # l:X is or_i(0, X)
            wrappers.append('l')
            expr = expr[2:]
        elif wrapper == 'u':
            # u:X is or_i(X, 0)
            wrappers.append('u')
            expr = expr[2:]
        else:
            break

    # Parse the core expression
    node = _parse_core_expr(expr, ctx, key_parser)

    # Apply wrappers in reverse order
    for wrapper in reversed(wrappers):
        if wrapper == 'a':
            node = MiniscriptNode(Fragment.WRAP_A, subs=[node], _ctx=ctx)
        elif wrapper == 's':
            node = MiniscriptNode(Fragment.WRAP_S, subs=[node], _ctx=ctx)
        elif wrapper == 'c':
            node = MiniscriptNode(Fragment.WRAP_C, subs=[node], _ctx=ctx)
        elif wrapper == 'd':
            node = MiniscriptNode(Fragment.WRAP_D, subs=[node], _ctx=ctx)
        elif wrapper == 'v':
            node = MiniscriptNode(Fragment.WRAP_V, subs=[node], _ctx=ctx)
        elif wrapper == 'j':
            node = MiniscriptNode(Fragment.WRAP_J, subs=[node], _ctx=ctx)
        elif wrapper == 'n':
            node = MiniscriptNode(Fragment.WRAP_N, subs=[node], _ctx=ctx)
        elif wrapper == 't':
            # t:X = and_v(X, 1)
            one = MiniscriptNode(Fragment.JUST_1, _ctx=ctx)
            node = MiniscriptNode(Fragment.AND_V, subs=[node, one], _ctx=ctx)
        elif wrapper == 'l':
            # l:X = or_i(0, X)
            zero = MiniscriptNode(Fragment.JUST_0, _ctx=ctx)
            node = MiniscriptNode(Fragment.OR_I, subs=[zero, node], _ctx=ctx)
        elif wrapper == 'u':
            # u:X = or_i(X, 0)
            zero = MiniscriptNode(Fragment.JUST_0, _ctx=ctx)
            node = MiniscriptNode(Fragment.OR_I, subs=[node, zero], _ctx=ctx)

    return node


def _parse_core_expr(expr: str, ctx: MiniscriptContext, key_parser: Callable[[str], bytes]) -> MiniscriptNode:
    """Parse a core miniscript expression (without wrappers)."""

    # Constants
    if expr == "0":
        return MiniscriptNode(Fragment.JUST_0, _ctx=ctx)
    if expr == "1":
        return MiniscriptNode(Fragment.JUST_1, _ctx=ctx)

    # Find the function name and arguments
    paren_idx = expr.find('(')
    if paren_idx == -1:
        raise ValueError(f"Invalid miniscript expression: {expr}")

    name = expr[:paren_idx]

    # Find matching close paren
    close_idx = _find_matching_paren(expr, paren_idx)
    if close_idx != len(expr) - 1:
        raise ValueError(f"Unexpected characters after expression: {expr}")

    args_str = expr[paren_idx + 1:close_idx]

    # Parse based on function name
    is_tapscript = ctx == MiniscriptContext.TAPSCRIPT

    if name == "pk_k":
        key = key_parser(args_str)
        return MiniscriptNode(Fragment.PK_K, keys=[key], _ctx=ctx)

    elif name == "pk_h":
        key = key_parser(args_str)
        return MiniscriptNode(Fragment.PK_H, keys=[key], _ctx=ctx)

    elif name == "pk":
        # pk(K) is syntactic sugar for c:pk_k(K)
        key = key_parser(args_str)
        inner = MiniscriptNode(Fragment.PK_K, keys=[key], _ctx=ctx)
        return MiniscriptNode(Fragment.WRAP_C, subs=[inner], _ctx=ctx)

    elif name == "pkh":
        # pkh(K) is syntactic sugar for c:pk_h(K)
        key = key_parser(args_str)
        inner = MiniscriptNode(Fragment.PK_H, keys=[key], _ctx=ctx)
        return MiniscriptNode(Fragment.WRAP_C, subs=[inner], _ctx=ctx)

    elif name == "older":
        n = int(args_str.strip())
        if n < 1 or n >= 0x80000000:
            raise ValueError(f"Invalid older value: {n}")
        return MiniscriptNode(Fragment.OLDER, k=n, _ctx=ctx)

    elif name == "after":
        n = int(args_str.strip())
        if n < 1 or n >= 0x80000000:
            raise ValueError(f"Invalid after value: {n}")
        return MiniscriptNode(Fragment.AFTER, k=n, _ctx=ctx)

    elif name == "sha256":
        h = bytes.fromhex(args_str.strip())
        if len(h) != 32:
            raise ValueError(f"sha256 requires 32-byte hash, got {len(h)}")
        return MiniscriptNode(Fragment.SHA256, data=h, _ctx=ctx)

    elif name == "hash256":
        h = bytes.fromhex(args_str.strip())
        if len(h) != 32:
            raise ValueError(f"hash256 requires 32-byte hash, got {len(h)}")
        return MiniscriptNode(Fragment.HASH256, data=h, _ctx=ctx)

    elif name == "ripemd160":
        h = bytes.fromhex(args_str.strip())
        if len(h) != 20:
            raise ValueError(f"ripemd160 requires 20-byte hash, got {len(h)}")
        return MiniscriptNode(Fragment.RIPEMD160, data=h, _ctx=ctx)

    elif name == "hash160":
        h = bytes.fromhex(args_str.strip())
        if len(h) != 20:
            raise ValueError(f"hash160 requires 20-byte hash, got {len(h)}")
        return MiniscriptNode(Fragment.HASH160, data=h, _ctx=ctx)

    elif name == "and_v":
        args = _split_args(args_str)
        if len(args) != 2:
            raise ValueError(f"and_v requires 2 arguments, got {len(args)}")
        x = _parse_miniscript_inner(args[0], ctx, key_parser)
        y = _parse_miniscript_inner(args[1], ctx, key_parser)
        return MiniscriptNode(Fragment.AND_V, subs=[x, y], _ctx=ctx)

    elif name == "and_b":
        args = _split_args(args_str)
        if len(args) != 2:
            raise ValueError(f"and_b requires 2 arguments, got {len(args)}")
        x = _parse_miniscript_inner(args[0], ctx, key_parser)
        y = _parse_miniscript_inner(args[1], ctx, key_parser)
        return MiniscriptNode(Fragment.AND_B, subs=[x, y], _ctx=ctx)

    elif name == "and_n":
        # and_n(X, Y) is syntactic sugar for andor(X, Y, 0)
        args = _split_args(args_str)
        if len(args) != 2:
            raise ValueError(f"and_n requires 2 arguments, got {len(args)}")
        x = _parse_miniscript_inner(args[0], ctx, key_parser)
        y = _parse_miniscript_inner(args[1], ctx, key_parser)
        z = MiniscriptNode(Fragment.JUST_0, _ctx=ctx)
        return MiniscriptNode(Fragment.ANDOR, subs=[x, y, z], _ctx=ctx)

    elif name == "or_b":
        args = _split_args(args_str)
        if len(args) != 2:
            raise ValueError(f"or_b requires 2 arguments, got {len(args)}")
        x = _parse_miniscript_inner(args[0], ctx, key_parser)
        y = _parse_miniscript_inner(args[1], ctx, key_parser)
        return MiniscriptNode(Fragment.OR_B, subs=[x, y], _ctx=ctx)

    elif name == "or_c":
        args = _split_args(args_str)
        if len(args) != 2:
            raise ValueError(f"or_c requires 2 arguments, got {len(args)}")
        x = _parse_miniscript_inner(args[0], ctx, key_parser)
        y = _parse_miniscript_inner(args[1], ctx, key_parser)
        return MiniscriptNode(Fragment.OR_C, subs=[x, y], _ctx=ctx)

    elif name == "or_d":
        args = _split_args(args_str)
        if len(args) != 2:
            raise ValueError(f"or_d requires 2 arguments, got {len(args)}")
        x = _parse_miniscript_inner(args[0], ctx, key_parser)
        y = _parse_miniscript_inner(args[1], ctx, key_parser)
        return MiniscriptNode(Fragment.OR_D, subs=[x, y], _ctx=ctx)

    elif name == "or_i":
        args = _split_args(args_str)
        if len(args) != 2:
            raise ValueError(f"or_i requires 2 arguments, got {len(args)}")
        x = _parse_miniscript_inner(args[0], ctx, key_parser)
        y = _parse_miniscript_inner(args[1], ctx, key_parser)
        return MiniscriptNode(Fragment.OR_I, subs=[x, y], _ctx=ctx)

    elif name == "andor":
        args = _split_args(args_str)
        if len(args) != 3:
            raise ValueError(f"andor requires 3 arguments, got {len(args)}")
        x = _parse_miniscript_inner(args[0], ctx, key_parser)
        y = _parse_miniscript_inner(args[1], ctx, key_parser)
        z = _parse_miniscript_inner(args[2], ctx, key_parser)
        return MiniscriptNode(Fragment.ANDOR, subs=[x, y, z], _ctx=ctx)

    elif name == "thresh":
        args = _split_args(args_str)
        if len(args) < 2:
            raise ValueError(f"thresh requires at least 2 arguments")
        k = int(args[0].strip())
        subs = [_parse_miniscript_inner(arg, ctx, key_parser) for arg in args[1:]]
        if k < 1 or k > len(subs):
            raise ValueError(f"Invalid thresh k={k} for {len(subs)} subexpressions")
        return MiniscriptNode(Fragment.THRESH, subs=subs, k=k, _ctx=ctx)

    elif name == "multi":
        if is_tapscript:
            raise ValueError("multi() not allowed in Tapscript, use multi_a()")
        args = _split_args(args_str)
        if len(args) < 2:
            raise ValueError(f"multi requires at least 2 arguments")
        k = int(args[0].strip())
        keys = [key_parser(arg) for arg in args[1:]]
        if k < 1 or k > len(keys):
            raise ValueError(f"Invalid multi k={k} for {len(keys)} keys")
        if len(keys) > 20:
            raise ValueError(f"multi supports at most 20 keys, got {len(keys)}")
        return MiniscriptNode(Fragment.MULTI, keys=keys, k=k, _ctx=ctx)

    elif name == "multi_a":
        if not is_tapscript:
            raise ValueError("multi_a() only allowed in Tapscript context")
        args = _split_args(args_str)
        if len(args) < 2:
            raise ValueError(f"multi_a requires at least 2 arguments")
        k = int(args[0].strip())
        keys = [key_parser(arg) for arg in args[1:]]
        if k < 1 or k > len(keys):
            raise ValueError(f"Invalid multi_a k={k} for {len(keys)} keys")
        return MiniscriptNode(Fragment.MULTI_A, keys=keys, k=k, _ctx=ctx)

    else:
        raise ValueError(f"Unknown miniscript fragment: {name}")


def _find_matching_paren(s: str, start: int) -> int:
    """Find the matching closing parenthesis."""
    if s[start] != '(':
        raise ValueError(f"Expected '(' at position {start}")
    depth = 0
    for i in range(start, len(s)):
        if s[i] == '(':
            depth += 1
        elif s[i] == ')':
            depth -= 1
            if depth == 0:
                return i
    raise ValueError("Unmatched parenthesis")


def _split_args(s: str) -> List[str]:
    """Split arguments at top-level commas."""
    args = []
    depth = 0
    current = []
    for ch in s:
        if ch == '(':
            depth += 1
            current.append(ch)
        elif ch == ')':
            depth -= 1
            current.append(ch)
        elif ch == ',' and depth == 0:
            args.append(''.join(current))
            current = []
        else:
            current.append(ch)
    if current:
        args.append(''.join(current))
    return [arg.strip() for arg in args]


# ---------------------------------------------------------------------------
# Witness size analysis
# ---------------------------------------------------------------------------


@dataclass
class SatisfactionInfo:
    """Information about satisfying a miniscript."""
    # Witness size in bytes (None if unsatisfiable)
    sat_size: Optional[int] = None
    # Dissatisfaction witness size (None if cannot be dissatisfied)
    dsat_size: Optional[int] = None
    # Whether satisfaction requires a signature
    has_sig: bool = False
    # Number of stack elements for satisfaction
    sat_stack: Optional[int] = None


def analyze_satisfaction(node: MiniscriptNode) -> SatisfactionInfo:
    """
    Analyze a miniscript to determine witness sizes for satisfaction.

    This computes the maximum witness size needed to satisfy the miniscript,
    which is useful for fee estimation.
    """
    ctx = node._ctx
    is_tapscript = ctx == MiniscriptContext.TAPSCRIPT

    # Signature sizes: Tapscript uses 65 bytes (Schnorr), P2WSH uses 72 bytes (ECDSA max)
    sig_size = 65 if is_tapscript else 72
    pubkey_size = 32 if is_tapscript else 33

    return _analyze_satisfaction_inner(node, sig_size, pubkey_size)


def _analyze_satisfaction_inner(node: MiniscriptNode, sig_size: int, pubkey_size: int) -> SatisfactionInfo:
    """Internal satisfaction analysis."""
    frag = node.fragment

    if frag == Fragment.JUST_0:
        return SatisfactionInfo(sat_size=None, dsat_size=0)

    elif frag == Fragment.JUST_1:
        return SatisfactionInfo(sat_size=0, dsat_size=None)

    elif frag == Fragment.PK_K:
        # Satisfaction: signature (sig_size + 1 for length)
        # Dissatisfaction: empty push (1 byte)
        return SatisfactionInfo(sat_size=1 + sig_size, dsat_size=1, has_sig=True, sat_stack=1)

    elif frag == Fragment.PK_H:
        # Satisfaction: signature + pubkey
        # Dissatisfaction: empty push + pubkey
        return SatisfactionInfo(
            sat_size=1 + sig_size + 1 + pubkey_size,
            dsat_size=1 + 1 + pubkey_size,
            has_sig=True,
            sat_stack=2
        )

    elif frag in (Fragment.OLDER, Fragment.AFTER):
        # No witness data needed, but cannot be dissatisfied
        return SatisfactionInfo(sat_size=0, dsat_size=None)

    elif frag in (Fragment.SHA256, Fragment.HASH256, Fragment.RIPEMD160, Fragment.HASH160):
        # Satisfaction: 32-byte preimage
        # Cannot be dissatisfied without signature
        return SatisfactionInfo(sat_size=1 + 32, dsat_size=None, sat_stack=1)

    elif frag == Fragment.WRAP_A:
        sub = _analyze_satisfaction_inner(node.subs[0], sig_size, pubkey_size)
        return sub

    elif frag == Fragment.WRAP_S:
        sub = _analyze_satisfaction_inner(node.subs[0], sig_size, pubkey_size)
        return sub

    elif frag == Fragment.WRAP_C:
        sub = _analyze_satisfaction_inner(node.subs[0], sig_size, pubkey_size)
        return sub

    elif frag == Fragment.WRAP_D:
        sub = _analyze_satisfaction_inner(node.subs[0], sig_size, pubkey_size)
        # Satisfaction: 1 (for the OP_IF element) + sub satisfaction
        # Dissatisfaction: 1 byte (empty push)
        sat = None if sub.sat_size is None else 1 + 1 + sub.sat_size
        return SatisfactionInfo(sat_size=sat, dsat_size=1, has_sig=sub.has_sig)

    elif frag == Fragment.WRAP_V:
        sub = _analyze_satisfaction_inner(node.subs[0], sig_size, pubkey_size)
        return SatisfactionInfo(sat_size=sub.sat_size, dsat_size=None, has_sig=sub.has_sig)

    elif frag == Fragment.WRAP_J:
        sub = _analyze_satisfaction_inner(node.subs[0], sig_size, pubkey_size)
        # Dissatisfaction: 1 byte (empty push)
        return SatisfactionInfo(sat_size=sub.sat_size, dsat_size=1, has_sig=sub.has_sig)

    elif frag == Fragment.WRAP_N:
        sub = _analyze_satisfaction_inner(node.subs[0], sig_size, pubkey_size)
        return sub

    elif frag == Fragment.AND_V:
        x = _analyze_satisfaction_inner(node.subs[0], sig_size, pubkey_size)
        y = _analyze_satisfaction_inner(node.subs[1], sig_size, pubkey_size)
        sat = None
        if x.sat_size is not None and y.sat_size is not None:
            sat = x.sat_size + y.sat_size
        return SatisfactionInfo(sat_size=sat, dsat_size=None, has_sig=x.has_sig or y.has_sig)

    elif frag == Fragment.AND_B:
        x = _analyze_satisfaction_inner(node.subs[0], sig_size, pubkey_size)
        y = _analyze_satisfaction_inner(node.subs[1], sig_size, pubkey_size)
        sat = None
        if x.sat_size is not None and y.sat_size is not None:
            sat = x.sat_size + y.sat_size
        dsat = None
        if x.dsat_size is not None and y.dsat_size is not None:
            dsat = x.dsat_size + y.dsat_size
        return SatisfactionInfo(sat_size=sat, dsat_size=dsat, has_sig=x.has_sig or y.has_sig)

    elif frag == Fragment.OR_B:
        x = _analyze_satisfaction_inner(node.subs[0], sig_size, pubkey_size)
        y = _analyze_satisfaction_inner(node.subs[1], sig_size, pubkey_size)
        # Can be satisfied by either branch
        sat_options = []
        if x.sat_size is not None and y.dsat_size is not None:
            sat_options.append(x.sat_size + y.dsat_size)
        if x.dsat_size is not None and y.sat_size is not None:
            sat_options.append(x.dsat_size + y.sat_size)
        sat = min(sat_options) if sat_options else None
        dsat = None
        if x.dsat_size is not None and y.dsat_size is not None:
            dsat = x.dsat_size + y.dsat_size
        return SatisfactionInfo(sat_size=sat, dsat_size=dsat, has_sig=x.has_sig or y.has_sig)

    elif frag == Fragment.OR_C:
        x = _analyze_satisfaction_inner(node.subs[0], sig_size, pubkey_size)
        y = _analyze_satisfaction_inner(node.subs[1], sig_size, pubkey_size)
        sat_options = []
        if x.sat_size is not None:
            sat_options.append(x.sat_size)
        if x.dsat_size is not None and y.sat_size is not None:
            sat_options.append(x.dsat_size + y.sat_size)
        sat = min(sat_options) if sat_options else None
        return SatisfactionInfo(sat_size=sat, dsat_size=None, has_sig=x.has_sig or y.has_sig)

    elif frag == Fragment.OR_D:
        x = _analyze_satisfaction_inner(node.subs[0], sig_size, pubkey_size)
        y = _analyze_satisfaction_inner(node.subs[1], sig_size, pubkey_size)
        sat_options = []
        if x.sat_size is not None:
            sat_options.append(x.sat_size)
        if x.dsat_size is not None and y.sat_size is not None:
            sat_options.append(x.dsat_size + y.sat_size)
        sat = min(sat_options) if sat_options else None
        dsat = None
        if x.dsat_size is not None and y.dsat_size is not None:
            dsat = x.dsat_size + y.dsat_size
        return SatisfactionInfo(sat_size=sat, dsat_size=dsat, has_sig=x.has_sig or y.has_sig)

    elif frag == Fragment.OR_I:
        x = _analyze_satisfaction_inner(node.subs[0], sig_size, pubkey_size)
        y = _analyze_satisfaction_inner(node.subs[1], sig_size, pubkey_size)
        sat_options = []
        if x.sat_size is not None:
            sat_options.append(x.sat_size + 1 + 1)  # + 1 for OP_IF selector
        if y.sat_size is not None:
            sat_options.append(y.sat_size + 1)  # + 1 for OP_IF selector
        sat = min(sat_options) if sat_options else None
        dsat_options = []
        if x.dsat_size is not None:
            dsat_options.append(x.dsat_size + 1 + 1)
        if y.dsat_size is not None:
            dsat_options.append(y.dsat_size + 1)
        dsat = min(dsat_options) if dsat_options else None
        return SatisfactionInfo(sat_size=sat, dsat_size=dsat, has_sig=x.has_sig or y.has_sig)

    elif frag == Fragment.ANDOR:
        x = _analyze_satisfaction_inner(node.subs[0], sig_size, pubkey_size)
        y = _analyze_satisfaction_inner(node.subs[1], sig_size, pubkey_size)
        z = _analyze_satisfaction_inner(node.subs[2], sig_size, pubkey_size)
        sat_options = []
        if x.sat_size is not None and y.sat_size is not None:
            sat_options.append(x.sat_size + y.sat_size)
        if x.dsat_size is not None and z.sat_size is not None:
            sat_options.append(x.dsat_size + z.sat_size)
        sat = min(sat_options) if sat_options else None
        dsat = None
        if x.dsat_size is not None and z.dsat_size is not None:
            dsat = x.dsat_size + z.dsat_size
        return SatisfactionInfo(
            sat_size=sat, dsat_size=dsat,
            has_sig=x.has_sig or y.has_sig or z.has_sig
        )

    elif frag == Fragment.MULTI:
        # k signatures + 1 dummy element (for CHECKMULTISIG bug)
        k = node.k
        sat = k * (1 + sig_size) + 1  # k signatures + dummy
        dsat = (k + 1) * 1  # k+1 empty pushes
        return SatisfactionInfo(sat_size=sat, dsat_size=dsat, has_sig=True, sat_stack=k + 1)

    elif frag == Fragment.MULTI_A:
        # k signatures + (n-k) empty pushes
        k = node.k
        n = len(node.keys)
        sat = k * (1 + sig_size) + (n - k) * 1
        dsat = n * 1  # n empty pushes
        return SatisfactionInfo(sat_size=sat, dsat_size=dsat, has_sig=True, sat_stack=n)

    elif frag == Fragment.THRESH:
        # Need exactly k satisfied, n-k dissatisfied
        k = node.k
        subs_info = [_analyze_satisfaction_inner(sub, sig_size, pubkey_size) for sub in node.subs]

        # Sort by satisfaction cost
        sats = [(s.sat_size, s.dsat_size, s.has_sig) for s in subs_info]

        # Compute satisfaction: k smallest satisfactions + (n-k) dissatisfactions
        sat_costs = sorted([s for s, d, h in sats if s is not None])
        dsat_costs = sorted([d for s, d, h in sats if d is not None])

        if len(sat_costs) >= k and len(dsat_costs) >= len(node.subs) - k:
            sat = sum(sat_costs[:k]) + sum(dsat_costs[:len(node.subs) - k])
        else:
            sat = None

        dsat = sum(dsat_costs) if len(dsat_costs) == len(node.subs) else None
        has_sig = any(s.has_sig for s in subs_info)

        return SatisfactionInfo(sat_size=sat, dsat_size=dsat, has_sig=has_sig)

    return SatisfactionInfo()


# ---------------------------------------------------------------------------
# Miniscript to string
# ---------------------------------------------------------------------------


def miniscript_to_str(node: MiniscriptNode) -> str:
    """Convert a MiniscriptNode back to miniscript string representation."""
    frag = node.fragment

    def key_to_str(key: bytes) -> str:
        return key.hex()

    if frag == Fragment.JUST_0:
        return "0"
    elif frag == Fragment.JUST_1:
        return "1"
    elif frag == Fragment.PK_K:
        return f"pk_k({key_to_str(node.keys[0])})"
    elif frag == Fragment.PK_H:
        return f"pk_h({key_to_str(node.keys[0])})"
    elif frag == Fragment.OLDER:
        return f"older({node.k})"
    elif frag == Fragment.AFTER:
        return f"after({node.k})"
    elif frag == Fragment.SHA256:
        return f"sha256({node.data.hex()})"
    elif frag == Fragment.HASH256:
        return f"hash256({node.data.hex()})"
    elif frag == Fragment.RIPEMD160:
        return f"ripemd160({node.data.hex()})"
    elif frag == Fragment.HASH160:
        return f"hash160({node.data.hex()})"
    elif frag == Fragment.WRAP_A:
        return f"a:{miniscript_to_str(node.subs[0])}"
    elif frag == Fragment.WRAP_S:
        return f"s:{miniscript_to_str(node.subs[0])}"
    elif frag == Fragment.WRAP_C:
        # Check for pk() and pkh() sugar
        inner = node.subs[0]
        if inner.fragment == Fragment.PK_K:
            return f"pk({key_to_str(inner.keys[0])})"
        elif inner.fragment == Fragment.PK_H:
            return f"pkh({key_to_str(inner.keys[0])})"
        return f"c:{miniscript_to_str(inner)}"
    elif frag == Fragment.WRAP_D:
        return f"d:{miniscript_to_str(node.subs[0])}"
    elif frag == Fragment.WRAP_V:
        return f"v:{miniscript_to_str(node.subs[0])}"
    elif frag == Fragment.WRAP_J:
        return f"j:{miniscript_to_str(node.subs[0])}"
    elif frag == Fragment.WRAP_N:
        return f"n:{miniscript_to_str(node.subs[0])}"
    elif frag == Fragment.AND_V:
        # Check for t:X sugar (and_v(X, 1))
        if node.subs[1].fragment == Fragment.JUST_1:
            return f"t:{miniscript_to_str(node.subs[0])}"
        return f"and_v({miniscript_to_str(node.subs[0])},{miniscript_to_str(node.subs[1])})"
    elif frag == Fragment.AND_B:
        return f"and_b({miniscript_to_str(node.subs[0])},{miniscript_to_str(node.subs[1])})"
    elif frag == Fragment.OR_B:
        return f"or_b({miniscript_to_str(node.subs[0])},{miniscript_to_str(node.subs[1])})"
    elif frag == Fragment.OR_C:
        return f"or_c({miniscript_to_str(node.subs[0])},{miniscript_to_str(node.subs[1])})"
    elif frag == Fragment.OR_D:
        return f"or_d({miniscript_to_str(node.subs[0])},{miniscript_to_str(node.subs[1])})"
    elif frag == Fragment.OR_I:
        # Check for l:X sugar (or_i(0, X))
        if node.subs[0].fragment == Fragment.JUST_0:
            return f"l:{miniscript_to_str(node.subs[1])}"
        # Check for u:X sugar (or_i(X, 0))
        if node.subs[1].fragment == Fragment.JUST_0:
            return f"u:{miniscript_to_str(node.subs[0])}"
        return f"or_i({miniscript_to_str(node.subs[0])},{miniscript_to_str(node.subs[1])})"
    elif frag == Fragment.ANDOR:
        # Check for and_n(X, Y) sugar (andor(X, Y, 0))
        if node.subs[2].fragment == Fragment.JUST_0:
            return f"and_n({miniscript_to_str(node.subs[0])},{miniscript_to_str(node.subs[1])})"
        return f"andor({miniscript_to_str(node.subs[0])},{miniscript_to_str(node.subs[1])},{miniscript_to_str(node.subs[2])})"
    elif frag == Fragment.MULTI:
        keys_str = ",".join(key_to_str(k) for k in node.keys)
        return f"multi({node.k},{keys_str})"
    elif frag == Fragment.MULTI_A:
        keys_str = ",".join(key_to_str(k) for k in node.keys)
        return f"multi_a({node.k},{keys_str})"
    elif frag == Fragment.THRESH:
        subs_str = ",".join(miniscript_to_str(s) for s in node.subs)
        return f"thresh({node.k},{subs_str})"

    raise ValueError(f"Unknown fragment: {frag}")
