"""Tapscript IF nesting must cost linear work (Core's O(1) ConditionStack).

Before this fix ``ScriptInterpreter._execute_script`` evaluated
``executing = not exec_stack or all(exec_stack)`` for every opcode. Tapscript
has no opcode limit and no script-size limit, so a leaf of the form
``(OP_1 OP_IF)*k OP_ENDIF*k`` scanned the whole condition stack on each of its
~3k opcodes: O(k^2) work, reachable from P2P tx relay (under the mempool lock)
and from block connect above assumevalid.

Bitcoin Core avoids this with ``class ConditionStack`` in
``src/script/interpreter.cpp``. It stores only the stack size and the position
of the first false entry, so ``all_true()`` is O(1).

These tests count work instead of timing it, so they do not depend on how
loaded the machine is. Two instruments are added together:

* every element that ``all()`` visits when called from ``ouroboros.script``,
  counted by shadowing the module-level name ``all``. This is where master
  spends its quadratic work, inside one C call that a line tracer cannot see;
* every Python line event in ``ouroboros/script.py``, counted with
  ``sys.settrace``. A fix that moved the scan into a Python loop would show
  up here instead.

Doubling k must roughly double the total (ratio < 3). On master the ratio is
about 4.
"""

from __future__ import annotations

import random
import sys
from collections.abc import Iterable

import pytest

import ouroboros.script as script_mod
from ouroboros.database import Transaction
from ouroboros.script import (
    SCRIPT_VERIFY_MINIMALIF,
    ScriptInterpreter,
    SigVersion,
)

OP_0 = 0x00
OP_1 = 0x51
OP_2 = 0x52
OP_NOP = 0x61
OP_IF = 0x63
OP_NOTIF = 0x64
OP_ELSE = 0x67
OP_ENDIF = 0x68

_SCRIPT_FILE = script_mod.__file__


def _tx() -> Transaction:
    return Transaction(txid=b"\x00" * 32, version=2, locktime=0, inputs=[], outputs=[])


def _run(script: bytes, sig_version: SigVersion, flags: int | None = None) -> list[bytes]:
    kwargs = {}
    if flags is not None:
        kwargs["flags"] = flags
    if sig_version == SigVersion.TAPSCRIPT:
        kwargs.update(
            input_amounts=[0],
            input_script_pubkeys=[b""],
            annex=None,
            leaf_hash=b"\x00" * 32,
            default_sighash=b"\x00" * 32,
        )
    return ScriptInterpreter()._execute_script(
        script,
        _tx(),
        input_index=0,
        script_pubkey=script,
        sig_version=sig_version,
        is_witness_v0=sig_version == SigVersion.WITNESS_V0,
        **kwargs,
    )


def _outcome(script: bytes, sig_version: SigVersion, flags: int | None = None):
    try:
        return ("ok", tuple(_run(script, sig_version, flags)))
    except ValueError:
        return ("err", None)


def _nested_if_leaf(k: int) -> bytes:
    return bytes([OP_1, OP_IF]) * k + bytes([OP_ENDIF]) * k + bytes([OP_1])


def _measure_work(script: bytes, monkeypatch: pytest.MonkeyPatch) -> tuple[int, int, list[bytes]]:
    """Run ``script`` as tapscript; return (all() visits, line events, stack)."""
    visits = 0

    def counting_all(iterable: Iterable[object]) -> bool:
        nonlocal visits
        for item in iterable:
            visits += 1
            if not item:
                return False
        return True

    # A module global shadows the builtin for every name lookup in script.py.
    monkeypatch.setattr(script_mod, "all", counting_all, raising=False)

    lines = 0

    def tracer(frame, event, arg):
        nonlocal lines
        if frame.f_code.co_filename != _SCRIPT_FILE:
            return None
        if event == "line":
            lines += 1
        return tracer

    old = sys.gettrace()
    sys.settrace(tracer)
    try:
        result = _run(script, SigVersion.TAPSCRIPT)
    finally:
        sys.settrace(old)
        monkeypatch.undo()
    return visits, lines, result


def test_tapscript_nested_if_work_is_linear(monkeypatch: pytest.MonkeyPatch) -> None:
    v1, l1, r1 = _measure_work(_nested_if_leaf(1000), monkeypatch)
    v2, l2, r2 = _measure_work(_nested_if_leaf(2000), monkeypatch)

    # The leaf is valid and leaves exactly one true element.
    assert r1 == [b"\x01"]
    assert r2 == [b"\x01"]
    # The tracer must have seen the interpreter loop, or it measured nothing.
    assert l1 > 3000, f"line tracer saw only {l1} events in script.py"

    w1, w2 = v1 + l1, v2 + l2
    ratio = w2 / w1
    assert ratio < 3.0, (
        f"condition-stack work is superlinear: k=1000 all-visits={v1} lines={l1}, "
        f"k=2000 all-visits={v2} lines={l2}, ratio {ratio:.2f} (linear ~2, quadratic ~4)"
    )


def test_counting_instrument_sees_a_quadratic_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    """Negative control: the instrument must report ~4x for a real O(k^2) scan."""
    visits = 0

    def counting_all(iterable: Iterable[object]) -> bool:
        nonlocal visits
        for item in iterable:
            visits += 1
            if not item:
                return False
        return True

    monkeypatch.setattr(script_mod, "all", counting_all, raising=False)
    counts = []
    for k in (1000, 2000):
        visits = 0
        exec_stack: list[bool] = []
        for _ in range(k):
            script_mod.all(exec_stack)  # what master did once per opcode
            exec_stack.append(True)
        counts.append(visits)
    assert counts[1] / counts[0] > 3.5


# ---------------------------------------------------------------------------
# Semantics: the new stack must accept and reject exactly what the old
# list-of-bools did, with the same final stack.
# ---------------------------------------------------------------------------


def _reference(script: bytes, sig_version: SigVersion, flags: int):
    """Model of master's exec_stack semantics on the tiny opcode alphabet below."""
    minimalif = sig_version == SigVersion.TAPSCRIPT or (
        sig_version == SigVersion.WITNESS_V0 and flags & SCRIPT_VERIFY_MINIMALIF
    )
    stack: list[bytes] = []
    exec_stack: list[bool] = []
    for op in script:
        executing = all(exec_stack)
        if op in (OP_IF, OP_NOTIF):
            val = False
            if executing:
                if not stack:
                    return ("err", None)
                top = stack.pop()
                if minimalif and top not in (b"", b"\x01"):
                    return ("err", None)
                val = any(top[:-1]) or (len(top) > 0 and top[-1] not in (0, 0x80))
                if op == OP_NOTIF:
                    val = not val
            exec_stack.append(val)
            continue
        if op == OP_ELSE:
            if not exec_stack:
                return ("err", None)
            exec_stack[-1] = not exec_stack[-1]
            continue
        if op == OP_ENDIF:
            if not exec_stack:
                return ("err", None)
            exec_stack.pop()
            continue
        if not executing:
            continue
        if op == OP_0:
            stack.append(b"")
        elif op in (OP_1, OP_2):
            stack.append(bytes([op - 0x50]))
        elif op == OP_NOP:
            pass
        else:  # pragma: no cover - alphabet is closed
            raise AssertionError(op)
    if exec_stack:
        return ("err", None)
    return ("ok", tuple(stack))


@pytest.mark.parametrize(
    "script, expected",
    [
        # nested false branch skips everything inside, ELSE under a false parent stays off
        (bytes([OP_0, OP_IF, OP_1, OP_IF, OP_2, OP_ELSE, OP_2, OP_ENDIF, OP_ENDIF, OP_1]), ("ok", (b"\x01",))),
        # ELSE flips only the top entry
        (bytes([OP_1, OP_IF, OP_0, OP_IF, OP_2, OP_ELSE, OP_1, OP_ENDIF, OP_ENDIF]), ("ok", (b"\x01",))),
        # repeated ELSE toggles back and forth
        (bytes([OP_1, OP_IF, OP_2, OP_ELSE, OP_0, OP_ELSE, OP_1, OP_ENDIF]), ("ok", (b"\x02", b"\x01"))),
        # NOTIF
        (bytes([OP_0, OP_NOTIF, OP_1, OP_ENDIF]), ("ok", (b"\x01",))),
        # a false entry below the top survives an ELSE on the top
        (bytes([OP_0, OP_IF, OP_ELSE, OP_1, OP_IF, OP_ELSE, OP_2, OP_ENDIF, OP_ENDIF]), ("ok", ())),
        (bytes([OP_1, OP_0, OP_IF, OP_ELSE, OP_IF, OP_ELSE, OP_2, OP_ENDIF, OP_ENDIF]), ("ok", ())),
        # unbalanced
        (bytes([OP_ELSE]), ("err", None)),
        (bytes([OP_ENDIF]), ("err", None)),
        (bytes([OP_1, OP_IF]), ("err", None)),
        # tapscript MINIMALIF
        (bytes([OP_2, OP_IF, OP_ENDIF]), ("err", None)),
    ],
)
def test_tapscript_condition_stack_semantics(script: bytes, expected) -> None:
    assert _outcome(script, SigVersion.TAPSCRIPT) == expected
    assert _reference(script, SigVersion.TAPSCRIPT, 0) == expected


# OP_1 and OP_ENDIF are weighted up so that well-formed scripts are common.
_ALPHABET = [OP_0, OP_1, OP_1, OP_1, OP_2, OP_NOP, OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF, OP_ENDIF]


@pytest.mark.parametrize("sig_version", [SigVersion.TAPSCRIPT, SigVersion.WITNESS_V0, SigVersion.BASE])
def test_condition_stack_matches_reference_model(sig_version: SigVersion) -> None:
    rng = random.Random(0xC0DE5 + int(sig_version))
    accepted = rejected = 0
    for i in range(40000):
        n = rng.randint(1, 14)
        script = bytes(rng.choice(_ALPHABET) for _ in range(n))
        # Alternate MINIMALIF so witness v0 is checked with and without it.
        flags = SCRIPT_VERIFY_MINIMALIF if i % 2 else 0
        got = _outcome(script, sig_version, flags)
        want = _reference(script, sig_version, flags)
        assert got == want, f"{sig_version.name} flags={flags} {script.hex()}: got {got}, want {want}"
        if got[0] == "ok":
            accepted += 1
        else:
            rejected += 1
    # Both outcomes are reached often, so the comparison cannot pass vacuously.
    assert accepted > 3000 and rejected > 3000, (accepted, rejected)
