"""The native (Rust) script interpreter is the default; ``OUROBOROS_NATIVE_SCRIPT=0``
forces the pure-Python one (item perf-fix-ouroboros-native-script-default).

Plan: ``docs/NATIVE-SCRIPT-DEFAULT.md``.  What these tests pin:

1. With ``OUROBOROS_NATIVE_SCRIPT`` unset (or empty), importing ouroboros
   selects the native interpreter, in ``ouroboros.script`` AND in
   ``ouroboros.validation`` (which binds the flag at import time and decides
   whether block validation queues script checks for the Rust pool).
2. ``OUROBOROS_NATIVE_SCRIPT=0`` / ``false`` / ``no`` / ``off`` selects the
   Python interpreter; ``1`` / ``true`` still selects native.
3. Fail-closed: the default asks for native, so an installed ``sync`` that
   lacks the native ABI makes the import fail loudly instead of quietly
   running Python.  The opt-out against the same broken ``sync`` imports
   fine (control: the failure is the default, not the fake module).
4. ``--par`` reaches the Rust pool by default: after
   ``init_script_check_threads(4)`` the block check queue drains through
   ``sync.script_verify_parallel`` with 4 threads, accept and reject alike.

Each check runs in a fresh interpreter: ``tests/conftest.py`` stubs ``sync``
and sets the opt-out before ouroboros is imported (the stub has no native
ABI), so the default can only be observed in a clean process with the real
compiled extension.

Command:
  PYTHONPATH=src .venv/bin/python -m pytest tests/test_perf_fix_native_script_default.py -v
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests._real_sync import load_real_sync

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
ENV = "OUROBOROS_NATIVE_SCRIPT"
_UNSET = object()

_real_sync = load_real_sync()
needs_real_sync = pytest.mark.skipif(
    _real_sync is None,
    reason="the compiled Rust `sync` extension is not built",
)

# Child prologue: prove the child imports THIS tree's src and, unless a fake
# sync was planted on purpose, the real compiled extension.
_PROLOGUE = f"""
import json, sys
import ouroboros
assert ouroboros.__file__.startswith({str(SRC)!r}), ouroboros.__file__
"""


def _child(code: str, env_value=_UNSET, prologue: bool = True):
    env = {k: v for k, v in os.environ.items() if k != ENV}
    if env_value is not _UNSET:
        env[ENV] = env_value
    env["PYTHONPATH"] = str(SRC)
    # -P: do not put the cwd / script dir on sys.path (only PYTHONPATH + site).
    return subprocess.run(
        [sys.executable, "-P", "-c", (_PROLOGUE if prologue else "") + code],
        env=env, cwd=str(REPO), capture_output=True, text=True, timeout=180,
    )


_SELECTION = """
import sync
assert not getattr(sync, "__ouroboros_test_stub__", False)
import ouroboros.script as s
import ouroboros.validation as v
print(json.dumps({"script": s.NATIVE_SCRIPT_ENABLED,
                  "validation": v.NATIVE_SCRIPT_ENABLED}))
"""


def _selection(env_value=_UNSET) -> dict:
    r = _child(_SELECTION, env_value)
    assert r.returncode == 0, r.stderr[-2000:]
    return json.loads(r.stdout.strip().splitlines()[-1])


@needs_real_sync
def test_unset_env_selects_native_interpreter():
    assert _selection() == {"script": True, "validation": True}


@needs_real_sync
def test_empty_env_selects_native_interpreter():
    assert _selection("") == {"script": True, "validation": True}


@needs_real_sync
@pytest.mark.parametrize("value", ["0", "false", "no", "off", "OFF", " 0 "])
def test_opt_out_selects_python_interpreter(value):
    assert _selection(value) == {"script": False, "validation": False}


@needs_real_sync
@pytest.mark.parametrize("value", ["1", "true", "on"])
def test_explicit_on_selects_native_interpreter(value):
    assert _selection(value) == {"script": True, "validation": True}


# A stale wheel: the real extension with its native script API removed
# BEFORE ouroboros is first imported (ouroboros/__init__.py pulls in
# ouroboros.script).  ouroboros/__init__.py needs the rest of ``sync``, so a
# bare fake package would fail for an unrelated reason.
_STALE_WHEEL_IMPORT = f"""
import json, sys
import sync
assert not getattr(sync, "__ouroboros_test_stub__", False)
del sync.script_native_abi
assert "ouroboros" not in sys.modules
import ouroboros
assert ouroboros.__file__.startswith({str(SRC)!r}), ouroboros.__file__
import ouroboros.script as s
print(json.dumps({{"script": s.NATIVE_SCRIPT_ENABLED}}))
"""


@needs_real_sync
def test_default_fails_closed_without_native_abi():
    r = _child(_STALE_WHEEL_IMPORT, prologue=False)
    assert r.returncode != 0, (
        "default (native) imported against a sync with no native ABI: "
        f"stdout={r.stdout!r}"
    )
    assert "no native script interpreter" in r.stderr, r.stderr[-2000:]
    assert f"{ENV}=0" in r.stderr, r.stderr[-2000:]


@needs_real_sync
def test_opt_out_imports_without_native_abi():
    """Control for the test above: the same stale wheel is fine with the
    Python interpreter forced, so the failure there is the default."""
    r = _child(_STALE_WHEEL_IMPORT, env_value="0", prologue=False)
    assert r.returncode == 0, r.stderr[-2000:]
    assert json.loads(r.stdout.strip().splitlines()[-1]) == {"script": False}


_PAR_POOL = """
import sync
assert not getattr(sync, "__ouroboros_test_stub__", False)
calls = []
_real = sync.script_verify_parallel
def _spy(jobs, threads):
    calls.append([len(jobs), threads])
    return _real(jobs, threads)
sync.script_verify_parallel = _spy

from ouroboros.database import Transaction, TxIn, TxOut
import ouroboros.validation as v

def spend():
    return Transaction(
        txid=b"\\x00" * 32, version=1, locktime=0,
        inputs=[TxIn(prev_txid=b"\\x11" * 32, prev_vout=0, script_sig=b"",
                     sequence=0xFFFFFFFF)],
        outputs=[TxOut(value=1000, script_pubkey=b"\\x51")],
    )

def queue(spk):
    tx = spend()
    utxo = {"value": 1000, "script_pubkey": spk}
    return [(1, tx, tx.inputs[0], utxo, 0, 0, [1000], [spk])]

threads = v.init_script_check_threads(4)
resolved = v.resolve_script_check_threads()
tv = v.TransactionValidator.__new__(v.TransactionValidator)
# The serial (Python) path would call this; the native pool must not.
tv._verify_input_signature = lambda *a, **k: (_ for _ in ()).throw(
    AssertionError("Python serial path used"))
ok = tv.run_script_check_queue(queue(b"\\x51"), resolved)        # OP_TRUE
bad = tv.run_script_check_queue(queue(b"\\x00"), resolved)       # OP_FALSE
print(json.dumps({"threads": threads, "resolved": resolved,
                  "ok": ok, "bad": bad, "calls": calls}))
"""


@needs_real_sync
def test_par_reaches_native_pool_by_default():
    r = _child(_PAR_POOL)
    assert r.returncode == 0, r.stderr[-2000:]
    got = json.loads(r.stdout.strip().splitlines()[-1])
    assert got["threads"] == 4 and got["resolved"] == 4, got
    assert got["calls"] == [[1, 4], [1, 4]], got
    assert got["ok"] is None, got
    assert got["bad"] == "Transaction 1 invalid: Invalid signature for input 0", got
