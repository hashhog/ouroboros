"""Tell the REAL compiled ``sync`` extension apart from the test stub.

``tests/conftest.py`` injects a stub module under the name ``sync`` so that the
pure-Python components can be imported without the Rust build.  That stub is
deliberate and useful, but it is installed *unconditionally*, which quietly
disarms ``pytest.importorskip("sync")``: the guard finds the stub, decides the
extension is present, and never skips.  Tests written to require the compiled
extension therefore ran against a mock of the very code they were checking.

This module restores the intent:

``real_sync_or_skip()``
    Module-level guard.  Returns the real compiled extension, or skips the
    whole test module when it genuinely is not built.  Drop-in replacement for
    ``pytest.importorskip("sync")`` in tests that must not run against a stub.

``real_sync_installed(real)``
    Context manager for the case where the code under test reaches ``sync``
    through an ouroboros module rather than through the test's own namespace
    (``ouroboros.validation`` binds ``import sync as _sync_module`` at import
    time; ``ouroboros.script`` re-imports it on every call).  Inside the block,
    ``sys.modules["sync"]`` is the real extension and every ouroboros module
    that had cached the stub points at the real one instead.  Everything is
    restored on exit, so the stub keeps serving the rest of the suite.
"""

from __future__ import annotations

import contextlib
import importlib
import sys

import pytest

#: Attribute stamped on the stub by ``tests/conftest.py``.
STUB_ATTR = "__ouroboros_test_stub__"

_SKIP_REASON = (
    "the compiled Rust `sync` extension is not built; this test must not run "
    "against tests/conftest.py's stub"
)

_real: object | None = None
_looked = False


def is_stub(module: object) -> bool:
    """True if ``module`` is the stub injected by ``tests/conftest.py``."""
    if module is None:
        return True
    if getattr(module, STUB_ATTR, False):
        return True
    # Belt and braces: the stub has always carried this sentinel __file__.
    return getattr(module, "__file__", None) == "<test-mock>"


def load_real_sync():
    """Return the real compiled ``sync`` extension, or ``None`` if unbuilt.

    The stub shadows the name in ``sys.modules``, so it is lifted out of the
    way for the duration of the import and put straight back afterwards: the
    rest of the suite keeps the stub it expects.
    """
    global _real, _looked
    if _looked:
        return _real
    _looked = True

    current = sys.modules.get("sync")
    if current is not None and not is_stub(current):
        _real = current
        return _real

    stub = sys.modules.pop("sync", None)
    try:
        candidate = importlib.import_module("sync")
        _real = None if is_stub(candidate) else candidate
    except ImportError:
        _real = None
    finally:
        if stub is not None:
            sys.modules["sync"] = stub
    return _real


def real_sync_or_skip():
    """Module-level guard: the real extension, else skip this test module."""
    real = load_real_sync()
    if real is None:
        pytest.skip(_SKIP_REASON, allow_module_level=True)
    return real


def _rebind_stub_references(stub, real):
    """Point every ouroboros module that cached ``stub`` at ``real``.

    Returns the list of ``(namespace, attribute)`` pairs that were swapped so
    the caller can put the stub back.
    """
    swapped = []
    for name, module in list(sys.modules.items()):
        if module is None:
            continue
        if name != "ouroboros" and not name.startswith("ouroboros."):
            continue
        namespace = getattr(module, "__dict__", None)
        if not namespace:
            continue
        for attr, value in list(namespace.items()):
            if value is stub:
                namespace[attr] = real
                swapped.append((namespace, attr))
    return swapped


@contextlib.contextmanager
def real_sync_installed(real=None):
    """Run the block with the real extension in place of the stub.

    Scoped and reversible: ``sys.modules["sync"]`` and every ouroboros module
    attribute that held the stub are restored on exit, so tests that legitimately
    depend on the stub are unaffected.
    """
    real = real if real is not None else load_real_sync()
    if real is None:
        pytest.skip(_SKIP_REASON)

    stub = sys.modules.get("sync")
    if stub is real:
        # Nothing shadowing the real extension (e.g. the src/ouroboros/tests
        # tree, which has no stub-installing conftest).
        yield real
        return

    sys.modules["sync"] = real
    swapped = _rebind_stub_references(stub, real) if stub is not None else []
    try:
        yield real
    finally:
        for namespace, attr in swapped:
            namespace[attr] = stub
        if stub is None:
            sys.modules.pop("sync", None)
        else:
            sys.modules["sync"] = stub
