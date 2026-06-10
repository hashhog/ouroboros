"""Erlay default-off gate (Core parity, 2026-06-09).

Bitcoin Core ships reconciliation OFF: DEFAULT_TXRECONCILIATION_ENABLE{false}
(net_processing.h:40), m_txreconciliation constructed only when the
DEBUG_ONLY -txreconciliation arg is passed (net_processing.cpp:2018-2022).
A default Core node therefore NEVER sends sendtxrcncl and silently ignores
any inbound sendtxrcncl (net_processing.cpp:3957-3961 — debug log only, no
disconnect, no misbehavior).

ouroboros' gate is PeerManager.erlay_enabled (p2p.py): every downstream
site — the reconciliation loop start plus the negotiate/register pairs on
all four connection paths — is conditioned on it, so flipping the default
to OUROBOROS_ERLAY-opt-in gives Core's default behavior:

* no sendtxrcncl initiated (the _negotiate_erlay sites are gated);
* inbound sendtxrcncl hits the Peer's unregistered-handler branch
  (peer.py "No handler for ..." debug path) — ignored, connection stays up;
* OUROBOROS_ERLAY=1 restores the full implementation (tests/test_erlay.py
  exercises it by force-setting erlay_enabled=True).
"""

def _make_pm():
    from ouroboros.p2p import PeerManager
    return PeerManager(network="regtest", max_peers=4)


class TestErlayDefaultOff:
    def test_default_disabled(self, monkeypatch):
        monkeypatch.delenv("OUROBOROS_ERLAY", raising=False)
        pm = _make_pm()
        assert pm.erlay_enabled is False
        assert pm.get_stats()["erlay_enabled"] is False

    def test_explicit_zero_disabled(self, monkeypatch):
        monkeypatch.setenv("OUROBOROS_ERLAY", "0")
        pm = _make_pm()
        assert pm.erlay_enabled is False

    def test_opt_in_enables(self, monkeypatch):
        monkeypatch.setenv("OUROBOROS_ERLAY", "1")
        pm = _make_pm()
        assert pm.erlay_enabled is True
        assert pm.get_stats()["erlay_enabled"] is True

    def test_no_reconciliation_task_by_default(self, monkeypatch):
        # The 2s reconciliation loop is started by start() only under the
        # erlay_enabled gate; a fresh default manager holds no task.
        monkeypatch.delenv("OUROBOROS_ERLAY", raising=False)
        pm = _make_pm()
        assert pm._reconciliation_task is None

    def test_broadcast_path_has_no_erlay_peers(self, monkeypatch):
        # With the feature off no peer can complete the sendtxrcncl
        # handshake, so tx announcement always falls back to INV/trickle
        # (broadcast_transaction checks is_erlay_peer per peer).
        monkeypatch.delenv("OUROBOROS_ERLAY", raising=False)
        pm = _make_pm()
        assert pm.get_erlay_peers() == []
        assert pm.is_erlay_peer("10.0.0.1:8333") is False


class TestInboundSendtxrcnclIgnored:
    """Inbound sendtxrcncl on a default node is ignored Core-style."""

    def test_handler_not_registered_by_default(self):
        # The Peer's dispatch loop routes unknown commands to a debug-log
        # no-op (peer.py "No handler for ..."), exactly Core's
        # net_processing.cpp:3957-3961 ignore semantics. sendtxrcncl only
        # gains a handler via PeerManager._register_erlay_handlers, which
        # every connection path calls under the erlay_enabled gate.
        from ouroboros.peer import Peer
        peer = Peer("127.0.0.1", 18444, "regtest")
        assert "sendtxrcncl" not in peer.message_handlers

    def test_register_erlay_handlers_is_the_only_registrar(self, monkeypatch):
        # Sanity: when the implementation IS enabled the handler appears —
        # proving the gate (not a missing feature) is what keeps the
        # default path silent.
        monkeypatch.setenv("OUROBOROS_ERLAY", "1")
        from ouroboros.peer import Peer
        pm = _make_pm()
        peer = Peer("127.0.0.1", 18444, "regtest")
        pm._register_erlay_handlers(peer, "127.0.0.1:18444")
        assert "sendtxrcncl" in peer.message_handlers
