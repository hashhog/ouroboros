"""Tests for the wallet wave: lockunspent / listlockunspent / getbalances /
walletcreatefundedpsbt RPC handlers.

References:
- bitcoin-core/src/wallet/rpc/coins.cpp::lockunspent
- bitcoin-core/src/wallet/rpc/coins.cpp::listlockunspent
- bitcoin-core/src/wallet/rpc/coins.cpp::getbalances
- bitcoin-core/src/wallet/rpc/spend.cpp::walletcreatefundedpsbt
"""

from __future__ import annotations

import base64
import hashlib
import os
import tempfile

import pytest


# ---------------------------------------------------------------------------
# Helpers — minimal stub wallet/db just rich enough to exercise the handlers.
# ---------------------------------------------------------------------------


class _StubKey:
    def __init__(self, secret: bytes, network: str = "mainnet"):
        from coincurve import PrivateKey

        self._privkey = PrivateKey(secret)
        self.secret = secret
        self.network = network
        self.pubkey = self._privkey.public_key.format(compressed=True)

    def get_p2wpkh_address(self) -> str:
        from ouroboros.wallet import _hash160
        import bech32

        h160 = _hash160(self.pubkey)
        hrp = "bc" if self.network == "mainnet" else "tb"
        converted = bech32.convertbits(h160, 8, 5)
        return bech32.bech32_encode(hrp, [0] + converted)

    def get_p2pkh_address(self) -> str:
        from ouroboros.wallet import _hash160
        import base58

        h160 = _hash160(self.pubkey)
        version = b"\x00" if self.network == "mainnet" else b"\x6f"
        return base58.b58encode_check(version + h160).decode()

    def get_p2sh_p2wpkh_address(self) -> str:
        from ouroboros.wallet import _hash160
        import base58

        h160 = _hash160(self.pubkey)
        redeem_script = b"\x00\x14" + h160
        script_hash = _hash160(redeem_script)
        version = b"\x05" if self.network == "mainnet" else b"\xc4"
        return base58.b58encode_check(version + script_hash).decode()

    def get_script_pubkey(self) -> bytes:
        from ouroboros.wallet import _hash160

        # P2WPKH
        return b"\x00\x14" + _hash160(self.pubkey)

    def to_wif(self) -> str:
        import base58

        version = b"\x80" if self.network == "mainnet" else b"\xef"
        return base58.b58encode_check(version + self.secret + b"\x01").decode()


class _StubDB:
    """Minimal db: tracks utxos by (txid, vout) keyed on script pubkey."""

    def __init__(self, best_height: int = 100):
        self._utxos_by_addr: dict[str, list[dict]] = {}
        self._best_height = best_height
        self._best_hash = b"\xab" * 32

    def add_utxo(
        self, address: str, txid: bytes, vout: int, value: int, height: int = 50,
        is_coinbase: bool = False, script_pubkey: bytes = b"",
    ) -> None:
        u = {
            "txid": txid.hex() if isinstance(txid, (bytes, bytearray)) else txid,
            "vout": vout,
            "value": value,
            "height": height,
            "is_coinbase": is_coinbase,
            "script_pubkey": script_pubkey,
        }
        self._utxos_by_addr.setdefault(address, []).append(u)

    def list_unspent_by_address(self, address: str, network: str = "mainnet"):
        return list(self._utxos_by_addr.get(address, []))

    def get_utxos_for_address(self, address: str, network: str = "mainnet"):
        return list(self._utxos_by_addr.get(address, []))

    def get_best_block(self):
        return self._best_hash, self._best_height

    def get_utxo(self, txid_bytes, vout):
        target = txid_bytes.hex() if isinstance(txid_bytes, (bytes, bytearray)) else txid_bytes
        for utxos in self._utxos_by_addr.values():
            for u in utxos:
                if u["txid"] == target and u["vout"] == vout:
                    return u
        return None


def _make_wallet(secret_hint: bytes, network: str = "mainnet"):
    """Construct a real Wallet (so locking integrates with _save) bound to a
    stub DB and one imported key."""
    from ouroboros.wallet import Wallet

    secret = hashlib.sha256(secret_hint).digest()
    key = _StubKey(secret, network=network)

    tmpdir = tempfile.mkdtemp(prefix="ouroboros-walletwave-")
    wallet = Wallet(data_dir=tmpdir, network=network, name="default")
    wallet.keys = [{"wif": key.to_wif()}]
    wallet._save()

    db = _StubDB(best_height=200)
    wallet.set_database(db)
    return wallet, key, db, tmpdir


class _StubNode:
    def __init__(self, wallet, network: str = "mainnet"):
        self.wallet = wallet
        self.network = network
        self.fee_estimator = None


@pytest.fixture
def rpc_with_wallet():
    from ouroboros.rpc import RPCServer

    wallet, key, db, tmpdir = _make_wallet(b"wallet-wave-tests-2026-05-06")
    rpc = RPCServer.__new__(RPCServer)
    rpc.node = _StubNode(wallet)
    rpc._current_wallet_name = None
    rpc._key = key  # stash for tests
    rpc._db = db
    rpc._tmpdir = tmpdir
    yield rpc


# ---------------------------------------------------------------------------
# lockunspent / listlockunspent
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lockunspent_persists_in_listlockunspent(rpc_with_wallet):
    txid = "a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0"
    ok = await rpc_with_wallet.rpc_lockunspent(
        unlock=False,
        transactions=[{"txid": txid, "vout": 1}],
    )
    assert ok is True

    locked = await rpc_with_wallet.rpc_listlockunspent()
    assert locked == [{"txid": txid, "vout": 1}]


@pytest.mark.asyncio
async def test_lockunspent_unlock_removes(rpc_with_wallet):
    txid = "a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0"
    await rpc_with_wallet.rpc_lockunspent(False, [{"txid": txid, "vout": 0}])
    assert (await rpc_with_wallet.rpc_listlockunspent()) == [{"txid": txid, "vout": 0}]

    ok = await rpc_with_wallet.rpc_lockunspent(True, [{"txid": txid, "vout": 0}])
    assert ok is True
    assert (await rpc_with_wallet.rpc_listlockunspent()) == []


@pytest.mark.asyncio
async def test_lockunspent_unlock_all_with_no_list(rpc_with_wallet):
    a = "a" * 64
    b = "b" * 64
    await rpc_with_wallet.rpc_lockunspent(False, [
        {"txid": a, "vout": 0},
        {"txid": b, "vout": 3},
    ])
    assert len(await rpc_with_wallet.rpc_listlockunspent()) == 2

    # unlock=True with no list = unlock everything (Core's UnlockAllCoins).
    await rpc_with_wallet.rpc_lockunspent(True, None)
    assert (await rpc_with_wallet.rpc_listlockunspent()) == []


@pytest.mark.asyncio
async def test_lockunspent_rejects_already_locked(rpc_with_wallet):
    from fastapi import HTTPException

    txid = "c" * 64
    await rpc_with_wallet.rpc_lockunspent(False, [{"txid": txid, "vout": 0}])
    with pytest.raises(HTTPException):
        await rpc_with_wallet.rpc_lockunspent(False, [{"txid": txid, "vout": 0}])


@pytest.mark.asyncio
async def test_lockunspent_rejects_unlock_when_not_locked(rpc_with_wallet):
    from fastapi import HTTPException

    txid = "d" * 64
    with pytest.raises(HTTPException):
        await rpc_with_wallet.rpc_lockunspent(True, [{"txid": txid, "vout": 0}])


@pytest.mark.asyncio
async def test_lockunspent_rejects_invalid_txid(rpc_with_wallet):
    from fastapi import HTTPException

    with pytest.raises(HTTPException):
        await rpc_with_wallet.rpc_lockunspent(False, [{"txid": "not-hex", "vout": 0}])
    with pytest.raises(HTTPException):
        await rpc_with_wallet.rpc_lockunspent(False, [{"txid": "ab" * 30, "vout": 0}])
    with pytest.raises(HTTPException):
        await rpc_with_wallet.rpc_lockunspent(False, [{"txid": "ab" * 32, "vout": -1}])


@pytest.mark.asyncio
async def test_lockunspent_persistent_survives_save(rpc_with_wallet):
    """Persistent locks should round-trip through wallet save/load.

    Reference: Core's persistent-lock semantics — written to wallet.dat,
    cleared only by an explicit unlock call.
    """
    from ouroboros.wallet import Wallet

    wallet = rpc_with_wallet.node.wallet
    txid = "e" * 64
    await rpc_with_wallet.rpc_lockunspent(False, [{"txid": txid, "vout": 5}], persistent=True)

    # Re-load the wallet from disk and confirm the lock is still there.
    fresh = Wallet(data_dir=str(wallet.data_dir), network=wallet.network, name=wallet.name)
    assert fresh.is_locked_coin(txid, 5)


@pytest.mark.asyncio
async def test_lockunspent_skips_locked_in_collect_utxos(rpc_with_wallet):
    """A locked UTXO must not appear in coin selection."""
    wallet = rpc_with_wallet.node.wallet
    key = rpc_with_wallet._key
    db = rpc_with_wallet._db
    addr = key.get_p2wpkh_address()

    txid_a = bytes.fromhex("11" * 32)
    txid_b = bytes.fromhex("22" * 32)
    db.add_utxo(addr, txid_a, 0, 100_000, height=50)
    db.add_utxo(addr, txid_b, 0, 200_000, height=51)

    before = wallet._collect_utxos()
    assert len(before) == 2

    await rpc_with_wallet.rpc_lockunspent(False, [{"txid": txid_a.hex(), "vout": 0}])
    after = wallet._collect_utxos()
    assert len(after) == 1
    assert after[0]["txid"] == txid_b.hex()


# ---------------------------------------------------------------------------
# getbalances
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_getbalances_buckets_split_correctly(rpc_with_wallet):
    """Confirmed → trusted; height==0 → untrusted_pending; coinbase < maturity → immature."""
    key = rpc_with_wallet._key
    db = rpc_with_wallet._db
    addr = key.get_p2wpkh_address()

    # Trusted: confirmed non-coinbase.
    db.add_utxo(addr, b"\xaa" * 32, 0, 100_000_000, height=50)  # 1 BTC
    # Untrusted pending: height = 0 (mempool).
    db.add_utxo(addr, b"\xbb" * 32, 0, 25_000_000, height=0)    # 0.25 BTC
    # Immature: coinbase, height 199 (best 200 → confs = 2 < 100).
    db.add_utxo(addr, b"\xcc" * 32, 0, 50_000_000, height=199, is_coinbase=True)  # 0.5 BTC

    result = await rpc_with_wallet.rpc_getbalances()

    assert "mine" in result
    mine = result["mine"]
    assert mine["trusted"] == pytest.approx(1.0)
    assert mine["untrusted_pending"] == pytest.approx(0.25)
    assert mine["immature"] == pytest.approx(0.5)

    # lastprocessedblock present and well-formed.
    assert "lastprocessedblock" in result
    assert result["lastprocessedblock"]["height"] == 200
    assert isinstance(result["lastprocessedblock"]["hash"], str)
    assert len(result["lastprocessedblock"]["hash"]) == 64


@pytest.mark.asyncio
async def test_getbalances_mature_coinbase_is_trusted(rpc_with_wallet):
    """Coinbase at height 50 with best height 200 → confs = 151 ≥ 100 → trusted."""
    key = rpc_with_wallet._key
    db = rpc_with_wallet._db
    addr = key.get_p2wpkh_address()

    db.add_utxo(addr, b"\xdd" * 32, 0, 50_00000000, height=50, is_coinbase=True)
    result = await rpc_with_wallet.rpc_getbalances()
    assert result["mine"]["trusted"] == pytest.approx(50.0)
    assert result["mine"]["immature"] == 0


@pytest.mark.asyncio
async def test_getbalances_empty_wallet(rpc_with_wallet):
    """No UTXOs → all buckets zero."""
    result = await rpc_with_wallet.rpc_getbalances()
    assert result["mine"]["trusted"] == 0
    assert result["mine"]["untrusted_pending"] == 0
    assert result["mine"]["immature"] == 0


# ---------------------------------------------------------------------------
# walletcreatefundedpsbt
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_walletcreatefundedpsbt_funds_from_wallet(rpc_with_wallet):
    """Empty inputs + outputs targeting a valid address must auto-fund."""
    from ouroboros.psbt import PSBT

    key = rpc_with_wallet._key
    db = rpc_with_wallet._db
    addr = key.get_p2wpkh_address()

    # Wallet has 1 BTC available.
    db.add_utxo(addr, b"\xee" * 32, 0, 100_000_000, height=50,
                script_pubkey=key.get_script_pubkey())

    # Send 0.1 BTC to a different address.
    other_secret = hashlib.sha256(b"recipient").digest()
    recipient = _StubKey(other_secret).get_p2wpkh_address()

    result = await rpc_with_wallet.rpc_walletcreatefundedpsbt(
        inputs=[],
        outputs=[{recipient: 0.1}],
        locktime=0,
        options={"fee_rate": 5},  # 5 sat/vB
    )
    assert "psbt" in result
    assert "fee" in result
    assert "changepos" in result
    assert result["fee"] > 0
    # Round-trip parse.
    decoded = PSBT.from_base64(result["psbt"])
    assert decoded.tx is not None
    # We should have at least 1 input + 2 outputs (recipient + change).
    assert len(decoded.tx.inputs) >= 1
    assert len(decoded.tx.outputs) >= 2


@pytest.mark.asyncio
async def test_walletcreatefundedpsbt_honors_manual_inputs(rpc_with_wallet):
    """Caller-supplied inputs must be retained verbatim in the resulting PSBT."""
    from ouroboros.psbt import PSBT

    key = rpc_with_wallet._key
    db = rpc_with_wallet._db
    addr = key.get_p2wpkh_address()

    txid_bytes = b"\x77" * 32
    db.add_utxo(addr, txid_bytes, 3, 100_000_000, height=50,
                script_pubkey=key.get_script_pubkey())

    other = _StubKey(hashlib.sha256(b"recipient2").digest()).get_p2wpkh_address()
    result = await rpc_with_wallet.rpc_walletcreatefundedpsbt(
        inputs=[{"txid": txid_bytes.hex(), "vout": 3}],
        outputs=[{other: 0.5}],
        options={"add_inputs": False, "fee_rate": 1},
    )
    psbt = PSBT.from_base64(result["psbt"])
    assert len(psbt.tx.inputs) == 1
    assert psbt.tx.inputs[0].prev_txid == txid_bytes
    assert psbt.tx.inputs[0].prev_vout == 3


@pytest.mark.asyncio
async def test_walletcreatefundedpsbt_rejects_unfundable_when_add_inputs_false(rpc_with_wallet):
    from fastapi import HTTPException

    other = _StubKey(hashlib.sha256(b"r").digest()).get_p2wpkh_address()
    with pytest.raises(HTTPException):
        await rpc_with_wallet.rpc_walletcreatefundedpsbt(
            inputs=[],
            outputs=[{other: 1.0}],
            options={"add_inputs": False},
        )


@pytest.mark.asyncio
async def test_walletcreatefundedpsbt_lockunspents_locks_selected(rpc_with_wallet):
    """When options.lockUnspents=True, every auto-selected UTXO ends up locked."""
    key = rpc_with_wallet._key
    db = rpc_with_wallet._db
    addr = key.get_p2wpkh_address()

    txid_bytes = b"\x99" * 32
    db.add_utxo(addr, txid_bytes, 0, 100_000_000, height=50,
                script_pubkey=key.get_script_pubkey())

    other = _StubKey(hashlib.sha256(b"r3").digest()).get_p2wpkh_address()
    result = await rpc_with_wallet.rpc_walletcreatefundedpsbt(
        inputs=[],
        outputs=[{other: 0.05}],
        options={"fee_rate": 1, "lockUnspents": True},
    )
    assert "psbt" in result
    locked = await rpc_with_wallet.rpc_listlockunspent()
    assert {"txid": txid_bytes.hex(), "vout": 0} in locked


@pytest.mark.asyncio
async def test_walletcreatefundedpsbt_changepos_explicit(rpc_with_wallet):
    """options.changePosition pins where the change output goes."""
    from ouroboros.psbt import PSBT

    key = rpc_with_wallet._key
    db = rpc_with_wallet._db
    addr = key.get_p2wpkh_address()

    db.add_utxo(addr, b"\x33" * 32, 0, 100_000_000, height=50,
                script_pubkey=key.get_script_pubkey())

    other = _StubKey(hashlib.sha256(b"r4").digest()).get_p2wpkh_address()
    result = await rpc_with_wallet.rpc_walletcreatefundedpsbt(
        inputs=[],
        outputs=[{other: 0.1}],
        options={"fee_rate": 5, "changePosition": 0},
    )
    assert result["changepos"] == 0
    psbt = PSBT.from_base64(result["psbt"])
    # Output 0 is now change; output 1 is the recipient (0.1 BTC = 10_000_000 sats).
    assert psbt.tx.outputs[1].value == 10_000_000
