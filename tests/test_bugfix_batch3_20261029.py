from types import SimpleNamespace

import pytest

from visold.ledger.transaction import Transaction
from visold.consensus.rate_defection import RateDefectionAuditor
from visold.kernel.config import Config
from visold.kernel.messages import MSG_GET_CHAIN, MSG_CHAIN
import visold.network.p2p as p2p_mod


def _register_tx(memo: str, amount: float = 5.0):
    return Transaction(
        sender="VSD31RxX5mJFFERnASDyF9F4zRo8U8",
        receiver="",
        amount=amount,
        fee=0.05,
        timestamp=1,
        pub_hex="01",
        sig_hex="01",
        memo=memo,
        nonce=1,
        expiry=2_000_000_000,
        tx_type=Transaction.TYPE_REGISTER,
    )


@pytest.mark.parametrize("memo", ["minr", "invest", "garbage", "identity:ab", "identity:bad..name"])
def test_bug3_unknown_or_malformed_register_memo_is_rejected(memo):
    tx = _register_tx(memo)
    ok, msg = tx.is_valid(reference_time=1, signature_already_verified=True)
    assert not ok, (memo, msg)


def test_bug3_valid_role_register_memos_still_pass_structural_validation():
    for memo in ("miner", "investor"):
        tx = _register_tx(memo)
        ok, msg = tx.is_valid(reference_time=1, signature_already_verified=True)
        assert ok, (memo, msg)


def test_bug4_identity_name_rejects_backslash():
    assert Transaction.identity_name_from_memo(r"identity:ali\ce") is None
    assert Transaction.identity_name_from_memo("identity:alice") == "alice"


class _FakeBlock:
    def __init__(self, i):
        self.i = i
    def to_dict(self):
        return {"index": self.i, "block_hash": f"h{self.i}"}


class _FakeChain:
    def height(self):
        return 2
    def get_block(self, i):
        return _FakeBlock(i) if 0 <= i <= 2 else None


class _FakePeer:
    peer_id = "peer-1234567890"
    def __init__(self):
        self.sent = []
    def send(self, msg):
        self.sent.append(msg)


def test_bug9_get_chain_notifies_with_actual_served_count(monkeypatch):
    net = p2p_mod.P2PNetwork.__new__(p2p_mod.P2PNetwork)
    net.blockchain = _FakeChain()
    net._local_chain_tip_hash = lambda: "h2"
    net._check_msg_rate = lambda _peer, _mtype: True
    net._callbacks = {}
    peer = _FakePeer()
    calls = []
    monkeypatch.setattr(p2p_mod, "_push_sync_request_notif", lambda *a: calls.append(a))

    net._handle_message(peer, {"type": MSG_GET_CHAIN, "from_idx": 0, "to_idx": 2})

    assert peer.sent and peer.sent[-1]["type"] == MSG_CHAIN
    assert len(peer.sent[-1]["blocks"]) == 3
    assert calls == [(peer.peer_id, 0, 2, 3)]


class _RateStorage:
    def __init__(self):
        self.blocks = {h: SimpleNamespace(miner_address="M") for h in range(1, 5)}
    def get_block(self, h):
        return self.blocks.get(h)
    def get_rate_defection_state(self):
        return {}
    def set_rate_defection_state(self, payload):
        self.persisted = payload


def test_bug11_same_verified_window_cannot_be_replayed_by_changing_actual_wins(monkeypatch):
    monkeypatch.setattr(Config, "RATE_AUDIT_WINDOW", 4)
    monkeypatch.setattr(Config, "RATE_AUDIT_CONSECUTIVE", 1)
    monkeypatch.setattr(Config, "RATE_AUDIT_CADENCE", 1)
    monkeypatch.setattr(Config, "RATE_AUDIT_THRESHOLD", 1.5)
    monkeypatch.setattr(Config, "RATE_AUDIT_VERIFY_TOLERANCE", 0.01)
    monkeypatch.setattr(Config, "AUTO_SLASH_RATE_DEFECTION", False)
    monkeypatch.setattr(Config, "RATE_SLASH_SCHEDULE", [0.05, 0.25, 0.75])

    auditor = RateDefectionAuditor(_RateStorage(), None)
    caps = {"M": 1.0, "OTHER": 3.0}
    base = {
        "miner": "M", "window_start": 1, "window_end": 4,
        "ratio": 4.0, "consecutive": 1, "actual_wins": 4,
    }
    ok1, msg1 = auditor.handle_received_evidence(dict(base), caps)
    replay = dict(base)
    replay["actual_wins"] = 999999
    ok2, msg2 = auditor.handle_received_evidence(replay, caps)

    assert ok1 and msg1 == "observed"
    assert ok2 and msg2 == "Duplicate (already processed)"
    assert auditor.offense_count("M") == 1


def test_bug11_dedup_retention_is_deterministic_oldest_first():
    # White-box regression for the old set-based, non-insertion-ordered trim.
    auditor = RateDefectionAuditor(_RateStorage(), None)
    for i in range(4100):
        auditor._seen_evidence[str(i)] = None
        while len(auditor._seen_evidence) > 4096:
            auditor._seen_evidence.popitem(last=False)
    assert len(auditor._seen_evidence) == 4096
    assert "0" not in auditor._seen_evidence
    assert "3" not in auditor._seen_evidence
    assert "4" in auditor._seen_evidence and "4099" in auditor._seen_evidence

from visold.storage.storage import Storage
from visold.mempool.pool import Mempool
from visold.wallet.wallet import Wallet
from visold.chain.roles import RoleManager
from visold.kernel.units import to_satoshi

FAR_EXPIRY = 2_000_000_000


def _signed_transfer(wallet, receiver, nonce, amount=1.0, timestamp=1):
    tx = Transaction(
        sender=wallet.address, receiver=receiver, amount=amount,
        fee=round(amount * Config.TX_FEE_RATE, 8), nonce=nonce,
        timestamp=timestamp, expiry=FAR_EXPIRY,
        tx_type=Transaction.TYPE_TRANSFER,
    )
    tx.sign(wallet)
    return tx


def test_bug13_removed_front_nonce_can_be_resubmitted_without_waiting(tmp_path):
    storage = Storage(str(tmp_path / "nonce-hole.db"))
    pool = Mempool(storage)
    sender = Wallet.generate()
    storage.credit_sat(sender.address, to_satoshi(100.0))
    receivers = [Wallet.generate().address for _ in range(4)]

    txs = [_signed_transfer(sender, receivers[i], i, timestamp=i + 1)
           for i in range(3)]
    for tx in txs:
        ok, msg = pool.add(tx)
        assert ok, msg
    pool.remove(txs[0].tx_id)
    assert 0 not in pool._pending_nonces[sender.address]
    assert pool._pending_nonces[sender.address] == {1, 2}

    replacement = _signed_transfer(sender, receivers[3], 0, timestamp=99)
    ok, msg = pool.add(replacement)
    assert ok, msg
    assert pool._pending_nonces[sender.address] == {0, 1, 2}


def test_bug19_mempool_rejects_register_when_balance_covers_stake_but_not_fee(tmp_path):
    storage = Storage(str(tmp_path / "register-fee.db"))
    pool = Mempool(storage)
    sender = Wallet.generate()
    storage.credit_sat(sender.address, to_satoshi(10.05))
    tx = Transaction(
        sender=sender.address, receiver="", amount=10.0, fee=0.10,
        memo="miner", nonce=0, expiry=FAR_EXPIRY,
        tx_type=Transaction.TYPE_REGISTER,
    )
    tx.sign(sender)
    ok, msg = pool.add(tx)
    assert not ok
    assert "stake+fee" in msg
    assert storage.mempool_size() == 0


def test_bug19_role_manager_preflight_includes_register_fee(tmp_path):
    storage = Storage(str(tmp_path / "role-preflight.db"))
    wallet = Wallet.generate()
    storage.credit_sat(wallet.address, to_satoshi(10.05))

    class _Pool:
        @staticmethod
        def pending_outflow_sat(_sender):
            return (0, 0, 0)
    class _Chain:
        mempool = _Pool()
    class _State:
        def __init__(self):
            self.calls = 0
        def post_sync(self, _event):
            self.calls += 1
            return True, "OK"

    state = _State()
    roles = RoleManager(storage, wallet, _Chain(), state)
    ok, msg = roles.register_miner(10.0)
    assert not ok
    assert "including fee" in msg
    assert state.calls == 0

from visold.chain.blockchain import Blockchain
from visold.chain.consensus_engine import ConsensusEngine


def test_bug19_candidate_evicts_register_that_became_unaffordable(tmp_path):
    storage = Storage(str(tmp_path / "register-evict.db"))
    chain = Blockchain(storage)
    chain._rolling_pruner.prune_async = lambda _height: None
    sender = Wallet.generate()
    miner = Wallet.generate()
    storage.credit_sat(sender.address, to_satoshi(10.20))

    tx = Transaction(
        sender=sender.address, receiver="", amount=10.0, fee=0.10,
        memo="miner", nonce=0, expiry=FAR_EXPIRY,
        tx_type=Transaction.TYPE_REGISTER,
    )
    tx.sign(sender)
    ok, msg = chain.mempool.add(tx)
    assert ok, msg
    assert storage.mempool_size() == 1

    # Simulate a legitimate state change after admission that makes the
    # pending REGISTER no longer affordable at candidate time.
    assert storage.debit_sat(sender.address, to_satoshi(0.15))
    candidate = ConsensusEngine(chain, miner).build_candidate_block(miner.address)
    assert all(t.tx_id != tx.tx_id for t in candidate.transactions)
    assert storage.mempool_size() == 0
    assert 0 not in chain.mempool._pending_nonces[sender.address]
