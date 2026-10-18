"""Tests for MEV protection as on-chain commit-reveal with a merkle proof.

A protected transfer is a commitment (a zero-value self-transfer carrying a salted
hash of the transfer), then the transfer itself, the reveal. The reveal carries the
commitment's block height and merkle path, and consensus checks them against block
headers only.
"""

from __future__ import annotations

import os
import time

from visold.chain.blockchain import Blockchain
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import (
    Transaction,
    parse_mev_commit_data,
    parse_mev_reveal_data,
)
from visold.mempool import mev
from visold.node.visold_node import VisoldNode
from visold.state.engine import StateEngine
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet

SAT = 100_000_000


def _chain(tmp_path):
    st = Storage(os.path.join(str(tmp_path), "mev.db"))
    bc = Blockchain(st)
    return st, bc


def _save_block(st, txs, miner):
    """Store a block without PoW checks (for the rules that read stored blocks)."""
    height = st.chain_height() + 1
    prev = st.get_block(height - 1)
    cb = Transaction.coinbase(miner.address, 1.0, height)
    block = Block(index=height, prev_hash=prev.block_hash,
                  transactions=[cb] + list(txs), miner_address=miner.address,
                  difficulty=1.0)
    assert block.mine()
    st.save_block(block)
    return block


def _build_block(bc, miner, txs):
    height = bc.height() + 1
    reward = bc.compute_reward_sat(height) / SAT
    cb = Transaction.coinbase(miner.address, reward, height)
    all_txs = [cb] + list(txs)
    root = bc.dry_run_state_root(all_txs, miner.address, height)
    block = Block(index=height, prev_hash=bc.latest_block().block_hash,
                  transactions=all_txs, miner_address=miner.address,
                  difficulty=bc.get_difficulty(), state_root=root,
                  timestamp=max(int(time.time()), bc.latest_block().timestamp + 1))
    assert block.mine(), "block failed to mine"
    return block


def _apply(bc, miner, txs):
    block = _build_block(bc, miner, txs)
    ok, msg = bc.apply_block(block)
    assert ok, msg
    return block


def _pair(sender, receiver, amount=1.0, fee=0.01, memo="", base_nonce=0, ts=None):
    """The transfer's contents and its commitment transaction (not yet placed)."""
    ts = int(ts or time.time())
    salt = mev.new_salt()
    core = mev.core_transfer(sender.address, receiver.address, amount, fee, memo,
                             base_nonce + 1, ts)
    commit = mev.build_commitment_tx(sender, base_nonce + 1, ts,
                                     core.mev_commitment(salt))
    return core, commit, salt


def _reveal(sender, core, salt, st, commit_txid, commit_height):
    steps = mev.reveal_steps_for_commit(st, commit_txid, commit_height)
    return mev.build_reveal_tx(sender, core, salt, commit_height, steps)


# ── transaction rules ───────────────────────────────────────────────────────────

def test_commitment_and_reveal_are_valid_transactions(tmp_path):
    st, bc = _chain(tmp_path)
    sender, receiver = Wallet.generate(), Wallet.generate()
    core, commit, salt = _pair(sender, receiver, memo="memo")
    ok, msg = commit.is_valid()
    assert ok, msg
    _save_block(st, [commit], sender)                      # commitment at height 1
    reveal = _reveal(sender, core, salt, st, commit.tx_id, 1)
    ok, msg = reveal.is_valid()
    assert ok, msg
    assert commit.receiver == sender.address and commit.amount == 0
    assert parse_mev_commit_data(commit.data) == core.mev_commitment(salt)
    salt_back, height, steps = parse_mev_reveal_data(reveal.data)
    assert salt_back == salt and height == 1 and steps
    assert reveal.nonce == commit.nonce + 1


def test_commitment_with_wrong_fee_is_rejected():
    sender = Wallet.generate()
    _, commit, _ = _pair(sender, Wallet.generate())
    commit.fee = 0.5
    ok, msg = commit.is_valid()
    assert not ok and "fee" in msg


def test_commitment_must_be_a_self_transfer():
    sender = Wallet.generate()
    _, commit, _ = _pair(sender, Wallet.generate())
    commit.receiver = Wallet.generate().address
    ok, msg = commit.is_valid()
    assert not ok and "self-transfer" in msg


def test_malformed_reveal_data_is_rejected():
    sender, receiver = Wallet.generate(), Wallet.generate()
    core, _, _ = _pair(sender, receiver)
    reveal = mev.build_reveal_tx(sender, core, mev.new_salt(), 1, [])
    reveal.data = "mev-reveal:not-a-valid-reference"
    ok, msg = reveal.is_valid()
    assert not ok and "malformed" in msg


# ── chain rules ─────────────────────────────────────────────────────────────────

def test_check_reveal_enforces_delay_age_and_match(tmp_path):
    st, bc = _chain(tmp_path)
    sender, receiver = Wallet.generate(), Wallet.generate()
    core, commit, salt = _pair(sender, receiver)
    _save_block(st, [commit], sender)                      # commitment at height 1
    reveal = _reveal(sender, core, salt, st, commit.tx_id, 1)
    ok, msg = mev.check_reveal(st, reveal, 2)
    assert not ok and "too recent" in msg
    ok, msg = mev.check_reveal(st, reveal, 4)              # exactly DELAY blocks later
    assert ok, msg
    tampered_core = mev.core_transfer(sender.address, receiver.address, 2.0, core.fee,
                                      core.memo, core.nonce, core.timestamp)
    tampered = mev.build_reveal_tx(sender, tampered_core, salt, 1,
                                   mev.reveal_steps_for_commit(st, commit.tx_id, 1))
    ok, msg = mev.check_reveal(st, tampered, 4)
    assert not ok and "not part of its block" in msg
    for _ in range(24):
        _save_block(st, [], sender)                        # tip is now 25
    ok, msg = mev.check_reveal(st, reveal, 25)
    assert not ok and "too old" in msg


def test_mempool_refuses_the_reveal_until_its_commitment_is_deep_enough(tmp_path):
    from visold.mempool import mev as mev_module
    st, bc = _chain(tmp_path)
    sender, receiver = Wallet.generate(), Wallet.generate()
    core, commit, salt = _pair(sender, receiver)
    genesis = st.get_block(0)
    cb = Transaction.coinbase(sender.address, 1.0, 1)
    b1 = Block(index=1, prev_hash=genesis.block_hash, transactions=[cb, commit],
               miner_address=sender.address, difficulty=1.0)
    steps = mev_module.merkle_steps([t.tx_id for t in b1.transactions], 1,
                                    mev_module._uses_v2_merkle(1))
    reveal = mev.build_reveal_tx(sender, core, salt, 1, steps)
    ok, msg = bc.mempool.add(reveal)                       # not even mined yet
    assert not ok and "MEV protection" in msg and "too recent" in msg
    _save_block(st, [commit], sender)                      # commitment at height 1
    ok, msg = bc.mempool.add(reveal)                       # next block is 2
    assert not ok and "too recent" in msg
    for _ in range(3):
        _save_block(st, [], sender)                        # tip 4, next block 5
    ok, msg = bc.mempool.add(reveal)
    # The MEV rule now passes; this chain never applied the commitment's nonce, so
    # any rejection is a sequence-number one, not an MEV one.
    assert "MEV protection" not in msg


def test_protection_status_reports_the_rules(tmp_path):
    st, _ = _chain(tmp_path)
    status = mev.protection_status(st)
    assert status["delay_blocks"] == Config.COMMIT_REVEAL_DELAY_BLOCKS
    assert status["max_age_blocks"] == Config.MEV_COMMIT_MAX_AGE_BLOCKS
    assert status["in_flight"] is None
    assert status["validator_mev_protected"] is False


# ── the node's protected send, through the real engine handler ─────────────────

class _Net:
    def __init__(self):
        self.sent = []

    def broadcast_tx(self, tx):
        self.sent.append(tx.tx_id)

    def _gossip(self, *args, **kwargs):
        pass


class _Wrapper:
    def __init__(self, eng):
        self.eng = eng

    def post_sync(self, evt, timeout=None):
        return self.eng._handle_new_tx(evt.payload, evt.source_peer_id)


def _engine(st, bc, wallet=None):
    eng = StateEngine.__new__(StateEngine)
    eng._storage = st
    eng._blockchain = bc
    eng._network = _Net()
    if wallet is not None:
        eng._mev_wallet = wallet
    return eng


def _node(st, bc, eng, wallet):
    node = VisoldNode.__new__(VisoldNode)
    node.storage = st
    node.blockchain = bc
    node.wallet = wallet
    node.identity = None
    node.state_engine = _Wrapper(eng)
    return node


def test_protected_send_holds_the_transfer_and_releases_it_later(tmp_path):
    st, bc = _chain(tmp_path)
    wallet, recipient = Wallet.generate(), Wallet.generate()
    st.credit(wallet.address, 10.0)
    eng = _engine(st, bc, wallet)
    node = _node(st, bc, eng, wallet)

    ok, msg = node.send_transaction(recipient.address, 1.0, "hi", protected=True)
    assert ok, msg
    flight = mev.load_flight(st)
    assert flight["phase"] == "commit" and flight["reveal_tx"] is None
    assert bc.mempool.size() == 1                          # the commitment only
    ok, msg = node.send_transaction(recipient.address, 1.0, "again", protected=True)
    assert not ok and "in progress" in msg

    eng._release_protected_transfer()                      # not mined yet: keep waiting
    assert mev.load_flight(st)["phase"] == "commit"

    commit_tx = bc.mempool.get_top(10)[0]
    bc.mempool.remove(commit_tx.tx_id)                     # what mining it would do
    _save_block(st, [commit_tx], wallet)                   # commitment at height 1
    eng._release_protected_transfer()                      # tip 1: too recent to reveal
    flight = mev.load_flight(st)
    assert flight["phase"] == "reveal" and flight["commit_height"] == 1
    assert flight["reveal_tx"] is None
    for _ in range(3):
        _save_block(st, [], wallet)                        # tip 4
    st.set_nonce(wallet.address, 1)                        # as applying the commitment does
    eng._release_protected_transfer()
    assert mev.load_flight(st) is None
    assert bc.mempool.size() == 1
    reveal = bc.mempool.get_top(1)[0]
    assert reveal.data.startswith(Config.MEV_REVEAL_PREFIX)
    # the commitment was broadcast when it was admitted, the reveal when it was released
    assert eng._network.sent == [commit_tx.tx_id, reveal.tx_id]


def test_flight_is_cancelled_when_its_commitment_disappears(tmp_path):
    st, bc = _chain(tmp_path)
    wallet = Wallet.generate()
    st.credit(wallet.address, 10.0)
    eng = _engine(st, bc, wallet)
    node = _node(st, bc, eng, wallet)
    ok, msg = node.send_transaction(Wallet.generate().address, 1.0, "", protected=True)
    assert ok, msg
    bc.mempool.remove(bc.mempool.get_top(10)[0].tx_id)     # dropped, never mined
    eng._release_protected_transfer()
    assert mev.load_flight(st) is None


def test_unprotected_send_is_admitted_at_once(tmp_path):
    st, bc = _chain(tmp_path)
    wallet, recipient = Wallet.generate(), Wallet.generate()
    st.credit(wallet.address, 10.0)
    eng = _engine(st, bc, wallet)
    node = _node(st, bc, eng, wallet)
    ok, msg = node.send_transaction(recipient.address, 1.0, "", protected=False)
    assert ok, msg
    assert mev.load_flight(st) is None
    assert bc.mempool.size() == 1
    assert bc.mempool.get_top(1)[0].data == ""


def test_protected_send_needs_room_for_the_commitment_fee(tmp_path):
    st, bc = _chain(tmp_path)
    wallet, recipient = Wallet.generate(), Wallet.generate()
    st.credit(wallet.address, 1.01)                        # exactly amount + fee
    eng = _engine(st, bc, wallet)
    node = _node(st, bc, eng, wallet)
    ok, msg = node.send_transaction(recipient.address, 1.0, "", protected=True)
    assert not ok and "commitment fee" in msg, msg
    assert mev.load_flight(st) is None and bc.mempool.size() == 0
    st.credit(wallet.address, 0.01)                        # now the commitment fee is covered
    ok, msg = node.send_transaction(recipient.address, 1.0, "", protected=True)
    assert ok, msg


def test_candidate_builder_refuses_a_reveal_that_is_too_early(tmp_path):
    from visold.chain.blockchain import CandidateTxRejected
    st, bc = _chain(tmp_path)
    sender, receiver = Wallet.generate(), Wallet.generate()
    core, commit, salt = _pair(sender, receiver)
    _save_block(st, [commit], sender)                      # commitment at height 1
    reveal = _reveal(sender, core, salt, st, commit.tx_id, 1)
    try:
        bc._candidate_precheck([reveal], 2, int(time.time()) + 1)
    except CandidateTxRejected as exc:
        assert "MEV protection" in str(exc) or any(
            "MEV protection" in str(arg) for arg in exc.args)
    else:
        raise AssertionError("a reveal two blocks after its commitment was not refused")


# ── end to end: commitment mined, early reveal refused, valid reveal applied ───

def test_end_to_end_reveal_is_refused_early_and_applied_when_deep_enough(
        tmp_path, monkeypatch):
    # Test-only speed-up: the difficulty check compares against get_difficulty().
    monkeypatch.setattr(Blockchain, "get_difficulty", lambda self: 1.0)
    st, bc = _chain(tmp_path)
    sender, recipient = Wallet.generate(), Wallet.generate()
    _apply(bc, sender, [])                                 # height 1: the sender is paid
    core, commit, salt = _pair(sender, recipient, 1.0,
                               round(1.0 * Config.TX_FEE_RATE, 8), "", 0)
    _apply(bc, sender, [commit])                           # height 2: commitment mined
    assert st.get_nonce(sender.address) == 1
    reveal = _reveal(sender, core, salt, st, commit.tx_id, 2)

    early = _build_block(bc, sender, [reveal])             # height 3
    ok, msg = bc.validate_block(early)
    assert not ok and "MEV protection" in msg, msg
    _apply(bc, sender, [])                                 # height 3 (empty)
    _apply(bc, sender, [])                                 # height 4 (empty)
    late = _build_block(bc, sender, [reveal])              # height 5: three blocks after
    ok, msg = bc.validate_block(late)
    assert ok, msg
    ok, msg = bc.apply_block(late)
    assert ok, msg
    assert st.get_balance_sat(recipient.address) == int(round(1.0 * SAT))
    assert st.get_nonce(sender.address) == 2
