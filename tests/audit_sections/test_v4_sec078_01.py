"""V4 regression tests for Section 78: Smart Contract Events and Event Index Consistency."""

from __future__ import annotations

import os
import tempfile
import time

from visold.chain.blockchain import Blockchain
from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _make_chain(td: str):
    db = os.path.join(td, "section78.db")
    st = Storage(db)
    bc = Blockchain(st)
    return st, bc


def _sign_call(
    sender_w: Wallet,
    contract: str,
    nonce: int,
    gas_limit: int = 50_000,
) -> Transaction:
    tx = Transaction(
        sender=sender_w.address,
        receiver=contract,
        amount=0.0,
        fee=0.0,
        nonce=nonce,
        tx_type=Transaction.TYPE_CALL,
        data="",
        gas_limit=gas_limit,
        gas_price=Config.VVM_MIN_GAS_PRICE,
    )
    tx.sign(sender_w)
    return tx


def test_log4_preserves_fourth_topic_in_event_index():
    """ContractEventIndex stores all 4 topics including topic3 for LOG4."""
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        sender_w = Wallet.generate()
        miner_w = Wallet.generate()
        sender, miner = sender_w.address, miner_w.address
        contract = "VSDceventtest000000000000000000000001"

        runtime = bytes.fromhex("604460336022601160006000a400")
        code_hash = sha256(runtime)
        st.save_contract_code(code_hash, runtime)
        st.save_contract(contract, code_hash, sender, int(time.time()))
        st.credit_sat(sender, 2_000_000_000)
        st.credit_sat(miner, 2_000_000_000)

        height = bc.height() + 1
        coinbase = Transaction.coinbase(
            miner, bc.compute_reward_sat(height) / Config.SATOSHI_PER_VSD, height
        )
        tx = _sign_call(sender_w, contract, st.get_nonce(sender))
        state_root = bc.dry_run_state_root([coinbase, tx], miner, height)
        block = Block(
            index=height,
            prev_hash=bc.latest_block().block_hash,
            transactions=[coinbase, tx],
            miner_address=miner,
            difficulty=bc.get_difficulty(),
            state_root=state_root,
        )
        assert block.mine()
        ok, msg = bc.apply_block(block)
        assert ok, msg

        receipt = st.get_vvm_receipt(tx.tx_id)
        assert receipt is not None
        assert receipt["logs"][0]["topics"] == ["0x11", "0x22", "0x33", "0x44"]

        events = bc.get_contract_events(contract)
        assert len(events) == 1
        assert events[0]["topic0"] == "0x11"
        assert events[0]["topic1"] == "0x22"
        assert events[0]["topic2"] == "0x33"
        assert events[0]["topic3"] == "0x44"


def test_restore_snapshot_state_clears_stale_event_index():
    """Storage.restore_snapshot_state() clears contract_event_index so stale events do not remain."""
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        sender_w = Wallet.generate()
        miner_w = Wallet.generate()
        sender, miner = sender_w.address, miner_w.address
        contract = "VSDceventtest000000000000000000000002"

        runtime = bytes.fromhex("60cc60006000a100")
        code_hash = sha256(runtime)
        st.save_contract_code(code_hash, runtime)
        st.save_contract(contract, code_hash, sender, int(time.time()))
        st.credit_sat(sender, 2_000_000_000)
        st.credit_sat(miner, 2_000_000_000)

        height = bc.height() + 1
        coinbase = Transaction.coinbase(
            miner, bc.compute_reward_sat(height) / Config.SATOSHI_PER_VSD, height
        )
        tx = _sign_call(sender_w, contract, st.get_nonce(sender))
        state_root = bc.dry_run_state_root([coinbase, tx], miner, height)
        block = Block(
            index=height,
            prev_hash=bc.latest_block().block_hash,
            transactions=[coinbase, tx],
            miner_address=miner,
            difficulty=bc.get_difficulty(),
            state_root=state_root,
        )
        assert block.mine()
        ok, msg = bc.apply_block(block)
        assert ok, msg
        assert len(bc.get_contract_events(contract)) == 1

        st.restore_snapshot_state({
            "version": 4,
            "balances": {},
            "nonces": {},
            "contracts": {},
            "roles": {},
            "name_claims": {},
            "state_channels": {},
            "contract_code": {},
            "contract_storage": {},
            "contract_storage_tags": {},
        })
        assert st.get_contract(contract) is None
        assert bc.get_contract_events(contract) == []


def test_index_logs_is_idempotent():
    """ContractEventIndex.index_logs() is idempotent and does not insert duplicate events."""
    with tempfile.TemporaryDirectory() as td:
        st, bc = _make_chain(td)
        contract = "VSDceventtest000000000000000000000003"
        tx_id = "ab" * 32
        logs = [{"address": contract, "topics": ["0xdd"], "data": "deadbeef"}]

        st.save_vvm_receipt(
            tx_id=tx_id,
            block_idx=1,
            contract_addr=contract,
            gas_used=21000,
            gas_limit=50000,
            success=True,
            return_data=b"",
            revert_reason="",
            logs=logs,
            storage_delta={},
        )
        st.save_vvm_receipt(
            tx_id=tx_id,
            block_idx=1,
            contract_addr=contract,
            gas_used=21000,
            gas_limit=50000,
            success=True,
            return_data=b"",
            revert_reason="",
            logs=logs,
            storage_delta={},
        )

        bc._event_index.index_logs(tx_id=tx_id, block_idx=1, contract_addr=contract, logs=logs)
        bc._event_index.index_logs(tx_id=tx_id, block_idx=1, contract_addr=contract, logs=logs)

        events = bc.get_contract_events(contract)
        assert len(events) == 1
        assert events[0]["tx_id"] == tx_id
        assert events[0]["log_index"] == 0
