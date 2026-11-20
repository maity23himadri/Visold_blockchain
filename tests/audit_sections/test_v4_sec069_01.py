"""
Section 69 V4 Regression Tests: Protocol Version Management and Backward Compatibility.
"""

import importlib.util
import os
import sys

V4_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if V4_ROOT not in sys.path:
    sys.path.insert(0, V4_ROOT)

os.environ.setdefault("VISOLD_STORAGE", "sqlite")

from visold.governance.engine import GovernanceEngine, UpgradePhase
from visold.governance.versioning import ProtocolVersionManager
from visold.kernel import compat
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.storage.storage import Storage


class _DummyBlock:
    def __init__(self, index: int, protocol_version: int, block_hash: str = ""):
        self.index = index
        self.protocol_version = protocol_version
        self.block_hash = block_hash or f"hash_{index}_{protocol_version}"
        self.finalized = True


def _activate_version(st: Storage, gov: GovernanceEngine, pvm: ProtocolVersionManager,
                      target_ver: int, start_height: int) -> int:
    ok, msg = gov.propose_upgrade(
        version=target_ver,
        signal_start_height=start_height,
        threshold=0.75,
        rollback_window=20,
    )
    assert ok, f"propose_upgrade({target_ver}) failed: {msg}"

    h = start_height
    prop = gov.get_proposal(target_ver)
    assert prop is not None
    for _ in range(Config.FORK_SIGNAL_WINDOW + 2):
        pvm.record_block_version(target_ver, h)
        gov.on_block_applied(_DummyBlock(h, target_ver))
        h += 1
        if prop.phase == UpgradePhase.LOCKED_IN:
            break

    assert prop.phase == UpgradePhase.LOCKED_IN, (
        f"Expected v{target_ver} LOCKED_IN, got {prop.phase}"
    )

    act_h = prop.activation_height
    while h <= act_h:
        pvm.record_block_version(target_ver, h)
        gov.on_block_applied(_DummyBlock(h, target_ver))
        h += 1

    assert prop.phase == UpgradePhase.ACTIVE
    return h


class TestV4Section69ProtocolVersion:
    def test_restart_preserves_proto_mgr_and_allows_next_upgrade_proposal(self, tmp_path):
        db_path = str(tmp_path / "visold_s69_1a.db")
        st = Storage(db_path=db_path)
        try:
            pvm = ProtocolVersionManager(st)
            gov = GovernanceEngine(st, pvm)

            next_h = _activate_version(st, gov, pvm, target_ver=2, start_height=1)
            assert pvm.current_version() == 2
            assert gov.get_active_version() == 2
        finally:
            st.close()

        st2 = Storage(db_path=db_path)
        try:
            pvm2 = ProtocolVersionManager(st2)
            gov2 = GovernanceEngine(st2, pvm2)

            assert gov2.get_active_version() == 2
            assert pvm2.current_version() == 2

            ok_v3, msg_v3 = gov2.propose_upgrade(version=3, signal_start_height=next_h + 100)
            assert ok_v3, f"Proposing v3 after restart should succeed: {msg_v3}"
        finally:
            st2.close()

    def test_restart_with_v3_active_accepts_v3_and_rejects_older_versions(self, tmp_path):
        db_path = str(tmp_path / "visold_s69_1b.db")
        st = Storage(db_path=db_path)
        try:
            pvm = ProtocolVersionManager(st)
            gov = GovernanceEngine(st, pvm)

            h = _activate_version(st, gov, pvm, target_ver=2, start_height=1)
            h = _activate_version(st, gov, pvm, target_ver=3, start_height=h + 60)
            assert pvm.current_version() == 3
            assert gov.get_active_version() == 3
        finally:
            st.close()

        st2 = Storage(db_path=db_path)
        try:
            pvm2 = ProtocolVersionManager(st2)
            gov2 = GovernanceEngine(st2, pvm2)

            assert gov2.get_active_version() == 3
            assert pvm2.current_version() == 3

            ok_v3, msg_v3 = gov2.validate_block_version(3, h)
            ok_v2, _ = gov2.validate_block_version(2, h)
            ok_v1, _ = gov2.validate_block_version(1, h)
            ok_v4, _ = gov2.validate_block_version(4, h)
            ok_v5, _ = gov2.validate_block_version(5, h)

            assert ok_v3, f"v3 should be accepted after restart: {msg_v3}"
            assert not ok_v2
            assert not ok_v1
            assert ok_v4
            assert not ok_v5
        finally:
            st2.close()

    def test_validate_block_version_rejects_zero_and_negative_versions(self, tmp_path):
        db_path = str(tmp_path / "visold_s69_2.db")
        st = Storage(db_path=db_path)
        try:
            pvm = ProtocolVersionManager(st)
            gov = GovernanceEngine(st, pvm)

            assert not pvm.validate_block_version(0)[0]
            assert not pvm.validate_block_version(-5)[0]
            assert not gov.validate_block_version(0, 1)[0]
            assert not gov.validate_block_version(-5, 1)[0]

            blk = Block.from_dict({
                "index": 1,
                "prev_hash": "0" * 64,
                "transactions": [],
                "miner_address": "VSDtest",
                "difficulty": 1.0,
                "timestamp": 1700000000,
                "nonce": 0,
                "block_hash": "0" * 64,
                "protocol_version": -5,
            })
            assert not gov.validate_block_version(blk.protocol_version, blk.index)[0]
        finally:
            st.close()

    def test_compat_cuda_and_opencl_available_false_when_missing(self):
        if importlib.util.find_spec("pycuda") is None:
            assert compat._CUDA_AVAILABLE is False
        if importlib.util.find_spec("pyopencl") is None:
            assert compat._OPENCL_AVAILABLE is False
