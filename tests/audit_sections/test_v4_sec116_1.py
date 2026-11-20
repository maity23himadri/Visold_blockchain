"""V4 regression tests for Section 116: Repair, Rollback and Storage Integrity."""

from types import SimpleNamespace

from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.selfhealing.hardening.patches import patch_rollback_executor
from visold.selfhealing.hardening.risk import (
    MultiSignalConfirmationWindow,
    RollbackAbuseGuard,
)
from visold.selfhealing.healing import (
    FreezeRegistry,
    HealingActionLayer,
    HealingActionLog,
    RateLimiter,
    ValidatorAlerter,
)
from visold.selfhealing.model import AnomalyKind, AnomalyReport, Severity, SeverityDecision
from visold.selfhealing.rollback import RollbackExecutor, SnapshotStore
from visold.selfhealing.storage_patch import patch_storage
from visold.storage.storage import Storage


def test_dry_run_preview_works_on_real_storage_block_objects(tmp_path):
    """
    _dry_run_preview() handles real Storage.get_block() Block objects
    so dry_run_preview() and hardened RollbackExecutor.execute() succeed.
    """
    storage = Storage(str(tmp_path / "node.db"))
    try:
        blk0 = Block(
            index=0,
            prev_hash="0" * 64,
            transactions=[],
            miner_address="VSD_MINER",
            difficulty=1.0,
            timestamp=1700000000,
        )
        storage.save_block(blk0)

        tx = Transaction(
            sender="VSD_ALICE",
            receiver="VSD_BOB",
            amount=10.0,
            fee=0.01,
            nonce=0,
            timestamp=1700000000,
        )
        blk1 = Block(
            index=1,
            prev_hash=blk0.block_hash,
            transactions=[tx],
            miner_address="VSD_MINER",
            difficulty=1.0,
            timestamp=1700000001,
        )
        storage.save_block(blk1)
        assert isinstance(storage.get_block(1), Block)

        tip = [1]

        def _do_rollback(target):
            tip[0] = target
            return True, "ok"

        blockchain_stub = SimpleNamespace(
            height=lambda: tip[0],
            rollback=_do_rollback,
            mempool=SimpleNamespace(
                add=lambda t: (True, "ok"),
                remove=lambda tx_id: None,
            ),
        )
        exec_ = RollbackExecutor(
            blockchain_stub, storage, SnapshotStore(str(tmp_path))
        )
        patch_rollback_executor(
            exec_, RollbackAbuseGuard(), MultiSignalConfirmationWindow()
        )

        preview = exec_.dry_run_preview(0, set())
        assert preview.preview_ok is True

        ok, msg = exec_.execute(0, set(), skip_preview=True)
        assert ok is True
    finally:
        storage.close()


def test_storage_slash_validator_updates_roles_table_on_sqlite(tmp_path):
    """
    _storage_slash_validator() updates the `roles` table in SQLite and returns True,
    and HealingActionLayer._trigger_slash() slashes the validator.
    """
    storage = Storage(str(tmp_path / "node.db"))
    try:
        conn = storage._conn()
        conn.execute(
            "INSERT INTO roles (address, role, stake, score, slashed, registered_at) "
            "VALUES (?, 'validator', 1000.0, 1.0, 0, 1)",
            ("VSD_VAL_1",),
        )
        conn.execute(
            "INSERT INTO roles (address, role, stake, score, slashed, registered_at) "
            "VALUES (?, 'validator', 1000.0, 1.0, 0, 1)",
            ("VSD_VAL_2",),
        )
        conn.commit()

        patch_storage(storage)
        result = storage.slash_validator("VSD_VAL_1")
        assert result is True

        row = conn.execute(
            "SELECT slashed FROM roles WHERE address=?", ("VSD_VAL_1",)
        ).fetchone()
        assert row["slashed"] == 1

        hal = HealingActionLayer(
            action_log=HealingActionLog(storage),
            rate_limiter=RateLimiter(),
            freeze_registry=FreezeRegistry(),
            alerter=ValidatorAlerter(SimpleNamespace(_gossip=lambda *a, **kw: None)),
            rollback_executor=SimpleNamespace(),
            circuit_breaker_ref=None,
            storage_ref=storage,
            blockchain_ref=SimpleNamespace(height=lambda: 1),
        )
        report = AnomalyReport(
            kind=AnomalyKind.DOUBLE_SIGN,
            source="rule",
            confidence=1.0,
            z_score=5.0,
            affected_addr="VSD_VAL_2",
            block_height=1,
            evidence={"height": 1},
            description="double sign",
            detected_at=1700000000.0,
        )
        decision = SeverityDecision(
            report=report,
            severity=Severity.HIGH,
            action_tags=["slash_validator"],
            attacker_ev=100.0,
            validator_ev=0.0,
            rationale="test",
            suppress=False,
        )
        hal._trigger_slash("VSD_VAL_2", decision)
        row_after = conn.execute(
            "SELECT slashed FROM roles WHERE address=?", ("VSD_VAL_2",)
        ).fetchone()
        assert row_after["slashed"] == 1
    finally:
        storage.close()


def test_restore_snapshot_state_succeeds_with_pending_implicit_sqlite_transaction(tmp_path):
    """
    Storage.restore_snapshot_state() handles an open implicit SQLite transaction
    without raising OperationalError.
    """
    storage = Storage(str(tmp_path / "node.db"))
    try:
        conn = storage._conn()
        conn.execute(
            "INSERT OR REPLACE INTO node_meta (key, value) VALUES ('k', 'v1')"
        )
        storage.restore_meta_values({"k": "v2"})
        assert storage.get_meta("k") == "v2"

        # Leave an implicit transaction open again, then call restore_snapshot_state
        conn.execute(
            "INSERT OR REPLACE INTO node_meta (key, value) VALUES ('k', 'v3')"
        )
        storage.restore_snapshot_state({"balances": {"VSD_ALICE": 500}})
        assert storage.get_balance_sat("VSD_ALICE") > 0
    finally:
        try:
            storage._conn().rollback()
        except Exception:
            pass
        storage.close()
