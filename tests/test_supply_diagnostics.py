"""Privacy, accounting and bounded-storage tests for supply tracing."""
import json
import sqlite3
from pathlib import Path

from visold.kernel.config import Config
from visold.resilience.supply_diagnostics import SupplyDiagnostics


class _FakeBlockchain:
    def compute_reward_sat(self, height):
        # Match a configurable epoch schedule: 100, then 50, then 25 sat.
        epoch = int(height) // int(Config.REWARD_DECAY_BLOCKS)
        return max(25, 100 // (2 ** epoch))


class _FakeStorage:
    _pgx_enabled = False

    def __init__(self, height=3):
        self._db = sqlite3.connect(":memory:")
        self._db.row_factory = sqlite3.Row
        self._db.execute("CREATE TABLE balances (address TEXT PRIMARY KEY, balance INTEGER)")
        self._db.executemany(
            "INSERT INTO balances(address, balance) VALUES (?,?)",
            [("addr-a", 300), (Config.BURN_ADDRESS, 1000)],
        )
        self._db.commit()
        self._height = height

    def _conn(self):
        return self._db

    def chain_height(self):
        return self._height


def test_expected_issuance_matches_per_block_sum_at_epoch_boundaries(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "REWARD_DECAY_BLOCKS", 4)
    diag = SupplyDiagnostics(_FakeStorage(), _FakeBlockchain(), str(tmp_path))
    for height in (0, 1, 3, 4, 7, 8, 9, 17):
        expected = sum(_FakeBlockchain().compute_reward_sat(h) for h in range(1, height + 1))
        assert diag.expected_issuance_sat(height) == expected


def test_real_reward_schedule_at_height_30_is_300_vsd(tmp_path):
    from visold.chain.blockchain import Blockchain

    chain = object.__new__(Blockchain)
    diag = SupplyDiagnostics(_FakeStorage(), chain, str(tmp_path))
    assert diag.expected_issuance_sat(30) == 30 * Config.INITIAL_REWARD
    assert chain.compute_reward_sat(1) == Config.INITIAL_REWARD
    assert Config.REWARD_DECAY_BLOCKS > 30


def test_supply_snapshot_excludes_burn_sink_and_compares_issued(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "REWARD_DECAY_BLOCKS", 4)
    storage = _FakeStorage(height=3)
    diag = SupplyDiagnostics(storage, _FakeBlockchain(), str(tmp_path))
    snapshot = diag.balance_snapshot()
    assert snapshot == {
        "height": 3,
        "held_sat": 300,
        "issued_sat": 300,
        "excess_sat": 0,
        "scan_ok": True,
    }


def test_account_ids_are_pseudonymous_and_log_rotation_is_bounded(tmp_path):
    diag = SupplyDiagnostics(_FakeStorage(), _FakeBlockchain(), str(tmp_path))
    private_address = "VSD-PRIVATE-ADDRESS-DO-NOT-LOG"
    diag.emit("synthetic_mutation", account_id=diag.account_id(private_address), amount_sat=200_000_000)
    for i in range(900):
        diag.emit("synthetic_event", index=i, detail="z" * 700)

    current = Path(diag.path).read_text(encoding="utf-8")
    assert private_address not in current
    assert diag.account_id(private_address) in current or Path(diag.path).with_name(Path(diag.path).name + ".1").exists()
    assert Path(diag.path).stat().st_size <= diag.MAX_FILE_BYTES
    backup = Path(diag.path).with_name(Path(diag.path).name + ".1")
    if backup.exists():
        assert backup.stat().st_size <= diag.MAX_FILE_BYTES
        assert Path(diag.path).stat().st_size + backup.stat().st_size <= 2 * diag.MAX_FILE_BYTES
        # Every retained line must be valid JSON; a rotation cannot truncate a row.
        for file in (Path(diag.path), backup):
            for line in file.read_text(encoding="utf-8").splitlines():
                json.loads(line)


def test_amount_normalization_does_not_turn_missing_values_into_zero(tmp_path):
    diag = SupplyDiagnostics(_FakeStorage(), _FakeBlockchain(), str(tmp_path))
    diag.emit("synthetic_amount", amount_sat=None)
    record = json.loads(Path(diag.path).read_text(encoding="utf-8").splitlines()[-1])
    assert record["amount_sat"] is None


def test_block_trace_pinpoints_first_over_issuance_transition(tmp_path, monkeypatch):
    import threading

    from visold.resilience.supply_diagnostics import install_supply_diagnostics

    monkeypatch.setattr(Config, "REWARD_DECAY_BLOCKS", 4)

    class WritableStorage(_FakeStorage):
        def __init__(self):
            super().__init__(height=3)

        def _get_balance_satoshi(self, address):
            row = self._db.execute(
                "SELECT balance FROM balances WHERE address=?", (address,)
            ).fetchone()
            return int(row[0]) if row else 0

        def credit_sat(self, address, amount_sat):
            current = self._get_balance_satoshi(address)
            self._db.execute(
                "INSERT OR REPLACE INTO balances(address,balance) VALUES (?,?)",
                (address, current + int(amount_sat)),
            )
            self._db.commit()

        def debit_sat(self, address, amount_sat):
            current = self._get_balance_satoshi(address)
            if current < amount_sat:
                return False
            self._db.execute(
                "INSERT OR REPLACE INTO balances(address,balance) VALUES (?,?)",
                (address, current - int(amount_sat)),
            )
            self._db.commit()
            return True

        def set_balance(self, address, balance):
            self._db.execute(
                "INSERT OR REPLACE INTO balances(address,balance) VALUES (?,?)",
                (address, int(balance)),
            )
            self._db.commit()

        def restore_accounts(self, snap):
            for address, (balance, nonce, volume, existed) in snap.items():
                if existed:
                    self.set_balance(address, balance)
                else:
                    self._db.execute("DELETE FROM balances WHERE address=?", (address,))
            self._db.commit()

        def wipe_all_balances(self):
            self._db.execute("DELETE FROM balances")
            self._db.commit()

        def _flush_block_batch(self, bal_updates, non_updates, vol_deltas):
            for address, balance in bal_updates.items():
                self.set_balance(address, balance)

    class WritableBlockchain(_FakeBlockchain):
        def __init__(self, storage):
            self.storage = storage
            self._lock = threading.RLock()

        def apply_block(self, block):
            # Expected reward rises by 50 units; this synthetic block credits
            # 52 units, so the trace should identify a +2-unit mismatch.
            self.storage.credit_sat("addr-a", 52)
            self.storage._height += 1
            return True

    storage = WritableStorage()
    blockchain = WritableBlockchain(storage)
    diag = install_supply_diagnostics(storage, blockchain, data_dir=str(tmp_path))
    assert blockchain.apply_block(object()) is True

    records = [json.loads(line) for line in Path(diag.path).read_text().splitlines()]
    summary = next(record for record in records if record["event"] == "block_apply_finished")
    assert summary["supply_before"]["excess_sat"] == 0
    assert summary["supply_after"]["excess_sat"] == 2, summary["supply_after"]
    assert summary["held_delta_sat"] == 52
    assert summary["issued_delta_sat"] == 50
    mutation = next(record for record in records if record["event"] == "balance_mutation")
    assert mutation["amount_sat"] == 52
    assert mutation["account_id"] == diag.account_id("addr-a")
    assert "addr-a" not in Path(diag.path).read_text()
