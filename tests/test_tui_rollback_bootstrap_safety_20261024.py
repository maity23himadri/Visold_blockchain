from types import SimpleNamespace

from visold.chain.blockchain import Blockchain


class _Pruner:
    def __init__(self, watermark):
        self.watermark = watermark
    def get_pruned_watermark(self):
        return self.watermark


class _Snaps:
    def __init__(self, manifest):
        self.manifest = manifest
    def get_servable_manifest(self):
        return list(self.manifest)


def _bc(height, watermark, manifest):
    bc = Blockchain.__new__(Blockchain)
    bc.height = lambda: height
    bc._rolling_pruner = _Pruner(watermark)
    bc._snapshot_engine = _Snaps(manifest)
    return bc


def test_unpruned_chain_can_rollback_to_genesis_and_still_serve():
    s = _bc(500, 0, []).rollback_bootstrap_safety()
    assert s["safe_floor"] == 0
    assert s["max_safe_rollback"] == 500
    assert s["anchor_snapshot"] is None


def test_snapshot_aligned_pruned_chain_reports_exact_safe_floor():
    s = _bc(1490, 601, [{"height": 600}, {"height": 1200}]).rollback_bootstrap_safety()
    assert s["safe_floor"] == 601
    assert s["max_safe_rollback"] == 889
    assert s["anchor_snapshot"] == 600


def test_legacy_gap_reports_no_bootstrap_safe_rollback_target():
    s = _bc(892, 890, [{"height": 600}]).rollback_bootstrap_safety()
    assert s["safe_floor"] is None
    assert s["max_safe_rollback"] == 0
