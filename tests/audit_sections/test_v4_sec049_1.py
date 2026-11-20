"""V4 regression tests for Section 49: Adaptive Hashrate Governor and Mining Throttling."""

from unittest.mock import patch

from visold.consensus.hashrate_governor import HashrateGovernor


def test_unsequenced_or_stale_ts_report_rejected_after_newer_sequenced_rate():
    """V4: HashrateGovernor.record_peer_hashrate() rejects unsequenced or
    stale-timestamp reports that would overwrite a newer sequenced report.
    """
    gov = HashrateGovernor()
    gov.update_local_actual_hashrate(10_000.0)
    now = 1_700_000_000.0

    with patch("visold.consensus.hashrate_governor.time.time", return_value=now):
        assert gov.record_peer_hashrate(
            "peer_a", 1000.0, reported_ts=now, sequence=10
        ) is True

        res_older = gov.record_peer_hashrate(
            "peer_a", 500_000.0, reported_ts=now - 40.0, sequence=None
        )
        assert res_older is False
        _cap, _req, dbg = gov.advise(1.0)
        assert dbg["observed_actual_total_hps"] == 10_000.0 + 1000.0

        res_no_ts = gov.record_peer_hashrate(
            "peer_a", 250_000.0, reported_ts=None, sequence=None
        )
        assert res_no_ts is False
        _cap2, _req2, dbg2 = gov.advise(1.0)
        assert dbg2["observed_actual_total_hps"] == 10_000.0 + 1000.0


def test_future_reported_ts_and_stale_reports_rejected():
    """V4: HashrateGovernor.record_peer_hashrate() rejects far-future timestamps
    and already-expired (stale) reports rather than admitting them.
    """
    gov = HashrateGovernor()
    gov.update_local_actual_hashrate(10_000.0)
    t0 = 1_700_000_000.0

    with patch("visold.consensus.hashrate_governor.time.time", return_value=t0):
        assert gov.record_peer_hashrate(
            "future_peer", 5_000.0, reported_ts=t0 + 299.0, sequence=None
        ) is False

    with patch("visold.consensus.hashrate_governor.time.time", return_value=t0 + 320.0):
        _cap, _req, dbg = gov.advise(1.0)
        assert dbg["peers_reporting"] == 0
        assert dbg["observed_actual_total_hps"] == 10_000.0

    with patch("visold.consensus.hashrate_governor.time.time", return_value=t0):
        accepted = gov.record_peer_hashrate(
            "stale_peer", 5_000.0, reported_ts=t0 - 200.0, sequence=1
        )
        assert accepted is False
        _cap2, _req2, dbg2 = gov.advise(1.0)
        assert "stale_peer" not in gov._peer_rates
        assert "stale_peer" not in gov._peer_report_meta
