import os
import sys
import tempfile
import time
import unittest

V4_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if V4_ROOT not in sys.path:
    sys.path.insert(0, V4_ROOT)

from visold.crypto.ecc import sig_to_hex
from visold.governance.engine import GovernanceEngine
from visold.governance.versioning import ProtocolVersionManager
from visold.ledger.block import Block
from visold.selfhealing.rollback import GovernanceRollbackVote
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet


def _sign_shbs_vote(wallet: Wallet, proposal_id: str, approve: bool) -> str:
    msg = f"VSD-SHBS-VOTE|{proposal_id}|{approve}".encode()
    return sig_to_hex(wallet.sign(msg))


class TestV4Section67GovernanceVoting(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmpdir.name, "test.db")
        self.storage = Storage(self.db_path)

    def tearDown(self):
        try:
            self.storage.close()
        except Exception:
            pass
        self._tmpdir.cleanup()

    def _seed_validators(self, wallets, stake=100.0):
        genesis = Block(
            index=0,
            prev_hash="0" * 64,
            transactions=[],
            miner_address=wallets[0].address,
            difficulty=1.0,
            timestamp=1700000000,
        )
        genesis.seal()
        self.storage.save_block(genesis)
        self.storage.set_meta("genesis_hash", genesis.block_hash)
        snapshot = [
            {"address": w.address, "stake_sat": int(stake * 10**8)}
            for w in wallets
        ]
        self.storage.record_block_validator_snapshot(0, genesis.block_hash, snapshot)
        for w in wallets:
            self.storage.set_role(w.address, "validator", stake=stake)
        return genesis

    def test_quorum_status_excludes_slashed_validator_vote_two_validators(self):
        """V4 Regression (Bug 1a): Slashed validator's prior approval must NOT count
        in quorum_status()."""
        v1 = Wallet.generate()
        v2 = Wallet.generate()
        self._seed_validators([v1, v2])

        vote = GovernanceRollbackVote(
            storage_ref=self.storage,
            proposal_id="prop-bug1a",
            rollback_depth=5,
            evidence={"reason": "test"},
        )
        res = vote.add_vote(
            v1.address, True, _sign_shbs_vote(v1, "prop-bug1a", True), v1.pub_hex
        )
        self.assertEqual(res, "accepted")

        self.storage.slash(v1.address)

        status = vote.quorum_status()
        self.assertEqual(status["total_validators"], 1)
        self.assertEqual(status["required"], 1)
        self.assertEqual(status["approve_count"], 0)
        self.assertFalse(status["reached"])
        self.assertFalse(status["fast_track"])

    def test_quorum_status_excludes_slashed_validator_vote_three_validators(self):
        """V4 Regression (Bug 1b): With 3 validators, v1 votes True and is slashed;
        v2 votes True and v3 votes False. Only 1/2 active validators approve, so
        quorum_status() must report reached=False and fast_track=False."""
        v1 = Wallet.generate()
        v2 = Wallet.generate()
        v3 = Wallet.generate()
        self._seed_validators([v1, v2, v3])

        vote = GovernanceRollbackVote(
            storage_ref=self.storage,
            proposal_id="prop-bug1b",
            rollback_depth=5,
            evidence={"reason": "test"},
        )
        self.assertEqual(
            vote.add_vote(
                v1.address, True, _sign_shbs_vote(v1, "prop-bug1b", True), v1.pub_hex
            ),
            "accepted",
        )
        self.storage.slash(v1.address)

        self.assertEqual(
            vote.add_vote(
                v2.address, True, _sign_shbs_vote(v2, "prop-bug1b", True), v2.pub_hex
            ),
            "accepted",
        )
        self.assertEqual(
            vote.add_vote(
                v3.address, False, _sign_shbs_vote(v3, "prop-bug1b", False), v3.pub_hex
            ),
            "accepted",
        )

        status = vote.quorum_status()
        self.assertEqual(status["total_validators"], 2)
        self.assertEqual(status["required"], 2)
        self.assertEqual(status["approve_count"], 1)
        self.assertEqual(status["reject_count"], 1)
        self.assertFalse(status["reached"])
        self.assertFalse(status["fast_track"])

    def test_add_vote_rejects_votes_after_is_expired(self):
        """V4 Regression (Bug 2): GovernanceRollbackVote.add_vote() must reject
        votes cast after VOTE_WINDOW_SECS has elapsed."""
        v1 = Wallet.generate()
        self._seed_validators([v1])

        vote = GovernanceRollbackVote(
            storage_ref=self.storage,
            proposal_id="prop-bug2",
            rollback_depth=5,
            evidence={"reason": "test"},
        )
        vote.created_at = time.time() - GovernanceRollbackVote.VOTE_WINDOW_SECS - 10.0
        self.assertTrue(vote.is_expired)

        res = vote.add_vote(
            v1.address, True, _sign_shbs_vote(v1, "prop-bug2", True), v1.pub_hex
        )
        self.assertNotEqual(res, "accepted")
        self.assertFalse(vote.quorum_status()["reached"])

    def test_emergency_vote_duplicate_and_quorum_validation(self):
        """Verify emergency_vote_preimage, duplicate-vote rejection, and 2-validator quorum."""
        v1 = Wallet.generate()
        v2 = Wallet.generate()
        self._seed_validators([v1, v2])

        proto_mgr = ProtocolVersionManager(self.storage)
        gov = GovernanceEngine(self.storage, proto_mgr)
        ok, _ = gov.propose_upgrade(version=2, signal_start_height=10, threshold=0.75)
        self.assertTrue(ok)

        eligible = lambda addr: addr in {v1.address, v2.address}
        now = 1700000100.0
        vote1 = gov.sign_emergency_vote(v1, 2, now=now)
        acc1, dis1, _ = gov.record_emergency_vote(vote1, is_eligible=eligible, now=now)
        self.assertTrue(acc1)
        self.assertFalse(dis1)

        vote1_dup = gov.sign_emergency_vote(v1, 2, now=now + 1)
        acc_dup, dis_dup, _ = gov.record_emergency_vote(
            vote1_dup, is_eligible=eligible, now=now + 1
        )
        self.assertFalse(acc_dup)
        self.assertFalse(dis_dup)

        vote2 = gov.sign_emergency_vote(v2, 2, now=now + 2)
        acc2, dis2, _ = gov.record_emergency_vote(vote2, is_eligible=eligible, now=now + 2)
        self.assertTrue(acc2)
        self.assertTrue(dis2)

    def test_storage_validator_vote_persistence_and_dedup(self):
        """Verify Storage.record_validator_vote deduplicates (block_hash, validator_addr)
        and preserves distinct-hash votes at the same height for equivocation detection."""
        v1 = Wallet.generate()
        self._seed_validators([v1])
        h1 = "a" * 64
        h2 = "b" * 64
        self.storage.record_validator_vote(h1, v1.address, "sig1", v1.pub_hex, block_idx=1)
        self.storage.record_validator_vote(h1, v1.address, "sig1_dup", v1.pub_hex, block_idx=1)
        self.storage.record_validator_vote(h2, v1.address, "sig2", v1.pub_hex, block_idx=1)

        votes = self.storage.get_validator_votes_at_height(1)
        self.assertEqual(len(votes), 2)
        hashes = {row["block_hash"] for row in votes}
        self.assertEqual(hashes, {h1, h2})


if __name__ == "__main__":
    unittest.main()
