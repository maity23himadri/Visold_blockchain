"""Two chains in one process must not share difficulty answers.

The difficulty cache used to be keyed by block height alone, so a value computed for one
chain could be returned to another chain in the same process."""

from __future__ import annotations

import os

from visold.chain.blockchain import Blockchain
from visold.consensus.difficulty import DifficultyEngine
from visold.kernel.config import Config
from visold.storage.storage import Storage


def test_two_chains_in_one_process_keep_their_own_difficulty(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "INITIAL_DIFFICULTY", 2.0)
    st_a = Storage(os.path.join(str(tmp_path), "a.db"))
    Blockchain(st_a)
    monkeypatch.setattr(Config, "INITIAL_DIFFICULTY", 3.0)
    st_b = Storage(os.path.join(str(tmp_path), "b.db"))
    Blockchain(st_b)
    # Both chains are created first, so creating a chain does not flush the other's answer.
    monkeypatch.setattr(Config, "INITIAL_DIFFICULTY", 2.0)
    assert DifficultyEngine.compute_next_difficulty(st_a, 0) == 2.0
    monkeypatch.setattr(Config, "INITIAL_DIFFICULTY", 3.0)
    assert DifficultyEngine.compute_next_difficulty(st_b, 0) == 3.0
    assert DifficultyEngine.compute_next_difficulty(st_a, 0) == 2.0
