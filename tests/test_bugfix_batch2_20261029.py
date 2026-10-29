from __future__ import annotations

import math
import os
import tempfile
import time

from visold.chain.blockchain import Blockchain
from visold.consensus.difficulty import DifficultyEngine
from visold.kernel.config import Config
from visold.ledger.block import Block
from visold.ledger.transaction import Transaction
from visold.storage.storage import Storage
from visold.wallet.wallet import Wallet

SAT = Config.SATOSHI_PER_VSD
FAR_EXPIRY = 2_000_000_000


def _chain(path):
    st = Storage(str(path))
    bc = Blockchain(st)
    bc._rolling_pruner.prune_async = lambda _height: None
    return st, bc


def _coinbase(bc, miner, height, *, amount=None):
    reward = bc.compute_reward_sat(height) / SAT if amount is None else amount
    return Transaction.coinbase(miner.address, reward, height)


def _extend(bc, miner, count, start_ts=None):
    out=[]
    ts = int(time.time()) + 300 if start_ts is None else start_ts
    for i in range(count):
        h=bc.height()+1
        cb=_coinbase(bc, miner, h)
        root=bc.dry_run_state_root([cb], miner.address, h)
        b=Block(index=h, prev_hash=bc.latest_block().block_hash,
                transactions=[cb], miner_address=miner.address,
                difficulty=bc.get_difficulty(), timestamp=ts+i*60,
                state_root=root)
        assert b.mine()
        ok,msg=bc.apply_block(b)
        assert ok,msg
        out.append(b)
    return out


def test_bug6_empty_miner_dry_run_is_side_effect_free(tmp_path):
    st,bc=_chain(tmp_path/'b6.db')
    role=Wallet.generate()
    st.set_role(role.address,'miner',1.0)
    before_empty=st.get_balance_sat('')
    before_sum=st.sum_all_balances_satoshi()
    before_issued=st.get_total_issued_satoshi()
    try:
        bc.dry_run_state_root([], '', bc.height()+1)
    except ValueError as exc:
        assert 'miner_address' in str(exc)
    else:
        raise AssertionError('empty miner dry-run must be rejected')
    assert st.get_balance_sat('') == before_empty
    assert st.sum_all_balances_satoshi() == before_sum
    assert st.get_total_issued_satoshi() == before_issued


def test_bug8_huge_transfer_is_rejected_without_conversion_exception():
    w=Wallet.generate(); r=Wallet.generate()
    tx=Transaction(sender=w.address, receiver=r.address, amount=1e301,
                   fee=0.0, nonce=0, expiry=FAR_EXPIRY)
    tx.sign(w)
    ok,msg=tx.is_valid()
    assert not ok
    assert 'range' in msg.lower()


def test_bug8_huge_vvm_gas_price_is_rejected_without_exception():
    w=Wallet.generate()
    tx=Transaction(sender=w.address, receiver='VSDc'+'ab'*18, amount=0.0,
                   fee=0.0, nonce=0, expiry=FAR_EXPIRY,
                   tx_type=Transaction.TYPE_CALL, gas_limit=21000,
                   gas_price=1e301, data='')
    tx.sign(w)
    ok,msg=tx.is_valid()
    assert not ok
    assert 'range' in msg.lower()


def test_bug8_nan_coinbase_validate_block_returns_false_not_exception(tmp_path):
    st,bc=_chain(tmp_path/'b8.db')
    miner=Wallet.generate(); h=bc.height()+1
    cb=_coinbase(bc, miner, h, amount=float('nan'))
    # Recompute stable tx id / block seal from the malformed canonical form.
    cb.tx_id = cb._compute_id()
    b=Block(index=h, prev_hash=bc.latest_block().block_hash,
            transactions=[cb], miner_address=miner.address,
            difficulty=bc.get_difficulty(), timestamp=int(time.time())+300,
            state_root='')
    b.seal()
    # PoW is not the point here: bypass it so execution reaches coinbase conversion.
    b.validate_pow=lambda: True
    ok,msg=bc.validate_block(b)
    assert not ok
    assert 'coinbase amount' in msg.lower()


def test_bug7_reorg_contains_apply_exception_and_restores_old_chain(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, 'INITIAL_DIFFICULTY', 0.001)
    monkeypatch.setattr(Config, 'DIFF_BOOTSTRAP_BLOCKS', 1)
    local_st,local=_chain(tmp_path/'local.db')
    peer_st,peer=_chain(tmp_path/'peer.db')
    prefix_miner=Wallet.generate(); local_miner=Wallet.generate(); peer_miner=Wallet.generate()
    base=int(time.time())+300
    DifficultyEngine.invalidate_cache(0)
    prefix=_extend(local,prefix_miner,2,base)
    for b in prefix:
        ok,msg=peer.apply_block(b); assert ok,msg
    DifficultyEngine.invalidate_cache(0)
    peer_suffix=_extend(peer,peer_miner,3,base+180)
    DifficultyEngine.invalidate_cache(0)
    local_suffix=_extend(local,local_miner,2,base+600)
    before_hash=local.latest_block().block_hash
    before_root=local_st.compute_state_root()
    real_apply=local.apply_block
    boom_hash=peer_suffix[1].block_hash
    def injected(block, *, defer_finality=False):
        if block.block_hash == boom_hash:
            raise OverflowError('injected BUG-7 validation exception')
        return real_apply(block, defer_finality=defer_finality)
    monkeypatch.setattr(local,'apply_block',injected)
    DifficultyEngine.invalidate_cache(0)
    ok,msg=local.reorg(peer_suffix)
    assert not ok
    assert 'exception' in msg.lower()
    assert local.latest_block().block_hash == before_hash
    assert local_st.compute_state_root() == before_root
    assert not local._critical_recovery


def test_bug5_invalid_pow_fork_is_rejected_before_reorg(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, 'INITIAL_DIFFICULTY', 0.001)
    st,bc=_chain(tmp_path/'b5.db')
    miner=Wallet.generate(); attacker=Wallet.generate()
    base=int(time.time())+300
    _extend(bc,miner,2,base)
    ancestor=bc.latest_block()
    # extend honest tip one more block so incoming fork overlaps ancestor and competes
    _extend(bc,miner,1,base+180)
    h=ancestor.index+1
    cb=_coinbase(bc,attacker,h)
    fork_diff = DifficultyEngine._compute_uncached(st, ancestor.index)
    # Build a block whose header is internally consistent (block_hash is the
    # hash of its own header) but whose PoW misses the canonical target at the
    # correct difficulty.  Only the PoW check may reject it, so this test isolates
    # the PoW preflight rather than the integrity or DAA checks.
    forged = None
    for nonce in range(1_000_000):
        cand = Block(index=h, prev_hash=ancestor.block_hash, transactions=[cb],
                     miner_address=attacker.address, difficulty=fork_diff,
                     timestamp=base+240, state_root='00'*32, nonce=nonce)
        if not cand.validate_pow():
            forged = cand
            break
    assert forged is not None, 'no nonce with an invalid PoW was found'
    forged.seal()
    assert forged.block_hash == forged.compute_hash()
    assert not forged.validate_pow()
    # second block makes incoming tip exceed local tip, matching original trigger
    cb2=_coinbase(bc,attacker,h+1)
    forged2=Block(index=h+1, prev_hash=forged.block_hash, transactions=[cb2],
                  miner_address=attacker.address, difficulty=forged.difficulty,
                  timestamp=base+300, state_root='11'*32)
    forged2.seal()
    calls=[]
    real_reorg=bc.reorg
    def spy(*a,**kw):
        calls.append(1); return real_reorg(*a,**kw)
    monkeypatch.setattr(bc,'reorg',spy)
    before=bc.latest_block().block_hash
    ok,msg=bc.accept_chain([ancestor,forged,forged2])
    assert not ok
    assert 'invalid pow' in msg.lower(), msg
    assert calls == []
    assert bc.latest_block().block_hash == before
