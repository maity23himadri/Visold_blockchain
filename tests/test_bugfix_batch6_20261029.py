from __future__ import annotations
import os, tempfile, hashlib
from types import SimpleNamespace

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import SECP256K1, derive_private_key, ECDSA
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature
from cryptography.hazmat.primitives import hashes

from visold.crypto.ecc import ECPoint, pub_to_address
from visold.crypto.hashing import sha256
from visold.kernel.lru_cache import LRUCache
from visold.kernel.messages import MSG_RESOLVE_RESP
from visold.network.p2p import P2PNetwork
from visold.storage.storage import Storage
from visold.vm.engine import VVMEngine, _chan_recover_address
from visold.vm.opcodes import Op
from visold.vm.precompiles import VVMPrecompiles
from visold.wallet.wallet import Wallet


def _push1(v): return bytes((Op.PUSH1, v & 0xff))
class _Tx: gas_price=0.0; tx_id='batch6'

def _install(st, addr, code, creator):
    h=sha256(code); st.save_contract_code(h, code); st.save_contract(addr,h,creator,1)

def _independent_recover(digest, v, r, s):
    N,P=ECPoint.N,ECPoint.P
    parity=v-27
    x=r
    if x>=P: return ''
    ys=(pow(x,3,P)+7)%P; y=pow(ys,(P+1)//4,P)
    if pow(y,2,P)!=ys: return ''
    if y%2 != parity: y=P-y
    R=ECPoint(x,y); rinv=pow(r,N-2,N); z=int.from_bytes(digest,'big')
    G=ECPoint(ECPoint.Gx,ECPoint.Gy)
    Q=((-z*rinv)%N)*G + ((s*rinv)%N)*R
    return '' if Q.is_inf() else pub_to_address(Q)

def _direct_sig(priv, digest):
    k=derive_private_key(priv, SECP256K1(), default_backend())
    der=k.sign(digest, ECDSA(Prehashed(hashes.SHA256())))
    return decode_dss_signature(der)

def test_bug29_blockfinalized_ignores_mutable_post_apply_flag(tmp_path):
    st=Storage(str(tmp_path/'b29.db')); w=Wallet.generate(); c='VSDc'+'11'*20
    # return BLOCKFINALIZED(1) as 32-byte word
    code=_push1(1)+bytes((Op.BLOCKFINALIZED,))+_push1(0)+bytes((Op.MSTORE,))+_push1(32)+_push1(0)+bytes((Op.RETURN,))
    _install(st,c,code,w.address)
    st.get_block=lambda h: SimpleNamespace(finalized=True, index=h)
    r=VVMEngine(st).call(caller=w.address,contract=c,calldata=b'',call_value=0,gas_limit=100000,block_ctx=SimpleNamespace(index=10),tx=_Tx())
    assert r.success and int.from_bytes(r.return_data,'big') == 0

def test_bug30_unverified_resolve_response_cannot_poison_cache():
    class S:
        def resolve_identity(self, uid): return None
    n=P2PNetwork.__new__(P2PNetwork); n.storage=S(); n._id_cache=LRUCache(16)
    n._check_msg_rate=lambda peer,mtype: True; n._seen_msgs=LRUCache(16); n._callbacks={}
    peer=SimpleNamespace(peer_id='peer', connected=True)
    n._handle_message(peer, {'type':MSG_RESOLVE_RESP,'user_id':'alice','result':{'wallet_addr':'VSDattacker','pub_hex':'bad','multiaddrs':[]}})
    assert n._id_cache.get('alice') is None

def test_bug30_verified_response_cannot_override_canonical_owner():
    canonical={'user_id':'alice','wallet_addr':'VSDowner','pub_hex':'good','multiaddrs':[]}
    class S:
        def resolve_identity(self, uid): return dict(canonical)
    n=P2PNetwork.__new__(P2PNetwork); n.storage=S(); n._id_cache=LRUCache(16)
    n._check_msg_rate=lambda peer,mtype: True; n._seen_msgs=LRUCache(16); n._callbacks={}
    peer=SimpleNamespace(peer_id='peer', connected=True)
    n._handle_message(peer, {'type':MSG_RESOLVE_RESP,'user_id':'alice','result':{'wallet_addr':'VSDattacker','pub_hex':'bad','multiaddrs':['/ip4/1.2.3.4/tcp/1']}})
    assert n._id_cache.get('alice') is None

def test_bug31_v28_recovery_uses_y_parity_not_r_plus_n():
    w=Wallet.generate(); digest=hashlib.sha256(b'batch6-v28').digest()
    # Generate until the standard v=28 parity recovers this key.
    for _ in range(128):
        r,s=_direct_sig(w.priv,digest)
        if _independent_recover(digest,28,r,s)==w.address:
            break
    else: raise AssertionError('could not obtain v=28 signature')
    assert _chan_recover_address(digest,28,r,s)==w.address
    calldata=digest+(28).to_bytes(32,'big')+r.to_bytes(32,'big')+s.to_bytes(32,'big')
    ok,out,_=VVMPrecompiles._ecrecover(calldata,5000)
    assert ok and out[-20:] != b'\x00'*20

def test_bug32_wallet_can_sign_exact_channel_digest():
    w=Wallet.generate(); digest=hashlib.sha256(b'channel-state-digest').digest()
    r,s=w.sign_digest(digest)
    assert any(_chan_recover_address(digest,v,r,s)==w.address for v in (27,28))

def test_bug32_ordinary_signing_convention_remains_distinct():
    w=Wallet.generate(); digest=hashlib.sha256(b'channel-state-digest-2').digest()
    r,s=w.sign(digest)  # hashes input then historical ecdsa_sign path
    assert not any(_chan_recover_address(digest,v,r,s)==w.address for v in (27,28))

def test_bug33_sqlite_channel_mutations_report_success(tmp_path):
    st=Storage(str(tmp_path/'b33.db'))
    cid='ab'*32
    assert st.create_channel(cid,'VSDc'+'22'*20,'A','B',100,10,1)
    assert st.close_channel(cid,2) is True
    assert st.get_channel(cid)['status']=='CLOSED'
    cid2='cd'*32
    assert st.create_channel(cid2,'VSDc'+'33'*20,'A','B',100,10,1)
    assert st.raise_dispute(cid2,1,60,40,2) is True
    assert st.get_channel(cid2)['status']=='DISPUTED'
    assert st.force_close_channel(cid2,20) is True
    assert st.get_channel(cid2)['status']=='FORCE_CLOSED'
