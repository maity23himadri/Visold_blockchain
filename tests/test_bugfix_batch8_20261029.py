from types import SimpleNamespace
import hashlib

from visold.crypto.base58 import b58encode
from visold.kernel.config import Config
from visold.network.udp.reliability import _UDPReassembler
from visold.network.udp.wire import _UDP_FRAG_MAX_PER_GROUP, _UDP_PAYLOAD_MAX, _F_FRAG
from visold.state.engine import StateEngine
from visold.vm.engine import VVMEngine
from visold.vm.frame import _VMFrame
from visold.vm.opcodes import Op


def _wallet_address_starting_vsdc():
    # Deterministically find a valid 20-byte EOA whose Base58 payload begins
    # with 'c', so the full wallet address begins with the characters VSDc.
    for i in range(1, 20000):
        raw = hashlib.sha256(str(i).encode()).digest()[:20]
        enc = b58encode(raw)
        if enc.startswith('c'):
            return 'VSD' + enc, raw
    raise AssertionError('failed to construct VSDc-prefixed EOA test vector')


def test_bug39_vsdc_prefixed_wallet_uses_eoa_abi_word():
    address, raw20 = _wallet_address_starting_vsdc()
    assert address.startswith('VSDc')
    frame = _VMFrame.__new__(_VMFrame)
    word = frame._addr_to_int(address)
    assert word == int.from_bytes(raw20, 'big')
    assert frame._int_to_addr(word) == address


def test_bug40_blockhash_zero_is_available_inside_window():
    h = '12' * 32
    class Storage:
        def get_block(self, n):
            return SimpleNamespace(block_hash=h) if n == 0 else None
    vm = VVMEngine(Storage())
    # PUSH1 0 ; BLOCKHASH ; STOP, executing in block #1.
    frame = _VMFrame(
        code=bytes((Op.PUSH1, 0, Op.BLOCKHASH, Op.STOP)), calldata=b'',
        caller='VSDx', address='VSDctest', origin='VSDx', call_value=0,
        gas_limit=100000, storage_ref=Storage(),
        block_ctx=SimpleNamespace(index=1, miner_address='', timestamp=1,
                                  difficulty=1.0), execution_id='40' * 32)
    vm._storage = frame.storage
    vm._execute(frame)
    assert not frame.reverted
    assert frame.stack[-1] == int(h, 16)


def test_bug41_reassembly_uses_offset_containment_not_fragment_count():
    r = _UDPReassembler(41)
    assert r.add_data(0, False, b'a')
    assert r.add_data(2, True, b'c')
    # Extra offset 3 makes the old count-based predicate think 3 fragments
    # means offsets 0..2 are complete even though offset 1 is missing.
    assert r.add_data(3, False, b'x') is False  # declared LAST=2
    assert r.complete() is False
    assert r.add_data(1, False, b'b')
    assert r.complete() is True
    assert r.reassemble() == b'abc'

    # An out-of-range fragment received before LAST must not poison completion.
    r2 = _UDPReassembler(42)
    assert r2.add_data(0, False, b'a')
    assert r2.add_data(2, False, b'x')
    assert r2.add_data(1, True, b'b')
    assert 2 not in r2.frags
    assert r2.complete() is True
    assert r2.reassemble() == b'ab'


def test_bug42_udp_fragment_limit_covers_configured_message_size():
    needed = (Config.MAX_MESSAGE_SIZE + _UDP_PAYLOAD_MAX - 1) // _UDP_PAYLOAD_MAX
    assert _UDP_FRAG_MAX_PER_GROUP >= needed
    assert needed > 2048  # proves this exercises the original 2,048 ceiling

    r = _UDPReassembler(43)
    assert r.add_data(2048, False, b'x') is True


def test_bug43_stale_mined_block_is_not_reported_applied_or_postprocessed():
    stale = SimpleNamespace(index=5, block_hash='stale', prev_hash='p',
                            miner_address='miner')
    canonical = SimpleNamespace(index=5, block_hash='canon', prev_hash='p')

    class Storage:
        def __init__(self): self.records=[]
        def get_block(self, h): return canonical if h == 5 else None
        def record_block_apply_result(self, h, ok): self.records.append((h, ok))
    class Chain:
        def height(self): return 7
        def apply_block(self, block): raise AssertionError('stale candidate must not apply')
    class Gov:
        def __init__(self): self.calls=[]
        def on_block_applied(self, b): self.calls.append(b)

    e = StateEngine.__new__(StateEngine)
    e._storage = Storage()
    e._blockchain = Chain()
    e._network = None
    e._governance = Gov()
    e._node_ref = None
    e._drain_orphans_for = lambda *a, **k: (_ for _ in ()).throw(
        AssertionError('post-apply orphan drain must not run'))

    ok, msg = e._handle_mine_result({'block': stale, 'consensus': None})
    assert ok is False
    assert 'not applied' in msg.lower()
    assert e._storage.records == []
    assert e._governance.calls == []


def test_bug44_personal_ledger_removes_orphan_and_reincluded_tx_gets_new_height(monkeypatch, tmp_path):
    import json
    import visold.rollup.ledger_sync as ls

    ledger_path = tmp_path / 'ledger.json'
    monkeypatch.setattr(ls, '_LOCAL_LEDGER_PATH', str(ledger_path))
    invalidated = getattr(ls, '_LOCAL_LEDGER_INVALIDATED_BLOCKS', None)
    if invalidated is not None:
        invalidated.clear()
    owner = 'VSDowner'
    tx = SimpleNamespace(sender=owner, receiver='VSDpeer', amount=1.0,
                         timestamp=10, tx_id='tx44', tx_type='transfer', data='')
    orphan = SimpleNamespace(index=5, block_hash='aa' * 32, transactions=[tx])
    replacement = SimpleNamespace(index=8, block_hash='bb' * 32, transactions=[tx])

    def write(block, entries):
        # Batch-7 worker had no block-hash argument; call the appropriate public
        # worker shape so baseline executes its real behavior instead of failing
        # merely because the Batch-8 helper signature is newer.
        import inspect
        if len(inspect.signature(ls._ledger_write_worker).parameters) == 3:
            ls._ledger_write_worker(block.index, entries, owner)
        else:
            ls._ledger_write_worker(block.index, block.block_hash, entries, owner)

    old_entries = ls._ledger_collect_entries(orphan, owner)
    write(orphan, old_entries)
    data = json.loads(ledger_path.read_text())
    assert data['entries'][0]['Block_Height'] == 5

    invalidate = getattr(ls, 'invalidate_local_ledger_block', None)
    if invalidate is not None:
        invalidate(orphan)
    data = json.loads(ledger_path.read_text())
    assert data['entries'] == []

    # A delayed writer for the orphan must not resurrect it after rollback.
    write(orphan, old_entries)
    assert json.loads(ledger_path.read_text())['entries'] == []

    new_entries = ls._ledger_collect_entries(replacement, owner)
    write(replacement, new_entries)
    data = json.loads(ledger_path.read_text())
    assert len(data['entries']) == 1
    assert data['entries'][0]['Tx_Hash'] == 'tx44'
    assert data['entries'][0]['Block_Height'] == 8
    assert data['entries'][0]['Block_Hash'] == replacement.block_hash


def test_bug46_l2_rpc_reports_no_admission_and_no_peers_as_failure(monkeypatch, tmp_path):
    import json
    import urllib.request
    from visold.api.rpc_server import RPCServer
    from visold.wallet.wallet import Wallet

    monkeypatch.setattr(RPCServer, 'TOKEN_FILE', str(tmp_path / 'rpc_token'))
    sender, receiver = Wallet.generate(), Wallet.generate()
    l2tx = sender.sign_l2_tx(receiver.address, 12345, 0)
    node = SimpleNamespace(blockchain=SimpleNamespace(), sequencer=None, network=None)
    srv = RPCServer(node, 0)
    srv.start()
    port = srv._server.server_address[1]
    try:
        body = json.dumps({
            'jsonrpc': '2.0', 'id': 1, 'method': 'vsd_sendL2Transaction',
            'params': [l2tx.to_dict()],
        }).encode()
        req = urllib.request.Request(
            f'http://127.0.0.1:{port}', data=body, method='POST',
            headers={'Authorization': f'Bearer {srv._token}',
                     'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=3) as resp:
            result = json.loads(resp.read().decode())['result']
        assert result['ok'] is False
        assert result['accepted_locally'] is False
        assert result['gossiped'] is False
        assert result['gossip_targets'] == 0
    finally:
        srv.stop()


def test_bug42_production_compression_reassembles_message_over_old_limit():
    import random
    from visold.network.udp.wire import _udp_compress, _udp_decompress

    raw = random.Random(12345).randbytes(3_100_000)
    compressed = _udp_compress(raw)
    chunks = [compressed[i:i + _UDP_PAYLOAD_MAX]
              for i in range(0, len(compressed), _UDP_PAYLOAD_MAX)]
    assert len(chunks) > 2048
    assert len(chunks) <= _UDP_FRAG_MAX_PER_GROUP

    r = _UDPReassembler(44)
    for off, chunk in enumerate(chunks):
        assert r.add_data(off, off == len(chunks) - 1, chunk)
    assert r.complete()
    assert _udp_decompress(r.reassemble()) == raw


def test_bug42_receiver_does_not_ack_unrepresentable_fragment():
    import threading
    from visold.network.udp.session import UDPSession

    s = UDPSession.__new__(UDPSession)
    s._liveness_lock = threading.Lock()
    s._liveness_expired = False
    s._last_hb_recv = 0.0
    s._last_hb_packet_recv = 0.0
    acks = []
    s.send_ack = acks.append
    # If dispatcher mistakenly proceeds, fail loudly.
    s._get_or_create_reassembler = lambda _fid: (_ for _ in ()).throw(
        AssertionError('invalid fragment must be rejected before reassembly'))
    s.on_packet(_F_FRAG, 99, 1, _UDP_FRAG_MAX_PER_GROUP, b'x')
    assert acks == []
