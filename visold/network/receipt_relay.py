# ─────────────────────────────────────────────────────────────────────────────
# Visold Authenticated Relay Receipts (VARR)
# Non-consensus, temporary, proof-carrying wallet mailbox for pruned history.
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations

import hashlib
import json
import time
from typing import Dict, Iterable, List, Optional, Tuple

from visold.crypto.ecc import ecdsa_verify, pub_from_hex, pub_to_address, sig_from_hex, sig_to_hex
from visold.crypto.hashing import sha256
from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.kernel.units import to_satoshi
from visold.ledger.transaction import Transaction
from visold.network.spv import SPVClient


_RECEIPT_DOMAIN = "VSD-VARR-RECEIPT-V1"
_ACK_DOMAIN = "VSD-VARR-ACK-V1"


def _canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _is_hex(s: object, n: int) -> bool:
    if not isinstance(s, str) or len(s) != n:
        return False
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


class ReceiptRelayManager:
    """Build, verify and persist compact authenticated transaction receipts.

    Security model:
      * Relay/custodian peers are untrusted.
      * The original tx signature authenticates the compact signed-field preimage.
      * tx_id is recomputed from that preimage.
      * A Merkle proof binds tx_id to the canonical block header retained after pruning.
      * ACKs are signed by the receiver wallet before relay copies become deletable.

    This module never mutates consensus state and never treats a receipt as money.
    Receipts are wallet-history metadata only; balances still come from block/snapshot
    consensus state.
    """

    def __init__(self, blockchain, storage, wallet, node_id: str):
        self.blockchain = blockchain
        self.storage = storage
        self.wallet = wallet
        self.node_id = str(node_id)

    # ── deterministic mailbox placement ──────────────────────────────────
    @staticmethod
    def mailbox_key(receiver: str, slot: int) -> str:
        return sha256(
            f"VSD-VARR-MAILBOX|{Config.CHAIN_ID}|{receiver}|{int(slot)}".encode()
        )

    @staticmethod
    def slots() -> range:
        return range(int(Config.RECEIPT_REPLICA_SLOTS))

    # ── compact transaction authentication ───────────────────────────────
    @staticmethod
    def _signed_fields_from_tx(tx: Transaction) -> List[List[str]]:
        # _canonical_fields already stores data as data_hash, so even a huge VVM
        # payload does not get duplicated into the relay receipt.
        return [[str(k), str(v)] for k, v in tx._canonical_fields()]

    @staticmethod
    def _signed_fields_tuple(receipt: dict) -> Optional[Tuple[Tuple[str, str], ...]]:
        raw = receipt.get("signed_fields")
        if not isinstance(raw, list) or not raw or len(raw) > 32:
            return None
        out = []
        for item in raw:
            if not (isinstance(item, list) and len(item) == 2
                    and isinstance(item[0], str) and isinstance(item[1], str)):
                return None
            if len(item[0]) > 64 or len(item[1]) > 4096:
                return None
            out.append((item[0], item[1]))
        return tuple(out)

    @staticmethod
    def _field_map(fields: Tuple[Tuple[str, str], ...]) -> Dict[str, str]:
        return {k: v for k, v in fields}

    def build_receipt(self, block, tx: Transaction) -> Optional[dict]:
        if tx.sender == "COINBASE" or not tx.receiver:
            return None
        try:
            fields = self._signed_fields_from_tx(tx)
            proof = SPVClient.get_merkle_proof(
                list(block.transactions), tx.tx_id, block_height=block.index)
            if proof is None:
                return None
            base = {
                "domain": _RECEIPT_DOMAIN,
                "version": 1,
                "chain_id": str(Config.CHAIN_ID),
                "block_height": int(block.index),
                "block_hash": str(block.block_hash),
                "merkle_root": str(block.merkle_root),
                "tx_id": str(tx.tx_id),
                "signed_fields": fields,
                "pub_hex": str(tx.pub_hex),
                "sig_hex": str(tx.sig_hex),
                "merkle_proof": proof,
            }
            base["receipt_id"] = sha256(_canonical_json(base))
            if len(_canonical_json(base)) > int(Config.RECEIPT_MAX_BYTES):
                log.warning("[VARR] receipt %s exceeds max compact size", tx.tx_id[:12])
                return None
            ok, _ = self.verify_receipt(base, require_canonical=True)
            return base if ok else None
        except Exception as exc:
            log.debug("[VARR] receipt build failed for %s: %s", tx.tx_id[:12], exc)
            return None

    def verify_receipt(self, receipt: dict, *, require_canonical: bool = True) -> Tuple[bool, str]:
        try:
            if not isinstance(receipt, dict):
                return False, "receipt is not an object"
            if len(_canonical_json(receipt)) > int(Config.RECEIPT_MAX_BYTES):
                return False, "receipt exceeds size limit"
            if receipt.get("domain") != _RECEIPT_DOMAIN or receipt.get("version") != 1:
                return False, "unsupported receipt domain/version"
            if str(receipt.get("chain_id", "")) != str(Config.CHAIN_ID):
                return False, "wrong chain_id"
            rid = receipt.get("receipt_id", "")
            if not _is_hex(rid, 64):
                return False, "invalid receipt_id"
            without_id = dict(receipt)
            without_id.pop("receipt_id", None)
            if sha256(_canonical_json(without_id)) != rid:
                return False, "receipt_id mismatch"
            txid = receipt.get("tx_id", "")
            if not _is_hex(txid, 64):
                return False, "invalid tx_id"
            fields = self._signed_fields_tuple(receipt)
            if fields is None:
                return False, "malformed signed_fields"
            fmap = self._field_map(fields)
            expected_names = [k for k, _ in Transaction(
                sender="x", receiver="y", amount=1, timestamp=1)._canonical_fields()]
            if [k for k, _ in fields] != expected_names:
                return False, "signed_fields schema/order mismatch"
            if fmap.get("chain_id") != str(Config.CHAIN_ID):
                return False, "signed transaction belongs to another chain"
            preimage = Transaction._encode_v2_fields(fields)
            if sha256(preimage) != txid:
                return False, "tx_id does not match signed fields"
            pub_hex = receipt.get("pub_hex", "")
            sig_hex = receipt.get("sig_hex", "")
            pub = pub_from_hex(pub_hex)
            if pub_to_address(pub) != fmap.get("sender"):
                return False, "sender/pubkey binding mismatch"
            sig = sig_from_hex(sig_hex)
            if not ecdsa_verify(pub, hashlib.sha256(preimage).digest(), sig):
                return False, "invalid transaction signature"
            height = int(receipt.get("block_height", -1))
            if height < 0:
                return False, "invalid block height"
            block_hash = receipt.get("block_hash", "")
            merkle_root = receipt.get("merkle_root", "")
            if not (_is_hex(block_hash, 64) and _is_hex(merkle_root, 64)):
                return False, "invalid block commitment"
            proof = receipt.get("merkle_proof")
            if not isinstance(proof, list) or len(proof) > 64:
                return False, "invalid Merkle proof"
            if not SPVClient.verify_merkle_proof(txid, proof, merkle_root):
                return False, "Merkle proof mismatch"
            if require_canonical:
                local = self.blockchain.get_block(height)
                if local is None:
                    return False, "canonical header unavailable"
                if local.block_hash != block_hash:
                    return False, "receipt references non-canonical block"
                if local.merkle_root != merkle_root:
                    return False, "receipt Merkle root differs from canonical header"
            return True, "OK"
        except Exception as exc:
            return False, f"receipt verification error: {exc}"

    def receipt_summary(self, receipt: dict) -> dict:
        fields = self._signed_fields_tuple(receipt) or tuple()
        fmap = self._field_map(fields)
        def as_int(name: str, default: int = 0) -> int:
            try:
                return int(fmap.get(name, str(default)))
            except Exception:
                return default
        return {
            "receipt_id": receipt["receipt_id"],
            "tx_id": receipt["tx_id"],
            "block_height": int(receipt["block_height"]),
            "block_hash": receipt["block_hash"],
            "sender": fmap.get("sender", ""),
            "receiver": fmap.get("receiver", ""),
            "amount_sat": as_int("amount_sat"),
            "timestamp": as_int("timestamp"),
            "tx_type": fmap.get("tx_type", ""),
        }

    # ── aux-SQLite relay persistence ─────────────────────────────────────
    def _conn(self):
        return self.storage._conn()

    def store_relay_receipt(self, receipt: dict, slot: int) -> Tuple[bool, str]:
        ok, reason = self.verify_receipt(receipt, require_canonical=True)
        if not ok:
            return False, reason
        slot = int(slot)
        if slot < 0 or slot >= int(Config.RECEIPT_REPLICA_SLOTS):
            return False, "invalid mailbox slot"
        summary = self.receipt_summary(receipt)
        now = int(time.time())
        try:
            with self.storage._aux_lock:
                c = self._conn()
                c.execute(
                    """INSERT OR IGNORE INTO relay_receipts
                       (receipt_id,receiver,slot,block_height,block_hash,receipt_json,stored_at,delivered_at)
                       VALUES (?,?,?,?,?,?,?,0)""",
                    (summary["receipt_id"], summary["receiver"], slot,
                     summary["block_height"], summary["block_hash"],
                     _canonical_json(receipt).decode("utf-8"), now))
                c.commit()
            return True, "stored"
        except Exception as exc:
            return False, f"receipt storage error: {exc}"

    def get_mailbox(self, receiver: str, slot: int, limit: Optional[int] = None) -> List[dict]:
        limit = max(1, min(int(limit or Config.RECEIPT_QUERY_LIMIT),
                           int(Config.RECEIPT_QUERY_LIMIT)))
        now_height = -1
        try:
            now_height = int(self.blockchain.height())
        except Exception:
            pass
        max_age = int(getattr(Config, "RECEIPT_MAX_AGE_BLOCKS", 0))
        cutoff = (now_height - max_age) if max_age > 0 and now_height >= 0 else -1
        try:
            with self.storage._aux_lock:
                c = self._conn()
                if cutoff >= 0:
                    rows = c.execute(
                        """SELECT receipt_json FROM relay_receipts
                           WHERE receiver=? AND slot=? AND delivered_at=0 AND block_height>=?
                           ORDER BY block_height ASC, receipt_id ASC LIMIT ?""",
                        (receiver, int(slot), cutoff, limit)).fetchall()
                else:
                    rows = c.execute(
                        """SELECT receipt_json FROM relay_receipts
                           WHERE receiver=? AND slot=? AND delivered_at=0
                           ORDER BY block_height ASC, receipt_id ASC LIMIT ?""",
                        (receiver, int(slot), limit)).fetchall()
            out = []
            for row in rows:
                raw = row[0] if not hasattr(row, 'keys') else row['receipt_json']
                try: out.append(json.loads(raw))
                except Exception: pass
            return out
        except Exception:
            return []

    def held_receipts(self, limit: int = 128) -> List[Tuple[int, dict]]:
        try:
            with self.storage._aux_lock:
                rows = self._conn().execute(
                    """SELECT slot,receipt_json FROM relay_receipts
                       WHERE delivered_at=0 ORDER BY stored_at ASC LIMIT ?""",
                    (max(1, int(limit)),)).fetchall()
            out=[]
            for r in rows:
                try: out.append((int(r[0]), json.loads(r[1])))
                except Exception: pass
            return out
        except Exception:
            return []

    def deliver_to_local_wallet(self, receipt: dict) -> Tuple[bool, str]:
        ok, reason = self.verify_receipt(receipt, require_canonical=True)
        if not ok:
            return False, reason
        s = self.receipt_summary(receipt)
        if s["receiver"] != self.wallet.address:
            return False, "receipt is not addressed to this wallet"
        now = int(time.time())
        try:
            with self.storage._aux_lock:
                c=self._conn()
                c.execute(
                    """INSERT OR IGNORE INTO wallet_receipts
                       (receipt_id,block_height,block_hash,sender,receiver,amount_sat,tx_type,timestamp,receipt_json,received_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (s["receipt_id"],s["block_height"],s["block_hash"],s["sender"],s["receiver"],
                     s["amount_sat"],s["tx_type"],s["timestamp"],
                     _canonical_json(receipt).decode("utf-8"),now))
                c.commit()
            return True, "delivered"
        except Exception as exc:
            return False, f"local receipt storage error: {exc}"

    def local_wallet_receipts(self, limit: int = 100) -> List[dict]:
        try:
            with self.storage._aux_lock:
                rows=self._conn().execute(
                    """SELECT receipt_id,block_height,block_hash,sender,receiver,amount_sat,tx_type,timestamp
                       FROM wallet_receipts ORDER BY block_height DESC, receipt_id DESC LIMIT ?""",
                    (max(1,min(int(limit),1000)),)).fetchall()
            keys=("receipt_id","block_height","block_hash","sender","receiver","amount_sat","tx_type","timestamp")
            return [dict(zip(keys, tuple(r))) for r in rows]
        except Exception:
            return []

    # ── receiver-authenticated deletion ──────────────────────────────────
    def make_ack(self, receipt_id: str) -> dict:
        payload = f"{_ACK_DOMAIN}|{Config.CHAIN_ID}|{self.wallet.address}|{receipt_id}".encode()
        sig = sig_to_hex(self.wallet.sign(payload))
        return {
            "domain": _ACK_DOMAIN,
            "version": 1,
            "chain_id": str(Config.CHAIN_ID),
            "receiver": self.wallet.address,
            "receipt_id": receipt_id,
            "pub_hex": self.wallet.pub_hex,
            "sig_hex": sig,
        }

    @staticmethod
    def verify_ack(ack: dict) -> Tuple[bool, str]:
        try:
            if not isinstance(ack, dict) or ack.get("domain") != _ACK_DOMAIN or ack.get("version") != 1:
                return False, "bad ACK domain/version"
            if str(ack.get("chain_id", "")) != str(Config.CHAIN_ID):
                return False, "wrong ACK chain"
            receiver = str(ack.get("receiver", ""))
            rid = str(ack.get("receipt_id", ""))
            if not receiver or not _is_hex(rid,64):
                return False, "bad ACK receiver/receipt_id"
            pub = pub_from_hex(str(ack.get("pub_hex", "")))
            if pub_to_address(pub) != receiver:
                return False, "ACK pubkey does not own receiver"
            sig = sig_from_hex(str(ack.get("sig_hex", "")))
            payload=f"{_ACK_DOMAIN}|{Config.CHAIN_ID}|{receiver}|{rid}".encode()
            if not ecdsa_verify(pub, hashlib.sha256(payload).digest(), sig):
                return False, "invalid receiver ACK signature"
            return True, "OK"
        except Exception as exc:
            return False, f"ACK verification error: {exc}"

    def accept_ack(self, ack: dict) -> Tuple[bool, str]:
        ok, reason = self.verify_ack(ack)
        if not ok:
            return False, reason
        rid=str(ack["receipt_id"]); receiver=str(ack["receiver"]); now=int(time.time())
        try:
            with self.storage._aux_lock:
                c=self._conn()
                # ACK only authorizes deletion of receipts actually addressed to
                # the signing receiver.  A valid signature for another wallet
                # cannot delete this mailbox's data.
                row=c.execute(
                    "SELECT 1 FROM relay_receipts WHERE receipt_id=? AND receiver=? LIMIT 1",
                    (rid,receiver)).fetchone()
                if row is None:
                    return True, "ACK valid; receipt not held here"
                c.execute(
                    """INSERT OR REPLACE INTO relay_receipt_acks
                       (receipt_id,receiver,ack_json,acked_at) VALUES (?,?,?,?)""",
                    (rid,receiver,_canonical_json(ack).decode("utf-8"),now))
                c.execute(
                    "UPDATE relay_receipts SET delivered_at=? WHERE receipt_id=? AND receiver=?",
                    (now,rid,receiver))
                c.commit()
            return True, "ACK accepted"
        except Exception as exc:
            return False, f"ACK persistence error: {exc}"

    def gc_delivered(self) -> int:
        cutoff=int(time.time())-int(Config.RECEIPT_ACK_GRACE_SECS)
        try:
            with self.storage._aux_lock:
                c=self._conn()
                cur=c.execute(
                    "DELETE FROM relay_receipts WHERE delivered_at>0 AND delivered_at<=?",
                    (cutoff,))
                n=max(0,int(cur.rowcount or 0)); c.commit(); return n
        except Exception:
            return 0
