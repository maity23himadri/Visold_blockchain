# Incoming Transfer Inbox — V4 patch (2026-10-27)

## Behaviour added

- Adds CLI menu option **30 — Incoming Transfers [N]**. `N` is the cumulative count of distinct incoming transfer notifications recorded by this wallet/node.
- After a remote transfer is successfully admitted to the receiver node's mempool, the receiver's local inbox records it and the live Recent Activity buffer receives an alert.
- The inbox persists in local `node_meta`, scoped to the receiving wallet. It keeps the latest 500 entries while preserving the cumulative count.
- Each entry lists the amount, sender identity/address, timestamp, transaction ID prefix, and a local status derived from retained canonical transaction storage and the current mempool.
- The CLI explicitly says a mempool sighting is **not confirmation**. If a transaction body is no longer in retained storage and the transaction is no longer in the mempool, the UI calls it **UNVERIFIED**, rather than falsely claiming it was never confirmed.

## Safety properties

- No transaction fields, validation rules, mempool admission rules, P2P message types, or consensus rules were changed.
- The recording hook is called only after `mempool.add(tx)` succeeds for a remote transaction.
- Only positive-value `transfer` transactions addressed exactly to this node's wallet qualify. Self-sends and `COINBASE` are excluded.
- Duplicate transaction IDs still present in the retained inbox do not increment the count or emit another alert.
- A sender name is displayed only when the local identity cache resolves to a matching confirmed name claim for that exact sender address. Otherwise, only the sender address is shown.
- Sender-supplied memos are not shown in this UI, avoiding terminal-control injection through memo text.
- Inbox failures are logged and do not reject or alter an otherwise admitted network transaction.

## Verification performed

- `python -m compileall -q ...` for the changed modules and new test: **passed**.
- Feature/UI regression command:
  `PYTHONPATH=. pytest -q tests/test_incoming_transfer_inbox_20261027.py tests/test_tui_frame_buffer.py tests/test_tui_input_synchronization.py tests/test_balance_history_recipient_fee_regression_20261019.py`
  **28 passed**.
- `PYTHONPATH=. python tools/check_architecture.py`: **ARCHITECTURE OK** (125 modules, 475 import edges, 22 contexts).
- `PYTHONPATH=. python visold_vsd_.py --help`: **exit 0**.
- Selected pruning/receipt integration run: **15 passed, 1 failed**. The failure is `tests/test_varr_receipt_relay.py::test_receipt_survives_body_pruning_and_preserves_sender` at the existing `bc.get_block(8).is_pruned is True` assertion. The same test and assertion also fail when run against the untouched original `V4.zip`, so this is a reproduced baseline failure, not attributed to this patch.
- `tools/verify_import.py` did not finish within 180 seconds; no pass is claimed for that audit.

## Files changed

- `visold/node/visold_node.py`
- `visold/state/engine.py`
- `visold/kernel/notifications.py`
- `visold/cli/interactive.py`
- `tests/test_incoming_transfer_inbox_20261027.py` (new)
