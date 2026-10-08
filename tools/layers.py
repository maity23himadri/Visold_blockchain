"""layers.py - the dependency layering of the bounded contexts (single source of truth).

A context may import its own modules and modules of contexts in LOWER layers only.
Enforced by tools/check_architecture.py; used by tools/gen_docs.py.
"""
LAYERS = [
    ("kernel",),
    ("crypto", "economics", "governance"),
    ("consensus", "rollup", "selfhealing"),
    ("resilience", "vm", "wallet"),
    ("ledger",),
    ("state", "storage"),
    ("mempool",),
    ("chain",),
    ("network",),
    ("api", "identity", "mining", "testing"),
    ("node",),
    ("cli",),
]
