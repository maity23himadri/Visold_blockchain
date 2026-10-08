#!/usr/bin/env python3
"""
check_architecture.py - keeps the modular layout healthy.  Pure standard library; reads only the package sources
(no imports are executed), so it is safe and fast to run on a phone:

    python tools/check_architecture.py

Rules enforced
  R1  no import cycles between modules                        (runtime imports; `if TYPE_CHECKING:` blocks ignored)
  R2  bounded contexts form a DAG that respects LAYERS below  (a context may only import from lower layers)
  R3  absolute imports only; nothing inside the package imports the visold_vsd_ entry facade
  R4  every `from visold.x import name` names something x really defines
  R5  every module compiles
Exit code 0 = healthy.
"""
import ast
import collections
import os
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(ROOT, "visold")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from layers import LAYERS   # noqa: E402  (lower index = lower layer)
LEVEL = {c: i for i, grp in enumerate(LAYERS) for c in grp}

mods = {}
for dp, dn, fn in os.walk(PKG):
    dn[:] = [d for d in dn if d != "__pycache__"]
    for f in fn:
        if f.endswith(".py") and f != "__init__.py":
            p = os.path.join(dp, f)
            mods["visold." + os.path.relpath(p, PKG)[:-3].replace(os.sep, ".")] = p
fails = []


def bound(tree):
    out = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(n.name)
        elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            out.add(n.id)
        elif isinstance(n, ast.Import):
            out |= {(a.asname or a.name.split(".")[0]) for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            out |= {(a.asname or a.name) for a in n.names}
        elif isinstance(n, ast.ExceptHandler) and n.name:
            out.add(n.name)
    return out


trees, defs, edges = {}, {}, collections.defaultdict(set)
for m, p in mods.items():
    src = open(p, encoding="utf-8").read()
    try:
        trees[m] = ast.parse(src, p)                                   # R5
    except SyntaxError as e:
        fails.append("R5 %s does not compile: %s" % (m, e))
        continue
    defs[m] = bound(trees[m])


def runtime_imports(body):
    for n in body:
        if isinstance(n, ast.If) and isinstance(n.test, ast.Name) and n.test.id == "TYPE_CHECKING":
            continue
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            yield n
        elif isinstance(n, (ast.Try, ast.If)):
            for blk in (n.body, getattr(n, "orelse", [])):
                yield from runtime_imports(blk)


for m, t in trees.items():
    for n in runtime_imports(t.body):
        if isinstance(n, ast.ImportFrom):
            if n.level:
                fails.append("R3 %s: relative import" % m)
            tgt = n.module or ""
            if tgt.startswith("visold_vsd_"):
                fails.append("R3 %s imports the entry facade" % m)
            if tgt.startswith("visold."):
                if tgt not in mods:
                    fails.append("R4 %s imports unknown module %s" % (m, tgt))
                    continue
                edges[m].add(tgt)
                for a in n.names:
                    if a.name not in defs[tgt]:
                        fails.append("R4 %s: '%s' is not defined in %s" % (m, a.name, tgt))
        else:
            for a in n.names:
                if a.name.startswith("visold_vsd_"):
                    fails.append("R3 %s imports the entry facade" % m)

# R1: cycles (iterative Tarjan)
index, low, on, st, comps, c = {}, {}, set(), [], [], [0]
sys.setrecursionlimit(10000)


def sc(v):
    index[v] = low[v] = c[0]; c[0] += 1; st.append(v); on.add(v)
    for w in edges.get(v, ()):
        if w not in index:
            sc(w); low[v] = min(low[v], low[w])
        elif w in on:
            low[v] = min(low[v], index[w])
    if low[v] == index[v]:
        comp = []
        while True:
            w = st.pop(); on.discard(w); comp.append(w)
            if w == v:
                break
        if len(comp) > 1:
            comps.append(comp)


for v in mods:
    if v not in index:
        sc(v)
for comp in comps:
    fails.append("R1 import cycle: %s" % " <-> ".join(sorted(comp)))

# R2: layering
ctx = lambda m: m.split(".")[1]
for m, ts in edges.items():
    for t in ts:
        a, b = ctx(m), ctx(t)
        if a == b:
            continue
        if a not in LEVEL or b not in LEVEL:
            fails.append("R2 context not in LAYERS: %s or %s (add it to tools/check_architecture.py)" % (a, b))
        elif LEVEL[b] >= LEVEL[a]:
            fails.append("R2 %s (%s, layer %d) imports %s (%s, layer %d) - dependencies must point DOWN"
                         % (m, a, LEVEL[a], t, b, LEVEL[b]))

ne = sum(len(v) for v in edges.values())
print("modules: %d | import edges: %d | contexts: %d" % (len(mods), ne, len({ctx(m) for m in mods})))
for f in fails[:40]:
    print("  FAIL", f)
print("ARCHITECTURE:", "OK - no cycles, layering respected" if not fails else "%d violation(s)" % len(fails))
sys.exit(1 if fails else 0)
