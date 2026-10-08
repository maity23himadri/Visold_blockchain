#!/usr/bin/env python3
"""
verify_static.py - proves the split moved code without altering it.

 A1  every original unit exists in exactly one generated module with an
     IDENTICAL AST (patched units compared against their declared patch)
 A2  the multiset of source lines (comments included) is preserved:
     original lines - import statements - doc header + declared patch delta
 A3  import graph of the generated package is acyclic (modules and contexts),
     has no relative imports, no import of the facade, and every imported
     name exists in its target module
"""
import ast
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import split as S              # noqa: E402
import analyzer                # noqa: E402
import check_map               # noqa: E402

import common              # noqa: E402
OUT = sys.argv[1] if len(sys.argv) > 1 else common.NEW
SRC = common.ORIG
fails = []


def fail(msg):
    fails.append(msg)
    print("  FAIL:", msg)


sp = S.Splitter(SRC, os.path.join(common.TMP, "unused"))
tree = sp.tree
U = sp.U
nodes = dict(zip([u["idx"] for u in U], tree.body))

# ───────────────────────────── load generated modules
mods = sorted(m for m in sp.units_of if m not in ("DOCS", "ENTRY"))
gen = {}


def is_header(n):
    if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str):
        return True
    if isinstance(n, (ast.Import, ast.ImportFrom)):
        return True
    if isinstance(n, ast.If) and isinstance(n.test, ast.Name) and n.test.id == "TYPE_CHECKING":
        return True
    if (isinstance(n, ast.Try) and len(n.body) == 1 and isinstance(n.body[0], ast.ImportFrom)
            and n.body[0].module.startswith("visold.") and len(n.handlers) == 1
            and ast.unparse(n.handlers[0].type) == "ImportError"):
        return True
    return False


for m in mods:
    path = os.path.join(OUT, "visold", *m.split("/")) + ".py"
    text = open(path, encoding="utf-8").read()
    t = ast.parse(text)
    k = 0
    while k < len(t.body) and is_header(t.body[k]):
        k += 1
    hdr_end = t.body[k - 1].end_lineno if k else 0
    gen[m] = dict(text=text, tree=t, header=t.body[:k], body=t.body[k:], lines=text.split("\n"), hdr_end=hdr_end)

# ───────────────────────────── A1: AST equality
print("A1 AST equality per unit")
n_cmp = 0
for m in mods:
    expected = []
    for u in sp.units_of[m]:
        if u["idx"] in sp.patch_of:
            lines, fc = sp.texts[u["idx"]]
            expected.extend(ast.parse("\n".join(lines[fc:])).body)
        else:
            expected.append(nodes[u["idx"]])
    got = gen[m]["body"]
    if len(expected) != len(got):
        fail("%s: expected %d body nodes, found %d" % (m, len(expected), len(got)))
        continue
    for e, g in zip(expected, got):
        n_cmp += 1
        if ast.dump(e) != ast.dump(g):
            fail("%s: AST differs for node at generated line %d" % (m, g.lineno))
unpatched = sum(1 for u in U if u["type"] not in S.IMPORTS and u["idx"] not in sp.patch_of
                and sp.mod_of[u["idx"]] not in ("DOCS", "ENTRY"))
print("   compared %d nodes in %d modules (%d unpatched units byte-for-byte AST-identical)" % (n_cmp, len(mods), unpatched))

# patched units must differ from the original ONLY by the declared text edits
for idx_, p in sp.patch_of.items():
    lines, fc = sp.texts[idx_]
    print("   patch %-15s unit '%s' (orig L%d-%d)" % (p["id"], U[idx_]["name"] or U[idx_]["type"], U[idx_]["node_start"], U[idx_]["end"]))

# ───────────────────────────── A2: line multiset
print("A2 line multiset (comments + code)")
L = sp.L
imp_lines = set()
for u in U:
    if u["type"] in S.IMPORTS:
        imp_lines.update(range(u["node_start"], u["end"] + 1))
u0 = U[0]
orig = collections.Counter()
for i, ln in enumerate(L, 1):
    if i in imp_lines or i <= u0["end"] or not ln.strip():
        continue
    orig[ln] += 1
# declared patch delta
for idx_, p in sp.patch_of.items():
    for old, new in p.get("replace", []):
        for ln in old.split("\n"):
            if ln.strip():
                orig[ln] -= 1
        for ln in new.split("\n"):
            if ln.strip():
                orig[ln] += 1
    for ln in p.get("prepend", "").split("\n"):
        if ln.strip():
            orig[ln] += 1
genc = collections.Counter()
for m in mods:
    for ln in gen[m]["lines"][gen[m]["hdr_end"]:]:
        if ln.strip():
            genc[ln] += 1
fac = open(os.path.join(OUT, "visold_vsd_.py"), encoding="utf-8").read().split("\n")
# the ENTRY blocks appear verbatim at the end of the facade
entry_lines = []
for u in sp.units_of["ENTRY"]:
    entry_lines += [x for x in sp.texts[u["idx"]][0]]
ft = "\n".join(fac)
for u in sp.units_of["ENTRY"]:
    blk = "\n".join(sp.texts[u["idx"]][0]).strip("\n")
    if blk not in ft:
        fail("facade does not contain ENTRY unit verbatim (orig L%d)" % u["node_start"])
    for ln in sp.texts[u["idx"]][0]:
        if ln.strip():
            genc[ln] += 1
missing = +(orig - genc)
extra = +(genc - orig)
if missing:
    fail("lines lost: %d, e.g. %r" % (sum(missing.values()), list(missing.items())[:3]))
if extra:
    fail("lines added: %d, e.g. %r" % (sum(extra.values()), list(extra.items())[:3]))
print("   original body lines (non-blank): %d | generated: %d | lost: %d | unexpected: %d" % (
    sum(orig.values()), sum(genc.values()), sum(missing.values()), sum(extra.values())))

# ───────────────────────────── A3: import graph
print("A3 import graph / layering")
defs_of = {}
for m in mods:
    names = set()
    for n in gen[m]["header"] + gen[m]["body"]:
        names |= analyzer.module_bound_names(n)
    defs_of[m] = names
E = collections.defaultdict(set)
n_edges = 0
for m in mods:
    for n in ast.walk(gen[m]["tree"]):
        pass
    def runtime_imports(body):
        for n in body:
            if isinstance(n, ast.If) and isinstance(n.test, ast.Name) and n.test.id == "TYPE_CHECKING":
                continue
            if isinstance(n, (ast.Import, ast.ImportFrom)):
                yield n
            elif isinstance(n, ast.Try):
                for x in n.body:
                    if isinstance(x, (ast.Import, ast.ImportFrom)):
                        yield x
    for n in runtime_imports(gen[m]["tree"].body):
        if isinstance(n, ast.ImportFrom):
            if n.level:
                fail("%s: relative import" % m)
            if n.module and n.module.startswith("visold"):
                tgt = n.module[len("visold."):].replace(".", "/")
                if tgt not in defs_of:
                    fail("%s: imports unknown module %s" % (m, n.module))
                    continue
                E[m].add(tgt)
                n_edges += 1
                for a in n.names:
                    if a.name not in defs_of[tgt]:
                        fail("%s: 'from %s import %s' but target does not define it" % (m, n.module, a.name))
            if n.module and "visold_vsd_" in n.module:
                fail("%s imports the facade" % m)
        elif isinstance(n, ast.Import):
            for a in n.names:
                if a.name.startswith("visold_vsd_"):
                    fail("%s imports the facade" % m)
comps = [c for c in check_map.sccs(mods, E) if len(c) > 1]
if comps:
    fail("module import cycles: %r" % comps)
CE = collections.defaultdict(set)
for m in E:
    for t in E[m]:
        if m.split("/")[0] != t.split("/")[0]:
            CE[m.split("/")[0]].add(t.split("/")[0])
ctxs = sorted(set(m.split("/")[0] for m in mods))
cc = [c for c in check_map.sccs(ctxs, CE) if len(c) > 1]
if cc:
    fail("context-level cycles: %r" % cc)
print("   %d modules, %d import edges, module cycles: %d, contexts: %d, context cycles: %d" % (
    len(mods), n_edges, len(comps), len(ctxs), len(cc)))
print("RESULT:", "ALL STATIC CHECKS PASSED" if not fails else "%d FAILURE(S)" % len(fails))
sys.exit(1 if fails else 0)
