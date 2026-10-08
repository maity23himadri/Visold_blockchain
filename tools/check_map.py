#!/usr/bin/env python3
import bisect, collections, importlib, pickle, sys
sys.setrecursionlimit(100000)
import os as _os; sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))

def load(mapmod='domain_map'):
    dm = importlib.import_module(mapmod)
    importlib.reload(dm)
    import common
    idx = pickle.load(open(common.ensure_index(), 'rb'))
    return dm, idx

IMPORTS = ('Import', 'ImportFrom')

def assign(dm, idx):
    U = idx['units']
    bl = sorted(dm.BOUNDARIES)
    starts = [b[0] for b in bl]
    mod_of = {}
    import ast as _ast
    _tree = _ast.parse(idx['text'])
    for u, n in zip(U, _tree.body):
        if u['type'] in IMPORTS:
            continue
        if u['idx'] == 0:
            mod_of[0] = 'DOCS'
            continue
        if isinstance(n, _ast.If) and isinstance(n.test, _ast.Compare) and isinstance(n.test.left, _ast.Name) \
                and n.test.left.id == '__name__':
            mod_of[u['idx']] = 'ENTRY'
            continue
        i = bisect.bisect_right(starts, u['node_start']) - 1
        if i < 0:
            mod_of[u['idx']] = None
        else:
            mod_of[u['idx']] = bl[i][1]
    for k, v in dm.OVERRIDES.items():
        for u in U:
            if u['type'] in IMPORTS: continue
            if k == u['name'] or k == '@%d' % u['node_start'] or k in u['defs'] and len(u['defs']) == 1:
                mod_of[u['idx']] = v
    return mod_of

def module_graph(idx, mod_of, kinds=('eager', 'lazy')):
    U = idx['units']
    owner = collections.defaultdict(list)
    for u in U:
        if u['type'] in IMPORTS: continue
        for d in u['defs']:
            owner[d].append(u['idx'])
    G = collections.defaultdict(lambda: collections.defaultdict(list))  # M1 -> M2 -> [(unit, name, kind)]
    for u in U:
        if u['type'] in IMPORTS: continue
        m1 = mod_of[u['idx']]
        for kind in kinds:
            for n in u[kind]:
                for v in owner.get(n, []):
                    if v == u['idx']: continue
                    m2 = mod_of[v]
                    if m2 != m1:
                        G[m1][m2].append((u['idx'], v, n, kind))
    return G

def sccs(nodes, E):
    index = {}; low = {}; st = []; on = set(); res = []; c = [0]
    def sc(v):
        index[v] = low[v] = c[0]; c[0] += 1; st.append(v); on.add(v)
        for w in E.get(v, ()):
            if w not in index:
                sc(w); low[v] = min(low[v], low[w])
            elif w in on:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            comp = []
            while True:
                w = st.pop(); on.discard(w); comp.append(w)
                if w == v: break
            res.append(comp)
    for v in nodes:
        if v not in index: sc(v)
    return res

def topo_levels(nodes, E):
    """longest-path layering of an acyclic module graph (deps have LOWER level)"""
    lvl = {}
    def f(v):
        if v in lvl: return lvl[v]
        lvl[v] = 0
        lvl[v] = 1 + max([f(w) for w in E.get(v, ())] or [-1])
        return lvl[v]
    for v in nodes: f(v)
    return lvl

def main():
    dm, idx = load()
    U = idx['units']; L = idx['lines']
    mod_of = assign(dm, idx)
    un = [u['idx'] for u in U if u['type'] not in IMPORTS and mod_of.get(u['idx']) is None]
    if un:
        print('UNASSIGNED units:', [(U[i]['node_start'], U[i]['name']) for i in un][:20])
    mods = sorted(set(m for m in mod_of.values() if m))
    size = collections.Counter(); cnt = collections.Counter()
    for u in U:
        if u['type'] in IMPORTS: continue
        m = mod_of[u['idx']]
        size[m] += u['end'] - u['start'] + 1; cnt[m] += 1
    print(f"{len(mods)} modules, {sum(cnt.values())} units")
    # co-location: names bound by >1 non-import unit must share a module
    b = collections.defaultdict(set)
    for u in U:
        if u['type'] in IMPORTS: continue
        for d in u['defs']: b[d].add(mod_of[u['idx']])
    bad = {k: v for k, v in b.items() if len(v) > 1}
    if bad: print('CO-LOCATION VIOLATIONS:', bad)
    G = module_graph(idx, mod_of)
    E = {m: set(G[m].keys()) for m in G}
    comps = [c for c in sccs(mods, E) if len(c) > 1]
    print('module-level cycles:', len(comps))
    for c in comps:
        print('  CYCLE among', sorted(c))
        cs = set(c)
        for m1 in sorted(c):
            for m2 in sorted(G[m1]):
                if m2 in cs:
                    ex = G[m1][m2][:3]
                    desc = ', '.join(f"{(U[a]['name'] or U[a]['type'])}->{n}({k[0]})" for a, v, n, k in ex)
                    print(f"     {m1} -> {m2}  [{len(G[m1][m2])}]  e.g. {desc}")
    if '--levels' in sys.argv and not comps:
        lv = topo_levels(mods, E)
        for m in sorted(mods, key=lambda x: (lv[x], x)):
            print(f"  L{lv[m]:<2} {m:34} {cnt[m]:>3}u {size[m]:>6}L  deps={sorted(E.get(m, []))}")
    return dm, idx, mod_of, G, comps

if __name__ == '__main__' and '--ctx' not in sys.argv:
    main()

def context_graph(G):
    C = collections.defaultdict(lambda: collections.defaultdict(list))
    for m1 in G:
        for m2 in G[m1]:
            c1, c2 = m1.split('/')[0], m2.split('/')[0]
            if c1 != c2:
                C[c1][c2].extend((m1, m2, x) for x in G[m1][m2][:1])
    return C

def report_contexts():
    dm, idx, mod_of, G, comps = main()
    mods = sorted(set(m for m in mod_of.values() if m and m not in ('DOCS', 'ENTRY')))
    C = context_graph({m: {k: v for k, v in d.items() if k not in ('DOCS', 'ENTRY')} for m, d in G.items() if m not in ('DOCS', 'ENTRY')})
    ctxs = sorted(set(m.split('/')[0] for m in mods))
    E = {c: set(C[c].keys()) for c in C}
    cs = [c for c in sccs(ctxs, E) if len(c) > 1]
    print('\ncontexts:', len(ctxs), '| context-level cycles:', len(cs))
    for c in cs:
        cset = set(c)
        print('  CYCLE', sorted(c))
        for a in sorted(c):
            for b in sorted(C[a]):
                if b in cset:
                    ex = C[a][b][:2]
                    print(f"     {a} -> {b}: " + '; '.join(f"{m1}->{m2}" for m1, m2, _ in ex))
    if not cs:
        lv = topo_levels(ctxs, E)
        for c in sorted(ctxs, key=lambda x: (lv[x], x)):
            print(f"  C{lv[c]:<2} {c:12} -> {sorted(E.get(c, []))}")

if __name__ == '__main__' and '--ctx' in sys.argv:
    report_contexts()
