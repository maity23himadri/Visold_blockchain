#!/usr/bin/env python3
"""Cross-validate analyzer.py against CPython's own symtable (independent implementation).
needs the original monolith (see tools/common.py)."""
import os, pickle, symtable, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common
idx = pickle.load(open(common.ensure_index(),'rb'))
L = idx['lines']; mod = idx['mod_names']

def sym_globals(tab, is_module_level=True, out=None):
    out = set() if out is None else out
    for s in tab.get_symbols():
        n = s.get_name()
        if not s.is_referenced(): continue
        if tab.get_type() == 'module':
            if not s.is_assigned() or True:
                out.add(n)
        elif s.is_global():
            out.add(n)
        elif tab.get_type() == 'class' and not (s.is_assigned() or s.is_parameter() or s.is_local()):
            out.add(n)
    for ch in tab.get_children():
        sym_globals(ch, False, out)
    return out

bad = 0; checked = 0
for u in idx['units']:
    if u['type'] in ('Import','ImportFrom'): continue
    src = '\n'.join(L[u['node_start']-1:u['end']])
    try:
        tab = symtable.symtable(src, '<unit>', 'exec')
    except SyntaxError as e:
        print('symtable syntax error unit', u['idx'], e); bad += 1; continue
    ref = sym_globals(tab) & mod
    mine = (u['eager'] | u['lazy'])
    own = u['defs']
    # for module-level unit own defs referenced inside the unit are not "global refs" in my model when def-units
    d1 = (ref - mine) - own
    d2 = (mine - ref) - own
    checked += 1
    if d1 or d2:
        bad += 1
        if bad <= 25:
            print(f"unit {u['idx']} [{u['type']} {u['name']}] lines {u['node_start']}-{u['end']}: only-symtable={sorted(d1)[:8]} only-mine={sorted(d2)[:8]}")
print('checked', checked, 'mismatching units', bad)
