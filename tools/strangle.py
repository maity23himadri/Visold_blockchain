#!/usr/bin/env python3
"""
strangle.py - Strangler-Fig migration in waves.

Wave k extracts every bounded context whose dependency level is <= k-1 (always a down-closed set, so extracted
modules never import from the remaining monolith).  The remainder is the ORIGINAL file with those units cut out and
replaced by a seam of imports - so after every wave the program is complete, runnable and verifiable.
The last wave leaves only the entry blocks, which is the final facade `visold_vsd_.py`.
No wave contains a loader for legacy code: the monolith simply shrinks.
"""
import json, os, re, shutil, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import split as S, check_map

import common
SRC = common.ORIG
ROOT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(common.TMP, "waves")
TOOLS = os.path.dirname(os.path.abspath(__file__))
shutil.rmtree(ROOT, ignore_errors=True)
sp = S.Splitter(SRC, os.path.join(common.TMP, "unused"))
E = sp.check_dag()
ctx = lambda m: m.split("/")[0]
ctxs = sorted({ctx(m) for m in E})
CE = {c: set() for c in ctxs}
for m in E:
    for t in E[m]:
        if ctx(m) != ctx(t):
            CE[ctx(m)].add(ctx(t))
lv = check_map.topo_levels(ctxs, CE)
total_lines = len(sp.L)
report, done = [], set()
for k in range(0, max(lv.values()) + 1):
    new_ctx = sorted(c for c in ctxs if lv[c] == k)
    extracted = {m for m in E if lv[ctx(m)] <= k}
    out = os.path.join(ROOT, "w%02d" % (k + 1))
    os.makedirs(out)
    sp.write_package(out, only=extracted)
    rem = sp.remainder_source(extracted)
    with open(os.path.join(out, "visold_vsd_.py"), "w", encoding="utf-8", newline="\n") as f:
        f.write(rem)
    gen_lines = sum(sp.module_source(m).count("\n") for m in extracted)
    r = dict(wave=k + 1, contexts=new_ctx, modules=len(extracted), remainder_lines=rem.count("\n"),
             remaining_pct=round(100.0 * rem.count("\n") / total_lines, 1), pkg_lines=gen_lines)
    c = subprocess.run([sys.executable, "-m", "compileall", "-q", out], capture_output=True, text=True)
    r["compile"] = "ok" if c.returncode == 0 else "FAIL"
    v = subprocess.run([sys.executable, os.path.join(TOOLS, "verify_runtime.py"), out], capture_output=True, text=True)
    m_ = re.search(r"records compared: (\d+) \| identical: (\d+) \| functions\+methods: (\d+)", v.stdout)
    r["runtime"] = "OK" if "RUNTIME RESULT: BYTECODE" in v.stdout else "REVIEW: " + v.stdout[-300:]
    r["records"] = m_.groups() if m_ else None
    a = subprocess.run([sys.executable, os.path.join(TOOLS, "ab_run.py"), out], capture_output=True, text=True,
                       env=dict(os.environ, AB_QUICK="1"))
    r["ab"] = "OK" if "IDENTICAL BEHAVIOUR" in a.stdout else "DIFF: " + a.stdout[-400:]
    report.append(r)
    print("W%02d +%-34s mods=%3d remainder=%5d lines (%4.1f%%) compile=%s runtime=%s ab=%s" % (
        k + 1, ",".join(new_ctx), len(extracted), r["remainder_lines"], r["remaining_pct"], r["compile"],
        r["runtime"][:2], r["ab"][:2]), flush=True)
json.dump(report, open(os.path.join(ROOT, "waves_report.json"), "w"), indent=1)
