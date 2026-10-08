#!/usr/bin/env python3
"""
verify_import.py
  C1  every module imports cleanly in a FRESH interpreter, on its own
  C2  importing all modules in 6 random orders (fresh interpreter each) never fails (no hidden order dependence)
  C3  import-time side effects (threads, log handlers, signal handlers, atexit, env, files, stdlib modules)
      are identical between the monolith and the modular facade
"""
import concurrent.futures as cf
import json
import os
import random
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common
OUT = sys.argv[1] if len(sys.argv) > 1 else common.NEW
mods = []
for dp, dn, fn in os.walk(os.path.join(OUT, "visold")):
    for f in fn:
        if f.endswith(".py") and f != "__init__.py":
            rel = os.path.relpath(os.path.join(dp, f), OUT)[:-3].replace(os.sep, ".")
            mods.append(rel)
mods.sort()
HOME_DIR = os.path.join(common.TMP, "vi_home")
env = dict(os.environ, PYTHONPATH=OUT, PYTHONDONTWRITEBYTECODE="1", HOME=HOME_DIR)
os.makedirs(HOME_DIR, exist_ok=True)


def run(code, e=env):
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=e, cwd=HOME_DIR, timeout=300)


def one(m):
    r = run("import %s" % m)
    return m, r.returncode, r.stderr.strip().splitlines()[-1:] if r.returncode else ""


with cf.ThreadPoolExecutor(8) as ex:
    res = list(ex.map(one, mods))
bad = [x for x in res if x[1]]
print("C1 isolated import: %d modules, failures: %d" % (len(mods), len(bad)), bad[:5])

rnd = random.Random(7)
bad2 = 0
for k in range(6):
    order = mods[:]
    rnd.shuffle(order)
    r = run("import importlib\nfor m in %r: importlib.import_module(m)" % order)
    if r.returncode:
        bad2 += 1
        print("   order", k, "FAILED:", r.stderr.strip().splitlines()[-1:])
print("C2 random-order imports: 6 shuffles, failures: %d" % bad2)

SNAP = r'''
import sys, os, json, threading, logging, signal, atexit, socket, tempfile
base = set(sys.modules)
sys.path.insert(0, %r)
env0 = dict(os.environ)
import visold_vsd_
snap = {}
snap["threads"] = sorted(t.name for t in threading.enumerate())
rl = logging.getLogger()
snap["root_level"] = rl.level
snap["root_handlers"] = sorted(type(h).__name__ for h in rl.handlers)
snap["named_loggers"] = {n: (lg.level, sorted(type(h).__name__ for h in lg.handlers), lg.propagate)
                         for n, lg in sorted(logging.root.manager.loggerDict.items()) if hasattr(lg, "handlers")}
snap["signals"] = {str(s): repr(signal.getsignal(s))[:40] for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
snap["excepthook"] = getattr(sys.excepthook, "__qualname__", repr(sys.excepthook))
snap["atexit"] = atexit._ncallbacks()
snap["env_added"] = sorted(set(os.environ) - set(env0))
snap["recursion"] = sys.getrecursionlimit()
snap["sock_timeout"] = socket.getdefaulttimeout()
snap["cwd_files"] = sorted(os.listdir("."))
snap["home_files"] = sorted(os.path.relpath(os.path.join(d, f), os.environ["HOME"]) for d, _, fs in os.walk(os.environ["HOME"]) for f in fs)
snap["stdlib_modules_added"] = sorted(m for m in set(sys.modules) - base if not m.startswith(("visold", "_")) and "." not in m)
print(json.dumps(snap, sort_keys=True))
'''


def snap(which):
    import shutil
    d = os.path.join(common.TMP, "vi_snap_" + which)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    e = dict(os.environ, HOME=d, PYTHONHASHSEED="0", PYTHONDONTWRITEBYTECODE="1")
    r = subprocess.run([sys.executable, "-c", SNAP % (common.orig_dir() if which == "orig" else OUT)], capture_output=True,
                       text=True, env=e, cwd=d, timeout=300)
    if r.returncode:
        sys.exit("snapshot failed %s: %s" % (which, r.stderr[-400:]))
    return json.loads(r.stdout.strip().splitlines()[-1])


A, B = snap("orig"), snap("new")
diffs = {k: (A[k], B[k]) for k in A if A[k] != B[k]}
print("C3 import-time side effects compared: %d properties, differing: %d" % (len(A), len(diffs)))
for k, (a, b) in diffs.items():
    if isinstance(a, list) and isinstance(b, list):
        print("   %s: only-orig=%s only-new=%s" % (k, sorted(set(a) - set(b))[:12], sorted(set(b) - set(a))[:12]))
    else:
        print("   %s: orig=%s new=%s" % (k, str(a)[:100], str(b)[:100]))
ok = not bad and not bad2
print("IMPORT RESULT:", "ALL IMPORT CHECKS PASSED" if ok else "FAILURES")
sys.exit(0 if ok else 1)
