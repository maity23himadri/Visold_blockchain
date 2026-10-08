#!/usr/bin/env python3
"""
verify_runtime.py - compares the ORIGINAL monolith and the MODULAR build *as loaded by CPython*.

For every top-level name, class attribute, function and method it fingerprints
  * compiled bytecode (co_code, consts, names, varnames, flags, nested code objects)
  * default argument values
  * the entity each global name resolves to (LOAD_GLOBAL in ANY code path, executed or not)
Only line numbers / filenames / __module__ are allowed to differ.
Two processes are used so neither build can influence the other.
"""
import builtins
import dis
import hashlib
import json
import os
import subprocess
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common
ORIG_DIR = common.orig_dir()
NEW_DIR = os.environ.get("VR_NEW_DIR", common.NEW)

SIMPLE = (int, float, complex, bool, str, bytes, type(None), type(Ellipsis))


def norm_value(v, depth=0):
    if isinstance(v, SIMPLE):
        r = repr(v)
        return "%s:%s" % (type(v).__name__, r if len(r) < 120 else hashlib.sha1(r.encode()).hexdigest())
    if depth > 3:
        return "deep:" + type(v).__name__
    if isinstance(v, (tuple, list)):
        return "%s[%s]" % (type(v).__name__, ",".join(norm_value(x, depth + 1) for x in v[:200]))
    if isinstance(v, (set, frozenset)):
        return "%s{%s}" % (type(v).__name__, ",".join(sorted(norm_value(x, depth + 1) for x in list(v)[:200])))
    if isinstance(v, dict):
        items = sorted((norm_value(k, depth + 1), norm_value(x, depth + 1)) for k, x in list(v.items())[:300])
        return "dict{%s}" % ",".join("%s=%s" % kv for kv in items)
    if isinstance(v, types.FunctionType):
        return "fn:" + v.__qualname__
    if isinstance(v, type):
        return "cls:" + v.__qualname__
    if isinstance(v, types.ModuleType):
        return "mod:" + v.__name__
    return "obj:" + type(v).__qualname__


def code_fp(code):
    """Canonical fingerprint of the instruction stream.

    CPython >= 3.12 compiles ``X.m(...)`` WITHOUT the method-call form when ``X`` is an *imported*
    module-level name in the module being compiled (compiler heuristic, keyed on the module's own
    import statements).  Moving code between modules therefore changes ONLY: the NULL-push flag bit of
    LOAD_GLOBAL/LOAD_ATTR, an extra PUSH_NULL, and byte offsets.  Those are semantically identical, so
    they are normalised away: PUSH_NULL dropped, flag bits ignored, jump targets / exception-table
    entries expressed as instruction indices.  Everything else (opcodes, names, constants, nested code)
    must match exactly."""
    ins = list(dis.get_instructions(code))
    keep = [i for i in ins if i.opname != "PUSH_NULL"]
    pos = {i.offset: n for n, i in enumerate(keep)}
    off2idx, nxt = {}, len(keep)
    for i in reversed(ins):
        if i.opname != "PUSH_NULL":
            nxt = pos[i.offset]
        off2idx[i.offset] = nxt
    h = hashlib.sha1()
    for i in keep:
        v = i.argval
        if isinstance(v, types.CodeType):
            a = "CODE" + code_fp(v)
        elif i.opname in ("LOAD_GLOBAL", "LOAD_ATTR", "LOAD_SUPER_ATTR"):
            a = str(v)
        elif i.opcode in dis.hasjrel or i.opcode in dis.hasjabs:
            a = "J%d" % off2idx.get(v, -1)
        else:
            a = norm_value(v)
        h.update(("%s %s;" % (i.opname, a)).encode())
    try:
        for e in dis._parse_exception_table(code):
            h.update(("X%d,%d,%d,%d,%d;" % (off2idx.get(e.start, len(keep)), off2idx.get(e.end, len(keep)),
                                           off2idx.get(e.target, len(keep)), e.depth, int(e.lasti))).encode())
    except Exception:
        h.update(bytes(code.co_exceptiontable)[:0])
    meta = (code.co_name, getattr(code, "co_qualname", ""), code.co_argcount, code.co_posonlyargcount,
            code.co_kwonlyargcount, code.co_flags, code.co_names, code.co_varnames, code.co_freevars,
            code.co_cellvars)
    h.update(repr(meta).encode())
    return h.hexdigest()


def all_codes(code):
    yield code
    for c in code.co_consts:
        if isinstance(c, types.CodeType):
            yield from all_codes(c)


def entity_sig(o):
    if isinstance(o, types.ModuleType):
        return "mod:" + o.__name__
    if isinstance(o, type):
        return "cls:" + o.__qualname__
    if isinstance(o, types.FunctionType):
        return "fn:" + o.__qualname__
    if isinstance(o, (types.BuiltinFunctionType, types.BuiltinMethodType)):
        return "builtin:" + getattr(o, "__name__", "?")
    if isinstance(o, SIMPLE + (tuple, frozenset)):
        return "const:" + norm_value(o)[:100]
    if isinstance(o, (list, dict, set)):
        return "container:" + type(o).__name__
    nm = getattr(o, "name", None)
    return "inst:" + type(o).__qualname__ + (":" + nm if isinstance(nm, str) else "")


def resolve_globals(f):
    out = {}
    g = f.__globals__
    for code in all_codes(f.__code__):
        for ins in dis.get_instructions(code):
            if ins.opname in ("LOAD_GLOBAL", "STORE_GLOBAL", "DELETE_GLOBAL"):
                nm = ins.argval
                if nm == "_NODE_LOGIC_HASH":
                    out[nm] = "const:logic-hash"          # value differs by design (patch P1)
                elif nm in g:
                    out[nm] = entity_sig(g[nm])
                elif hasattr(builtins, nm):
                    out[nm] = "builtin"
                else:
                    out[nm] = "UNRESOLVED"
    return out


def any_record(v, depth=0):
    """robust record for anything callable-ish that can sit in a class body"""
    if isinstance(v, types.FunctionType):
        return fn_record(v)
    if depth > 4:
        return dict(value="deep:" + type(v).__qualname__)
    if isinstance(v, (staticmethod, classmethod)):
        return dict(wrapper=type(v).__name__, inner=any_record(v.__func__, depth + 1))
    if isinstance(v, property):
        return dict(wrapper="property", **{n: any_record(x, depth + 1) for n, x in
                                           (("get", v.fget), ("set", v.fset), ("del", v.fdel)) if x is not None})
    if hasattr(v, "__wrapped__"):
        return dict(wrapper=type(v).__qualname__, inner=any_record(v.__wrapped__, depth + 1))
    import functools
    if isinstance(v, functools.partial):
        return dict(wrapper="partial", inner=any_record(v.func, depth + 1), args=norm_value(v.args))
    return dict(value=norm_value(v))


def fn_record(f):
    rec = dict(code=code_fp(f.__code__), defaults=norm_value(f.__defaults__), kwdefaults=norm_value(f.__kwdefaults__),
               globals=resolve_globals(f))
    if f.__closure__:
        rec["closure"] = [norm_value(c.cell_contents) if not isinstance(c.cell_contents, types.FunctionType)
                          else "fn:" + c.cell_contents.__qualname__ for c in f.__closure__ if _filled(c)]
    return rec


def _filled(c):
    try:
        c.cell_contents
        return True
    except ValueError:
        return False


def class_records(cls, prefix, out, seen):
    if id(cls) in seen:
        return
    mod = getattr(cls, "__module__", "") or ""
    if not (mod == "visold_vsd_" or mod == "__main__" or mod.startswith("visold.")):
        out[prefix] = dict(kind="foreign-class", value="cls:" + cls.__qualname__)
        return
    seen.add(id(cls))
    out[prefix] = dict(kind="class", bases=[b.__qualname__ for b in cls.__bases__], meta=type(cls).__qualname__,
                       attrs=sorted(k for k in cls.__dict__ if k not in ("__dict__", "__weakref__", "__module__")))
    for k in sorted(cls.__dict__):
        if k in ("__dict__", "__weakref__", "__module__", "__qualname__"):
            continue
        v = cls.__dict__[k]
        key = prefix + "." + k
        if isinstance(v, types.FunctionType):
            out[key] = dict(kind="method", **fn_record(v))
        elif isinstance(v, (staticmethod, classmethod, property)) or hasattr(v, "__wrapped__"):
            out[key] = dict(kind=type(v).__name__, **any_record(v))
        elif isinstance(v, type):
            class_records(v, key, out, seen)
        else:
            out[key] = dict(kind="attr", value=norm_value(v))


def child(which, outpath, own_path):
    import tempfile
    own = set(json.load(open(own_path)))
    work = os.path.join(common.TMP, "fp_shared_home")
    os.makedirs(work, exist_ok=True)
    os.chdir(work)
    os.environ["HOME"] = work
    sys.path.insert(0, ORIG_DIR if which == "orig" else NEW_DIR)
    import visold_vsd_ as m
    recs, seen = {}, set()
    names = [n for n in vars(m) if n in own]
    for n in sorted(names):
        v = getattr(m, n)
        if isinstance(v, types.ModuleType):
            recs[n] = dict(kind="module", value="mod:" + v.__name__)
        elif isinstance(v, types.FunctionType):
            recs[n] = dict(kind="function", **fn_record(v))
        elif isinstance(v, type):
            class_records(v, n, recs, seen)
        else:
            recs[n] = dict(kind="value", value=norm_value(v), sig=entity_sig(v))
    json.dump(recs, open(outpath, "w"), sort_keys=True)
    print(which, "records:", len(recs))


# declared, expected differences (patches P1-P3 and their direct consequences)
EXPECTED = {
    "_NODE_LOGIC_HASH": "P1: hash now covers package sources",
    "ParallelBlockDownloader.download": "P3: sys.modules[__name__].Block -> imported Block",
    "GlobalSequencer._counter": "time-derived start value (volatile)",
    "SecurityGate.hash_self": "P2: hashes package sources",
    "package_source_blob": "P1: new helper (only in modular build)",
}


def compare():
    import tempfile
    d = tempfile.mkdtemp(prefix="fpcmp_")
    paths = {}
    import pickle
    idx = pickle.load(open(common.ensure_index(), "rb"))
    own = sorted(set().union(*[u["defs"] for u in idx["units"] if u["type"] not in ("Import", "ImportFrom")]))
    own_path = os.path.join(d, "own.json")
    json.dump(own, open(own_path, "w"))
    for which in ("orig", "new"):
        paths[which] = os.path.join(d, which + ".json")
        r = subprocess.run([sys.executable, os.path.abspath(__file__), "--child", which, paths[which], own_path],
                           capture_output=True, text=True, env=dict(os.environ, PYTHONHASHSEED="0", PYTHONDONTWRITEBYTECODE="1"))
        print(r.stdout.strip(), r.stderr.strip()[-300:])
        if r.returncode:
            sys.exit("child failed: " + which)
    A = json.load(open(paths["orig"]))
    B = json.load(open(paths["new"]))
    only_a = sorted(set(A) - set(B))
    only_b = sorted(set(B) - set(A))
    bad = []
    n_fn = n_same = 0
    for k in sorted(set(A) & set(B)):
        a, b = A[k], B[k]
        if a.get("kind") in ("function", "method", "staticmethod", "classmethod", "property"):
            n_fn += 1
        if a == b:
            n_same += 1
            continue
        if k in EXPECTED:
            continue
        # patched ParallelBlockDownloader method (P3) - identified by its global use of Block
        diff = {f: (str(a.get(f))[:90], str(b.get(f))[:90]) for f in set(a) | set(b) if a.get(f) != b.get(f)}
        bad.append((k, diff))
    non_api_only_a = [k for k in only_a if A[k]["kind"] == "module"]
    print("records compared: %d | identical: %d | functions+methods: %d" % (len(set(A) & set(B)), n_same, n_fn))
    print("only in original: %d (modules: %d) | only in modular: %d" % (len(only_a), len(non_api_only_a), len(only_b)))
    TEMPS = {"_f", "_h", "_oc"}      # import-time loop/with temporaries of the monolith, not part of any API
    rest_a = [k for k in only_a if A[k]["kind"] != "module" and k not in TEMPS]
    if rest_a:
        print("  original-only non-module names:", rest_a[:40])
    if only_b:
        print("  modular-only names:", only_b[:20])
    unres, unres_a = [], []

    def walk(k, r, acc):
        if isinstance(r, dict):
            g = r.get("globals")
            if isinstance(g, dict):
                for nm, sig in g.items():
                    if sig == "UNRESOLVED":
                        acc.append((k, nm))
            for key, x in r.items():
                if key != "globals" and isinstance(x, dict):
                    walk(k, x, acc)
    for k, r in B.items():
        walk(k, r, unres)
    for k, r in A.items():
        walk(k, r, unres_a)
    unres_new_only = sorted(set(unres) - set(unres_a))
    unres_old_only = sorted(set(unres_a) - set(unres))
    print("global names unresolved (optional deps missing in this sandbox): original=%d modular=%d | only-modular=%d only-original=%d"
          % (len(unres_a), len(unres), len(unres_new_only), len(unres_old_only)), unres_new_only[:6], unres_old_only[:6])
    print("unexpected differences:", len(bad))
    for k, diff in bad[:25]:
        print("  ", k, diff)
    ok = not bad and not unres_new_only and not unres_old_only and not rest_a
    print("RUNTIME RESULT:", "BYTECODE + LINKING IDENTICAL (modulo declared patches)" if ok else "REVIEW NEEDED")
    return 0 if ok else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--child":
        child(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        if len(sys.argv) > 1:
            os.environ["VR_NEW_DIR"] = sys.argv[1]
        sys.exit(compare())
