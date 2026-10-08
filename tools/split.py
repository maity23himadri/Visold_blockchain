#!/usr/bin/env python3
"""
split.py - mechanical, verifiable modularization of the Visold monolith.

Every top-level unit is moved VERBATIM into the module chosen by domain_map.py.
The only generated code is: module headers, import statements, package
__init__ files and the thin entry/facade.  The only edited code is the short,
explicit PATCHES list below (constructs that depend on *where* the code lives:
__file__ and sys.modules[__name__]).

usage: split.py [--src FILE] [--out DIR]
"""
import ast
import collections
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import analyzer            # noqa: E402
import check_map           # noqa: E402
import domain_map          # noqa: E402

PKG = "visold"
IMPORTS = ("Import", "ImportFrom")
DUNDERS = {"__file__", "__name__", "__doc__", "__spec__", "__package__", "__builtins__", "__loader__"}

# ──────────────────────────────────────────────────────────────────────────
# PATCHES: the complete list of edited code (everything else is byte-identical)
# ──────────────────────────────────────────────────────────────────────────
HELPER_SOURCE_BLOB = '''def package_source_blob() -> bytes:
    """Deterministic byte blob of the whole ``visold`` package source.

    The monolith fingerprinted its own single source file.  After
    modularization the equivalent software identity is the ordered
    concatenation of every ``.py`` file of the package (relative POSIX path,
    NUL, file bytes, NUL).  Two nodes running identical package sources
    therefore compute identical hashes regardless of install location.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    entries = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
        for fn in sorted(filenames):
            if fn.endswith(".py"):
                full = os.path.join(dirpath, fn)
                entries.append((os.path.relpath(full, root).replace(os.sep, "/"), full))
    entries.sort()
    blob = bytearray()
    for rel, full in entries:
        with open(full, "rb") as fh:
            blob += rel.encode("utf-8") + b"\\0" + fh.read() + b"\\0"
    return bytes(blob)


'''

PATCHES = [
    dict(
        id="P1-logic-hash",
        select=lambda u: u["node_start"] == 3579,
        prepend=HELPER_SOURCE_BLOB,
        replace=[(
            "try:\n    with open(__file__, 'rb') as _f:\n"
            "        _NODE_LOGIC_HASH: str = hashlib.sha256(_f.read()).hexdigest()[:32]\n"
            "except Exception:\n",
            "try:\n"
            "    _NODE_LOGIC_HASH: str = hashlib.sha256(package_source_blob()).hexdigest()[:32]\n"
            "except Exception:\n")],
        adds=["os"], defines={"package_source_blob": "kernel/source_identity"},
        why="open(__file__) hashed the single monolith file; now hashes the package sources."),
    dict(
        id="P2-hash-self",
        select=lambda u: u["name"] == "SecurityGate",
        replace=[(
            "            with open(__file__, 'rb') as f:\n"
            "                return sha256(f.read())\n",
            "            return sha256(package_source_blob())\n")],
        adds=["package_source_blob"],
        why="SecurityGate.hash_self() hashed __file__ (the monolith); now hashes the package sources."),
    dict(
        id="P3-block-lookup",
        select=lambda u: u["name"] == "ParallelBlockDownloader",
        replace=[(
            "            # Import Block from the main module namespace contextually\n"
            "            import sys\n"
            "            mod = sys.modules[__name__]\n"
            "            block = mod.Block.from_dict(block_dict)\n",
            "            # Block lives in visold.ledger.block (was: sys.modules[__name__].Block)\n"
            "            block = Block.from_dict(block_dict)\n")],
        adds=["Block"],
        why="sys.modules[__name__] resolved Block in the monolith namespace; now a normal import."),
]


# ──────────────────────────────────────────────────────────────────────────
def modpath(m):
    return PKG + "." + m.replace("/", ".")


def build_import_table(tree):
    plain = collections.defaultdict(list)    # top-level name -> [dotted names]
    aliased = {}                              # bound alias -> dotted module
    fromimp = {}                              # bound name -> (module, name, asname)
    for n in tree.body:
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.asname:
                    aliased[a.asname] = a.name
                else:
                    top = a.name.split(".")[0]
                    if a.name not in plain[top]:
                        plain[top].append(a.name)
        elif isinstance(n, ast.ImportFrom):
            assert n.level == 0
            for a in n.names:
                assert a.name != "*"
                fromimp[a.asname or a.name] = (n.module, a.name, a.asname)
    cats = [set(plain), set(aliased), set(fromimp)]
    for i in range(3):
        for j in range(i + 1, 3):
            assert not (cats[i] & cats[j]), cats[i] & cats[j]
    return plain, aliased, fromimp


def render_std(names, table):
    plain, aliased, fromimp = table
    p, a, groups = set(), set(), collections.defaultdict(set)
    for nm in names:
        if nm in plain:
            for d in plain[nm]:
                p.add("import " + d)
        elif nm in aliased:
            a.add("import %s as %s" % (aliased[nm], nm))
        elif nm in fromimp:
            mod, name, asname = fromimp[nm]
            groups[mod].add(name + (" as " + asname if asname else ""))
        else:
            raise KeyError(nm)
    out = sorted(p) + sorted(a)
    for mod in sorted(groups):
        out.append(_wrap_from(mod, sorted(groups[mod])))
    return out


def _wrap_from(mod, names, indent=""):
    one = "%sfrom %s import %s" % (indent, mod, ", ".join(names))
    if len(one) <= 96:
        return one
    body = ",\n".join("%s    %s" % (indent, n) for n in names)
    return "%sfrom %s import (\n%s,\n%s)" % (indent, mod, body, indent)


def ranges(units):
    spans = sorted((u["node_start"], u["end"]) for u in units)
    merged = []
    for a, b in spans:
        if merged and a <= merged[-1][1] + 2:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    return ", ".join("L%d-%d" % (a, b) if a != b else "L%d" % a for a, b in merged)


class Splitter:
    def __init__(self, src, out):
        self.src, self.out = src, out
        self.idx = analyzer.analyze(src)
        self.text = self.idx["text"]
        self.L = self.idx["lines"]
        self.U = self.idx["units"]
        self.tree = ast.parse(self.text)
        self.table = build_import_table(self.tree)
        self.mod_of = check_map.assign(domain_map, self.idx)
        self.licence = "\n".join(self.L[0:9])
        self.cython = "\n".join(self.L[10:19])
        self._prepare()

    # ---------------------------------------------------------------- prep
    def _prepare(self):
        U, L = self.U, self.L
        # names definitely bound / possibly undefined
        self.definite, self.bound = set(), set()
        for u in U:
            if u["type"] in IMPORTS:
                continue
            self.bound |= u["defs"]
            self.definite |= u["definite"]
        self.owner = {}
        for u in U:
            if u["type"] in IMPORTS:
                continue
            m = self.mod_of[u["idx"]]
            for d in u["defs"]:
                if d in self.owner:
                    assert self.owner[d] == m, (d, self.owner[d], m)
                self.owner[d] = m
        self.patch_of = {}
        for p in PATCHES:
            hit = [u for u in U if u["type"] not in IMPORTS and p["select"](u)]
            assert len(hit) == 1, (p["id"], len(hit))
            self.patch_of[hit[0]["idx"]] = p
            for nm, mod in p.get("defines", {}).items():
                self.owner[nm] = mod
                self.definite.add(nm)
        # texts (leading trivia attaches forward; import statements are dropped)
        imp_lines = set()
        for u in U:
            if u["type"] in IMPORTS:
                imp_lines.update(range(u["node_start"], u["end"] + 1))
        self.texts, prev_end = {}, 0
        for u in U:
            if u["type"] in IMPORTS:
                continue
            a, b = prev_end + 1, u["end"]
            keep = [i for i in range(a, b + 1) if i not in imp_lines]
            lines = [L[i - 1] for i in keep]
            first_code = sum(1 for i in keep if i < u["node_start"])
            self.texts[u["idx"]] = (lines, first_code)
            prev_end = b
        # apply patches
        self.patch_log = []
        for idx_, p in self.patch_of.items():
            lines, fc = self.texts[idx_]
            code = "\n".join(lines[fc:])
            for old, new in p.get("replace", []):
                assert code.count(old) == 1, (p["id"], "replace target must match exactly once")
                code = code.replace(old, new)
            code = p.get("prepend", "") + code
            self.texts[idx_] = (lines[:fc] + code.split("\n"), fc)
            self.patch_log.append((p["id"], p["why"], self.mod_of[idx_]))
        self.units_of = collections.defaultdict(list)
        for u in U:
            if u["type"] in IMPORTS:
                continue
            self.units_of[self.mod_of[u["idx"]]].append(u)

    # ------------------------------------------------------------ analysis
    def runtime_names(self, m):
        r = set()
        for u in self.units_of[m]:
            r |= u["eager"] | u["lazy"] | u["dyn"]
            p = self.patch_of.get(u["idx"])
            if p:
                r |= set(p.get("adds", ()))
        return r

    def own_defs(self, m):
        d = set()
        for u in self.units_of[m]:
            d |= u["defs"]
        for p in PATCHES:
            for nm, mod in p.get("defines", {}).items():
                if mod == m:
                    d.add(nm)
        return d

    def deps(self, m):
        """module -> {dep module: [names]} including patch-added edges"""
        own = self.own_defs(m)
        out = collections.defaultdict(set)
        names = self.runtime_names(m)
        for nm in names:
            if nm in own or nm in DUNDERS:
                continue
            o = self.owner.get(nm)
            if o is not None and o != m:
                out[o].add(nm)
        return out

    def check_dag(self):
        mods = [m for m in self.units_of if m not in ("DOCS", "ENTRY")]
        E = {m: set(self.deps(m)) for m in mods}
        comps = [c for c in check_map.sccs(mods, E) if len(c) > 1]
        assert not comps, comps
        return E

    # ---------------------------------------------------------- generation
    def module_source(self, m):
        units = self.units_of[m]
        runtime = self.runtime_names(m)
        own = self.own_defs(m)
        ann = set()
        for u in units:
            ann |= u["ann"]
        ann = (ann - runtime) - own
        std, cross, guarded, typing_x = set(), collections.defaultdict(set), collections.defaultdict(set), collections.defaultdict(set)
        for nm in runtime:
            if nm in own or nm in DUNDERS:
                continue
            o = self.owner.get(nm)
            if o is not None:
                (cross if nm in self.definite else guarded)[o].add(nm)
            elif nm in self.table[0] or nm in self.table[1] or nm in self.table[2]:
                std.add(nm)
            else:
                raise KeyError("%s: unresolved name %s" % (m, nm))
        for nm in ann:
            o = self.owner.get(nm)
            if o is not None and o != m:
                typing_x[o].add(nm)
            elif nm in self.table[0] or nm in self.table[1] or nm in self.table[2]:
                std.add(nm)
        if typing_x:
            std.add("TYPE_CHECKING")
        parts = []
        parts.append(self.licence)
        parts.append(self.cython)
        banner = ""
        first_lines, _ = self.texts[units[0]["idx"]]
        for ln in first_lines:
            s = ln.strip()
            if s.startswith("#") and "SECTION" in s:
                banner = s.lstrip("#").strip()
                break
        defs = [u["name"] for u in units if u["name"] and not u["name"].startswith("_")]
        doc = "%s\n\n%s\n%sOrigin: visold_vsd_.py %s" % (
            modpath(m), banner and ("Original section: " + banner + "\n") or "",
            ("Defines: " + ", ".join(defs[:8]) + (" ..." if len(defs) > 8 else "") + "\n") if defs else "",
            ranges(units))
        parts.append('"""' + doc.replace('"""', "'''") + '\n"""')
        imp = render_std(std, self.table)
        head = "\n".join(imp)
        xi = []
        for o in sorted(cross):
            xi.append(_wrap_from(modpath(o), sorted(cross[o])))
        gi = []
        for o in sorted(guarded):
            for nm in sorted(guarded[o]):
                gi.append("try:  # optional dependency: name may be undefined, exactly as in the monolith\n"
                          "    from %s import %s\nexcept ImportError:\n    pass" % (modpath(o), nm))
        ti = []
        if typing_x:
            ti.append("if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)")
            for o in sorted(typing_x):
                ti.append(_wrap_from(modpath(o), sorted(typing_x[o]), indent="    "))
        blocks = [x for x in ("\n".join(parts[:2]), parts[2], head, "\n".join(xi), "\n\n".join(gi), "\n".join(ti)) if x]
        # licence+cython comment block stays first; docstring after
        header = blocks[0] + "\n" + blocks[1]
        rest = "\n\n".join(blocks[2:])
        body = []
        for i, u in enumerate(units):
            lines, _ = self.texts[u["idx"]]
            while lines and not lines[0].strip():
                lines = lines[1:]
            while lines and not lines[-1].strip():
                lines = lines[:-1]
            body.append("\n".join(lines))
        return header + "\n\n" + rest + "\n\n\n" + "\n\n\n".join(body) + "\n"

    TEMPS = {"_e", "_reg_e", "_f", "_h", "_oc", "_ok", "_suite", "_sys_main"}   # loop/except/with temporaries

    def compute_exports(self, only=None):
        """names re-exported by the facade: (definite exports by module, conditionally-defined names)"""
        entry_defs = set()
        for u in self.units_of["ENTRY"]:
            entry_defs |= u["defs"]
        exports = collections.defaultdict(list)
        for nm in sorted(self.definite):
            o = self.owner.get(nm)
            if o and o not in ("DOCS", "ENTRY") and nm not in entry_defs and nm in self.bound and (only is None or o in only):
                exports[o].append(nm)
        cond = sorted(n for n in self.bound - self.definite
                      if self.owner.get(n) not in (None, "DOCS", "ENTRY") and n not in entry_defs
                      and n not in self.TEMPS and (only is None or self.owner[n] in only))
        return exports, cond

    def render_exports(self, exports, cond):
        mods = list(exports)
        first = {m: min(u["idx"] for u in self.units_of[m]) for m in mods}
        out = []
        for m in sorted(mods, key=lambda x: first[x]):
            out.append("# noqa: F401 - re-exported for backward compatibility")
            out.append(_wrap_from(modpath(m), exports[m]))
        out.append("")
        out.append("# conditionally defined names (optional dependencies): exported only if they exist, as before")
        for nm in cond:
            out.append("try:\n    from %s import %s  # noqa: F401\nexcept ImportError:\n    pass" % (modpath(self.owner[nm]), nm))
        return out

    def facade_source(self):
        exports, cond = self.compute_exports()
        out = [self.licence, "", '"""Visold (VSD) - entry point and compatibility facade (strangler-fig).\n\n'
               "The implementation now lives in the ``visold`` package (see docs/ARCHITECTURE.md).\n"
               "This file keeps the historical entry point (``python visold_vsd_.py ...``) and the\n"
               "historical flat namespace (``from visold_vsd_ import Blockchain``) working.\n"
               'It contains no implementation code and loads no legacy source.\n"""',
               "import os",
               "import sys",
               "",
               "",
               "def _find_root():",
               '    """folder that contains the visold/ package: next to this file, else next to argv[0], else the cwd"""',
               "    cands = []",
               "    try:",
               "        cands.append(os.path.dirname(os.path.abspath(__file__)))",
               "    except NameError:  # exec()-style launchers do not define __file__",
               "        pass",
               "    if sys.argv and sys.argv[0]:",
               "        cands.append(os.path.dirname(os.path.abspath(sys.argv[0])))",
               "    cands.append(os.getcwd())",
               "    for c in cands:",
               '        if os.path.isfile(os.path.join(c, "visold", "__init__.py")):',
               "            return c",
               "    return cands[0]",
               "",
               "",
               "_HERE = _find_root()",
               "if _HERE not in sys.path:",
               "    sys.path.insert(0, _HERE)",
               ""]
        out += self.render_exports(exports, cond)
        out.append("")
        for u in self.units_of["ENTRY"]:
            lines, _ = self.texts[u["idx"]]
            while lines and not lines[0].strip():
                lines = lines[1:]
            out.append("")
            out.append("\n".join(lines).rstrip())
        return "\n".join(out) + "\n", exports

    # ------------------------------------------------------- strangler waves
    def write_package(self, out, only=None):
        """write package modules (all, or only the given set) + __init__ files; returns module list"""
        mods = sorted(m for m in self.units_of if m not in ("DOCS", "ENTRY") and (only is None or m in only))
        dirs = set()
        for m in mods:
            path = os.path.join(out, PKG, *m.split("/")) + ".py"
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(self.module_source(m))
            parts = m.split("/")
            for i in range(1, len(parts)):
                dirs.add("/".join(parts[:i]))
        ctx_doc = getattr(domain_map, "CONTEXT_DOCS", {})
        for d in sorted(dirs) + [""]:
            path = os.path.join(out, PKG, *([p for p in d.split("/") if p] + ["__init__.py"]))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            title = PKG if not d else modpath(d)
            body = ctx_doc.get(d.split("/")[0], "Subpackage of the Visold protocol implementation.") if d else \
                "Visold (VSD) blockchain protocol - modular package.\nSee docs/ARCHITECTURE.md for the context map and layering rules."
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(self.licence + '\n\n"""%s\n\n%s\n"""\n' % (title, body))
        return mods

    def remainder_source(self, extracted):
        """the monolith with `extracted` modules cut out and replaced by imports (strangler seam)"""
        imp_lines = set()
        for u in self.U:
            if u["type"] in IMPORTS:
                imp_lines.update(range(u["node_start"], u["end"] + 1))
        delete, prev_end = set(), 0
        for u in self.U:
            if u["type"] in IMPORTS:
                continue
            a, b = prev_end + 1, u["end"]
            if self.mod_of[u["idx"]] in extracted:
                delete.update(i for i in range(a, b + 1) if i not in imp_lines)
            prev_end = b
        first_import_block_end = max(i for i in imp_lines if i < 1900)
        exports, cond = self.compute_exports(only=set(extracted))
        seam = ["", "# ── STRANGLER SEAM: names below now live in the visold package (%d modules extracted) ──" % len(extracted)]
        seam += self.render_exports(exports, cond)
        seam += [""]
        out = []
        for i, ln in enumerate(self.L, 1):
            if i in delete:
                continue
            out.append(ln)
            if i == first_import_block_end:
                out.extend(seam)
        return "\n".join(out)

    # --------------------------------------------------------------- write
    def write(self):
        out = self.out
        if os.path.exists(out):
            shutil.rmtree(out)
        os.makedirs(os.path.join(out, PKG))
        os.makedirs(os.path.join(out, "docs"))
        E = self.check_dag()
        mods = sorted(m for m in self.units_of if m not in ("DOCS", "ENTRY"))
        stats = {}
        dirs = set()
        for m in mods:
            src = self.module_source(m)
            path = os.path.join(out, PKG, *m.split("/")) + ".py"
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(src)
            parts = m.split("/")
            for i in range(1, len(parts)):
                dirs.add("/".join(parts[:i]))
            stats[m] = dict(lines=src.count("\n"), units=len(self.units_of[m]),
                            origin=ranges(self.units_of[m]), deps=sorted(E[m]))
        ctx_doc = getattr(domain_map, "CONTEXT_DOCS", {})
        for d in sorted(dirs) + [""]:
            path = os.path.join(out, PKG, *([p for p in d.split("/") if p] + ["__init__.py"]))
            title = PKG if not d else modpath(d)
            body = ctx_doc.get(d, ctx_doc.get(d.split("/")[0], "Subpackage of the Visold protocol implementation.") if d else
                               "Visold (VSD) blockchain protocol - modular package.\nSee docs/ARCHITECTURE.md for the context map and layering rules.")
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(self.licence + '\n\n"""%s\n\n%s\n"""\n' % (title, body))
        fac, exports = self.facade_source()
        with open(os.path.join(out, "visold_vsd_.py"), "w", encoding="utf-8", newline="\n") as f:
            f.write(fac)
        doc0 = ast.literal_eval(ast.get_source_segment(self.text, self.tree.body[0]))
        with open(os.path.join(out, "docs", "ORIGINAL_MODULE_DOCSTRING.txt"), "w", encoding="utf-8", newline="\n") as f:
            f.write(doc0)
        report = dict(modules=stats, patches=self.patch_log,
                      facade_exports=sum(len(v) for v in exports.values()),
                      guarded=sorted(n for n in self.bound - self.definite if n in self.owner))
        with open(os.path.join(out, "docs", "build_report.json"), "w", encoding="utf-8") as f:
            json.dump(report, f, indent=1, ensure_ascii=False)
        return report


if __name__ == "__main__":
    import common
    src = common.ORIG
    out = os.path.join(common.TMP, "build")
    a = sys.argv[1:]
    if "--src" in a:
        src = a[a.index("--src") + 1]
    if "--out" in a:
        out = a[a.index("--out") + 1]
    sp = Splitter(src, out)
    rep = sp.write()
    tot = sum(v["lines"] for v in rep["modules"].values())
    print("modules: %d | generated module lines: %d | facade exports: %d" % (len(rep["modules"]), tot, rep["facade_exports"]))
    for pid, why, m in rep["patches"]:
        print("  patch %-16s in %-24s %s" % (pid, m, why))
