#!/usr/bin/env python3
"""
analyzer.py - scope-aware static analysis of a monolithic Python module.

Partitions the file into *units* (top-level statements + their leading
trivia, so that every source line belongs to exactly one unit) and computes,
for each unit:

  defs          names bound at module scope by the unit
  eager         module-level names needed while the unit is *executed*
                (decorators, bases, defaults, annotations, class-body code,
                module-level expressions)  -> must be importable at import time
  lazy          module-level names only needed when a function body runs
  gwrites       names rebound from inside functions through `global X`
  dyn           names reached through dynamic constructs (string/globals())

Name resolution implements Python's real scoping rules (class scopes are
skipped by nested functions, comprehensions have own scope, global/nonlocal).
"""
import ast
import builtins
import pickle
import sys

BUILTINS = set(dir(builtins))


# --------------------------------------------------------------------------
# scope model
# --------------------------------------------------------------------------
class Scope:
    __slots__ = ("kind", "bound", "gdecl", "ndecl", "parent", "name")

    def __init__(self, kind, parent, name=""):
        self.kind = kind          # module | function | class | lambda | comp
        self.bound = set()
        self.gdecl = set()
        self.ndecl = set()
        self.parent = parent
        self.name = name


def _pattern_names(p, out):
    for n in ast.walk(p):
        if isinstance(n, ast.MatchAs) and n.name:
            out.add(n.name)
        elif isinstance(n, ast.MatchStar) and n.name:
            out.add(n.name)
        elif isinstance(n, ast.MatchMapping) and n.rest:
            out.add(n.rest)


class _Binder(ast.NodeVisitor):
    """Collect names bound in ONE scope (does not descend into nested scopes)."""

    def __init__(self, scope):
        self.s = scope
        self.rebinds = set()      # names bound via an explicitly-global declaration

    def _bind(self, name):
        if name in self.s.gdecl:
            self.rebinds.add(name)
        elif name in self.s.ndecl:
            pass
        else:
            self.s.bound.add(name)

    # nested scopes: bind the def/class name only
    def visit_FunctionDef(self, n):
        self._bind(n.name)
        self._walrus(n.decorator_list, n.args.defaults, n.args.kw_defaults)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, n):
        self._bind(n.name)
        self._walrus(n.decorator_list, n.bases, [k.value for k in n.keywords])

    def visit_Lambda(self, n):
        self._walrus(n.args.defaults, n.args.kw_defaults)

    def _walrus(self, *groups):
        for g in groups:
            for e in g:
                if e is not None:
                    for x in ast.walk(e):
                        if isinstance(x, ast.NamedExpr) and isinstance(x.target, ast.Name):
                            self._bind(x.target.id)

    def _comp(self, n):
        for x in ast.walk(n):
            if isinstance(x, ast.NamedExpr) and isinstance(x.target, ast.Name):
                self._bind(x.target.id)
        # first iterator is evaluated in this scope; may hold walrus only (handled)

    visit_ListComp = visit_SetComp = visit_DictComp = visit_GeneratorExp = _comp

    def visit_Name(self, n):
        if isinstance(n.ctx, (ast.Store, ast.Del)):
            self._bind(n.id)

    def visit_Import(self, n):
        for a in n.names:
            self._bind(a.asname or a.name.split(".")[0])

    def visit_ImportFrom(self, n):
        for a in n.names:
            if a.name == "*":
                self.s.bound.add("*")
            else:
                self._bind(a.asname or a.name)

    def visit_ExceptHandler(self, n):
        if n.name:
            self._bind(n.name)
        self.generic_visit(n)

    def visit_Global(self, n):
        pass  # handled in the pre-pass

    def visit_Nonlocal(self, n):
        pass

    def visit_match_case(self, n):
        names = set()
        _pattern_names(n.pattern, names)
        for x in names:
            self._bind(x)
        self.generic_visit(n)


class _DeclScan(ast.NodeVisitor):
    """Find global/nonlocal declarations of ONE scope."""

    def __init__(self, scope):
        self.s = scope

    def visit_FunctionDef(self, n):
        pass

    visit_AsyncFunctionDef = visit_ClassDef = visit_Lambda = visit_FunctionDef

    def visit_ListComp(self, n):
        pass

    visit_SetComp = visit_DictComp = visit_GeneratorExp = visit_ListComp

    def visit_Global(self, n):
        self.s.gdecl.update(n.names)

    def visit_Nonlocal(self, n):
        self.s.ndecl.update(n.names)


def _fill_scope(scope, body, params=()):
    scan = _DeclScan(scope)
    for st in body:
        scan.visit(st)
    for p in params:
        scope.bound.add(p)
    b = _Binder(scope)
    for st in body:
        b.visit(st)
    return b.rebinds


def _params(args):
    out = [a.arg for a in args.posonlyargs + args.args + args.kwonlyargs]
    if args.vararg:
        out.append(args.vararg.arg)
    if args.kwarg:
        out.append(args.kwarg.arg)
    return out


# --------------------------------------------------------------------------
# main walker
# --------------------------------------------------------------------------
class Walker:
    def __init__(self, module_names):
        self.mod = module_names           # names bound at module scope (any unit)
        self.eager = set()
        self.lazy = set()
        self.gwrites = set()
        self.gwrite_funcs = {}            # name -> [function qualnames]
        self.undefined = set()
        self.dyn = set()
        self.names_seen_in_cls_body = set()
        self._qual = []

    # -- resolution --------------------------------------------------------
    def _resolve(self, name, scope):
        if scope.kind == "module":
            return "g"
        if name in scope.gdecl:
            return "g"
        if name in scope.bound:
            # class bodies fall back to globals when not yet assigned: be conservative
            if scope.kind == "class" and name in self.mod:
                return "both"
            return "l"
        if name in scope.ndecl:
            return "l"
        s = scope.parent
        while s is not None and s.kind != "module":
            if s.kind != "class":
                if name in s.gdecl:
                    return "g"
                if name in s.bound or name in s.ndecl:
                    return "l"
            s = s.parent
        return "g"

    def _use(self, name, scope, eager):
        r = self._resolve(name, scope)
        if r == "l":
            return
        if name in self.mod:
            (self.eager if eager else self.lazy).add(name)
        elif name not in BUILTINS:
            self.undefined.add(name)

    # -- traversal ---------------------------------------------------------
    def visit(self, node, scope, eager):
        t = type(node)
        m = getattr(self, "v_" + t.__name__, None)
        if m is not None:
            return m(node, scope, eager)
        for ch in ast.iter_child_nodes(node):
            self.visit(ch, scope, eager)

    def v_Name(self, n, scope, eager):
        if isinstance(n.ctx, ast.Load) or isinstance(n.ctx, ast.Del):
            self._use(n.id, scope, eager)
        elif isinstance(n.ctx, ast.Store):
            # a store to an explicitly-global name inside a function = rebinding
            if n.id in scope.gdecl and scope.kind in ("function", "lambda", "comp"):
                self.gwrites.add(n.id)
                self.gwrite_funcs.setdefault(n.id, []).append(".".join(self._qual) or "?")

    def v_Global(self, n, scope, eager):
        pass

    def _func_header(self, n, scope, eager):
        for d in n.decorator_list:
            self.visit(d, scope, eager)
        a = n.args
        for d in a.defaults:
            self.visit(d, scope, eager)
        for d in a.kw_defaults:
            if d is not None:
                self.visit(d, scope, eager)
        for arg in a.posonlyargs + a.args + a.kwonlyargs + [x for x in (a.vararg, a.kwarg) if x]:
            if arg.annotation is not None:
                self.visit(arg.annotation, scope, eager)
        if getattr(n, "returns", None) is not None:
            self.visit(n.returns, scope, eager)

    def v_FunctionDef(self, n, scope, eager):
        self._func_header(n, scope, eager)
        fs = Scope("function", scope, n.name)
        _fill_scope(fs, n.body, _params(n.args))
        self._qual.append(n.name)
        for st in n.body:
            self.visit(st, fs, False)
        self._qual.pop()

    v_AsyncFunctionDef = v_FunctionDef

    def v_Lambda(self, n, scope, eager):
        a = n.args
        for d in a.defaults:
            self.visit(d, scope, eager)
        for d in a.kw_defaults:
            if d is not None:
                self.visit(d, scope, eager)
        ls = Scope("lambda", scope, "<lambda>")
        for p in _params(a):
            ls.bound.add(p)
        self.visit(n.body, ls, False)

    def v_ClassDef(self, n, scope, eager):
        for d in n.decorator_list:
            self.visit(d, scope, eager)
        for b in n.bases:
            self.visit(b, scope, eager)
        for k in n.keywords:
            self.visit(k.value, scope, eager)
        cs = Scope("class", scope, n.name)
        _fill_scope(cs, n.body)
        self._qual.append(n.name)
        for st in n.body:
            self.visit(st, cs, eager)
        self._qual.pop()

    def _comp(self, n, scope, eager):
        gens = n.generators
        self.visit(gens[0].iter, scope, eager)
        cs = Scope("comp", scope, "<comp>")
        for g in gens:
            for x in ast.walk(g.target):
                if isinstance(x, ast.Name):
                    cs.bound.add(x.id)
        for x in ast.walk(n):  # walrus inside comprehension binds in enclosing scope; ignore
            pass
        for i, g in enumerate(gens):
            if i > 0:
                self.visit(g.iter, cs, eager)
            for c in g.ifs:
                self.visit(c, cs, eager)
        if isinstance(n, ast.DictComp):
            self.visit(n.key, cs, eager)
            self.visit(n.value, cs, eager)
        else:
            self.visit(n.elt, cs, eager)

    v_ListComp = v_SetComp = v_DictComp = v_GeneratorExp = _comp

    def v_Call(self, n, scope, eager):
        # dynamic constructs: globals()/vars()/locals() and `'name' in globals()`
        for ch in ast.iter_child_nodes(n):
            self.visit(ch, scope, eager)

    def v_Compare(self, n, scope, eager):
        # 'time' in globals()
        if (isinstance(n.left, ast.Constant) and isinstance(n.left.value, str)
                and any(isinstance(op, (ast.In, ast.NotIn)) for op in n.ops)
                and any(isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
                        and c.func.id == "globals" for c in n.comparators)):
            self.dyn.add(n.left.value)
        for ch in ast.iter_child_nodes(n):
            self.visit(ch, scope, eager)


# --------------------------------------------------------------------------
# unit extraction
# --------------------------------------------------------------------------
def unit_name(n):
    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return n.name
    return None


def module_bound_names(node):
    """names bound at module scope by one top-level statement"""
    s = Scope("module", None)
    _fill_scope(s, [node])
    return s.bound


def _string_ann_names(node, mod_names):
    """module-level names mentioned only inside *string* annotations (forward refs)."""
    out = set()

    def strnames(txt):
        try:
            t = ast.parse(txt, mode="eval")
        except Exception:
            return set()
        return {n.id for n in ast.walk(t) if isinstance(n, ast.Name)}

    for n in ast.walk(node):
        anns = []
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            a = n.args
            anns += [x.annotation for x in a.posonlyargs + a.args + a.kwonlyargs
                     + [y for y in (a.vararg, a.kwarg) if y] if x.annotation]
            if n.returns:
                anns.append(n.returns)
        elif isinstance(n, ast.AnnAssign):
            anns.append(n.annotation)
        for an in anns:
            for c in ast.walk(an):
                if isinstance(c, ast.Constant) and isinstance(c.value, str):
                    out |= strnames(c.value) & mod_names
    return out


def _target_names(t):
    return {x.id for x in ast.walk(t) if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Store)}


def _terminates(body):
    if not body:
        return False
    last = body[-1]
    if isinstance(last, ast.Raise):
        return True
    if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
        if ast.unparse(last.value.func) in ("sys.exit", "exit", "quit", "os._exit"):
            return True
    return False


def definite(body):
    """names DEFINITELY bound after `body` completes normally (conservative)."""
    out = set()
    for st in body:
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(st.name)
        elif isinstance(st, ast.Assign):
            for t in st.targets:
                out |= _target_names(t)
        elif isinstance(st, ast.AnnAssign):
            if st.value is not None and isinstance(st.target, ast.Name):
                out.add(st.target.id)
        elif isinstance(st, ast.Import):
            for a in st.names:
                out.add(a.asname or a.name.split(".")[0])
        elif isinstance(st, ast.ImportFrom):
            for a in st.names:
                out.add(a.asname or a.name)
        elif isinstance(st, ast.If):
            paths = []
            if not _terminates(st.body):
                paths.append(definite(st.body))
            if not _terminates(st.orelse):
                paths.append(definite(st.orelse))
            if paths:
                out |= set.intersection(*paths)
        elif isinstance(st, ast.Try):
            paths = []
            main = definite(st.body) | definite(st.orelse)
            if not _terminates(st.body):
                paths.append(main)
            for h in st.handlers:
                if _terminates(h.body):
                    continue
                hp = definite(h.body)
                if h.name:
                    hp.discard(h.name)
                paths.append(hp)
            if paths:
                out |= set.intersection(*paths)
            out |= definite(st.finalbody)
        elif isinstance(st, ast.With) or isinstance(st, ast.AsyncWith):
            out |= definite(st.body)
        # For/While/Match: not definite
    return out


def analyze(path):
    text = open(path, encoding="utf-8").read()
    lines = text.split("\n")
    tree = ast.parse(text)
    body = tree.body

    # --- partition source lines -> units (leading trivia attaches to next unit)
    ends = [n.end_lineno for n in body]
    starts = []
    prev_end = 0
    for i, n in enumerate(body):
        first = n.lineno
        if getattr(n, "decorator_list", None):
            first = min([first] + [d.lineno for d in n.decorator_list])
        starts.append(first)

    units = []
    prev_end = 0
    # header = everything before first unit's trivia is handled by caller (docstring etc.)
    for i, n in enumerate(body):
        extent_start = prev_end + 1
        units.append({
            "idx": i,
            "type": type(n).__name__,
            "node_start": starts[i],
            "start": extent_start,
            "end": ends[i],
            "name": unit_name(n),
        })
        prev_end = ends[i]
    tail_trivia = (prev_end + 1, len(lines))

    # --- module-level bindings per unit
    mod_names = set()
    for u, n in zip(units, body):
        u["defs"] = set(module_bound_names(n))
        mod_names |= u["defs"]

    # --- walk each unit
    for u, n in zip(units, body):
        w = Walker(mod_names)
        modscope = Scope("module", None)
        modscope.bound = set(mod_names)
        # module-level statements execute eagerly
        w.visit(n, modscope, True)
        u["eager"] = set(w.eager)
        u["lazy"] = set(w.lazy) - set(w.eager)
        u["gwrites"] = set(w.gwrites)
        u["gwrite_funcs"] = dict(w.gwrite_funcs)
        u["undefined"] = set(w.undefined)
        u["dyn"] = set(w.dyn)
        u["ann"] = _string_ann_names(n, mod_names) - u["eager"] - u["lazy"]
        u["definite"] = definite([n])
        # a unit's own defs are not dependencies on itself
        u["eager"] -= u["defs"] if u["type"] in ("FunctionDef", "ClassDef", "AsyncFunctionDef") else set()
        u["lazy"] -= u["defs"] if u["type"] in ("FunctionDef", "ClassDef", "AsyncFunctionDef") else set()

    return {"text": text, "lines": lines, "units": units, "tail": tail_trivia,
            "mod_names": mod_names, "tree_len": len(body)}


if __name__ == "__main__":
    import common
    src = sys.argv[1] if len(sys.argv) > 1 else common.ORIG
    out = sys.argv[2] if len(sys.argv) > 2 else common.INDEX
    idx = analyze(src)
    # strip heavy text for pickle? keep (2.8MB)
    with open(out, "wb") as f:
        pickle.dump(idx, f)
    print("units:", len(idx["units"]), "module names:", len(idx["mod_names"]), "->", out)
