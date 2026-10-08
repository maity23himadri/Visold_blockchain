#!/usr/bin/env python3
"""
ab_run.py - behavioural A/B comparison: original monolith vs modular build.

Each scenario runs in a pristine cwd + HOME for BOTH builds; stdout+stderr, the exit code and the set of files
created are compared after normalising volatile tokens (timestamps, durations, temp paths, random identifiers).
Entropy is made deterministic per calling function (sitecustomize below) so that import-order differences cannot
change what a given function draws; OpenSSL-generated keys cannot be seeded and are normalised instead.

usage: ab_run.py [NEW_BUILD_DIR] ["ARGS|STDIN-with-\\\\n-escapes" ...]
"""
import difflib
import os
import re
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

ORIG = os.path.join(common.orig_dir(), "visold_vsd_.py")
NEW = (sys.argv[1] if len(sys.argv) > 1 else common.NEW) + "/visold_vsd_.py"
SITE_SRC = "# Deterministic entropy keyed by the *calling function* (not global order), so that import-order\n# differences between monolith and package cannot change the values a given function draws.\nimport os, sys, hashlib\n_cnt = {}\ndef _site(depth):\n    f = sys._getframe(depth)\n    while f is not None:\n        if 'visold' in f.f_code.co_filename:\n            c = f.f_code\n            return getattr(c, 'co_qualname', c.co_name)\n        f = f.f_back\n    return '<other>'\ndef _det_urandom(n):\n    k = _site(2)\n    _cnt[k] = _cnt.get(k, 0) + 1\n    out = b''; i = 0\n    while len(out) < n:\n        out += hashlib.sha256(('%s|%d|%d' % (k, _cnt[k], i)).encode()).digest(); i += 1\n    return out[:n]\nos.urandom = _det_urandom\nimport random as _r\n_inst = {}\ndef _wrap(name):\n    def w(*a, **k):\n        s = _site(2)\n        r = _inst.get(s)\n        if r is None:\n            r = _inst[s] = _r.Random(hashlib.sha256(('r|' + s).encode()).digest())\n        return getattr(r, name)(*a, **k)\n    setattr(_r, name, w)\nfor _n in ('random', 'randint', 'randrange', 'choice', 'choices', 'shuffle', 'sample', 'uniform',\n           'getrandbits', 'randbytes', 'gauss', 'triangular', 'expovariate'):\n    _wrap(_n)\n"
SITE = os.path.join(common.TMP, "ab_site")
os.makedirs(SITE, exist_ok=True)
with open(os.path.join(SITE, "sitecustomize.py"), "w") as _f:
    _f.write(SITE_SRC)

# (args, stdin, unordered).  `unordered`: background threads interleave log lines -> compare as multisets.
# The last two scenarios are end-to-end scripted interactive sessions: first-run account creation -> full VisoldNode
# start-up (storage, P2P, state engine, mempool, sentinel, SHBS, RPC ...) -> menu panels -> clean exit.
E2E_BASIC = "1\nab_user\n\n\x00SLEEP:8\x00" + "0\n"
E2E_PANELS = "1\ne2euser\n\n\x00SLEEP:8\x0016\n\n17\n\n19\n\n22\n\n6\n\n26\n\n\n\x00SLEEP:1\x00" + "0\n"
SCEN = [
    (["--version"], None, False),
    (["--test-sc-name-1"], None, False),
    (["--verify-hardened"], None, False),
    (["--test"], None, False),
    (["--cli", "--help"], None, False),
    (["--cli", "wallet", "create", "--password", "pw-for-ab-test", "--out", "ab_wallet.json"], None, False),
    ([], E2E_BASIC, True),
    ([], E2E_PANELS, True),
]
if os.environ.get("AB_QUICK"):             # skip the long menu-panel session (used per strangler wave)
    SCEN = SCEN[:-1]
if len(sys.argv) > 2:
    SCEN = []
    for spec_ in sys.argv[2:]:
        args_, sep_, stdin_ = spec_.partition("|")
        SCEN.append((args_.split(), stdin_.replace("\\n", "\n") if sep_ else None, bool(sep_)))

VOLATILE = [
    (re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<TS>"),
    (re.compile(r"\b\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b"), "<TIME>"),
    (re.compile(r"\b1[6-9]\d{8}(?:\.\d+)?\b"), "<EPOCH>"),
    (re.compile(r"\b\d+(?:\.\d+)?\s?(?:ms|us|\u00b5s|s|sec|secs|seconds)\b"), "<DUR>"),
    (re.compile(r"\b[0-9a-f]{32,128}\b"), "<HEX>"),
    (re.compile(re.escape(common.TMP) + r"[A-Za-z0-9_./-]*"), "<TMP>"),
    (re.compile(re.escape(os.path.dirname(NEW)) + r"[A-Za-z0-9_./-]*"), "<TMP>"),
    (re.compile(r"0x[0-9a-fA-F]{6,}"), "<ADDR>"),
    (re.compile(r"VSD[1-9A-HJ-NP-Za-km-z]{20,}"), "<VSD-ADDR>"),      # keygen uses OpenSSL RNG (not seedable)
    (re.compile(r"\b[0-9a-f]{8}\b"), "<H8>"),                         # random tx ids in self-tests
    (re.compile(r"\bpid[= ]\d+\b"), "pid=<PID>"),
]


def norm(s):
    for rx, rep in VOLATILE:
        s = rx.sub(rep, s)
    return s


def cleanup_children():
    """The node spawns a relay_server.py subprocess (start_new_session=True) that OUTLIVES the node in BOTH builds
    (pre-existing behaviour).  Left running it would hold the relay port window and skew the next run, so kill it."""
    me = os.getpid()
    for pid in os.listdir("/proc"):
        if pid.isdigit() and int(pid) != me:
            try:
                cmd = open("/proc/%s/cmdline" % pid, "rb").read().replace(b"\0", b" ").decode("utf-8", "replace")
            except Exception:
                continue
            if "relay_server.py" in cmd and common.TMP in cmd:
                try:
                    os.kill(int(pid), 9)
                except Exception:
                    pass


def run(kind, script, args, timeout, stdin=None):
    cleanup_children()
    base = os.path.join(common.TMP, "ab_%s" % kind)
    shutil.rmtree(base, ignore_errors=True)
    os.makedirs(base + "/home")
    if stdin is not None:
        # interactive e2e sessions: this sandbox has no IPv6, and the IPv4 fallback of UDPTransport re-binds the
        # configured "::" address (pre-existing quirk, identical in both builds).  Pre-seed an IPv4 config for both.
        os.makedirs(base + "/home/.visold")
        with open(base + "/home/.visold/config.json", "w") as _cf:
            _cf.write('{"bind_address": "127.0.0.1", "loopback": "127.0.0.1"}')
    env = dict(os.environ, HOME=base + "/home", PYTHONHASHSEED="0", PYTHONDONTWRITEBYTECODE="1")
    env["PYTHONPATH"] = SITE + (os.pathsep + os.path.dirname(script) if kind == "new" else "")
    t = time.time()
    try:
        if stdin is not None and "\x00SLEEP:" in stdin:
            # timed stdin: chunks separated by \x00SLEEP:<seconds>\x00 so background start-up work can settle
            import threading
            parts = re.split(r"\x00SLEEP:([0-9.]+)\x00", stdin)
            pr = subprocess.Popen([sys.executable, script] + args, cwd=base, env=env, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            bufs = {"o": b"", "e": b""}

            def feed():
                try:
                    for i, part in enumerate(parts):
                        if i % 2 == 0:
                            pr.stdin.write(part.encode())
                            pr.stdin.flush()
                        else:
                            time.sleep(float(part))
                    pr.stdin.close()
                except Exception:
                    pass

            def drain(key, fh):
                bufs[key] = fh.read()
            ths = [threading.Thread(target=feed, daemon=True),
                   threading.Thread(target=drain, args=("o", pr.stdout), daemon=True),
                   threading.Thread(target=drain, args=("e", pr.stderr), daemon=True)]
            for th in ths:
                th.start()
            try:
                pr.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                pr.kill()
                pr.wait()
                raise subprocess.TimeoutExpired(pr.args, timeout, output=bufs["o"], stderr=bufs["e"])
            for th in ths[1:]:
                th.join(5)
            p = subprocess.CompletedProcess(pr.args, pr.returncode, bufs["o"], bufs["e"])
        else:
            p = subprocess.run([sys.executable, script] + args, cwd=base, env=env, capture_output=True, timeout=timeout,
                               input=stdin.encode() if stdin is not None else None,
                               stdin=None if stdin is not None else subprocess.DEVNULL)
        out = (p.stdout + b"\n--stderr--\n" + p.stderr).decode("utf-8", "replace")
        rc = p.returncode
    except subprocess.TimeoutExpired as e:
        out = ((e.stdout or b"") + b"\n--stderr--\n" + (e.stderr or b"")).decode("utf-8", "replace") + "\n<<TIMEOUT>>"
        rc = "TIMEOUT"
    cleanup_children()
    files = []
    for dp, dn, fn in os.walk(base):
        for f in fn:
            files.append(os.path.relpath(os.path.join(dp, f), base))
    return rc, out, sorted(files), time.time() - t


ok_all = True
for args, stdin_text, unordered in SCEN:
    to = 40 if stdin_text else 600
    ro = run("orig", ORIG, args, to, stdin_text)
    rn = run("new", NEW, args, to, stdin_text)
    a, b = norm(ro[1]).splitlines(), norm(rn[1]).splitlines()
    if unordered:
        a, b = sorted(a), sorted(b)
    same_out, same_rc, same_files = a == b, ro[0] == rn[0], ro[2] == rn[2]
    flag = "SAME" if (same_out and same_rc and same_files) else "DIFF"
    ok_all &= flag == "SAME"
    label = " ".join(args) or ("<interactive e2e session, %d input lines>" % stdin_text.count("\n") if stdin_text else "<no args>")
    print("[%s] %-58s rc=%s/%s  lines=%d/%d  files=%d/%d  time=%.1fs/%.1fs" % (
        flag, label[:58], ro[0], rn[0], len(a), len(b), len(ro[2]), len(rn[2]), ro[3], rn[3]))
    if not same_files:
        print("   files only-orig:", sorted(set(ro[2]) - set(rn[2]))[:6], "only-new:", sorted(set(rn[2]) - set(ro[2]))[:6])
    if not same_out or not same_rc:
        d = list(difflib.unified_diff(a, b, "orig", "new", lineterm="", n=1))
        print("   %d diff lines; first:" % len(d))
        for ln in d[:24]:
            print("   " + ln[:150])
print("A/B RESULT:", "IDENTICAL BEHAVIOUR in all scenarios" if ok_all else "DIFFERENCES FOUND")
sys.exit(0 if ok_all else 1)
