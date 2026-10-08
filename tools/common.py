"""common.py - path configuration shared by the refactoring / verification tools.

  VISOLD_ORIG  path of the ORIGINAL monolith (visold_vsd_.py, 55,370 lines)      [default: ./visold_vsd_original.py]
  VISOLD_NEW   root of the modular build (directory containing visold/ and visold_vsd_.py)  [default: parent of tools/]
"""
import os
import shutil
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ORIG = os.environ.get("VISOLD_ORIG") or next(
    (p for p in (os.path.join(os.getcwd(), "visold_vsd_original.py"), os.path.join(HERE, "visold_vsd_original.py"),
                 "/mnt/user-data/uploads/visold_vsd_.py") if os.path.exists(p)), "visold_vsd_original.py")
NEW = os.environ.get("VISOLD_NEW") or os.path.dirname(HERE)
TMP = os.path.join(tempfile.gettempdir(), "visold_tools")
os.makedirs(TMP, exist_ok=True)
INDEX = os.path.join(TMP, "index.pkl")


def orig_dir():
    """a directory containing the original monolith under its historical name (for importing / running it)"""
    d = os.path.join(TMP, "orig")
    os.makedirs(d, exist_ok=True)
    dst = os.path.join(d, "visold_vsd_.py")
    if not os.path.exists(dst) or os.path.getsize(dst) != os.path.getsize(ORIG):
        shutil.copyfile(ORIG, dst)
    return d


def ensure_index():
    import pickle
    import analyzer
    if not os.path.exists(INDEX) or os.path.getmtime(INDEX) < os.path.getmtime(ORIG):
        with open(INDEX, "wb") as f:
            pickle.dump(analyzer.analyze(ORIG), f)
    return INDEX
