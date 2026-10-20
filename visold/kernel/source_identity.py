# ─────────────────────────────────────────────────────────────────────────────
#  Visold (VSD) Blockchain Protocol
#  Copyright (c) 2025 Visold Contributors
#  Licensed under the MIT License.
#
#  The original and canonical source is maintained by the Visold Project.
#  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#  the license agreement.
# ─────────────────────────────────────────────────────────────────────────────
# cython: language_level=3
# cython: boundscheck=True
# cython: wraparound=True
# cython: cdivision=True
# cython: nonecheck=True
# cython: initializedcheck=False
# cython: infer_types=True
# cython: optimize.use_switch=True
# cython: optimize.unpack_method_calls=True
"""visold.kernel.source_identity

Original section: SECTION 0A: NODE LOGIC HASH — Software Identity for Handshake Verification

Origin: visold_vsd_.py L3579-3583
"""

import hashlib
import json
import os
from typing import Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 0A: NODE LOGIC HASH — Software Identity for Handshake Verification
# ─────────────────────────────────────────────────────────────────────────────
# Computed from the package's ordered Python source files.  Some Android/Termux
# deployments ship bytecode only; those must include the build-generated
# visold/_build_identity.json manifest so they advertise the same build ID.
# An empty source tree is NOT a valid software hash (SHA256(b"") would create a
# misleading e3b0c442... value).  If neither source nor manifest is available,
# report "unknown" so P2P trust classification can fail safe.

_MANIFEST_NAME = "_build_identity.json"
_HASH_ALGORITHM = "visold-package-source-v1"


def _package_root() -> str:
    """Find the ``visold`` package root for source and sourceless imports."""
    module_path = os.path.abspath(__file__)
    module_dir = os.path.dirname(module_path)
    if os.path.basename(module_dir) == "__pycache__":
        # Sourceless/custom loaders can expose a .pyc under __pycache__; step
        # back through kernel/__pycache__ to the package directory.
        return os.path.dirname(os.path.dirname(module_dir))
    return os.path.dirname(module_dir)


def package_source_blob(root: Optional[str] = None) -> bytes:
    """Return deterministic package source bytes; excludes bytecode caches.

    Each entry is encoded as ``relative/path\0file-bytes\0`` in sorted path
    order.  ``root`` is injectable for deterministic tests/build tooling.
    """
    root = os.path.abspath(root or _package_root())
    entries = []
    if not os.path.isdir(root):
        return b""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
        for fn in sorted(filenames):
            if fn.endswith(".py"):
                full = os.path.join(dirpath, fn)
                entries.append((os.path.relpath(full, root).replace(os.sep, "/"), full))
    entries.sort()
    blob = bytearray()
    for rel, full in entries:
        try:
            with open(full, "rb") as fh:
                content = fh.read()
        except OSError:
            # A partially readable source tree is not a reliable identity.
            raise
        blob += rel.encode("utf-8") + b"\0" + content + b"\0"
    return bytes(blob)


def _read_build_manifest(root: str) -> Tuple[Optional[str], Optional[int]]:
    """Return manifest hash and expected source-file count when well formed."""
    path = os.path.join(root, _MANIFEST_NAME)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            obj = json.load(fh)
        if obj.get("algorithm") != _HASH_ALGORITHM:
            return None, None
        digest = obj.get("package_source_sha256")
        count = obj.get("source_file_count")
        if (not isinstance(digest, str) or len(digest) != 64
                or any(ch not in "0123456789abcdef" for ch in digest.lower())):
            return None, None
        if not isinstance(count, int) or count < 1:
            return None, None
        return digest.lower(), count
    except (OSError, ValueError, TypeError):
        return None, None


def compute_node_logic_hash(root: Optional[str] = None) -> str:
    """Compute the 32-hex build fingerprint, avoiding the empty-tree hash.

    Full source deployments hash the source currently installed.  Bytecode-only
    deployments can use the build manifest.  A partially stripped source tree
    is marked unknown rather than hashing only the files that happened to remain.
    """
    root = os.path.abspath(root or _package_root())
    manifest_hash, manifest_count = _read_build_manifest(root)
    try:
        blob = package_source_blob(root)
    except Exception:
        return manifest_hash[:32] if manifest_hash else "unknown"

    if blob:
        # The source blob format has one entry per .py file; count entries from
        # the same deterministic walker to detect a partially stripped package.
        source_count = 0
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d != "__pycache__"]
            source_count += sum(1 for fn in filenames if fn.endswith(".py"))
        if manifest_count is not None and source_count < manifest_count:
            return "unknown"
        return hashlib.sha256(blob).hexdigest()[:32]

    if manifest_hash:
        return manifest_hash[:32]
    return "unknown"


_NODE_LOGIC_HASH: str = compute_node_logic_hash()
