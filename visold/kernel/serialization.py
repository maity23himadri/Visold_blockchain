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
"""visold.kernel.serialization


Origin: visold_vsd_.py L3374-3385
"""

import json
from collections import defaultdict


# ═════════════════════════════════════════════════════════════════════════════

# ── F-03 FIX: Removed global monkey-patch of collections.defaultdict.
# The original `collections.defaultdict = dict` corrupted the entire stdlib
# for the process lifetime, silently converting defaultdicts to plain dicts and
# causing KeyError in mempool, peer reputation, and any library using defaultdict.
# The root cause was JSON serialisation of defaultdict objects.  Fixed at the
# serialisation boundary by using a custom encoder (see _SafeJSONEncoder below).

def _serialize(obj) -> str:
    """JSON-serialize obj, safely converting defaultdicts and sets."""
    return json.dumps(obj, cls=_SafeJSONEncoder, default=str)


class _SafeJSONEncoder(json.JSONEncoder):
    """Convert defaultdict → dict and set → list so json.dumps never fails."""
    def default(self, obj):
        if isinstance(obj, defaultdict):
            return dict(obj)
        if isinstance(obj, set):
            return sorted(obj)
        return super().default(obj)
