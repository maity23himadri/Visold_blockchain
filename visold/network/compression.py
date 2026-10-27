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
"""visold.network.compression

Original section: SECTION 6A: P2P MESSAGE COMPRESSION ENGINE

Defines: CompressionEngine
Origin: visold_vsd_.py L16223-16349
"""

import threading
import zlib

from visold.kernel.compat import _ZSTD_AVAILABLE
from visold.kernel.config import Config
from visold.kernel.compression_utils import (
    DecompressedSizeLimitError, bounded_zlib_decompress)
from visold.kernel.logging_setup import log

try:  # optional dependency: name may be undefined, exactly as in the monolith
    from visold.kernel.compat import _zstd_mod
except ImportError:
    pass


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6A: P2P MESSAGE COMPRESSION ENGINE
# Reduces bandwidth by compressing large P2P frames using zstd or zlib.
# Both endpoints negotiate compression in HELLO; old nodes that lack this
# field simply operate without compression (backward-compatible).
# ─────────────────────────────────────────────────────────────────────────────
class CompressionEngine:
    """
    Transparent message compression for the P2P frame layer.

    Design
    ──────
    • Frames above Config.COMPRESS_THRESHOLD bytes are compressed.
    • Compressed frames are prefixed with Config.COMPRESS_MAGIC (2 bytes)
      so receivers can detect and decompress them unambiguously.
    • zstandard is used when available (3–5× faster than zlib at equivalent
      compression ratios).  zlib is the stdlib fallback.
    • Compression is applied AFTER JSON serialization and BEFORE TLS/TCP
      write, so TLS encryption still provides full confidentiality.

    Throughput impact (estimated on a block message of ~100 KB):
      • zstd level=3:  ~200 MB/s compress, ~800 MB/s decompress, 3× smaller
      • zlib level=3:  ~50 MB/s compress,  ~200 MB/s decompress, 2.5× smaller
    """

    MAGIC       = Config.COMPRESS_MAGIC          # b'\xc0\xde'
    MAGIC_LEN   = len(Config.COMPRESS_MAGIC)
    THRESHOLD   = Config.COMPRESS_THRESHOLD

    _lock = threading.Lock()
    _zstd_cctx = None
    _zstd_dctx = None

    @classmethod
    def _init_zstd(cls):
        if cls._zstd_cctx is None and _ZSTD_AVAILABLE:
            cls._zstd_cctx = _zstd_mod.ZstdCompressor(level=3)
            cls._zstd_dctx = _zstd_mod.ZstdDecompressor()

    @classmethod
    def compress(cls, data: bytes) -> bytes:
        """Compress `data` if it exceeds the threshold.  Returns raw or encoded bytes.

        BUG-FIX v6.9.8: Compressed payloads are Base64-encoded before being
        returned.  The P2P framing layer uses '\n' as a message delimiter, but
        arbitrary compressed binary data routinely contains 0x0a (\n) bytes
        internally.  Previously, recv_line's buf.split(b"\n", 1) would split
        mid-frame on such an internal byte, producing a truncated slice that
        failed decompression and silently dropped the connection.

        Wire format for compressed frames: MAGIC (2 bytes) + base64(payload)
        This is 100% ASCII — no embedded \n possible — so \n-delimiter framing
        is safe.  decompress() detects the MAGIC prefix and base64-decodes first.

        Uncompressed frames (JSON < threshold) are returned as-is — they are
        already ASCII and contain no \n except the delimiter appended by send().
        """
        if not Config.COMPRESSION_ENABLED or len(data) < cls.THRESHOLD:
            return data
        try:
            with cls._lock:
                cls._init_zstd()
                if _ZSTD_AVAILABLE and cls._zstd_cctx:
                    compressed = cls._zstd_cctx.compress(data)
                else:
                    compressed = zlib.compress(data, level=3)
            # Only use compression if it actually reduces size
            if len(compressed) < len(data):
                # Base64-encode to guarantee no 0x0a bytes in the wire frame
                import base64 as _b64
                return cls.MAGIC + _b64.b64encode(compressed)
        except Exception:
            pass
        return data

    @classmethod
    def decompress(cls, data: bytes) -> bytes:
        """Decompress `data` if it starts with MAGIC.  Returns original bytes.

        Enforce the same hard frame-size ceiling after decompression as on the
        wire. Decompression must remain bounded while inflating; checking the
        length only after ``decompress()`` would already have allocated the
        attacker-controlled expanded payload.
        Malformed/non-compressed data retains the legacy fail-closed behavior;
        exceeding the decompressed-size ceiling raises a typed exception so
        the peer layer can score and disconnect the sender deterministically.
        """
        if not data.startswith(cls.MAGIC):
            return data
        # BUG-FIX v6.9.8: Base64-decode the payload before decompressing.
        # compress() now base64-encodes the compressed bytes to guarantee the
        # wire frame contains no embedded 0x0a (\n) bytes.
        import base64 as _b64
        try:
            raw_compressed = _b64.b64decode(data[cls.MAGIC_LEN:])
        except Exception as e:
            log.debug(f"Base64 decode failed, treating as raw: {e}")
            return data
        payload = raw_compressed
        _limit  = Config.MAX_MESSAGE_SIZE
        try:
            with cls._lock:
                cls._init_zstd()
                if _ZSTD_AVAILABLE and cls._zstd_dctx:
                    # Use streaming reads rather than decompress() so the
                    # output ceiling bounds allocation during inflation even
                    # when the frame advertises an unknown or hostile size.
                    import io as _io
                    with cls._zstd_dctx.stream_reader(
                            _io.BytesIO(payload),
                            read_size=min(128 * 1024, _limit + 1),
                            read_across_frames=False) as _reader:
                        result = _reader.read(_limit + 1)
                    if len(result) > _limit:
                        log.warning(
                            "CRIT-02: zstd decompression hit output cap "
                            f"({_limit} bytes) — dropping oversized frame")
                        raise DecompressedSizeLimitError(
                            f"decompressed output exceeds {_limit}-byte limit")
                    return result
                else:
                    # zlib: ``zlib.decompress(..., bufsize=...)`` does NOT
                    # cap decompressed output.  Use a Decompress object with
                    # an explicit max_length so the memory bound is enforced
                    # while inflation is happening, not after the allocation.
                    return bounded_zlib_decompress(payload, _limit)
        except DecompressedSizeLimitError:
            log.warning(
                "CRIT-02: compressed message exceeded decompressed output cap "
                f"({_limit} bytes) — rejecting frame")
            raise
        except zlib.error as e:
            log.debug(f"Decompression size-cap triggered or corrupt frame: {e}")
            return data
        except Exception as e:
            log.debug(f"Decompression failed: {e} — treating as raw")
            return data

    @classmethod
    def supports_compression(cls) -> bool:
        return Config.COMPRESSION_ENABLED
