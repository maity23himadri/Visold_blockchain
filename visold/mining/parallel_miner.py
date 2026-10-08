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
"""visold.mining.parallel_miner


Defines: ParallelMiner
Origin: visold_vsd_.py L39057-39542
"""

import threading
import time
from typing import Optional, TYPE_CHECKING

from visold.consensus.difficulty import DifficultyEngine
from visold.kernel.compat import _CUDA_AVAILABLE, _NUMPY_AVAILABLE, _OPENCL_AVAILABLE
from visold.kernel.config import Config
from visold.kernel.logging_setup import log
from visold.mining.gpu_kernels import _CUDA_SHA256_KERNEL, _OPENCL_SHA256_KERNEL
from visold.mining.workers import _build_mine_template, _cy_mine_worker

if TYPE_CHECKING:  # annotation-only references (no runtime import, no cycle)
    from visold.ledger.block import Block


class ParallelMiner:
    """
    Unified parallel mining front-end.

    Owns the GPU context (if any) and exposes a single mine(block, stop_event)
    call that is a drop-in replacement for the old single-threaded Block.mine().
    Backend is auto-detected once on the first mine() call.

    Public API
    ──────────
    mine(block, stop_event)  →  bool
        On True:  block.nonce / block.block_hash / block.timestamp updated.
        On False: aborted by stop_event — block state is undefined.

    backend_info()  →  dict
        Returns backend name, thread count, GPU device, etc.

    Binary header layout (136 bytes, little-endian integers)
    ─────────────────────────────────────────────────────────
      0  version            uint32   4 B
      4  protocol_version   uint32   4 B
      8  block_index        uint64   8 B
     16  nonce              uint64   8 B  ← GPU writes each thread's nonce here
     24  timestamp          uint64   8 B
     32  difficulty         double   8 B
     40  prev_hash          bytes   32 B
     72  merkle_root        bytes   32 B
    104  sha256(vrf_proof)  bytes   32 B
    136  [end]
    """

    HEADER_LEN   = 136
    NONCE_OFFSET = 16    # byte offset of the nonce field in binary header

    def __init__(self):
        self._backend     = "cpu"
        self._initialized = False
        self._lock        = threading.Lock()
        # CUDA state
        self._cuda_ctx    = None
        self._cuda_mod    = None
        self._cuda_drv    = None
        # OpenCL state
        self._cl          = None
        self._cl_ctx      = None
        self._cl_queue    = None
        self._cl_prog     = None
        # Config snapshot (read once at init)
        self._n_threads   = Config.MINING_THREADS
        self._gpu_device  = Config.MINING_GPU_DEVICE
        self._gpu_batch   = Config.MINING_GPU_BATCH

    # ── Lazy backend initialisation ───────────────────────────────────────────

    def initialize(self) -> str:
        """Detect and set up the best available backend.  Thread-safe."""
        if self._initialized:
            return self._backend
        with self._lock:
            if self._initialized:
                return self._backend
            if Config.MINING_GPU_ENABLED:
                if _CUDA_AVAILABLE and self._try_init_cuda():
                    self._backend = "cuda"
                elif _OPENCL_AVAILABLE and self._try_init_opencl():
                    self._backend = "opencl"
                else:
                    log.warning(
                        "GPU mining requested (VISOLD_MINING_GPU=1) but no "
                        "usable backend found.  Install pycuda or pyopencl, "
                        "and ensure the GPU driver is present.  "
                        "Falling back to CPU multi-thread mining."
                    )
            if self._backend == "cpu":
                log.info(
                    f"Mining backend: CPU  {self._n_threads} threads  "
                    f"(set VISOLD_MINING_GPU=1 to enable GPU acceleration)"
                )
            self._initialized = True
        return self._backend

    # ── CUDA init ─────────────────────────────────────────────────────────────

    def _try_init_cuda(self) -> bool:
        try:
            import pycuda.driver    as _drv
            import pycuda.compiler  as _comp
            _drv.init()
            n = _drv.Device.count()
            if n == 0:
                log.warning("CUDA: no NVIDIA devices detected.")
                return False
            idx = min(self._gpu_device, n - 1)
            dev = _drv.Device(idx)
            ctx = dev.make_context()
            mod = _comp.SourceModule(_CUDA_SHA256_KERNEL, no_extern_c=True)
            self._cuda_drv = _drv
            self._cuda_ctx = ctx
            self._cuda_mod = mod
            log.info(
                f"Mining backend: CUDA  device {idx}  {dev.name()}  "
                f"{dev.total_memory()/(1<<30):.1f} GB  "
                f"batch={self._gpu_batch:,}"
            )
            return True
        except Exception as exc:
            log.debug(f"CUDA init failed: {exc}")
            return False

    # ── OpenCL init ───────────────────────────────────────────────────────────

    def _try_init_opencl(self) -> bool:
        try:
            import pyopencl as _cl_mod
            platforms = _cl_mod.get_platforms()
            if not platforms:
                log.warning("OpenCL: no platforms found.")
                return False
            gpus = []
            for p in platforms:
                try:
                    gpus += p.get_devices(device_type=_cl_mod.device_type.GPU)
                except Exception:
                    pass
            devs = gpus or platforms[0].get_devices()
            if not devs:
                log.warning("OpenCL: no devices found.")
                return False
            idx  = min(self._gpu_device, len(devs) - 1)
            dev  = devs[idx]
            ctx  = _cl_mod.Context([dev])
            que  = _cl_mod.CommandQueue(ctx)
            prog = _cl_mod.Program(ctx, _OPENCL_SHA256_KERNEL).build()
            self._cl      = _cl_mod
            self._cl_ctx  = ctx
            self._cl_queue= que
            self._cl_prog = prog
            log.info(
                f"Mining backend: OpenCL  device {idx}  {dev.name}  "
                f"batch={self._gpu_batch:,}"
            )
            return True
        except Exception as exc:
            log.debug(f"OpenCL init failed: {exc}")
            return False

    # ── Public mine() ─────────────────────────────────────────────────────────

    def mine(self, block: 'Block',
             stop_event: Optional[threading.Event] = None,
             max_hps: float = 0.0) -> bool:
        """
        Mine block in-place with the best available backend.
        Returns True  → block.nonce / block.block_hash / block.timestamp set.
        Returns False → aborted (stop_event fired); block state undefined.

        v7.6.0 — `max_hps` is the OPTIONAL aggregate hashrate cap for THIS
        miner across all worker threads.  When > 0, every CPU worker self-
        throttles so the sum of the threads averages no more than max_hps
        H/s.  When 0 (default) mining runs at full hardware speed — the
        legacy behaviour, bit-for-bit.

        The cap is applied LOCALLY only.  No consensus rule, header field,
        or hash output is altered — a throttled miner produces exactly the
        same valid block at exactly the same nonce as an unthrottled miner
        would, just later.

        GPU backends currently ignore max_hps (the kernel batch size is the
        natural pacing knob there); future work can plumb it through.
        """
        self.initialize()
        if self._backend == "cuda":
            return self._mine_cuda(block, stop_event, max_hps=max_hps)
        if self._backend == "opencl":
            return self._mine_opencl(block, stop_event, max_hps=max_hps)
        return self._mine_cpu(block, stop_event, max_hps=max_hps)

    def backend_info(self) -> dict:
        """Return backend details for CLI / RPC status display."""
        return {
            "backend":     self._backend.upper(),
            "cpu_threads": self._n_threads,
            "gpu_enabled": Config.MINING_GPU_ENABLED,
            "gpu_device":  self._gpu_device,
            "gpu_batch":   self._gpu_batch,
            "cuda_avail":  _CUDA_AVAILABLE,
            "opencl_avail":_OPENCL_AVAILABLE,
        }

    # ── CPU parallel (Cython-optimised) ──────────────────────────────────────

    def _mine_cpu(self, block: 'Block',
                  stop_event: Optional[threading.Event] = None,
                  max_hps: float = 0.0) -> bool:
        """
        Spawn N Cython-typed worker threads each covering a strided nonce range.

        Striding pattern (N = thread count):
          thread 0 → nonces  0,  N, 2N, 3N, …
          thread 1 → nonces  1, N+1, 2N+1, …
          thread k → nonces  k, N+k, 2N+k, …

        Uses _cy_mine_worker instead of the old _cpu_mine_thread for:
          • Pre-serialised JSON template  — no per-nonce json.dumps / dict alloc
          • bytes target comparison       — no per-nonce hex→bigint conversion
          • C-typed loop variables        — when compiled with Cython
          • Same GIL-releasing hashlib    — true N-core parallel SHA-256

        Compiled speedup vs interpreted:  3–8× on the mining inner loop.
        Interpreted speedup vs old code:  1.5–2× (template + bytes cmp alone).

        v7.6.0 — When max_hps > 0 the per-thread cap is max_hps / N and each
        thread throttles itself with a small sleep every
        Config.HASHRATE_THROTTLE_BATCH_SIZE nonces.  See _cy_mine_worker
        for the throttle algorithm.
        """
        target       = DifficultyEngine.difficulty_to_target(block.difficulty)
        target_bytes = target.to_bytes(32, 'big')   # pre-convert once for cmp

        # Pre-render the JSON format template once per candidate block
        import json as _json
        header_base  = _json.loads(_json.dumps(block.header_dict(), default=str))
        orig_ts      = header_base.pop('timestamp', int(time.time()))
        header_base.pop('nonce', None)
        fmt_template = _build_mine_template(header_base)

        N           = self._n_threads
        result      = []
        result_lock = threading.Lock()
        thread_stop = threading.Event()

        # ── v7.6.0 Per-thread throttle parameters ─────────────────────────
        # Distribute the aggregate cap evenly across the N workers.  When
        # max_hps == 0 (or HASHRATE_OPTIMIZATION_ENABLED is False) per_thread
        # is also 0, which makes _cy_mine_worker's throttle a no-op.
        if max_hps and max_hps > 0.0 and N > 0:
            per_thread = float(max_hps) / float(N)
            batch_sz   = int(Config.HASHRATE_THROTTLE_BATCH_SIZE)
            if batch_sz < 1:
                batch_sz = 1
        else:
            per_thread = 0.0
            batch_sz   = 0

        workers = [
            threading.Thread(
                target = _cy_mine_worker,
                args   = (fmt_template, target_bytes,
                          orig_ts,           # initial_ts
                          i,                 # nonce_start
                          N,                 # nonce_step (stride)
                          16,                # min_iters
                          result, result_lock, thread_stop,
                          per_thread,        # max_hps_per_thread (0 = unlimited)
                          batch_sz),         # throttle_batch     (0 = no throttle)
                daemon = True,
                name   = f"vsd-miner-{i}",
            )
            for i in range(N)
        ]
        for w in workers:
            w.start()

        # Wait for a solution or an external stop from MiningEngine
        while not thread_stop.is_set():
            if stop_event and stop_event.is_set():
                thread_stop.set()
                break
            thread_stop.wait(timeout=0.05)

        for w in workers:
            w.join(timeout=2.0)

        if result:
            nonce, hex_hash, ts = result[0]
            block.nonce      = nonce
            block.block_hash = hex_hash
            block.timestamp  = ts
            return True
        return False

    # ── GPU helpers ───────────────────────────────────────────────────────────

    def _build_binary_header(self, block: 'Block', nonce: int = 0) -> bytes:
        """
        Serialise the block header as a 136-byte little-endian binary struct.
        Layout is shared between CUDA and OpenCL kernels (NONCE_OFFSET = 16).
        """
        import struct as _s, hashlib as _hl

        def h2b(h: str) -> bytes:
            raw = bytes.fromhex(h) if h else b''
            return (raw + b'\x00' * 32)[:32]

        vrf_h = (_hl.sha256(block.vrf_proof.encode()).digest()
                 if block.vrf_proof else b'\x00' * 32)

        buf  = _s.pack('<II', block.version, block.protocol_version)  # 8
        buf += _s.pack('<Q',  block.index)                             # 8
        buf += _s.pack('<Q',  nonce)                                   # 8  ← NONCE_OFFSET=16
        buf += _s.pack('<Q',  block.timestamp)                         # 8
        buf += _s.pack('<d',  block.difficulty)                        # 8
        buf += h2b(block.prev_hash)                                    # 32
        buf += h2b(block.merkle_root)                                  # 32
        buf += vrf_h                                                   # 32
        assert len(buf) == self.HEADER_LEN
        return buf

    @staticmethod
    def _target_to_words(target: int) -> list:
        """Split 256-bit target into 8 big-endian uint32 words."""
        return [(target >> (i * 32)) & 0xFFFFFFFF for i in range(7, -1, -1)]

    def _json_verify(self, block: 'Block', nonce: int) -> bool:
        """
        Verify a GPU-found nonce with the canonical JSON-based hash.
        GPU uses binary SHA-256; canonical chain uses JSON SHA-256.
        Most nonces that pass binary SHA-256 also pass JSON SHA-256 at
        low-medium difficulty; at high difficulty the CPU quickly confirms.
        """
        block.nonce      = nonce
        block.block_hash = block.compute_hash()
        return DifficultyEngine.validate_pow_target(
            block.block_hash, block.difficulty)

    # ── CUDA mine ─────────────────────────────────────────────────────────────

    def _mine_cuda(self, block: 'Block',
                   stop_event: Optional[threading.Event] = None,
                   max_hps: float = 0.0) -> bool:
        """
        Launch repeated CUDA kernel batches until a valid nonce is found.
        Each launch evaluates self._gpu_batch nonces in parallel across all
        GPU threads.  The kernel signals a hit via device-side 64-bit atomicMin
        into found_nonce (initialised to UINT64_MAX before each launch).

        v7.6.0 — `max_hps` is accepted for signature compatibility with
        _mine_cpu but is currently NOT applied to GPU kernels.  GPUs natively
        pace themselves via the kernel batch size (self._gpu_batch); future
        work can convert max_hps into a "skip every Nth batch" delay.  When
        the GPU path falls back to CPU mining it forwards max_hps so the
        throttle is preserved.
        """
        if not _NUMPY_AVAILABLE:
            log.error("CUDA mining requires numpy (pip install numpy). "
                      "Falling back to CPU.")
            self._backend = "cpu"
            return self._mine_cpu(block, stop_event, max_hps=max_hps)
        try:
            import numpy as np
            drv  = self._cuda_drv
            fn   = self._cuda_mod.get_function("mine_kernel")
            THRD = 256
            BTCH = self._gpu_batch
            GRID = (BTCH + THRD - 1) // THRD
            U64MAX = np.uint64(0xFFFFFFFFFFFFFFFF)

            target  = DifficultyEngine.difficulty_to_target(block.difficulty)
            t_words = np.array(self._target_to_words(target), dtype=np.uint32)
            hdr_np  = np.frombuffer(
                self._build_binary_header(block), dtype=np.uint8).copy()
            nonce_base = np.uint64(0)

            while True:
                if stop_event and stop_event.is_set():
                    return False

                found = np.array([U64MAX], dtype=np.uint64)
                fn(drv.In(hdr_np),
                   nonce_base,
                   drv.In(t_words),
                   drv.InOut(found),
                   np.uint32(BTCH),
                   np.uint32(16),
                   block=(THRD, 1, 1),
                   grid=(GRID, 1))
                drv.Context.synchronize()

                if found[0] != U64MAX:
                    candidate = int(found[0])
                    if self._json_verify(block, candidate):
                        return True
                    # binary hit didn't pass JSON hash — resume after it
                    nonce_base = np.uint64(candidate + 1)
                else:
                    nonce_base = np.uint64(int(nonce_base) + BTCH)

                # Refresh timestamp in header for next batch
                new_ts = int(time.time())
                if new_ts > block.timestamp:
                    block.timestamp = new_ts
                    hdr_np = np.frombuffer(
                        self._build_binary_header(block,
                                                  nonce=int(nonce_base)),
                        dtype=np.uint8).copy()

        except Exception as exc:
            log.error(f"CUDA mining error ({exc}) — falling back to CPU.")
            self._backend = "cpu"
            return self._mine_cpu(block, stop_event, max_hps=max_hps)

    # ── OpenCL mine ───────────────────────────────────────────────────────────

    def _mine_opencl(self, block: 'Block',
                     stop_event: Optional[threading.Event] = None,
                     max_hps: float = 0.0) -> bool:
        """
        Identical algorithm to _mine_cuda but uses pyopencl.
        Works on AMD, Intel, and NVIDIA GPUs without proprietary drivers.

        v7.6.0 — `max_hps` is accepted for signature compatibility but is
        not currently applied to OpenCL kernels.  See _mine_cuda for details.
        """
        if not _NUMPY_AVAILABLE:
            log.error("OpenCL mining requires numpy (pip install numpy). "
                      "Falling back to CPU.")
            self._backend = "cpu"
            return self._mine_cpu(block, stop_event, max_hps=max_hps)
        try:
            import numpy as np
            cl    = self._cl
            ctx   = self._cl_ctx
            queue = self._cl_queue
            prog  = self._cl_prog
            BTCH  = self._gpu_batch
            U64MAX= np.uint64(0xFFFFFFFFFFFFFFFF)

            target  = DifficultyEngine.difficulty_to_target(block.difficulty)
            t_words = np.array(self._target_to_words(target), dtype=np.uint32)
            hdr_np  = np.frombuffer(
                self._build_binary_header(block), dtype=np.uint8).copy()
            hdr_buf = cl.Buffer(ctx,
                                cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR,
                                hostbuf=hdr_np)
            tgt_buf = cl.Buffer(ctx,
                                cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR,
                                hostbuf=t_words)
            nonce_base = np.uint64(0)

            while True:
                if stop_event and stop_event.is_set():
                    return False

                found     = np.array([U64MAX], dtype=np.uint64)
                found_buf = cl.Buffer(
                    ctx,
                    cl.mem_flags.READ_WRITE | cl.mem_flags.COPY_HOST_PTR,
                    hostbuf=found)

                prog.mine_kernel(
                    queue, (BTCH,), None,
                    hdr_buf,
                    nonce_base,
                    tgt_buf,
                    found_buf,
                    np.uint32(BTCH),
                    np.uint32(16),
                )
                queue.finish()
                cl.enqueue_copy(queue, found, found_buf)
                queue.finish()

                if found[0] != U64MAX:
                    candidate = int(found[0])
                    if self._json_verify(block, candidate):
                        return True
                    nonce_base = np.uint64(candidate + 1)
                else:
                    nonce_base = np.uint64(int(nonce_base) + BTCH)

                new_ts = int(time.time())
                if new_ts > block.timestamp:
                    block.timestamp = new_ts
                    hdr_np = np.frombuffer(
                        self._build_binary_header(block,
                                                  nonce=int(nonce_base)),
                        dtype=np.uint8).copy()
                    hdr_buf = cl.Buffer(
                        ctx,
                        cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR,
                        hostbuf=hdr_np)

        except Exception as exc:
            log.error(f"OpenCL mining error ({exc}) — falling back to CPU.")
            self._backend = "cpu"
            return self._mine_cpu(block, stop_event, max_hps=max_hps)
