"""V4 regression tests for Section 44 (Session 04): GPU Mining Kernels and Hash Computation Correctness."""

import ctypes
import hashlib
import os
import re
import subprocess
import tempfile
import threading
import types

from visold.consensus.difficulty import DifficultyEngine
from visold.ledger.block import Block
from visold.mining.gpu_kernels import _CUDA_SHA256_KERNEL, _OPENCL_SHA256_KERNEL
from visold.mining.parallel_miner import GPU_KERNELS_VERIFIED, ParallelMiner


def _compile_kernel_sha256_harness(build_dir: str):
    k_match = re.search(
        r"__constant__\s+unsigned int K\[64\]\s*=\s*\{[^}]+\};",
        _CUDA_SHA256_KERNEL,
    )
    assert k_match, "Could not locate CUDA K[64]"
    cuda_k = k_match.group(0).replace("__constant__ ", "static ")

    macros_match = re.search(
        r"(#define ROTR32.*?#define SIG1[^\n]+)",
        _CUDA_SHA256_KERNEL,
        re.DOTALL,
    )
    assert macros_match, "Could not locate CUDA SHA-256 macros"
    cuda_macros = macros_match.group(1)

    fn_match = re.search(
        r"__device__\s+void\s+sha256_block\s*\(.*?\n\}",
        _CUDA_SHA256_KERNEL,
        re.DOTALL,
    )
    assert fn_match, "Could not locate CUDA sha256_block"
    cuda_fn = fn_match.group(0).replace("__device__ ", "")

    cl_macros_match = re.search(
        r"(#define ROTR\(x,n\).*?#define SIG1[^\n]+)",
        _OPENCL_SHA256_KERNEL,
        re.DOTALL,
    )
    assert cl_macros_match, "Could not locate OpenCL SHA-256 macros"
    cl_macros = cl_macros_match.group(1).replace(
        "(rotate((uint)(x),(uint)(32u-(n))))",
        "(((x)>>(n))|((x)<<(32u-(n))))",
    )

    cl_k_match = re.search(
        r"__constant\s+uint SHA_K\[64\]\s*=\s*\{[^}]+\};",
        _OPENCL_SHA256_KERNEL,
    )
    assert cl_k_match, "Could not locate OpenCL SHA_K[64]"
    cl_k = re.sub(
        r"\buint\b",
        "unsigned int",
        cl_k_match.group(0).replace("__constant ", "static "),
    )

    cl_fn_match = re.search(
        r"void\s+sha256_hash\s*\(.*?\n\}",
        _OPENCL_SHA256_KERNEL,
        re.DOTALL,
    )
    assert cl_fn_match, "Could not locate OpenCL sha256_hash"
    cl_fn = cl_fn_match.group(0).replace("__private ", "")
    cl_fn = re.sub(r"\buchar\b", "unsigned char", cl_fn)
    cl_fn = re.sub(r"\buint\b", "unsigned int", cl_fn)
    cl_fn = re.sub(r"\bulong\b", "unsigned long long", cl_fn)

    instrumented_cuda_fn = cuda_fn.replace(
        "void sha256_block(",
        "int cuda_sha256_overflow_check(",
    ).replace(
        "unsigned int padded[32];",
        "struct { unsigned int padded[32]; unsigned int canary[4]; } _s;\n"
        "    for (int _c = 0; _c < 4; _c++) _s.canary[_c] = 0xDEADBEEFu;\n"
        "    unsigned int *padded = _s.padded;",
    )
    last_brace = instrumented_cuda_fn.rfind("}")
    if "padded[32]" in cuda_fn:
        instrumented_cuda_fn = (
            instrumented_cuda_fn[:last_brace]
            + "\n    int corrupted = 0;\n"
            + "    for (int _c = 0; _c < 4; _c++) if (_s.canary[_c] != 0xDEADBEEFu) corrupted++;\n"
            + "    return corrupted;\n}"
        )
    else:
        instrumented_cuda_fn = (
            "int cuda_sha256_overflow_check(const unsigned char *data, unsigned int len, unsigned char *hash) {\n"
            "    sha256_block(data, len, hash);\n"
            "    return 0;\n}"
        )

    c_src = f"""
#include <stdint.h>
{cuda_macros}
{cuda_k}
{cuda_fn}
{instrumented_cuda_fn}

#undef ROTR
#undef CH
#undef MAJ
#undef EP0
#undef EP1
#undef SIG0
#undef SIG1
{cl_macros}
{cl_k}
{cl_fn}
"""
    c_path = os.path.join(build_dir, "gpu_sha256_harness.c")
    so_path = os.path.join(build_dir, "gpu_sha256_harness.so")
    with open(c_path, "w") as f:
        f.write(c_src)

    res = subprocess.run(
        ["gcc", "-shared", "-fPIC", "-O2", c_path, "-o", so_path],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        raise RuntimeError(f"gcc failed:\n{res.stderr}")

    lib = ctypes.CDLL(so_path)
    lib.sha256_block.argtypes = [ctypes.c_char_p, ctypes.c_uint, ctypes.c_char_p]
    lib.sha256_hash.argtypes = [ctypes.c_char_p, ctypes.c_uint, ctypes.c_char_p]
    lib.cuda_sha256_overflow_check.argtypes = [
        ctypes.c_char_p,
        ctypes.c_uint,
        ctypes.c_char_p,
    ]
    lib.cuda_sha256_overflow_check.restype = ctypes.c_int
    return lib


def test_gpu_sha256_no_buffer_overflow_and_correct_digest():
    """V4: CUDA sha256_block and OpenCL sha256_hash do not overflow padded[],
    compute exact FIPS 180-4 SHA-256 digests on 136-byte headers and 50-byte inputs,
    and reflect mutations in the last 16 bytes of the 136-byte header.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    exec_dir = base_dir
    with tempfile.TemporaryDirectory(dir=base_dir) as _probe_dir:
        _probe = os.path.join(_probe_dir, "_probe.sh")
        with open(_probe, "w") as _pf:
            _pf.write("#!/bin/sh\n")
        os.chmod(_probe, 0o755)
        if not os.access(_probe, os.X_OK) or base_dir.startswith("/storage/emulated"):
            exec_dir = tempfile.gettempdir()
    with tempfile.TemporaryDirectory(dir=exec_dir) as build_dir:
        lib = _compile_kernel_sha256_harness(build_dir)

        miner = ParallelMiner()
        blk_a = Block(
            index=1,
            prev_hash="11" * 32,
            transactions=[],
            miner_address="VSD_MINER_1",
            difficulty=1.0,
            timestamp=1700000000,
            nonce=42,
            vrf_proof="proof_A",
        )
        hdr_a = miner._build_binary_header(blk_a, nonce=42)
        assert len(hdr_a) == 136

        hdr_b = hdr_a[:120] + bytes([b ^ 0xFF for b in hdr_a[120:]])
        assert hdr_a != hdr_b

        out_cuda_a = ctypes.create_string_buffer(32)
        out_cuda_b = ctypes.create_string_buffer(32)
        out_cl_a = ctypes.create_string_buffer(32)
        out_cl_b = ctypes.create_string_buffer(32)

        corrupted_words = lib.cuda_sha256_overflow_check(
            hdr_a, len(hdr_a), out_cuda_a
        )
        assert corrupted_words == 0

        lib.sha256_block(hdr_a, len(hdr_a), out_cuda_a)
        lib.sha256_block(hdr_b, len(hdr_b), out_cuda_b)
        lib.sha256_hash(hdr_a, len(hdr_a), out_cl_a)
        lib.sha256_hash(hdr_b, len(hdr_b), out_cl_b)

        expected_a = hashlib.sha256(hdr_a).digest()
        expected_b = hashlib.sha256(hdr_b).digest()
        assert expected_a != expected_b

        assert out_cuda_a.raw == expected_a
        assert out_cl_a.raw == expected_a
        assert out_cuda_b.raw == expected_b
        assert out_cl_b.raw == expected_b
        assert out_cuda_a.raw != out_cuda_b.raw
        assert out_cl_a.raw != out_cl_b.raw

        msg_50 = b"A" * 50
        out_50 = ctypes.create_string_buffer(32)
        lib.sha256_block(msg_50, len(msg_50), out_50)
        assert out_50.raw == hashlib.sha256(msg_50).digest()


def test_opencl_kernel_enables_extended_atomics_pragma():
    """V4: _OPENCL_SHA256_KERNEL enables cl_khr_int64_extended_atomics when using atom_min."""
    assert "atom_min(" in _OPENCL_SHA256_KERNEL
    assert "cl_khr_int64_base_atomics" in _OPENCL_SHA256_KERNEL
    assert "cl_khr_int64_extended_atomics" in _OPENCL_SHA256_KERNEL


def test_json_verify_seals_block_and_validates_pow():
    """V4: _json_verify validates against canonical Block.compute_hash() and seals the block."""
    assert GPU_KERNELS_VERIFIED is False
    miner = ParallelMiner()
    blk1 = Block(
        index=5,
        prev_hash="aa" * 32,
        transactions=[],
        miner_address="VSD_ALICE",
        difficulty=0.001,
        timestamp=1700000100,
        nonce=16,
        state_root="bb" * 32,
        vrf_output="cc" * 32,
    )

    assert miner._json_verify(blk1, 16) is True
    assert blk1.validate_pow() is True
    assert blk1._sealed is True


def test_mine_cuda_handles_zero_target_and_nan_difficulty():
    """V4: _mine_cuda fails closed (returns False) on target == 0 and NaN difficulty
    without launching kernels or crashing.
    """
    sample_target = (1 << 240) - 1
    words = ParallelMiner._target_to_words(sample_target)
    assert len(words) == 8
    reconstructed = int.from_bytes(
        b"".join(w.to_bytes(4, "big") for w in words), "big"
    )
    assert reconstructed == sample_target

    class _DummyInOut:
        def __init__(self, arr):
            self.arr = arr

    dummy_drv = types.SimpleNamespace(
        In=lambda x: x,
        InOut=lambda x: _DummyInOut(x),
        Context=types.SimpleNamespace(synchronize=lambda: None),
    )

    launches = {"count": 0}
    stop_evt = threading.Event()

    def _dummy_kernel(*args, **kwargs):
        launches["count"] += 1
        if launches["count"] >= 3:
            stop_evt.set()

    miner = ParallelMiner()
    miner._initialized = True
    miner._backend = "cuda"
    miner._cuda_drv = dummy_drv
    miner._cuda_mod = types.SimpleNamespace(get_function=lambda name: _dummy_kernel)
    miner._gpu_batch = 256

    blk_zero = Block(
        index=1,
        prev_hash="00" * 32,
        transactions=[],
        miner_address="VSD_MINER",
        difficulty=64.0,
        timestamp=1700000000,
    )
    assert DifficultyEngine.difficulty_to_target(64.0) == 0
    assert blk_zero.mine() is False
    assert miner._mine_cuda(blk_zero, stop_event=stop_evt) is False
    assert launches["count"] == 0

    blk_nan = Block(
        index=1,
        prev_hash="00" * 32,
        transactions=[],
        miner_address="VSD_MINER",
        difficulty=float("nan"),
        timestamp=1700000000,
    )
    assert blk_nan.mine() is False
    assert miner._mine_cuda(blk_nan) is False
