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
"""visold.mining.gpu_kernels


Origin: visold_vsd_.py L38799-38957, L38961-39054
"""




# ── CUDA SHA-256 kernel (C source; compiled at runtime by pycuda) ─────────────

_CUDA_SHA256_KERNEL = r"""
/*
 * Visold CUDA Mining Kernel
 *
 * Each thread evaluates one nonce.  The block header is a fixed 136-byte
 * binary struct with the nonce stored as a little-endian uint64 at byte
 * offset NONCE_OFFSET.  We compute SHA-256 of the full struct and compare
 * the resulting hash (big-endian 256-bit integer) against the 256-bit target.
 *
 * Binary header layout
 * ────────────────────
 *  0  version           uint32 LE  4 bytes
 *  4  protocol_version  uint32 LE  4 bytes
 *  8  block_index       uint64 LE  8 bytes
 * 16  nonce             uint64 LE  8 bytes   ← NONCE_OFFSET
 * 24  timestamp         uint64 LE  8 bytes
 * 32  difficulty        double LE  8 bytes
 * 40  prev_hash         bytes      32 bytes
 * 72  merkle_root       bytes      32 bytes
 *104  vrf_proof_hash    bytes      32 bytes  (SHA-256 of vrf_proof hex)
 *136  [end]
 *
 * SHA-256 reference: FIPS 180-4
 */

#define NONCE_OFFSET 16
#define HEADER_LEN   136

__constant__ unsigned int K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,
    0x923f82a4u,0xab1c5ed5u,0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
    0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,0xe49b69c1u,0xefbe4786u,
    0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,
    0x06ca6351u,0x14292967u,0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
    0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,0xa2bfe8a1u,0xa81a664bu,
    0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,
    0x5b9cca4fu,0x682e6ff3u,0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
    0x90beffbau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

#define ROTR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z)  (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x)     (ROTR32(x,2) ^ROTR32(x,13)^ROTR32(x,22))
#define EP1(x)     (ROTR32(x,6) ^ROTR32(x,11)^ROTR32(x,25))
#define SIG0(x)    (ROTR32(x,7) ^ROTR32(x,18)^((x)>>3))
#define SIG1(x)    (ROTR32(x,17)^ROTR32(x,19)^((x)>>10))

/* 64-bit atomic min via CAS loop (works on all Compute Capabilities) */
__device__ void atomic_min_ull(unsigned long long *addr,
                                unsigned long long  val) {
    unsigned long long old = *addr, assumed;
    do {
        assumed = old;
        if (assumed <= val) return;
        old = atomicCAS(addr, assumed, val);
    } while (old != assumed);
}

__device__ void sha256_block(const unsigned char *data, unsigned int len,
                              unsigned char *out)
{
    unsigned int h0=0x6a09e667u, h1=0xbb67ae85u,
                 h2=0x3c6ef372u, h3=0xa54ff53au,
                 h4=0x510e527fu, h5=0x9b05688cu,
                 h6=0x1f83d9abu, h7=0x5be0cd19u;

    /* Padding into at most 2 x 512-bit blocks (sufficient for 136-byte input) */
    unsigned int padded[32];   /* 2 x 16 words = 32 words = 128 bytes        */
    for (int i = 0; i < 32; i++) padded[i] = 0;

    /* Copy data big-endian word-at-a-time */
    unsigned int full = len / 4, rem = len % 4;
    for (unsigned int i = 0; i < full; i++) {
        padded[i] = ((unsigned int)data[i*4+0] << 24)
                  | ((unsigned int)data[i*4+1] << 16)
                  | ((unsigned int)data[i*4+2] <<  8)
                  |  (unsigned int)data[i*4+3];
    }
    /* Remaining bytes + 0x80 pad byte */
    if (rem) {
        unsigned int w = 0;
        for (unsigned int j = 0; j < rem; j++)
            w |= (unsigned int)data[full*4+j] << (24 - j*8);
        w |= 0x80u << (24 - rem*8);
        padded[full] = w;
    } else {
        padded[full] = 0x80000000u;
    }
    /* Bit-length in last two words of the last block */
    unsigned long long bits = (unsigned long long)len * 8ULL;
    unsigned int n_blk = ((len + 8) < 56) ? 1 : 2;
    padded[n_blk*16 - 2] = (unsigned int)(bits >> 32);
    padded[n_blk*16 - 1] = (unsigned int)(bits & 0xFFFFFFFFu);

    /* Process each 512-bit block */
    for (unsigned int blk = 0; blk < n_blk; blk++) {
        unsigned int W[64];
        for (int i = 0;  i < 16; i++) W[i] = padded[blk*16 + i];
        for (int i = 16; i < 64; i++)
            W[i] = SIG1(W[i-2]) + W[i-7] + SIG0(W[i-15]) + W[i-16];
        unsigned int a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,hh=h7,t1,t2;
        for (int i = 0; i < 64; i++) {
            t1 = hh + EP1(e) + CH(e,f,g) + K[i] + W[i];
            t2 = EP0(a) + MAJ(a,b,c);
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h0+=a; h1+=b; h2+=c; h3+=d; h4+=e; h5+=f; h6+=g; h7+=hh;
    }
    /* Write digest big-endian */
#define WR4(off,v) \
    out[off+0]=(unsigned char)((v)>>24); \
    out[off+1]=(unsigned char)((v)>>16); \
    out[off+2]=(unsigned char)((v)>>8);  \
    out[off+3]=(unsigned char)(v);
    WR4(0,h0) WR4(4,h1) WR4(8,h2) WR4(12,h3)
    WR4(16,h4) WR4(20,h5) WR4(24,h6) WR4(28,h7)
#undef WR4
}

__global__ void mine_kernel(
    const unsigned char  *hdr_tpl,      /* 136-byte header template, nonce=0 */
    unsigned long long    nonce_base,    /* add tid to get this thread's nonce */
    const unsigned int   *target32,     /* 256-bit target as 8 BE uint32 words */
    unsigned long long   *found_nonce,  /* output — UINT64_MAX if not found    */
    unsigned int          batch_size,
    unsigned int          min_iters
)
{
    unsigned int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= batch_size) return;

    unsigned long long nonce = nonce_base + (unsigned long long)tid;
    if (nonce < (unsigned long long)min_iters) return;

    /* Build local header with this thread's nonce (little-endian) */
    unsigned char hdr[HEADER_LEN];
    for (int i = 0; i < HEADER_LEN; i++) hdr[i] = hdr_tpl[i];
    for (int i = 0; i < 8; i++)
        hdr[NONCE_OFFSET + i] = (unsigned char)((nonce >> (i*8)) & 0xFFu);

    unsigned char digest[32];
    sha256_block(hdr, HEADER_LEN, digest);

    /* Compare digest (big-endian 256-bit int) with target word-by-word */
    for (int w = 0; w < 8; w++) {
        unsigned int dw = ((unsigned int)digest[w*4+0] << 24)
                        | ((unsigned int)digest[w*4+1] << 16)
                        | ((unsigned int)digest[w*4+2] <<  8)
                        |  (unsigned int)digest[w*4+3];
        if (dw < target32[w]) { atomic_min_ull(found_nonce, nonce); return; }
        if (dw > target32[w]) return;
        /* equal in this word → continue to next */
    }
    atomic_min_ull(found_nonce, nonce);   /* digest == target (exact hit) */
}
"""


# ── OpenCL SHA-256 kernel ─────────────────────────────────────────────────────

_OPENCL_SHA256_KERNEL = r"""
/* Visold OpenCL Mining Kernel — identical algorithm to the CUDA version */

#pragma OPENCL EXTENSION cl_khr_int64_base_atomics : enable

#define NONCE_OFFSET 16
#define HEADER_LEN   136

#define ROTR(x,n) (rotate((uint)(x),(uint)(32u-(n))))
#define CH(x,y,z)  (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x)     (ROTR(x,2u)^ROTR(x,13u)^ROTR(x,22u))
#define EP1(x)     (ROTR(x,6u)^ROTR(x,11u)^ROTR(x,25u))
#define SIG0(x)    (ROTR(x,7u)^ROTR(x,18u)^((x)>>3u))
#define SIG1(x)    (ROTR(x,17u)^ROTR(x,19u)^((x)>>10u))

__constant uint SHA_K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,
    0x923f82a4u,0xab1c5ed5u,0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
    0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,0xe49b69c1u,0xefbe4786u,
    0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,
    0x06ca6351u,0x14292967u,0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
    0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,0xa2bfe8a1u,0xa81a664bu,
    0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,
    0x5b9cca4fu,0x682e6ff3u,0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
    0x90beffbau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

void sha256_hash(__private const uchar *data, uint len, __private uchar *out) {
    uint h0=0x6a09e667u,h1=0xbb67ae85u,h2=0x3c6ef372u,h3=0xa54ff53au;
    uint h4=0x510e527fu,h5=0x9b05688cu,h6=0x1f83d9abu,h7=0x5be0cd19u;
    uint padded[32]; for(int i=0;i<32;i++) padded[i]=0;
    uint full=len/4, rem=len%4;
    for(uint i=0;i<full;i++)
        padded[i]=((uint)data[i*4]<<24)|((uint)data[i*4+1]<<16)
                 |((uint)data[i*4+2]<<8)|(uint)data[i*4+3];
    if(rem){
        uint w=0;
        for(uint j=0;j<rem;j++) w|=((uint)data[full*4+j])<<(24-j*8);
        w|=0x80u<<(24-rem*8); padded[full]=w;
    } else padded[full]=0x80000000u;
    ulong bits=(ulong)len*8UL;
    uint nb=((len+8)<56)?1:2;
    padded[nb*16-2]=(uint)(bits>>32); padded[nb*16-1]=(uint)(bits&0xFFFFFFFFu);
    for(uint blk=0;blk<nb;blk++){
        uint W[64];
        for(int i=0;i<16;i++) W[i]=padded[blk*16+i];
        for(int i=16;i<64;i++) W[i]=SIG1(W[i-2])+W[i-7]+SIG0(W[i-15])+W[i-16];
        uint a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,hh=h7,t1,t2;
        for(int i=0;i<64;i++){
            t1=hh+EP1(e)+CH(e,f,g)+SHA_K[i]+W[i];
            t2=EP0(a)+MAJ(a,b,c);
            hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
        }
        h0+=a;h1+=b;h2+=c;h3+=d;h4+=e;h5+=f;h6+=g;h7+=hh;
    }
#define WR4(off,v) out[off]=(v)>>24;out[off+1]=((v)>>16)&0xff;\
                   out[off+2]=((v)>>8)&0xff;out[off+3]=(v)&0xff;
    WR4(0,h0)WR4(4,h1)WR4(8,h2)WR4(12,h3)
    WR4(16,h4)WR4(20,h5)WR4(24,h6)WR4(28,h7)
#undef WR4
}

__kernel void mine_kernel(
    __global const uchar *hdr_tpl,
    ulong  nonce_base,
    __global const uint *target32,
    __global ulong *found_nonce,
    uint batch_size,
    uint min_iters
){
    uint tid = get_global_id(0);
    if(tid >= batch_size) return;
    ulong nonce = nonce_base + (ulong)tid;
    if(nonce < (ulong)min_iters) return;

    uchar hdr[HEADER_LEN];
    for(int i=0;i<HEADER_LEN;i++) hdr[i]=hdr_tpl[i];
    for(int i=0;i<8;i++) hdr[NONCE_OFFSET+i]=(uchar)((nonce>>(i*8))&0xFFu);

    uchar digest[32];
    sha256_hash(hdr, HEADER_LEN, digest);

    for(int w=0;w<8;w++){
        uint dw=((uint)digest[w*4]<<24)|((uint)digest[w*4+1]<<16)
               |((uint)digest[w*4+2]<<8)|(uint)digest[w*4+3];
        if(dw < target32[w]){ atom_min(found_nonce, nonce); return; }
        if(dw > target32[w]) return;
    }
    atom_min(found_nonce, nonce);
}
"""
