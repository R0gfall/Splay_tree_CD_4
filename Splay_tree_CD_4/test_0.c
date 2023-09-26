#ifdef  AMD_GPU
#define ll1lll1	
#endif

#ifdef  NVIDIA_GPU
#define ll11ll1	
#endif

#ifdef  INTEL_GPU
#define l1l1ll1	
#endif


#ifdef FAST_KERNEL
#define ll11l11   
#endif

#ifdef NO_EXT
#define ll11l1l
#endif


#pragma OPENCL EXTENSION cl_khr_global_int32_base_atomics: enable

#ifdef ll1lll1		// AMD_GPU
#pragma OPENCL EXTENSION cl_amd_printf:enable
#endif


#ifdef ll1lll1		// AMD_GPU
//#define BITALIGN
#endif

#if defined(ll1lll1) && !defined(ll11l1l)		// AMD_GPU && !NO_EXT
#pragma OPENCL EXTENSION cl_amd_media_ops : enable
#define bswap_dword(x) (amd_bytealign (amd_bytealign(x, (x)<<16, 3), amd_bytealign((x)>>16, x, 1), 2))
#elif defined(ll11ll1) 				// NVIDIA_GPU

__inline
unsigned int bswap_dword(unsigned int x)
{
    x = rotate(x, 16U);
    return ((x & 0x00FF00FF) << 8) + ((x >> 8) & 0x00FF00FF);
}

/*

__inline
unsigned int bswap_dword(unsigned int x)
{
unsigned int res;
asm("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(res) : "r"(x));
return (res);
}
*/
#else		 // generic or Intel

#define bswap_dword(a) (as_uint(as_uchar4(a).wzyx))

/*

#define bswap_dword(x) ( (((x) & 0x000000ff) << 24) | \
                    (((x) & 0x0000ff00) <<  8) | \
                    (((x) & 0x00ff0000) >>  8) | \
                (((x) & 0xff000000) >> 24) )
*/

#endif

//#include <sha512.h>
#define SHA_LONG64 unsigned long
#define U64(C)     (unsigned long)C

#define SHA384_DIGEST_LENGTH	48
#define SHA512_DIGEST_LENGTH	64
#define SHA_LBLOCK	16


typedef struct SHA512state_st
{
    SHA_LONG64 h0, h1, h2, h3, h4, h5, h6, h7;
    //	SHA_LONG64 Nl,Nh;
    //	union {
    //		SHA_LONG64	d[SHA_LBLOCK];
    //		unsigned char	p[SHA512_CBLOCK];
    //	} u;
    //	unsigned int num,md_len;
} SHA512_CTX;

__constant SHA_LONG64 K512[80] = {
        U64(0x428a2f98d728ae22),U64(0x7137449123ef65cd),
        U64(0xb5c0fbcfec4d3b2f),U64(0xe9b5dba58189dbbc),
        U64(0x3956c25bf348b538),U64(0x59f111f1b605d019),
        U64(0x923f82a4af194f9b),U64(0xab1c5ed5da6d8118),
        U64(0xd807aa98a3030242),U64(0x12835b0145706fbe),
        U64(0x243185be4ee4b28c),U64(0x550c7dc3d5ffb4e2),
        U64(0x72be5d74f27b896f),U64(0x80deb1fe3b1696b1),
        U64(0x9bdc06a725c71235),U64(0xc19bf174cf692694),
        U64(0xe49b69c19ef14ad2),U64(0xefbe4786384f25e3),
        U64(0x0fc19dc68b8cd5b5),U64(0x240ca1cc77ac9c65),
        U64(0x2de92c6f592b0275),U64(0x4a7484aa6ea6e483),
        U64(0x5cb0a9dcbd41fbd4),U64(0x76f988da831153b5),
        U64(0x983e5152ee66dfab),U64(0xa831c66d2db43210),
        U64(0xb00327c898fb213f),U64(0xbf597fc7beef0ee4),
        U64(0xc6e00bf33da88fc2),U64(0xd5a79147930aa725),
        U64(0x06ca6351e003826f),U64(0x142929670a0e6e70),
        U64(0x27b70a8546d22ffc),U64(0x2e1b21385c26c926),
        U64(0x4d2c6dfc5ac42aed),U64(0x53380d139d95b3df),
        U64(0x650a73548baf63de),U64(0x766a0abb3c77b2a8),
        U64(0x81c2c92e47edaee6),U64(0x92722c851482353b),
        U64(0xa2bfe8a14cf10364),U64(0xa81a664bbc423001),
        U64(0xc24b8b70d0f89791),U64(0xc76c51a30654be30),
        U64(0xd192e819d6ef5218),U64(0xd69906245565a910),
        U64(0xf40e35855771202a),U64(0x106aa07032bbd1b8),
        U64(0x19a4c116b8d2d0c8),U64(0x1e376c085141ab53),
        U64(0x2748774cdf8eeb99),U64(0x34b0bcb5e19b48a8),
        U64(0x391c0cb3c5c95a63),U64(0x4ed8aa4ae3418acb),
        U64(0x5b9cca4f7763e373),U64(0x682e6ff3d6b2b8a3),
        U64(0x748f82ee5defb2fc),U64(0x78a5636f43172f60),
        U64(0x84c87814a1f0ab72),U64(0x8cc702081a6439ec),
        U64(0x90befffa23631e28),U64(0xa4506cebde82bde9),
        U64(0xbef9a3f7b2c67915),U64(0xc67178f2e372532b),
        U64(0xca273eceea26619c),U64(0xd186b8c721c0c207),
        U64(0xeada7dd6cde0eb1e),U64(0xf57d4f7fee6ed178),
        U64(0x06f067aa72176fba),U64(0x0a637dc5a2c898a6),
        U64(0x113f9804bef90dae),U64(0x1b710b35131c471b),
        U64(0x28db77f523047d84),U64(0x32caab7b40c72493),
        U64(0x3c9ebe0a15c9bebc),U64(0x431d67c49c100d4c),
        U64(0x4cc5d4becb3e42b6),U64(0x597f299cfc657e2a),
        U64(0x5fcb6fab3ad6faec),U64(0x6c44198c4a475817) };


#ifdef ll11ll1		// NVIDIA_GPU
inline ulong cuda_ROTR(ulong x, int n) {
    uint2 a, result;

    a = as_uint2(x);
    if (n < 32) {
        asm("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(result.x) : "r"(a.x), "r"(a.y), "r"(n));
        asm("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(result.y) : "r"(a.y), "r"(a.x), "r"(n));
    }
    else {
        asm("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(result.x) : "r"(a.y), "r"(a.x), "r"(n));
        asm("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(result.y) : "r"(a.x), "r"(a.y), "r"(n));
    }
    return (as_ulong(result));
}

inline ulong cuda_SHR(ulong x, int n) {
    uint2 a, result;

    a = as_uint2(x);
    asm("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(result.x) : "r"(a.x), "r"(a.y), "r"(n));
    asm("shr.b32 %0, %1, %2;" : "=r"(result.y) : "r"(a.y), "r"(n));
    return (as_ulong(result));
}



#define ROTR(a,n)     rotate((unsigned long)(a),(unsigned long)(64-n))
//#define ROTR(a,n) cuda_ROTR(a,n)
//#define ROTR8(a,n) cuda_ROTR(a,n)

#define ROTR8(a,n)     rotate((unsigned long)(a),(unsigned long)(64-n))
//#define ROTR(x,s)	(((x)>>s) + ((x)<<(64-s)))
//#define ROTR8(x,s)	(((x)>>s) + ((x)<<(64-s)))

#define SHR(a,n)  	((a) >> n)
//#define SHR(a,n)  	cuda_SHR(a, n)


#else
#define ROTR(a, n)	((n < 32) ? as_ulong((uint2) (amd_bitalign(as_uint2(a).y, as_uint2(a).x, n) , amd_bitalign(as_uint2(a).x, as_uint2(a).y, n))) :\
                                    as_ulong((uint2) (amd_bitalign(as_uint2(a).x, as_uint2(a).y, n - 32) , amd_bitalign(as_uint2(a).y, as_uint2(a).x, n - 32))))


//#define ROTR(x, n)	((n) < 32 ? (amd_bitalign((uint)((x) >> 32), (uint)(x), (uint)(n)) | ((ulong)amd_bitalign((uint)(x), (uint)((x) >> 32), (uint)(n)) << 32)) : (amd_bitalign((uint)(x), (uint)((x) >> 32), (uint)(n) - 32) | ((ulong)amd_bitalign((uint)((x) >> 32), (uint)(x), (uint)(n) - 32) << 32)))
//#define ROTR8(a,n)     rotate((unsigned long)(a),(unsigned long)(64-n))
#define ROTR8(a, n)	 as_ulong((uint2) (amd_bytealign(as_uint2(a).y, as_uint2(a).x, 1) , amd_bytealign(as_uint2(a).x, as_uint2(a).y, 1)))


#define SHR(a,n)  	as_ulong ((uint2) (amd_bitalign(as_uint2(a).y, as_uint2(a).x, n), (as_uint2(a).y >> n)))



#endif

//#define Ch(x,y,z)	(((x) & (y)) ^ ((~(x)) & (z)))
#ifdef ll11ll1		// NVIDIA_GPU
#define Ch(x,y,z)	((((y) ^ (z)) & (x)) ^ (z)) 
#else
#define Ch(x,y,z)	bitselect (z,y,x)
#endif
//#define Maj(x,y,z)	(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
//#define Maj(x,y,z)	(((x) & (y)) | (((x)|(y)) & (z))) 
#ifdef ll11ll1		// NVIDIA_GPU
#define Maj(a,b,c)	(tmp = xor_save, xor_save = (a)^(b), tmp = (xor_save & tmp) ^ (b))
#else
#define Maj(x,y,z)	bitselect(x,y,(z)^(x)) 
#endif



#define Sigma0_512(x)	(ROTR((x),28) ^ ROTR((x),34) ^ ROTR((x),39))
#define Sigma1_512(x)	(ROTR((x),14) ^ ROTR((x),18) ^ ROTR((x),41))
#define sigma0_512(x)	(ROTR((x),1)  ^ ROTR8((x),8) ^ SHR ((x),7))
#define sigma1_512(x)	(ROTR((x),19) ^ ROTR((x),61) ^ SHR((x),6))

#define	ROUND_00_15_512(i,a,b,c,d,e,f,g,h)		\
	T1 += h + Sigma1_512(e) + Ch(e,f,g) + K512[i];	\
	h = Sigma0_512(a) + Maj(a,b,c);			\
	d += T1;	h += T1;		

#if defined (ll1lll1) && !defined (ll11l11)   	// AMD_GPU && !FAST_KERNEL
#define	ROUND_16_80_512(i,a,b,c,d,e,f,g,h,X,X1,X14,X9)	 {	\
	s0 = sigma0_512(X1);	\
	s1 = sigma1_512(X14);	\
	T1 = X += s0 + s1 + X9;			\
	ROUND_00_15_512(i,a,b,c,d,e,f,g,h);		} 

#else
#define	ROUND_16_80_512(i,a,b,c,d,e,f,g,h,X)		\
	s0 = X[(i+1)&0x0f];	s0 = sigma0_512(s0);	\
	s1 = X[(i+14)&0x0f];	s1 = sigma1_512(s1);	\
	T1 = X[(i)&0x0f] += s0 + s1 + X[(i+9)&0x0f];	\
	ROUND_00_15_512(i,a,b,c,d,e,f,g,h);		
#endif

//#include "aes.cuh"

#define AES_ENCRYPT	1
#define AES_DECRYPT	0

/* Because array size can't be a const in C, the following two are macros.
   Both sizes are in bytes. */
#define AES_MAXNR 14
#define AES_BLOCK_SIZE 16

#if defined(OPENSSL_FIPS)
#define FIPS_AES_SIZE_T	int
#endif

   /* This should be a hidden type, but EVP requires that the size be known */
struct aes_key_st {
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
    //    int rounds;
};
typedef struct aes_key_st AES_KEY;

const char* AES_options(void);

typedef unsigned int u32;
typedef unsigned long u64;
typedef unsigned char u8;


int AES_set_decrypt_key_256(u64 rk0, u64 rk1, u64 rk2, u64 rk3, const int bits, AES_KEY* key);

void AES_decrypt(__constant unsigned int* in, u32* s0, u32* s1, u32* s2, u32* s3,
    const int bits, const AES_KEY* key);


//#include "maindef.h"
typedef unsigned char  byte;
typedef unsigned short word;
typedef unsigned int   dword;
typedef unsigned char  boolean;
typedef unsigned char  BIT;
typedef	unsigned int ULONG;

#define  MAXPASSWORD       256


typedef struct {
    long psw_cnt;
    unsigned int charset_len;
    unsigned int psw_len;
    unsigned int static_len;
    long max_psw;
    byte RawCharset[256 * 2]; 		// WideChar for rar 3.0, UTF8 for rar 5.0 (2 bytes UTF8 if not only ASCII)
    byte static_pass[MAXPASSWORD * 2];	// the same

    uint salt[4];
    uint hashedsalt[8];
    uint docid[4];
    uint key_length;
    uint spinCount;
} inParams_t;


int sha_block_2013(ULONG* W, int len, __constant inParams_t* in);

a = 18446744073709551615;


__kernel
//__attribute__((reqd_work_group_size(THREADS_PER_BLOCK, 1, 1))) 
void OFF2013Brute_GPU(
    __constant inParams_t* in,
    __global int* valid_num)
{
    long psw_num;
    int l;
    int RawLength;
    int tid;
    unsigned int data[160]; // 256 Unicode chars + Salt (16) + sha512_padding

    byte* block = (byte*)data;

    tid = get_global_id(0);
    psw_num = in->psw_cnt + tid;

    if (psw_num >= in->max_psw) return;

#define Reverse_index(i) ( (i) ^ 0x03 )

    data[0] = bswap_dword(in->docid[0]);
    data[1] = bswap_dword(in->docid[1]);
    data[2] = bswap_dword(in->docid[2]);
    data[3] = bswap_dword(in->docid[3]);

    RawLength = 16 + (in->psw_len + in->static_len) * 2;

#ifdef DEMO_VERSION
    data[4] = data[5] = data[6] = 0;
#else
    data[RawLength / 4] = 0;
#endif


    l = in->psw_len;
    // block[l] = '\0';
   //  RawPsw[l*2+1] = '\0';
    l--;

    while (l >= 0) {
        block[Reverse_index(16 + (l + in->static_len) * 2)] = in->RawCharset[(psw_num % in->charset_len) * 2];
        block[Reverse_index(16 + (l + in->static_len) * 2 + 1)] = in->RawCharset[(psw_num % in->charset_len) * 2 + 1];
        l--;
        psw_num /= in->charset_len;
    }

    for (l = 0; l < in->static_len; l++) {
        block[Reverse_index(l * 2 + 16)] = in->static_pass[l * 2];
        block[Reverse_index(l * 2 + 17)] = in->static_pass[l * 2 + 1];
    }

    block[Reverse_index(RawLength)] = 0x80;

#ifdef DEMO_VERSION
    data[7] = data[8] = data[9] = data[10] =
        data[11] = data[12] = data[13] = data[14] =
        data[15] = data[16] = data[17] = data[18] =
        data[19] = data[20] = data[21] = data[22] =
        data[23] = data[24] = data[25] = data[26] =
        data[27] = data[28] = data[29] = data[30] = 0;
    data[31] = RawLength * 8;
#else  
    data[RawLength / 4 + 1] = data[RawLength / 4 + 2] = data[RawLength / 4 + 3] = data[RawLength / 4 + 4] =
        data[RawLength / 4 + 5] = data[RawLength / 4 + 6] = data[RawLength / 4 + 7] = data[RawLength / 4 + 8] =
        data[RawLength / 4 + 9] = data[RawLength / 4 + 10] = data[RawLength / 4 + 11] = data[RawLength / 4 + 12] =
        data[RawLength / 4 + 13] = data[RawLength / 4 + 14] = data[RawLength / 4 + 15] = data[RawLength / 4 + 16] =
        data[RawLength / 4 + 17] = data[RawLength / 4 + 18] = data[RawLength / 4 + 19] = data[RawLength / 4 + 20] =
        data[RawLength / 4 + 21] = data[RawLength / 4 + 22] = data[RawLength / 4 + 23] = data[RawLength / 4 + 24] =
        data[RawLength / 4 + 25] = data[RawLength / 4 + 26] = data[RawLength / 4 + 27] = data[RawLength / 4 + 28] =
        data[RawLength / 4 + 29] = data[RawLength / 4 + 30] = data[RawLength / 4 + 31] = data[RawLength / 4 + 32] = 0;

    data[((RawLength + 17) / 128) * 32 + 31] = RawLength * 8;
#endif

    if (sha_block_2013(data, (RawLength + 17) / 128 + 1, in) == 0)
        *valid_num = get_global_id(0);

}



int sha_block_2013(ULONG* W, int len, __constant inParams_t* in)
{
    SHA512_CTX ctx;

    ctx.h0 = U64(0x6a09e667f3bcc908);
    ctx.h1 = U64(0xbb67ae8584caa73b);
    ctx.h2 = U64(0x3c6ef372fe94f82b);
    ctx.h3 = U64(0xa54ff53a5f1d36f1);
    ctx.h4 = U64(0x510e527fade682d1);
    ctx.h5 = U64(0x9b05688c2b3e6c1f);
    ctx.h6 = U64(0x1f83d9abfb41bd6b);
    ctx.h7 = U64(0x5be0cd19137e2179);


    SHA_LONG64	a, b, c, d, e, f, g, h, s0, s1, T1;
    SHA_LONG64	xor_save, tmp;
    SHA_LONG64  X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15;
    int i;


    SHA_LONG64* X = (SHA_LONG64*)W;

    for (; ;) {
        a = ctx.h0;	b = ctx.h1;	c = ctx.h2;	d = ctx.h3;
        e = ctx.h4;	f = ctx.h5;	g = ctx.h6;	h = ctx.h7;

        xor_save = b ^ c;

#if defined (ll1lll1)		// AMD_GPU
        T1 = X0 = ROTR(X[0], 32);	ROUND_00_15_512(0, a, b, c, d, e, f, g, h);
        T1 = X1 = ROTR(X[1], 32);	ROUND_00_15_512(1, h, a, b, c, d, e, f, g);
        T1 = X2 = ROTR(X[2], 32);	ROUND_00_15_512(2, g, h, a, b, c, d, e, f);
        T1 = X3 = ROTR(X[3], 32);	ROUND_00_15_512(3, f, g, h, a, b, c, d, e);
        T1 = X4 = ROTR(X[4], 32);	ROUND_00_15_512(4, e, f, g, h, a, b, c, d);
        T1 = X5 = ROTR(X[5], 32);	ROUND_00_15_512(5, d, e, f, g, h, a, b, c);
        T1 = X6 = ROTR(X[6], 32);	ROUND_00_15_512(6, c, d, e, f, g, h, a, b);
        T1 = X7 = ROTR(X[7], 32);	ROUND_00_15_512(7, b, c, d, e, f, g, h, a);
        T1 = X8 = ROTR(X[8], 32);	ROUND_00_15_512(8, a, b, c, d, e, f, g, h);
        T1 = X9 = ROTR(X[9], 32);	ROUND_00_15_512(9, h, a, b, c, d, e, f, g);
        T1 = X10 = ROTR(X[10], 32);	ROUND_00_15_512(10, g, h, a, b, c, d, e, f);
        T1 = X11 = ROTR(X[11], 32);	ROUND_00_15_512(11, f, g, h, a, b, c, d, e);
        T1 = X12 = ROTR(X[12], 32);	ROUND_00_15_512(12, e, f, g, h, a, b, c, d);
        T1 = X13 = ROTR(X[13], 32);	ROUND_00_15_512(13, d, e, f, g, h, a, b, c);
        T1 = X14 = ROTR(X[14], 32);	ROUND_00_15_512(14, c, d, e, f, g, h, a, b);
        T1 = X15 = ROTR(X[15], 32);	ROUND_00_15_512(15, b, c, d, e, f, g, h, a);

        ROUND_16_80_512(16 + 0, a, b, c, d, e, f, g, h, X0, X1, X14, X9);
        ROUND_16_80_512(16 + 1, h, a, b, c, d, e, f, g, X1, X2, X15, X10);
        ROUND_16_80_512(16 + 2, g, h, a, b, c, d, e, f, X2, X3, X0, X11);
        ROUND_16_80_512(16 + 3, f, g, h, a, b, c, d, e, X3, X4, X1, X12);
        ROUND_16_80_512(16 + 4, e, f, g, h, a, b, c, d, X4, X5, X2, X13);
        ROUND_16_80_512(16 + 5, d, e, f, g, h, a, b, c, X5, X6, X3, X14);
        ROUND_16_80_512(16 + 6, c, d, e, f, g, h, a, b, X6, X7, X4, X15);
        ROUND_16_80_512(16 + 7, b, c, d, e, f, g, h, a, X7, X8, X5, X0);
        ROUND_16_80_512(16 + 8, a, b, c, d, e, f, g, h, X8, X9, X6, X1);
        ROUND_16_80_512(16 + 9, h, a, b, c, d, e, f, g, X9, X10, X7, X2);
        ROUND_16_80_512(16 + 10, g, h, a, b, c, d, e, f, X10, X11, X8, X3);
        ROUND_16_80_512(16 + 11, f, g, h, a, b, c, d, e, X11, X12, X9, X4);
        ROUND_16_80_512(16 + 12, e, f, g, h, a, b, c, d, X12, X13, X10, X5);
        ROUND_16_80_512(16 + 13, d, e, f, g, h, a, b, c, X13, X14, X11, X6);
        ROUND_16_80_512(16 + 14, c, d, e, f, g, h, a, b, X14, X15, X12, X7);
        ROUND_16_80_512(16 + 15, b, c, d, e, f, g, h, a, X15, X0, X13, X8);
        ROUND_16_80_512(16 + 16, a, b, c, d, e, f, g, h, X0, X1, X14, X9);
        ROUND_16_80_512(16 + 17, h, a, b, c, d, e, f, g, X1, X2, X15, X10);
        ROUND_16_80_512(16 + 18, g, h, a, b, c, d, e, f, X2, X3, X0, X11);
        ROUND_16_80_512(16 + 19, f, g, h, a, b, c, d, e, X3, X4, X1, X12);
        ROUND_16_80_512(16 + 20, e, f, g, h, a, b, c, d, X4, X5, X2, X13);
        ROUND_16_80_512(16 + 21, d, e, f, g, h, a, b, c, X5, X6, X3, X14);
        ROUND_16_80_512(16 + 22, c, d, e, f, g, h, a, b, X6, X7, X4, X15);
        ROUND_16_80_512(16 + 23, b, c, d, e, f, g, h, a, X7, X8, X5, X0);
        ROUND_16_80_512(16 + 24, a, b, c, d, e, f, g, h, X8, X9, X6, X1);
        ROUND_16_80_512(16 + 25, h, a, b, c, d, e, f, g, X9, X10, X7, X2);
        ROUND_16_80_512(16 + 26, g, h, a, b, c, d, e, f, X10, X11, X8, X3);
        ROUND_16_80_512(16 + 27, f, g, h, a, b, c, d, e, X11, X12, X9, X4);
        ROUND_16_80_512(16 + 28, e, f, g, h, a, b, c, d, X12, X13, X10, X5);
        ROUND_16_80_512(16 + 29, d, e, f, g, h, a, b, c, X13, X14, X11, X6);
        ROUND_16_80_512(16 + 30, c, d, e, f, g, h, a, b, X14, X15, X12, X7);
        ROUND_16_80_512(16 + 31, b, c, d, e, f, g, h, a, X15, X0, X13, X8);
        ROUND_16_80_512(16 + 32, a, b, c, d, e, f, g, h, X0, X1, X14, X9);
        ROUND_16_80_512(16 + 33, h, a, b, c, d, e, f, g, X1, X2, X15, X10);
        ROUND_16_80_512(16 + 34, g, h, a, b, c, d, e, f, X2, X3, X0, X11);
        ROUND_16_80_512(16 + 35, f, g, h, a, b, c, d, e, X3, X4, X1, X12);
        ROUND_16_80_512(16 + 36, e, f, g, h, a, b, c, d, X4, X5, X2, X13);
        ROUND_16_80_512(16 + 37, d, e, f, g, h, a, b, c, X5, X6, X3, X14);
        ROUND_16_80_512(16 + 38, c, d, e, f, g, h, a, b, X6, X7, X4, X15);
        ROUND_16_80_512(16 + 39, b, c, d, e, f, g, h, a, X7, X8, X5, X0);
        ROUND_16_80_512(16 + 40, a, b, c, d, e, f, g, h, X8, X9, X6, X1);
        ROUND_16_80_512(16 + 41, h, a, b, c, d, e, f, g, X9, X10, X7, X2);
        ROUND_16_80_512(16 + 42, g, h, a, b, c, d, e, f, X10, X11, X8, X3);
        ROUND_16_80_512(16 + 43, f, g, h, a, b, c, d, e, X11, X12, X9, X4);
        ROUND_16_80_512(16 + 44, e, f, g, h, a, b, c, d, X12, X13, X10, X5);
        ROUND_16_80_512(16 + 45, d, e, f, g, h, a, b, c, X13, X14, X11, X6);
        ROUND_16_80_512(16 + 46, c, d, e, f, g, h, a, b, X14, X15, X12, X7);
        ROUND_16_80_512(16 + 47, b, c, d, e, f, g, h, a, X15, X0, X13, X8);
        ROUND_16_80_512(16 + 48, a, b, c, d, e, f, g, h, X0, X1, X14, X9);
        ROUND_16_80_512(16 + 49, h, a, b, c, d, e, f, g, X1, X2, X15, X10);
        ROUND_16_80_512(16 + 50, g, h, a, b, c, d, e, f, X2, X3, X0, X11);
        ROUND_16_80_512(16 + 51, f, g, h, a, b, c, d, e, X3, X4, X1, X12);
        ROUND_16_80_512(16 + 52, e, f, g, h, a, b, c, d, X4, X5, X2, X13);
        ROUND_16_80_512(16 + 53, d, e, f, g, h, a, b, c, X5, X6, X3, X14);
        ROUND_16_80_512(16 + 54, c, d, e, f, g, h, a, b, X6, X7, X4, X15);
        ROUND_16_80_512(16 + 55, b, c, d, e, f, g, h, a, X7, X8, X5, X0);
        ROUND_16_80_512(16 + 56, a, b, c, d, e, f, g, h, X8, X9, X6, X1);
        ROUND_16_80_512(16 + 57, h, a, b, c, d, e, f, g, X9, X10, X7, X2);
        ROUND_16_80_512(16 + 58, g, h, a, b, c, d, e, f, X10, X11, X8, X3);
        ROUND_16_80_512(16 + 59, f, g, h, a, b, c, d, e, X11, X12, X9, X4);
        ROUND_16_80_512(16 + 60, e, f, g, h, a, b, c, d, X12, X13, X10, X5);
        ROUND_16_80_512(16 + 61, d, e, f, g, h, a, b, c, X13, X14, X11, X6);
        ROUND_16_80_512(16 + 62, c, d, e, f, g, h, a, b, X14, X15, X12, X7);
        ROUND_16_80_512(16 + 63, b, c, d, e, f, g, h, a, X15, X0, X13, X8);

#else				// NVIDIA_GPU
        T1 = X[0] = ROTR(X[0], 32);	ROUND_00_15_512(0, a, b, c, d, e, f, g, h);
        T1 = X[1] = ROTR(X[1], 32);	ROUND_00_15_512(1, h, a, b, c, d, e, f, g);
        T1 = X[2] = ROTR(X[2], 32);	ROUND_00_15_512(2, g, h, a, b, c, d, e, f);
        T1 = X[3] = ROTR(X[3], 32);	ROUND_00_15_512(3, f, g, h, a, b, c, d, e);
        T1 = X[4] = ROTR(X[4], 32);	ROUND_00_15_512(4, e, f, g, h, a, b, c, d);
        T1 = X[5] = ROTR(X[5], 32);	ROUND_00_15_512(5, d, e, f, g, h, a, b, c);
        T1 = X[6] = ROTR(X[6], 32);	ROUND_00_15_512(6, c, d, e, f, g, h, a, b);
        T1 = X[7] = ROTR(X[7], 32);	ROUND_00_15_512(7, b, c, d, e, f, g, h, a);
        T1 = X[8] = ROTR(X[8], 32);	ROUND_00_15_512(8, a, b, c, d, e, f, g, h);
        T1 = X[9] = ROTR(X[9], 32);	ROUND_00_15_512(9, h, a, b, c, d, e, f, g);
        T1 = X[10] = ROTR(X[10], 32);	ROUND_00_15_512(10, g, h, a, b, c, d, e, f);
        T1 = X[11] = ROTR(X[11], 32);	ROUND_00_15_512(11, f, g, h, a, b, c, d, e);
        T1 = X[12] = ROTR(X[12], 32);	ROUND_00_15_512(12, e, f, g, h, a, b, c, d);
        T1 = X[13] = ROTR(X[13], 32);	ROUND_00_15_512(13, d, e, f, g, h, a, b, c);
        T1 = X[14] = ROTR(X[14], 32);	ROUND_00_15_512(14, c, d, e, f, g, h, a, b);
        T1 = X[15] = ROTR(X[15], 32);	ROUND_00_15_512(15, b, c, d, e, f, g, h, a);

        ROUND_16_80_512(16 + 0, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 1, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 2, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 3, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 4, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 5, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 6, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 7, b, c, d, e, f, g, h, a, X);

        ROUND_16_80_512(16 + 8, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 9, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 10, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 11, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 12, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 13, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 14, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 15, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 16, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 17, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 18, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 19, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 20, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 21, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 22, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 23, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 24, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 25, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 26, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 27, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 28, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 29, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 30, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 31, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 32, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 33, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 34, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 35, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 36, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 37, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 38, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 39, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 40, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 41, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 42, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 43, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 44, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 45, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 46, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 47, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 48, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 49, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 50, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 51, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 52, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 53, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 54, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 55, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 56, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 57, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 58, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 59, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 60, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 61, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 62, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 63, b, c, d, e, f, g, h, a, X);
#endif

        ctx.h0 += a;	ctx.h1 += b;	ctx.h2 += c;	ctx.h3 += d;
        ctx.h4 += e;	ctx.h5 += f;	ctx.h6 += g;	ctx.h7 += h;

#ifdef DEMO_VERSION
        break;
#else
        if (--len == 0) break;
        X += SHA_LBLOCK;
#endif

    } // for


    for (unsigned int spin = 0; spin < in->spinCount; spin++)
    {
        a = U64(0x6a09e667f3bcc908);
        b = U64(0xbb67ae8584caa73b);
        c = U64(0x3c6ef372fe94f82b);
        d = U64(0xa54ff53a5f1d36f1);
        e = U64(0x510e527fade682d1);
        f = U64(0x9b05688c2b3e6c1f);
        g = U64(0x1f83d9abfb41bd6b);
        h = U64(0x5be0cd19137e2179);

        xor_save = b ^ c;

#if defined (ll1lll1)		// AMD_GPU
        T1 = X0 = ((unsigned long)bswap_dword(spin)
            << 32) | (ctx.h0 >> 32);		ROUND_00_15_512(0, a, b, c, d, e, f, g, h);
        T1 = X1 = (ctx.h0 << 32) | (ctx.h1 >> 32);	ROUND_00_15_512(1, h, a, b, c, d, e, f, g);
        T1 = X2 = (ctx.h1 << 32) | (ctx.h2 >> 32);	ROUND_00_15_512(2, g, h, a, b, c, d, e, f);
        T1 = X3 = (ctx.h2 << 32) | (ctx.h3 >> 32);	ROUND_00_15_512(3, f, g, h, a, b, c, d, e);
        T1 = X4 = (ctx.h3 << 32) | (ctx.h4 >> 32);	ROUND_00_15_512(4, e, f, g, h, a, b, c, d);
        T1 = X5 = (ctx.h4 << 32) | (ctx.h5 >> 32);	ROUND_00_15_512(5, d, e, f, g, h, a, b, c);
        T1 = X6 = (ctx.h5 << 32) | (ctx.h6 >> 32);	ROUND_00_15_512(6, c, d, e, f, g, h, a, b);
        T1 = X7 = (ctx.h6 << 32) | (ctx.h7 >> 32);	ROUND_00_15_512(7, b, c, d, e, f, g, h, a);
        T1 = X8 = (ctx.h7 << 32) | U64(0x80000000);	ROUND_00_15_512(8, a, b, c, d, e, f, g, h);
        T1 = X9 = U64(0);				ROUND_00_15_512(9, h, a, b, c, d, e, f, g);
        T1 = X10 = U64(0);				ROUND_00_15_512(10, g, h, a, b, c, d, e, f);
        T1 = X11 = U64(0);				ROUND_00_15_512(11, f, g, h, a, b, c, d, e);
        T1 = X12 = U64(0);				ROUND_00_15_512(12, e, f, g, h, a, b, c, d);
        T1 = X13 = U64(0);				ROUND_00_15_512(13, d, e, f, g, h, a, b, c);
        T1 = X14 = U64(0);				ROUND_00_15_512(14, c, d, e, f, g, h, a, b);
        T1 = X15 = U64(0x220);				ROUND_00_15_512(15, b, c, d, e, f, g, h, a);

        ROUND_16_80_512(16 + 0, a, b, c, d, e, f, g, h, X0, X1, X14, X9);
        ROUND_16_80_512(16 + 1, h, a, b, c, d, e, f, g, X1, X2, X15, X10);
        ROUND_16_80_512(16 + 2, g, h, a, b, c, d, e, f, X2, X3, X0, X11);
        ROUND_16_80_512(16 + 3, f, g, h, a, b, c, d, e, X3, X4, X1, X12);
        ROUND_16_80_512(16 + 4, e, f, g, h, a, b, c, d, X4, X5, X2, X13);
        ROUND_16_80_512(16 + 5, d, e, f, g, h, a, b, c, X5, X6, X3, X14);
        ROUND_16_80_512(16 + 6, c, d, e, f, g, h, a, b, X6, X7, X4, X15);
        ROUND_16_80_512(16 + 7, b, c, d, e, f, g, h, a, X7, X8, X5, X0);
        ROUND_16_80_512(16 + 8, a, b, c, d, e, f, g, h, X8, X9, X6, X1);
        ROUND_16_80_512(16 + 9, h, a, b, c, d, e, f, g, X9, X10, X7, X2);
        ROUND_16_80_512(16 + 10, g, h, a, b, c, d, e, f, X10, X11, X8, X3);
        ROUND_16_80_512(16 + 11, f, g, h, a, b, c, d, e, X11, X12, X9, X4);
        ROUND_16_80_512(16 + 12, e, f, g, h, a, b, c, d, X12, X13, X10, X5);
        ROUND_16_80_512(16 + 13, d, e, f, g, h, a, b, c, X13, X14, X11, X6);
        ROUND_16_80_512(16 + 14, c, d, e, f, g, h, a, b, X14, X15, X12, X7);
        ROUND_16_80_512(16 + 15, b, c, d, e, f, g, h, a, X15, X0, X13, X8);
        ROUND_16_80_512(16 + 16, a, b, c, d, e, f, g, h, X0, X1, X14, X9);
        ROUND_16_80_512(16 + 17, h, a, b, c, d, e, f, g, X1, X2, X15, X10);
        ROUND_16_80_512(16 + 18, g, h, a, b, c, d, e, f, X2, X3, X0, X11);
        ROUND_16_80_512(16 + 19, f, g, h, a, b, c, d, e, X3, X4, X1, X12);
        ROUND_16_80_512(16 + 20, e, f, g, h, a, b, c, d, X4, X5, X2, X13);
        ROUND_16_80_512(16 + 21, d, e, f, g, h, a, b, c, X5, X6, X3, X14);
        ROUND_16_80_512(16 + 22, c, d, e, f, g, h, a, b, X6, X7, X4, X15);
        ROUND_16_80_512(16 + 23, b, c, d, e, f, g, h, a, X7, X8, X5, X0);
        ROUND_16_80_512(16 + 24, a, b, c, d, e, f, g, h, X8, X9, X6, X1);
        ROUND_16_80_512(16 + 25, h, a, b, c, d, e, f, g, X9, X10, X7, X2);
        ROUND_16_80_512(16 + 26, g, h, a, b, c, d, e, f, X10, X11, X8, X3);
        ROUND_16_80_512(16 + 27, f, g, h, a, b, c, d, e, X11, X12, X9, X4);
        ROUND_16_80_512(16 + 28, e, f, g, h, a, b, c, d, X12, X13, X10, X5);
        ROUND_16_80_512(16 + 29, d, e, f, g, h, a, b, c, X13, X14, X11, X6);
        ROUND_16_80_512(16 + 30, c, d, e, f, g, h, a, b, X14, X15, X12, X7);
        ROUND_16_80_512(16 + 31, b, c, d, e, f, g, h, a, X15, X0, X13, X8);
        ROUND_16_80_512(16 + 32, a, b, c, d, e, f, g, h, X0, X1, X14, X9);
        ROUND_16_80_512(16 + 33, h, a, b, c, d, e, f, g, X1, X2, X15, X10);
        ROUND_16_80_512(16 + 34, g, h, a, b, c, d, e, f, X2, X3, X0, X11);
        ROUND_16_80_512(16 + 35, f, g, h, a, b, c, d, e, X3, X4, X1, X12);
        ROUND_16_80_512(16 + 36, e, f, g, h, a, b, c, d, X4, X5, X2, X13);
        ROUND_16_80_512(16 + 37, d, e, f, g, h, a, b, c, X5, X6, X3, X14);
        ROUND_16_80_512(16 + 38, c, d, e, f, g, h, a, b, X6, X7, X4, X15);
        ROUND_16_80_512(16 + 39, b, c, d, e, f, g, h, a, X7, X8, X5, X0);
        ROUND_16_80_512(16 + 40, a, b, c, d, e, f, g, h, X8, X9, X6, X1);
        ROUND_16_80_512(16 + 41, h, a, b, c, d, e, f, g, X9, X10, X7, X2);
        ROUND_16_80_512(16 + 42, g, h, a, b, c, d, e, f, X10, X11, X8, X3);
        ROUND_16_80_512(16 + 43, f, g, h, a, b, c, d, e, X11, X12, X9, X4);
        ROUND_16_80_512(16 + 44, e, f, g, h, a, b, c, d, X12, X13, X10, X5);
        ROUND_16_80_512(16 + 45, d, e, f, g, h, a, b, c, X13, X14, X11, X6);
        ROUND_16_80_512(16 + 46, c, d, e, f, g, h, a, b, X14, X15, X12, X7);
        ROUND_16_80_512(16 + 47, b, c, d, e, f, g, h, a, X15, X0, X13, X8);
        ROUND_16_80_512(16 + 48, a, b, c, d, e, f, g, h, X0, X1, X14, X9);
        ROUND_16_80_512(16 + 49, h, a, b, c, d, e, f, g, X1, X2, X15, X10);
        ROUND_16_80_512(16 + 50, g, h, a, b, c, d, e, f, X2, X3, X0, X11);
        ROUND_16_80_512(16 + 51, f, g, h, a, b, c, d, e, X3, X4, X1, X12);
        ROUND_16_80_512(16 + 52, e, f, g, h, a, b, c, d, X4, X5, X2, X13);
        ROUND_16_80_512(16 + 53, d, e, f, g, h, a, b, c, X5, X6, X3, X14);
        ROUND_16_80_512(16 + 54, c, d, e, f, g, h, a, b, X6, X7, X4, X15);
        ROUND_16_80_512(16 + 55, b, c, d, e, f, g, h, a, X7, X8, X5, X0);
        ROUND_16_80_512(16 + 56, a, b, c, d, e, f, g, h, X8, X9, X6, X1);
        ROUND_16_80_512(16 + 57, h, a, b, c, d, e, f, g, X9, X10, X7, X2);
        ROUND_16_80_512(16 + 58, g, h, a, b, c, d, e, f, X10, X11, X8, X3);
        ROUND_16_80_512(16 + 59, f, g, h, a, b, c, d, e, X11, X12, X9, X4);
        ROUND_16_80_512(16 + 60, e, f, g, h, a, b, c, d, X12, X13, X10, X5);
        ROUND_16_80_512(16 + 61, d, e, f, g, h, a, b, c, X13, X14, X11, X6);
        ROUND_16_80_512(16 + 62, c, d, e, f, g, h, a, b, X14, X15, X12, X7);
        ROUND_16_80_512(16 + 63, b, c, d, e, f, g, h, a, X15, X0, X13, X8);

#else				// NVIDIA_GPU
        T1 = X[0] = ((unsigned long)bswap_dword(spin)
            << 32) | (ctx.h0 >> 32);	ROUND_00_15_512(0, a, b, c, d, e, f, g, h);
        T1 = X[1] = (ctx.h0 << 32) | (ctx.h1 >> 32);	ROUND_00_15_512(1, h, a, b, c, d, e, f, g);
        T1 = X[2] = (ctx.h1 << 32) | (ctx.h2 >> 32);	ROUND_00_15_512(2, g, h, a, b, c, d, e, f);
        T1 = X[3] = (ctx.h2 << 32) | (ctx.h3 >> 32);	ROUND_00_15_512(3, f, g, h, a, b, c, d, e);
        T1 = X[4] = (ctx.h3 << 32) | (ctx.h4 >> 32);	ROUND_00_15_512(4, e, f, g, h, a, b, c, d);
        T1 = X[5] = (ctx.h4 << 32) | (ctx.h5 >> 32);	ROUND_00_15_512(5, d, e, f, g, h, a, b, c);
        T1 = X[6] = (ctx.h5 << 32) | (ctx.h6 >> 32);	ROUND_00_15_512(6, c, d, e, f, g, h, a, b);
        T1 = X[7] = (ctx.h6 << 32) | (ctx.h7 >> 32);	ROUND_00_15_512(7, b, c, d, e, f, g, h, a);
        T1 = X[8] = (ctx.h7 << 32) | U64(0x80000000);	ROUND_00_15_512(8, a, b, c, d, e, f, g, h);
        T1 = X[9] = U64(0);				ROUND_00_15_512(9, h, a, b, c, d, e, f, g);
        T1 = X[10] = U64(0);				ROUND_00_15_512(10, g, h, a, b, c, d, e, f);
        T1 = X[11] = U64(0);				ROUND_00_15_512(11, f, g, h, a, b, c, d, e);
        T1 = X[12] = U64(0);				ROUND_00_15_512(12, e, f, g, h, a, b, c, d);
        T1 = X[13] = U64(0);				ROUND_00_15_512(13, d, e, f, g, h, a, b, c);
        T1 = X[14] = U64(0);				ROUND_00_15_512(14, c, d, e, f, g, h, a, b);
        T1 = X[15] = U64(0x220);				ROUND_00_15_512(15, b, c, d, e, f, g, h, a);

        ROUND_16_80_512(16 + 0, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 1, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 2, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 3, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 4, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 5, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 6, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 7, b, c, d, e, f, g, h, a, X);

        ROUND_16_80_512(16 + 8, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 9, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 10, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 11, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 12, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 13, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 14, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 15, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 16, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 17, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 18, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 19, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 20, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 21, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 22, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 23, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 24, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 25, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 26, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 27, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 28, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 29, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 30, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 31, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 32, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 33, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 34, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 35, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 36, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 37, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 38, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 39, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 40, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 41, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 42, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 43, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 44, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 45, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 46, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 47, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 48, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 49, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 50, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 51, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 52, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 53, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 54, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 55, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 56, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 57, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 58, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 59, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 60, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 61, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 62, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 63, b, c, d, e, f, g, h, a, X);
#endif

        ctx.h0 = a + U64(0x6a09e667f3bcc908);	ctx.h1 = b + U64(0xbb67ae8584caa73b);
        ctx.h2 = c + U64(0x3c6ef372fe94f82b);	ctx.h3 = d + U64(0xa54ff53a5f1d36f1);
        ctx.h4 = e + U64(0x510e527fade682d1);	ctx.h5 = f + U64(0x9b05688c2b3e6c1f);
        ctx.h6 = g + U64(0x1f83d9abfb41bd6b);	ctx.h7 = h + U64(0x5be0cd19137e2179);


    } // sha * 50000


    // make_key 1

    {
        a = U64(0x6a09e667f3bcc908);
        b = U64(0xbb67ae8584caa73b);
        c = U64(0x3c6ef372fe94f82b);
        d = U64(0xa54ff53a5f1d36f1);
        e = U64(0x510e527fade682d1);
        f = U64(0x9b05688c2b3e6c1f);
        g = U64(0x1f83d9abfb41bd6b);
        h = U64(0x5be0cd19137e2179);

        xor_save = b ^ c;

#if defined (ll1lll1)		// AMD_GPU
        T1 = X0 = ctx.h0;		 	ROUND_00_15_512(0, a, b, c, d, e, f, g, h);
        T1 = X1 = ctx.h1;			ROUND_00_15_512(1, h, a, b, c, d, e, f, g);
        T1 = X2 = ctx.h2;			ROUND_00_15_512(2, g, h, a, b, c, d, e, f);
        T1 = X3 = ctx.h3;			ROUND_00_15_512(3, f, g, h, a, b, c, d, e);
        T1 = X4 = ctx.h4;			ROUND_00_15_512(4, e, f, g, h, a, b, c, d);
        T1 = X5 = ctx.h5;			ROUND_00_15_512(5, d, e, f, g, h, a, b, c);
        T1 = X6 = ctx.h6;			ROUND_00_15_512(6, c, d, e, f, g, h, a, b);
        T1 = X7 = ctx.h7;			ROUND_00_15_512(7, b, c, d, e, f, g, h, a);
        T1 = X8 = U64(0xfea7d2763b4b9e79);	ROUND_00_15_512(8, a, b, c, d, e, f, g, h);
        T1 = X9 = U64(0x8000000000000000);	ROUND_00_15_512(9, h, a, b, c, d, e, f, g);
        T1 = X10 = U64(0);			ROUND_00_15_512(10, g, h, a, b, c, d, e, f);
        T1 = X11 = U64(0);			ROUND_00_15_512(11, f, g, h, a, b, c, d, e);
        T1 = X12 = U64(0);			ROUND_00_15_512(12, e, f, g, h, a, b, c, d);
        T1 = X13 = U64(0);			ROUND_00_15_512(13, d, e, f, g, h, a, b, c);
        T1 = X14 = U64(0);			ROUND_00_15_512(14, c, d, e, f, g, h, a, b);
        T1 = X15 = U64(0x240);			ROUND_00_15_512(15, b, c, d, e, f, g, h, a);


        ROUND_16_80_512(16 + 0, a, b, c, d, e, f, g, h, X0, X1, X14, X9);
        ROUND_16_80_512(16 + 1, h, a, b, c, d, e, f, g, X1, X2, X15, X10);
        ROUND_16_80_512(16 + 2, g, h, a, b, c, d, e, f, X2, X3, X0, X11);
        ROUND_16_80_512(16 + 3, f, g, h, a, b, c, d, e, X3, X4, X1, X12);
        ROUND_16_80_512(16 + 4, e, f, g, h, a, b, c, d, X4, X5, X2, X13);
        ROUND_16_80_512(16 + 5, d, e, f, g, h, a, b, c, X5, X6, X3, X14);
        ROUND_16_80_512(16 + 6, c, d, e, f, g, h, a, b, X6, X7, X4, X15);
        ROUND_16_80_512(16 + 7, b, c, d, e, f, g, h, a, X7, X8, X5, X0);
        ROUND_16_80_512(16 + 8, a, b, c, d, e, f, g, h, X8, X9, X6, X1);
        ROUND_16_80_512(16 + 9, h, a, b, c, d, e, f, g, X9, X10, X7, X2);
        ROUND_16_80_512(16 + 10, g, h, a, b, c, d, e, f, X10, X11, X8, X3);
        ROUND_16_80_512(16 + 11, f, g, h, a, b, c, d, e, X11, X12, X9, X4);
        ROUND_16_80_512(16 + 12, e, f, g, h, a, b, c, d, X12, X13, X10, X5);
        ROUND_16_80_512(16 + 13, d, e, f, g, h, a, b, c, X13, X14, X11, X6);
        ROUND_16_80_512(16 + 14, c, d, e, f, g, h, a, b, X14, X15, X12, X7);
        ROUND_16_80_512(16 + 15, b, c, d, e, f, g, h, a, X15, X0, X13, X8);
        ROUND_16_80_512(16 + 16, a, b, c, d, e, f, g, h, X0, X1, X14, X9);
        ROUND_16_80_512(16 + 17, h, a, b, c, d, e, f, g, X1, X2, X15, X10);
        ROUND_16_80_512(16 + 18, g, h, a, b, c, d, e, f, X2, X3, X0, X11);
        ROUND_16_80_512(16 + 19, f, g, h, a, b, c, d, e, X3, X4, X1, X12);
        ROUND_16_80_512(16 + 20, e, f, g, h, a, b, c, d, X4, X5, X2, X13);
        ROUND_16_80_512(16 + 21, d, e, f, g, h, a, b, c, X5, X6, X3, X14);
        ROUND_16_80_512(16 + 22, c, d, e, f, g, h, a, b, X6, X7, X4, X15);
        ROUND_16_80_512(16 + 23, b, c, d, e, f, g, h, a, X7, X8, X5, X0);
        ROUND_16_80_512(16 + 24, a, b, c, d, e, f, g, h, X8, X9, X6, X1);
        ROUND_16_80_512(16 + 25, h, a, b, c, d, e, f, g, X9, X10, X7, X2);
        ROUND_16_80_512(16 + 26, g, h, a, b, c, d, e, f, X10, X11, X8, X3);
        ROUND_16_80_512(16 + 27, f, g, h, a, b, c, d, e, X11, X12, X9, X4);
        ROUND_16_80_512(16 + 28, e, f, g, h, a, b, c, d, X12, X13, X10, X5);
        ROUND_16_80_512(16 + 29, d, e, f, g, h, a, b, c, X13, X14, X11, X6);
        ROUND_16_80_512(16 + 30, c, d, e, f, g, h, a, b, X14, X15, X12, X7);
        ROUND_16_80_512(16 + 31, b, c, d, e, f, g, h, a, X15, X0, X13, X8);
        ROUND_16_80_512(16 + 32, a, b, c, d, e, f, g, h, X0, X1, X14, X9);
        ROUND_16_80_512(16 + 33, h, a, b, c, d, e, f, g, X1, X2, X15, X10);
        ROUND_16_80_512(16 + 34, g, h, a, b, c, d, e, f, X2, X3, X0, X11);
        ROUND_16_80_512(16 + 35, f, g, h, a, b, c, d, e, X3, X4, X1, X12);
        ROUND_16_80_512(16 + 36, e, f, g, h, a, b, c, d, X4, X5, X2, X13);
        ROUND_16_80_512(16 + 37, d, e, f, g, h, a, b, c, X5, X6, X3, X14);
        ROUND_16_80_512(16 + 38, c, d, e, f, g, h, a, b, X6, X7, X4, X15);
        ROUND_16_80_512(16 + 39, b, c, d, e, f, g, h, a, X7, X8, X5, X0);
        ROUND_16_80_512(16 + 40, a, b, c, d, e, f, g, h, X8, X9, X6, X1);
        ROUND_16_80_512(16 + 41, h, a, b, c, d, e, f, g, X9, X10, X7, X2);
        ROUND_16_80_512(16 + 42, g, h, a, b, c, d, e, f, X10, X11, X8, X3);
        ROUND_16_80_512(16 + 43, f, g, h, a, b, c, d, e, X11, X12, X9, X4);
        ROUND_16_80_512(16 + 44, e, f, g, h, a, b, c, d, X12, X13, X10, X5);
        ROUND_16_80_512(16 + 45, d, e, f, g, h, a, b, c, X13, X14, X11, X6);
        ROUND_16_80_512(16 + 46, c, d, e, f, g, h, a, b, X14, X15, X12, X7);
        ROUND_16_80_512(16 + 47, b, c, d, e, f, g, h, a, X15, X0, X13, X8);
        ROUND_16_80_512(16 + 48, a, b, c, d, e, f, g, h, X0, X1, X14, X9);
        ROUND_16_80_512(16 + 49, h, a, b, c, d, e, f, g, X1, X2, X15, X10);
        ROUND_16_80_512(16 + 50, g, h, a, b, c, d, e, f, X2, X3, X0, X11);
        ROUND_16_80_512(16 + 51, f, g, h, a, b, c, d, e, X3, X4, X1, X12);
        ROUND_16_80_512(16 + 52, e, f, g, h, a, b, c, d, X4, X5, X2, X13);
        ROUND_16_80_512(16 + 53, d, e, f, g, h, a, b, c, X5, X6, X3, X14);
        ROUND_16_80_512(16 + 54, c, d, e, f, g, h, a, b, X6, X7, X4, X15);
        ROUND_16_80_512(16 + 55, b, c, d, e, f, g, h, a, X7, X8, X5, X0);
        ROUND_16_80_512(16 + 56, a, b, c, d, e, f, g, h, X8, X9, X6, X1);
        ROUND_16_80_512(16 + 57, h, a, b, c, d, e, f, g, X9, X10, X7, X2);
        ROUND_16_80_512(16 + 58, g, h, a, b, c, d, e, f, X10, X11, X8, X3);
        ROUND_16_80_512(16 + 59, f, g, h, a, b, c, d, e, X11, X12, X9, X4);
        ROUND_16_80_512(16 + 60, e, f, g, h, a, b, c, d, X12, X13, X10, X5);
        ROUND_16_80_512(16 + 61, d, e, f, g, h, a, b, c, X13, X14, X11, X6);
        ROUND_16_80_512(16 + 62, c, d, e, f, g, h, a, b, X14, X15, X12, X7);
        ROUND_16_80_512(16 + 63, b, c, d, e, f, g, h, a, X15, X0, X13, X8);

#else				// NVIDIA_GPU

        T1 = X[0] = ctx.h0;		 	ROUND_00_15_512(0, a, b, c, d, e, f, g, h);
        T1 = X[1] = ctx.h1;			ROUND_00_15_512(1, h, a, b, c, d, e, f, g);
        T1 = X[2] = ctx.h2;			ROUND_00_15_512(2, g, h, a, b, c, d, e, f);
        T1 = X[3] = ctx.h3;			ROUND_00_15_512(3, f, g, h, a, b, c, d, e);
        T1 = X[4] = ctx.h4;			ROUND_00_15_512(4, e, f, g, h, a, b, c, d);
        T1 = X[5] = ctx.h5;			ROUND_00_15_512(5, d, e, f, g, h, a, b, c);
        T1 = X[6] = ctx.h6;			ROUND_00_15_512(6, c, d, e, f, g, h, a, b);
        T1 = X[7] = ctx.h7;			ROUND_00_15_512(7, b, c, d, e, f, g, h, a);
        T1 = X[8] = U64(0xfea7d2763b4b9e79);		ROUND_00_15_512(8, a, b, c, d, e, f, g, h);
        T1 = X[9] = U64(0x8000000000000000);	ROUND_00_15_512(9, h, a, b, c, d, e, f, g);
        T1 = X[10] = U64(0);			ROUND_00_15_512(10, g, h, a, b, c, d, e, f);
        T1 = X[11] = U64(0);			ROUND_00_15_512(11, f, g, h, a, b, c, d, e);
        T1 = X[12] = U64(0);			ROUND_00_15_512(12, e, f, g, h, a, b, c, d);
        T1 = X[13] = U64(0);			ROUND_00_15_512(13, d, e, f, g, h, a, b, c);
        T1 = X[14] = U64(0);			ROUND_00_15_512(14, c, d, e, f, g, h, a, b);
        T1 = X[15] = U64(0x240);			ROUND_00_15_512(15, b, c, d, e, f, g, h, a);

        ROUND_16_80_512(16 + 0, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 1, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 2, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 3, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 4, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 5, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 6, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 7, b, c, d, e, f, g, h, a, X);

        ROUND_16_80_512(16 + 8, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 9, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 10, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 11, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 12, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 13, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 14, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 15, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 16, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 17, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 18, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 19, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 20, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 21, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 22, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 23, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 24, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 25, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 26, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 27, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 28, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 29, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 30, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 31, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 32, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 33, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 34, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 35, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 36, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 37, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 38, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 39, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 40, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 41, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 42, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 43, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 44, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 45, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 46, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 47, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 48, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 49, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 50, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 51, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 52, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 53, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 54, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 55, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 56, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 57, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 58, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 59, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 60, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 61, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 62, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 63, b, c, d, e, f, g, h, a, X);
#endif
        a = a + U64(0x6a09e667f3bcc908);	b = b + U64(0xbb67ae8584caa73b);
        c = c + U64(0x3c6ef372fe94f82b);	d = d + U64(0xa54ff53a5f1d36f1);
        e = e + U64(0x510e527fade682d1);	f = f + U64(0x9b05688c2b3e6c1f);
        g = g + U64(0x1f83d9abfb41bd6b);	h = h + U64(0x5be0cd19137e2179);

    }

    AES_KEY key;
    ULONG A, B, C, D;


    AES_set_decrypt_key_256(a, b, c, d, in->key_length, &key);


    AES_decrypt(in->salt, &A, &B, &C, &D, in->key_length, &key);
    A ^= bswap_dword(in->docid[0]);
    B ^= bswap_dword(in->docid[1]);
    C ^= bswap_dword(in->docid[2]);
    D ^= bswap_dword(in->docid[3]);

    // make_key 2

    {
        a = U64(0x6a09e667f3bcc908);
        b = U64(0xbb67ae8584caa73b);
        c = U64(0x3c6ef372fe94f82b);
        d = U64(0xa54ff53a5f1d36f1);
        e = U64(0x510e527fade682d1);
        f = U64(0x9b05688c2b3e6c1f);
        g = U64(0x1f83d9abfb41bd6b);
        h = U64(0x5be0cd19137e2179);

        xor_save = b ^ c;

#if defined (ll1lll1)		// AMD_GPU
        T1 = X0 = ctx.h0;		 	ROUND_00_15_512(0, a, b, c, d, e, f, g, h);
        T1 = X1 = ctx.h1;			ROUND_00_15_512(1, h, a, b, c, d, e, f, g);
        T1 = X2 = ctx.h2;			ROUND_00_15_512(2, g, h, a, b, c, d, e, f);
        T1 = X3 = ctx.h3;			ROUND_00_15_512(3, f, g, h, a, b, c, d, e);
        T1 = X4 = ctx.h4;			ROUND_00_15_512(4, e, f, g, h, a, b, c, d);
        T1 = X5 = ctx.h5;			ROUND_00_15_512(5, d, e, f, g, h, a, b, c);
        T1 = X6 = ctx.h6;			ROUND_00_15_512(6, c, d, e, f, g, h, a, b);
        T1 = X7 = ctx.h7;			ROUND_00_15_512(7, b, c, d, e, f, g, h, a);
        T1 = X8 = U64(0xd7aa0f6d3061344e);	ROUND_00_15_512(8, a, b, c, d, e, f, g, h);
        T1 = X9 = U64(0x8000000000000000);	ROUND_00_15_512(9, h, a, b, c, d, e, f, g);
        T1 = X10 = U64(0);			ROUND_00_15_512(10, g, h, a, b, c, d, e, f);
        T1 = X11 = U64(0);			ROUND_00_15_512(11, f, g, h, a, b, c, d, e);
        T1 = X12 = U64(0);			ROUND_00_15_512(12, e, f, g, h, a, b, c, d);
        T1 = X13 = U64(0);			ROUND_00_15_512(13, d, e, f, g, h, a, b, c);
        T1 = X14 = U64(0);			ROUND_00_15_512(14, c, d, e, f, g, h, a, b);
        T1 = X15 = U64(0x240);			ROUND_00_15_512(15, b, c, d, e, f, g, h, a);


        ROUND_16_80_512(16 + 0, a, b, c, d, e, f, g, h, X0, X1, X14, X9);
        ROUND_16_80_512(16 + 1, h, a, b, c, d, e, f, g, X1, X2, X15, X10);
        ROUND_16_80_512(16 + 2, g, h, a, b, c, d, e, f, X2, X3, X0, X11);
        ROUND_16_80_512(16 + 3, f, g, h, a, b, c, d, e, X3, X4, X1, X12);
        ROUND_16_80_512(16 + 4, e, f, g, h, a, b, c, d, X4, X5, X2, X13);
        ROUND_16_80_512(16 + 5, d, e, f, g, h, a, b, c, X5, X6, X3, X14);
        ROUND_16_80_512(16 + 6, c, d, e, f, g, h, a, b, X6, X7, X4, X15);
        ROUND_16_80_512(16 + 7, b, c, d, e, f, g, h, a, X7, X8, X5, X0);
        ROUND_16_80_512(16 + 8, a, b, c, d, e, f, g, h, X8, X9, X6, X1);
        ROUND_16_80_512(16 + 9, h, a, b, c, d, e, f, g, X9, X10, X7, X2);
        ROUND_16_80_512(16 + 10, g, h, a, b, c, d, e, f, X10, X11, X8, X3);
        ROUND_16_80_512(16 + 11, f, g, h, a, b, c, d, e, X11, X12, X9, X4);
        ROUND_16_80_512(16 + 12, e, f, g, h, a, b, c, d, X12, X13, X10, X5);
        ROUND_16_80_512(16 + 13, d, e, f, g, h, a, b, c, X13, X14, X11, X6);
        ROUND_16_80_512(16 + 14, c, d, e, f, g, h, a, b, X14, X15, X12, X7);
        ROUND_16_80_512(16 + 15, b, c, d, e, f, g, h, a, X15, X0, X13, X8);
        ROUND_16_80_512(16 + 16, a, b, c, d, e, f, g, h, X0, X1, X14, X9);
        ROUND_16_80_512(16 + 17, h, a, b, c, d, e, f, g, X1, X2, X15, X10);
        ROUND_16_80_512(16 + 18, g, h, a, b, c, d, e, f, X2, X3, X0, X11);
        ROUND_16_80_512(16 + 19, f, g, h, a, b, c, d, e, X3, X4, X1, X12);
        ROUND_16_80_512(16 + 20, e, f, g, h, a, b, c, d, X4, X5, X2, X13);
        ROUND_16_80_512(16 + 21, d, e, f, g, h, a, b, c, X5, X6, X3, X14);
        ROUND_16_80_512(16 + 22, c, d, e, f, g, h, a, b, X6, X7, X4, X15);
        ROUND_16_80_512(16 + 23, b, c, d, e, f, g, h, a, X7, X8, X5, X0);
        ROUND_16_80_512(16 + 24, a, b, c, d, e, f, g, h, X8, X9, X6, X1);
        ROUND_16_80_512(16 + 25, h, a, b, c, d, e, f, g, X9, X10, X7, X2);
        ROUND_16_80_512(16 + 26, g, h, a, b, c, d, e, f, X10, X11, X8, X3);
        ROUND_16_80_512(16 + 27, f, g, h, a, b, c, d, e, X11, X12, X9, X4);
        ROUND_16_80_512(16 + 28, e, f, g, h, a, b, c, d, X12, X13, X10, X5);
        ROUND_16_80_512(16 + 29, d, e, f, g, h, a, b, c, X13, X14, X11, X6);
        ROUND_16_80_512(16 + 30, c, d, e, f, g, h, a, b, X14, X15, X12, X7);
        ROUND_16_80_512(16 + 31, b, c, d, e, f, g, h, a, X15, X0, X13, X8);
        ROUND_16_80_512(16 + 32, a, b, c, d, e, f, g, h, X0, X1, X14, X9);
        ROUND_16_80_512(16 + 33, h, a, b, c, d, e, f, g, X1, X2, X15, X10);
        ROUND_16_80_512(16 + 34, g, h, a, b, c, d, e, f, X2, X3, X0, X11);
        ROUND_16_80_512(16 + 35, f, g, h, a, b, c, d, e, X3, X4, X1, X12);
        ROUND_16_80_512(16 + 36, e, f, g, h, a, b, c, d, X4, X5, X2, X13);
        ROUND_16_80_512(16 + 37, d, e, f, g, h, a, b, c, X5, X6, X3, X14);
        ROUND_16_80_512(16 + 38, c, d, e, f, g, h, a, b, X6, X7, X4, X15);
        ROUND_16_80_512(16 + 39, b, c, d, e, f, g, h, a, X7, X8, X5, X0);
        ROUND_16_80_512(16 + 40, a, b, c, d, e, f, g, h, X8, X9, X6, X1);
        ROUND_16_80_512(16 + 41, h, a, b, c, d, e, f, g, X9, X10, X7, X2);
        ROUND_16_80_512(16 + 42, g, h, a, b, c, d, e, f, X10, X11, X8, X3);
        ROUND_16_80_512(16 + 43, f, g, h, a, b, c, d, e, X11, X12, X9, X4);
        ROUND_16_80_512(16 + 44, e, f, g, h, a, b, c, d, X12, X13, X10, X5);
        ROUND_16_80_512(16 + 45, d, e, f, g, h, a, b, c, X13, X14, X11, X6);
        ROUND_16_80_512(16 + 46, c, d, e, f, g, h, a, b, X14, X15, X12, X7);
        ROUND_16_80_512(16 + 47, b, c, d, e, f, g, h, a, X15, X0, X13, X8);
        ROUND_16_80_512(16 + 48, a, b, c, d, e, f, g, h, X0, X1, X14, X9);
        ROUND_16_80_512(16 + 49, h, a, b, c, d, e, f, g, X1, X2, X15, X10);
        ROUND_16_80_512(16 + 50, g, h, a, b, c, d, e, f, X2, X3, X0, X11);
        ROUND_16_80_512(16 + 51, f, g, h, a, b, c, d, e, X3, X4, X1, X12);
        ROUND_16_80_512(16 + 52, e, f, g, h, a, b, c, d, X4, X5, X2, X13);
        ROUND_16_80_512(16 + 53, d, e, f, g, h, a, b, c, X5, X6, X3, X14);
        ROUND_16_80_512(16 + 54, c, d, e, f, g, h, a, b, X6, X7, X4, X15);
        ROUND_16_80_512(16 + 55, b, c, d, e, f, g, h, a, X7, X8, X5, X0);
        ROUND_16_80_512(16 + 56, a, b, c, d, e, f, g, h, X8, X9, X6, X1);
        ROUND_16_80_512(16 + 57, h, a, b, c, d, e, f, g, X9, X10, X7, X2);
        ROUND_16_80_512(16 + 58, g, h, a, b, c, d, e, f, X10, X11, X8, X3);
        ROUND_16_80_512(16 + 59, f, g, h, a, b, c, d, e, X11, X12, X9, X4);
        ROUND_16_80_512(16 + 60, e, f, g, h, a, b, c, d, X12, X13, X10, X5);
        ROUND_16_80_512(16 + 61, d, e, f, g, h, a, b, c, X13, X14, X11, X6);
        ROUND_16_80_512(16 + 62, c, d, e, f, g, h, a, b, X14, X15, X12, X7);
        ROUND_16_80_512(16 + 63, b, c, d, e, f, g, h, a, X15, X0, X13, X8);
#else				// NVIDIA_GPU

        T1 = X[0] = ctx.h0;		 	ROUND_00_15_512(0, a, b, c, d, e, f, g, h);
        T1 = X[1] = ctx.h1;			ROUND_00_15_512(1, h, a, b, c, d, e, f, g);
        T1 = X[2] = ctx.h2;			ROUND_00_15_512(2, g, h, a, b, c, d, e, f);
        T1 = X[3] = ctx.h3;			ROUND_00_15_512(3, f, g, h, a, b, c, d, e);
        T1 = X[4] = ctx.h4;			ROUND_00_15_512(4, e, f, g, h, a, b, c, d);
        T1 = X[5] = ctx.h5;			ROUND_00_15_512(5, d, e, f, g, h, a, b, c);
        T1 = X[6] = ctx.h6;			ROUND_00_15_512(6, c, d, e, f, g, h, a, b);
        T1 = X[7] = ctx.h7;			ROUND_00_15_512(7, b, c, d, e, f, g, h, a);
        T1 = X[8] = U64(0xd7aa0f6d3061344e);	ROUND_00_15_512(8, a, b, c, d, e, f, g, h);
        T1 = X[9] = U64(0x8000000000000000);	ROUND_00_15_512(9, h, a, b, c, d, e, f, g);
        T1 = X[10] = U64(0);			ROUND_00_15_512(10, g, h, a, b, c, d, e, f);
        T1 = X[11] = U64(0);			ROUND_00_15_512(11, f, g, h, a, b, c, d, e);
        T1 = X[12] = U64(0);			ROUND_00_15_512(12, e, f, g, h, a, b, c, d);
        T1 = X[13] = U64(0);			ROUND_00_15_512(13, d, e, f, g, h, a, b, c);
        T1 = X[14] = U64(0);			ROUND_00_15_512(14, c, d, e, f, g, h, a, b);
        T1 = X[15] = U64(0x240);			ROUND_00_15_512(15, b, c, d, e, f, g, h, a);

        ROUND_16_80_512(16 + 0, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 1, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 2, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 3, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 4, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 5, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 6, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 7, b, c, d, e, f, g, h, a, X);

        ROUND_16_80_512(16 + 8, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 9, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 10, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 11, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 12, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 13, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 14, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 15, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 16, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 17, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 18, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 19, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 20, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 21, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 22, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 23, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 24, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 25, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 26, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 27, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 28, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 29, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 30, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 31, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 32, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 33, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 34, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 35, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 36, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 37, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 38, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 39, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 40, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 41, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 42, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 43, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 44, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 45, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 46, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 47, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 48, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 49, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 50, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 51, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 52, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 53, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 54, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 55, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 56, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 57, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 58, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 59, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 60, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 61, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 62, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 63, b, c, d, e, f, g, h, a, X);
#endif

        ctx.h0 = a + U64(0x6a09e667f3bcc908);	ctx.h1 = b + U64(0xbb67ae8584caa73b);
        ctx.h2 = c + U64(0x3c6ef372fe94f82b);	ctx.h3 = d + U64(0xa54ff53a5f1d36f1);
        ctx.h4 = e + U64(0x510e527fade682d1);	ctx.h5 = f + U64(0x9b05688c2b3e6c1f);
        ctx.h6 = g + U64(0x1f83d9abfb41bd6b);	ctx.h7 = h + U64(0x5be0cd19137e2179);

    }

    AES_set_decrypt_key_256(ctx.h0, ctx.h1, ctx.h2, ctx.h3, in->key_length, &key);



    // Hash Verifier
    {

        a = U64(0x6a09e667f3bcc908);
        b = U64(0xbb67ae8584caa73b);
        c = U64(0x3c6ef372fe94f82b);
        d = U64(0xa54ff53a5f1d36f1);
        e = U64(0x510e527fade682d1);
        f = U64(0x9b05688c2b3e6c1f);
        g = U64(0x1f83d9abfb41bd6b);
        h = U64(0x5be0cd19137e2179);

        xor_save = b ^ c;

#if defined (ll1lll1)		// AMD_GPU
        T1 = X0 = ((unsigned long)A << 32) + (unsigned long)B;	 	ROUND_00_15_512(0, a, b, c, d, e, f, g, h);
        T1 = X1 = ((unsigned long)C << 32) + (unsigned long)D;		ROUND_00_15_512(1, h, a, b, c, d, e, f, g);
        T1 = X2 = U64(0x8000000000000000);	ROUND_00_15_512(2, g, h, a, b, c, d, e, f);
        T1 = X3 = U64(0);			ROUND_00_15_512(3, f, g, h, a, b, c, d, e);
        T1 = X4 = U64(0);			ROUND_00_15_512(4, e, f, g, h, a, b, c, d);
        T1 = X5 = U64(0);			ROUND_00_15_512(5, d, e, f, g, h, a, b, c);
        T1 = X6 = U64(0);			ROUND_00_15_512(6, c, d, e, f, g, h, a, b);
        T1 = X7 = U64(0);			ROUND_00_15_512(7, b, c, d, e, f, g, h, a);
        T1 = X8 = U64(0);			ROUND_00_15_512(8, a, b, c, d, e, f, g, h);
        T1 = X9 = U64(0);			ROUND_00_15_512(9, h, a, b, c, d, e, f, g);
        T1 = X10 = U64(0);			ROUND_00_15_512(10, g, h, a, b, c, d, e, f);
        T1 = X11 = U64(0);			ROUND_00_15_512(11, f, g, h, a, b, c, d, e);
        T1 = X12 = U64(0);			ROUND_00_15_512(12, e, f, g, h, a, b, c, d);
        T1 = X13 = U64(0);			ROUND_00_15_512(13, d, e, f, g, h, a, b, c);
        T1 = X14 = U64(0);			ROUND_00_15_512(14, c, d, e, f, g, h, a, b);
        T1 = X15 = U64(0x80);			ROUND_00_15_512(15, b, c, d, e, f, g, h, a);


        ROUND_16_80_512(16 + 0, a, b, c, d, e, f, g, h, X0, X1, X14, X9);
        ROUND_16_80_512(16 + 1, h, a, b, c, d, e, f, g, X1, X2, X15, X10);
        ROUND_16_80_512(16 + 2, g, h, a, b, c, d, e, f, X2, X3, X0, X11);
        ROUND_16_80_512(16 + 3, f, g, h, a, b, c, d, e, X3, X4, X1, X12);
        ROUND_16_80_512(16 + 4, e, f, g, h, a, b, c, d, X4, X5, X2, X13);
        ROUND_16_80_512(16 + 5, d, e, f, g, h, a, b, c, X5, X6, X3, X14);
        ROUND_16_80_512(16 + 6, c, d, e, f, g, h, a, b, X6, X7, X4, X15);
        ROUND_16_80_512(16 + 7, b, c, d, e, f, g, h, a, X7, X8, X5, X0);
        ROUND_16_80_512(16 + 8, a, b, c, d, e, f, g, h, X8, X9, X6, X1);
        ROUND_16_80_512(16 + 9, h, a, b, c, d, e, f, g, X9, X10, X7, X2);
        ROUND_16_80_512(16 + 10, g, h, a, b, c, d, e, f, X10, X11, X8, X3);
        ROUND_16_80_512(16 + 11, f, g, h, a, b, c, d, e, X11, X12, X9, X4);
        ROUND_16_80_512(16 + 12, e, f, g, h, a, b, c, d, X12, X13, X10, X5);
        ROUND_16_80_512(16 + 13, d, e, f, g, h, a, b, c, X13, X14, X11, X6);
        ROUND_16_80_512(16 + 14, c, d, e, f, g, h, a, b, X14, X15, X12, X7);
        ROUND_16_80_512(16 + 15, b, c, d, e, f, g, h, a, X15, X0, X13, X8);
        ROUND_16_80_512(16 + 16, a, b, c, d, e, f, g, h, X0, X1, X14, X9);
        ROUND_16_80_512(16 + 17, h, a, b, c, d, e, f, g, X1, X2, X15, X10);
        ROUND_16_80_512(16 + 18, g, h, a, b, c, d, e, f, X2, X3, X0, X11);
        ROUND_16_80_512(16 + 19, f, g, h, a, b, c, d, e, X3, X4, X1, X12);
        ROUND_16_80_512(16 + 20, e, f, g, h, a, b, c, d, X4, X5, X2, X13);
        ROUND_16_80_512(16 + 21, d, e, f, g, h, a, b, c, X5, X6, X3, X14);
        ROUND_16_80_512(16 + 22, c, d, e, f, g, h, a, b, X6, X7, X4, X15);
        ROUND_16_80_512(16 + 23, b, c, d, e, f, g, h, a, X7, X8, X5, X0);
        ROUND_16_80_512(16 + 24, a, b, c, d, e, f, g, h, X8, X9, X6, X1);
        ROUND_16_80_512(16 + 25, h, a, b, c, d, e, f, g, X9, X10, X7, X2);
        ROUND_16_80_512(16 + 26, g, h, a, b, c, d, e, f, X10, X11, X8, X3);
        ROUND_16_80_512(16 + 27, f, g, h, a, b, c, d, e, X11, X12, X9, X4);
        ROUND_16_80_512(16 + 28, e, f, g, h, a, b, c, d, X12, X13, X10, X5);
        ROUND_16_80_512(16 + 29, d, e, f, g, h, a, b, c, X13, X14, X11, X6);
        ROUND_16_80_512(16 + 30, c, d, e, f, g, h, a, b, X14, X15, X12, X7);
        ROUND_16_80_512(16 + 31, b, c, d, e, f, g, h, a, X15, X0, X13, X8);
        ROUND_16_80_512(16 + 32, a, b, c, d, e, f, g, h, X0, X1, X14, X9);
        ROUND_16_80_512(16 + 33, h, a, b, c, d, e, f, g, X1, X2, X15, X10);
        ROUND_16_80_512(16 + 34, g, h, a, b, c, d, e, f, X2, X3, X0, X11);
        ROUND_16_80_512(16 + 35, f, g, h, a, b, c, d, e, X3, X4, X1, X12);
        ROUND_16_80_512(16 + 36, e, f, g, h, a, b, c, d, X4, X5, X2, X13);
        ROUND_16_80_512(16 + 37, d, e, f, g, h, a, b, c, X5, X6, X3, X14);
        ROUND_16_80_512(16 + 38, c, d, e, f, g, h, a, b, X6, X7, X4, X15);
        ROUND_16_80_512(16 + 39, b, c, d, e, f, g, h, a, X7, X8, X5, X0);
        ROUND_16_80_512(16 + 40, a, b, c, d, e, f, g, h, X8, X9, X6, X1);
        ROUND_16_80_512(16 + 41, h, a, b, c, d, e, f, g, X9, X10, X7, X2);
        ROUND_16_80_512(16 + 42, g, h, a, b, c, d, e, f, X10, X11, X8, X3);
        ROUND_16_80_512(16 + 43, f, g, h, a, b, c, d, e, X11, X12, X9, X4);
        ROUND_16_80_512(16 + 44, e, f, g, h, a, b, c, d, X12, X13, X10, X5);
        ROUND_16_80_512(16 + 45, d, e, f, g, h, a, b, c, X13, X14, X11, X6);
        ROUND_16_80_512(16 + 46, c, d, e, f, g, h, a, b, X14, X15, X12, X7);
        ROUND_16_80_512(16 + 47, b, c, d, e, f, g, h, a, X15, X0, X13, X8);
        ROUND_16_80_512(16 + 48, a, b, c, d, e, f, g, h, X0, X1, X14, X9);
        ROUND_16_80_512(16 + 49, h, a, b, c, d, e, f, g, X1, X2, X15, X10);
        ROUND_16_80_512(16 + 50, g, h, a, b, c, d, e, f, X2, X3, X0, X11);
        ROUND_16_80_512(16 + 51, f, g, h, a, b, c, d, e, X3, X4, X1, X12);
        ROUND_16_80_512(16 + 52, e, f, g, h, a, b, c, d, X4, X5, X2, X13);
        ROUND_16_80_512(16 + 53, d, e, f, g, h, a, b, c, X5, X6, X3, X14);
        ROUND_16_80_512(16 + 54, c, d, e, f, g, h, a, b, X6, X7, X4, X15);
        ROUND_16_80_512(16 + 55, b, c, d, e, f, g, h, a, X7, X8, X5, X0);
        ROUND_16_80_512(16 + 56, a, b, c, d, e, f, g, h, X8, X9, X6, X1);
        ROUND_16_80_512(16 + 57, h, a, b, c, d, e, f, g, X9, X10, X7, X2);
        ROUND_16_80_512(16 + 58, g, h, a, b, c, d, e, f, X10, X11, X8, X3);
        ROUND_16_80_512(16 + 59, f, g, h, a, b, c, d, e, X11, X12, X9, X4);
        ROUND_16_80_512(16 + 60, e, f, g, h, a, b, c, d, X12, X13, X10, X5);
        ROUND_16_80_512(16 + 61, d, e, f, g, h, a, b, c, X13, X14, X11, X6);
        ROUND_16_80_512(16 + 62, c, d, e, f, g, h, a, b, X14, X15, X12, X7);
        ROUND_16_80_512(16 + 63, b, c, d, e, f, g, h, a, X15, X0, X13, X8);
#else				// NVIDIA_GPU

        T1 = X[0] = ((unsigned long)A << 32) + (unsigned long)B; 	 	ROUND_00_15_512(0, a, b, c, d, e, f, g, h);
        T1 = X[1] = ((unsigned long)C << 32) + (unsigned long)D;			ROUND_00_15_512(1, h, a, b, c, d, e, f, g);
        T1 = X[2] = U64(0x8000000000000000);	ROUND_00_15_512(2, g, h, a, b, c, d, e, f);
        T1 = X[3] = U64(0);			ROUND_00_15_512(3, f, g, h, a, b, c, d, e);
        T1 = X[4] = U64(0);			ROUND_00_15_512(4, e, f, g, h, a, b, c, d);
        T1 = X[5] = U64(0);			ROUND_00_15_512(5, d, e, f, g, h, a, b, c);
        T1 = X[6] = U64(0);			ROUND_00_15_512(6, c, d, e, f, g, h, a, b);
        T1 = X[7] = U64(0);			ROUND_00_15_512(7, b, c, d, e, f, g, h, a);
        T1 = X[8] = U64(0);			ROUND_00_15_512(8, a, b, c, d, e, f, g, h);
        T1 = X[9] = U64(0);			ROUND_00_15_512(9, h, a, b, c, d, e, f, g);
        T1 = X[10] = U64(0);			ROUND_00_15_512(10, g, h, a, b, c, d, e, f);
        T1 = X[11] = U64(0);			ROUND_00_15_512(11, f, g, h, a, b, c, d, e);
        T1 = X[12] = U64(0);			ROUND_00_15_512(12, e, f, g, h, a, b, c, d);
        T1 = X[13] = U64(0);			ROUND_00_15_512(13, d, e, f, g, h, a, b, c);
        T1 = X[14] = U64(0);			ROUND_00_15_512(14, c, d, e, f, g, h, a, b);
        T1 = X[15] = U64(0x80);			ROUND_00_15_512(15, b, c, d, e, f, g, h, a);

        ROUND_16_80_512(16 + 0, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 1, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 2, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 3, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 4, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 5, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 6, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 7, b, c, d, e, f, g, h, a, X);

        ROUND_16_80_512(16 + 8, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 9, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 10, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 11, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 12, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 13, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 14, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 15, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 16, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 17, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 18, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 19, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 20, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 21, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 22, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 23, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 24, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 25, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 26, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 27, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 28, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 29, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 30, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 31, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 32, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 33, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 34, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 35, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 36, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 37, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 38, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 39, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 40, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 41, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 42, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 43, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 44, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 45, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 46, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 47, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 48, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 49, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 50, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 51, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 52, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 53, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 54, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 55, b, c, d, e, f, g, h, a, X);
        ROUND_16_80_512(16 + 56, a, b, c, d, e, f, g, h, X);
        ROUND_16_80_512(16 + 57, h, a, b, c, d, e, f, g, X);
        ROUND_16_80_512(16 + 58, g, h, a, b, c, d, e, f, X);
        ROUND_16_80_512(16 + 59, f, g, h, a, b, c, d, e, X);
        ROUND_16_80_512(16 + 60, e, f, g, h, a, b, c, d, X);
        ROUND_16_80_512(16 + 61, d, e, f, g, h, a, b, c, X);
        ROUND_16_80_512(16 + 62, c, d, e, f, g, h, a, b, X);
        ROUND_16_80_512(16 + 63, b, c, d, e, f, g, h, a, X);
#endif
        ctx.h0 = a + U64(0x6a09e667f3bcc908);	ctx.h1 = b + U64(0xbb67ae8584caa73b);
        ctx.h2 = c + U64(0x3c6ef372fe94f82b);	ctx.h3 = d + U64(0xa54ff53a5f1d36f1);
        ctx.h4 = e + U64(0x510e527fade682d1);	ctx.h5 = f + U64(0x9b05688c2b3e6c1f);
        ctx.h6 = g + U64(0x1f83d9abfb41bd6b);	ctx.h7 = h + U64(0x5be0cd19137e2179);

    }


    AES_decrypt(in->hashedsalt, &A, &B, &C, &D, in->key_length, &key);

    A ^= bswap_dword(in->docid[0]);
    B ^= bswap_dword(in->docid[1]);
    C ^= bswap_dword(in->docid[2]);
    D ^= bswap_dword(in->docid[3]);

    if (A == (ULONG)(ctx.h0 >> 32) && B == (ULONG)(ctx.h0) &&
        C == (ULONG)(ctx.h1 >> 32) && D == (ULONG)(ctx.h1)) return (0);
    else return (1);

}




//********************************#include "aes_core.cu"

__constant u32 Te4[256] = {
    0x63636363U, 0x7c7c7c7cU, 0x77777777U, 0x7b7b7b7bU,
    0xf2f2f2f2U, 0x6b6b6b6bU, 0x6f6f6f6fU, 0xc5c5c5c5U,
    0x30303030U, 0x01010101U, 0x67676767U, 0x2b2b2b2bU,
    0xfefefefeU, 0xd7d7d7d7U, 0xababababU, 0x76767676U,
    0xcacacacaU, 0x82828282U, 0xc9c9c9c9U, 0x7d7d7d7dU,
    0xfafafafaU, 0x59595959U, 0x47474747U, 0xf0f0f0f0U,
    0xadadadadU, 0xd4d4d4d4U, 0xa2a2a2a2U, 0xafafafafU,
    0x9c9c9c9cU, 0xa4a4a4a4U, 0x72727272U, 0xc0c0c0c0U,
    0xb7b7b7b7U, 0xfdfdfdfdU, 0x93939393U, 0x26262626U,
    0x36363636U, 0x3f3f3f3fU, 0xf7f7f7f7U, 0xccccccccU,
    0x34343434U, 0xa5a5a5a5U, 0xe5e5e5e5U, 0xf1f1f1f1U,
    0x71717171U, 0xd8d8d8d8U, 0x31313131U, 0x15151515U,
    0x04040404U, 0xc7c7c7c7U, 0x23232323U, 0xc3c3c3c3U,
    0x18181818U, 0x96969696U, 0x05050505U, 0x9a9a9a9aU,
    0x07070707U, 0x12121212U, 0x80808080U, 0xe2e2e2e2U,
    0xebebebebU, 0x27272727U, 0xb2b2b2b2U, 0x75757575U,
    0x09090909U, 0x83838383U, 0x2c2c2c2cU, 0x1a1a1a1aU,
    0x1b1b1b1bU, 0x6e6e6e6eU, 0x5a5a5a5aU, 0xa0a0a0a0U,
    0x52525252U, 0x3b3b3b3bU, 0xd6d6d6d6U, 0xb3b3b3b3U,
    0x29292929U, 0xe3e3e3e3U, 0x2f2f2f2fU, 0x84848484U,
    0x53535353U, 0xd1d1d1d1U, 0x00000000U, 0xededededU,
    0x20202020U, 0xfcfcfcfcU, 0xb1b1b1b1U, 0x5b5b5b5bU,
    0x6a6a6a6aU, 0xcbcbcbcbU, 0xbebebebeU, 0x39393939U,
    0x4a4a4a4aU, 0x4c4c4c4cU, 0x58585858U, 0xcfcfcfcfU,
    0xd0d0d0d0U, 0xefefefefU, 0xaaaaaaaaU, 0xfbfbfbfbU,
    0x43434343U, 0x4d4d4d4dU, 0x33333333U, 0x85858585U,
    0x45454545U, 0xf9f9f9f9U, 0x02020202U, 0x7f7f7f7fU,
    0x50505050U, 0x3c3c3c3cU, 0x9f9f9f9fU, 0xa8a8a8a8U,
    0x51515151U, 0xa3a3a3a3U, 0x40404040U, 0x8f8f8f8fU,
    0x92929292U, 0x9d9d9d9dU, 0x38383838U, 0xf5f5f5f5U,
    0xbcbcbcbcU, 0xb6b6b6b6U, 0xdadadadaU, 0x21212121U,
    0x10101010U, 0xffffffffU, 0xf3f3f3f3U, 0xd2d2d2d2U,
    0xcdcdcdcdU, 0x0c0c0c0cU, 0x13131313U, 0xececececU,
    0x5f5f5f5fU, 0x97979797U, 0x44444444U, 0x17171717U,
    0xc4c4c4c4U, 0xa7a7a7a7U, 0x7e7e7e7eU, 0x3d3d3d3dU,
    0x64646464U, 0x5d5d5d5dU, 0x19191919U, 0x73737373U,
    0x60606060U, 0x81818181U, 0x4f4f4f4fU, 0xdcdcdcdcU,
    0x22222222U, 0x2a2a2a2aU, 0x90909090U, 0x88888888U,
    0x46464646U, 0xeeeeeeeeU, 0xb8b8b8b8U, 0x14141414U,
    0xdedededeU, 0x5e5e5e5eU, 0x0b0b0b0bU, 0xdbdbdbdbU,
    0xe0e0e0e0U, 0x32323232U, 0x3a3a3a3aU, 0x0a0a0a0aU,
    0x49494949U, 0x06060606U, 0x24242424U, 0x5c5c5c5cU,
    0xc2c2c2c2U, 0xd3d3d3d3U, 0xacacacacU, 0x62626262U,
    0x91919191U, 0x95959595U, 0xe4e4e4e4U, 0x79797979U,
    0xe7e7e7e7U, 0xc8c8c8c8U, 0x37373737U, 0x6d6d6d6dU,
    0x8d8d8d8dU, 0xd5d5d5d5U, 0x4e4e4e4eU, 0xa9a9a9a9U,
    0x6c6c6c6cU, 0x56565656U, 0xf4f4f4f4U, 0xeaeaeaeaU,
    0x65656565U, 0x7a7a7a7aU, 0xaeaeaeaeU, 0x08080808U,
    0xbabababaU, 0x78787878U, 0x25252525U, 0x2e2e2e2eU,
    0x1c1c1c1cU, 0xa6a6a6a6U, 0xb4b4b4b4U, 0xc6c6c6c6U,
    0xe8e8e8e8U, 0xddddddddU, 0x74747474U, 0x1f1f1f1fU,
    0x4b4b4b4bU, 0xbdbdbdbdU, 0x8b8b8b8bU, 0x8a8a8a8aU,
    0x70707070U, 0x3e3e3e3eU, 0xb5b5b5b5U, 0x66666666U,
    0x48484848U, 0x03030303U, 0xf6f6f6f6U, 0x0e0e0e0eU,
    0x61616161U, 0x35353535U, 0x57575757U, 0xb9b9b9b9U,
    0x86868686U, 0xc1c1c1c1U, 0x1d1d1d1dU, 0x9e9e9e9eU,
    0xe1e1e1e1U, 0xf8f8f8f8U, 0x98989898U, 0x11111111U,
    0x69696969U, 0xd9d9d9d9U, 0x8e8e8e8eU, 0x94949494U,
    0x9b9b9b9bU, 0x1e1e1e1eU, 0x87878787U, 0xe9e9e9e9U,
    0xcecececeU, 0x55555555U, 0x28282828U, 0xdfdfdfdfU,
    0x8c8c8c8cU, 0xa1a1a1a1U, 0x89898989U, 0x0d0d0d0dU,
    0xbfbfbfbfU, 0xe6e6e6e6U, 0x42424242U, 0x68686868U,
    0x41414141U, 0x99999999U, 0x2d2d2d2dU, 0x0f0f0f0fU,
    0xb0b0b0b0U, 0x54545454U, 0xbbbbbbbbU, 0x16161616U,
};
__constant u32 Td0[256] = {
    0x51f4a750U, 0x7e416553U, 0x1a17a4c3U, 0x3a275e96U,
    0x3bab6bcbU, 0x1f9d45f1U, 0xacfa58abU, 0x4be30393U,
    0x2030fa55U, 0xad766df6U, 0x88cc7691U, 0xf5024c25U,
    0x4fe5d7fcU, 0xc52acbd7U, 0x26354480U, 0xb562a38fU,
    0xdeb15a49U, 0x25ba1b67U, 0x45ea0e98U, 0x5dfec0e1U,
    0xc32f7502U, 0x814cf012U, 0x8d4697a3U, 0x6bd3f9c6U,
    0x038f5fe7U, 0x15929c95U, 0xbf6d7aebU, 0x955259daU,
    0xd4be832dU, 0x587421d3U, 0x49e06929U, 0x8ec9c844U,
    0x75c2896aU, 0xf48e7978U, 0x99583e6bU, 0x27b971ddU,
    0xbee14fb6U, 0xf088ad17U, 0xc920ac66U, 0x7dce3ab4U,
    0x63df4a18U, 0xe51a3182U, 0x97513360U, 0x62537f45U,
    0xb16477e0U, 0xbb6bae84U, 0xfe81a01cU, 0xf9082b94U,
    0x70486858U, 0x8f45fd19U, 0x94de6c87U, 0x527bf8b7U,
    0xab73d323U, 0x724b02e2U, 0xe31f8f57U, 0x6655ab2aU,
    0xb2eb2807U, 0x2fb5c203U, 0x86c57b9aU, 0xd33708a5U,
    0x302887f2U, 0x23bfa5b2U, 0x02036abaU, 0xed16825cU,
    0x8acf1c2bU, 0xa779b492U, 0xf307f2f0U, 0x4e69e2a1U,
    0x65daf4cdU, 0x0605bed5U, 0xd134621fU, 0xc4a6fe8aU,
    0x342e539dU, 0xa2f355a0U, 0x058ae132U, 0xa4f6eb75U,
    0x0b83ec39U, 0x4060efaaU, 0x5e719f06U, 0xbd6e1051U,
    0x3e218af9U, 0x96dd063dU, 0xdd3e05aeU, 0x4de6bd46U,
    0x91548db5U, 0x71c45d05U, 0x0406d46fU, 0x605015ffU,
    0x1998fb24U, 0xd6bde997U, 0x894043ccU, 0x67d99e77U,
    0xb0e842bdU, 0x07898b88U, 0xe7195b38U, 0x79c8eedbU,
    0xa17c0a47U, 0x7c420fe9U, 0xf8841ec9U, 0x00000000U,
    0x09808683U, 0x322bed48U, 0x1e1170acU, 0x6c5a724eU,
    0xfd0efffbU, 0x0f853856U, 0x3daed51eU, 0x362d3927U,
    0x0a0fd964U, 0x685ca621U, 0x9b5b54d1U, 0x24362e3aU,
    0x0c0a67b1U, 0x9357e70fU, 0xb4ee96d2U, 0x1b9b919eU,
    0x80c0c54fU, 0x61dc20a2U, 0x5a774b69U, 0x1c121a16U,
    0xe293ba0aU, 0xc0a02ae5U, 0x3c22e043U, 0x121b171dU,
    0x0e090d0bU, 0xf28bc7adU, 0x2db6a8b9U, 0x141ea9c8U,
    0x57f11985U, 0xaf75074cU, 0xee99ddbbU, 0xa37f60fdU,
    0xf701269fU, 0x5c72f5bcU, 0x44663bc5U, 0x5bfb7e34U,
    0x8b432976U, 0xcb23c6dcU, 0xb6edfc68U, 0xb8e4f163U,
    0xd731dccaU, 0x42638510U, 0x13972240U, 0x84c61120U,
    0x854a247dU, 0xd2bb3df8U, 0xaef93211U, 0xc729a16dU,
    0x1d9e2f4bU, 0xdcb230f3U, 0x0d8652ecU, 0x77c1e3d0U,
    0x2bb3166cU, 0xa970b999U, 0x119448faU, 0x47e96422U,
    0xa8fc8cc4U, 0xa0f03f1aU, 0x567d2cd8U, 0x223390efU,
    0x87494ec7U, 0xd938d1c1U, 0x8ccaa2feU, 0x98d40b36U,
    0xa6f581cfU, 0xa57ade28U, 0xdab78e26U, 0x3fadbfa4U,
    0x2c3a9de4U, 0x5078920dU, 0x6a5fcc9bU, 0x547e4662U,
    0xf68d13c2U, 0x90d8b8e8U, 0x2e39f75eU, 0x82c3aff5U,
    0x9f5d80beU, 0x69d0937cU, 0x6fd52da9U, 0xcf2512b3U,
    0xc8ac993bU, 0x10187da7U, 0xe89c636eU, 0xdb3bbb7bU,
    0xcd267809U, 0x6e5918f4U, 0xec9ab701U, 0x834f9aa8U,
    0xe6956e65U, 0xaaffe67eU, 0x21bccf08U, 0xef15e8e6U,
    0xbae79bd9U, 0x4a6f36ceU, 0xea9f09d4U, 0x29b07cd6U,
    0x31a4b2afU, 0x2a3f2331U, 0xc6a59430U, 0x35a266c0U,
    0x744ebc37U, 0xfc82caa6U, 0xe090d0b0U, 0x33a7d815U,
    0xf104984aU, 0x41ecdaf7U, 0x7fcd500eU, 0x1791f62fU,
    0x764dd68dU, 0x43efb04dU, 0xccaa4d54U, 0xe49604dfU,
    0x9ed1b5e3U, 0x4c6a881bU, 0xc12c1fb8U, 0x4665517fU,
    0x9d5eea04U, 0x018c355dU, 0xfa877473U, 0xfb0b412eU,
    0xb3671d5aU, 0x92dbd252U, 0xe9105633U, 0x6dd64713U,
    0x9ad7618cU, 0x37a10c7aU, 0x59f8148eU, 0xeb133c89U,
    0xcea927eeU, 0xb761c935U, 0xe11ce5edU, 0x7a47b13cU,
    0x9cd2df59U, 0x55f2733fU, 0x1814ce79U, 0x73c737bfU,
    0x53f7cdeaU, 0x5ffdaa5bU, 0xdf3d6f14U, 0x7844db86U,
    0xcaaff381U, 0xb968c43eU, 0x3824342cU, 0xc2a3405fU,
    0x161dc372U, 0xbce2250cU, 0x283c498bU, 0xff0d9541U,
    0x39a80171U, 0x080cb3deU, 0xd8b4e49cU, 0x6456c190U,
    0x7bcb8461U, 0xd532b670U, 0x486c5c74U, 0xd0b85742U,
};
__constant u32 Td1[256] = {
    0x5051f4a7U, 0x537e4165U, 0xc31a17a4U, 0x963a275eU,
    0xcb3bab6bU, 0xf11f9d45U, 0xabacfa58U, 0x934be303U,
    0x552030faU, 0xf6ad766dU, 0x9188cc76U, 0x25f5024cU,
    0xfc4fe5d7U, 0xd7c52acbU, 0x80263544U, 0x8fb562a3U,
    0x49deb15aU, 0x6725ba1bU, 0x9845ea0eU, 0xe15dfec0U,
    0x02c32f75U, 0x12814cf0U, 0xa38d4697U, 0xc66bd3f9U,
    0xe7038f5fU, 0x9515929cU, 0xebbf6d7aU, 0xda955259U,
    0x2dd4be83U, 0xd3587421U, 0x2949e069U, 0x448ec9c8U,
    0x6a75c289U, 0x78f48e79U, 0x6b99583eU, 0xdd27b971U,
    0xb6bee14fU, 0x17f088adU, 0x66c920acU, 0xb47dce3aU,
    0x1863df4aU, 0x82e51a31U, 0x60975133U, 0x4562537fU,
    0xe0b16477U, 0x84bb6baeU, 0x1cfe81a0U, 0x94f9082bU,
    0x58704868U, 0x198f45fdU, 0x8794de6cU, 0xb7527bf8U,
    0x23ab73d3U, 0xe2724b02U, 0x57e31f8fU, 0x2a6655abU,
    0x07b2eb28U, 0x032fb5c2U, 0x9a86c57bU, 0xa5d33708U,
    0xf2302887U, 0xb223bfa5U, 0xba02036aU, 0x5ced1682U,
    0x2b8acf1cU, 0x92a779b4U, 0xf0f307f2U, 0xa14e69e2U,
    0xcd65daf4U, 0xd50605beU, 0x1fd13462U, 0x8ac4a6feU,
    0x9d342e53U, 0xa0a2f355U, 0x32058ae1U, 0x75a4f6ebU,
    0x390b83ecU, 0xaa4060efU, 0x065e719fU, 0x51bd6e10U,
    0xf93e218aU, 0x3d96dd06U, 0xaedd3e05U, 0x464de6bdU,
    0xb591548dU, 0x0571c45dU, 0x6f0406d4U, 0xff605015U,
    0x241998fbU, 0x97d6bde9U, 0xcc894043U, 0x7767d99eU,
    0xbdb0e842U, 0x8807898bU, 0x38e7195bU, 0xdb79c8eeU,
    0x47a17c0aU, 0xe97c420fU, 0xc9f8841eU, 0x00000000U,
    0x83098086U, 0x48322bedU, 0xac1e1170U, 0x4e6c5a72U,
    0xfbfd0effU, 0x560f8538U, 0x1e3daed5U, 0x27362d39U,
    0x640a0fd9U, 0x21685ca6U, 0xd19b5b54U, 0x3a24362eU,
    0xb10c0a67U, 0x0f9357e7U, 0xd2b4ee96U, 0x9e1b9b91U,
    0x4f80c0c5U, 0xa261dc20U, 0x695a774bU, 0x161c121aU,
    0x0ae293baU, 0xe5c0a02aU, 0x433c22e0U, 0x1d121b17U,
    0x0b0e090dU, 0xadf28bc7U, 0xb92db6a8U, 0xc8141ea9U,
    0x8557f119U, 0x4caf7507U, 0xbbee99ddU, 0xfda37f60U,
    0x9ff70126U, 0xbc5c72f5U, 0xc544663bU, 0x345bfb7eU,
    0x768b4329U, 0xdccb23c6U, 0x68b6edfcU, 0x63b8e4f1U,
    0xcad731dcU, 0x10426385U, 0x40139722U, 0x2084c611U,
    0x7d854a24U, 0xf8d2bb3dU, 0x11aef932U, 0x6dc729a1U,
    0x4b1d9e2fU, 0xf3dcb230U, 0xec0d8652U, 0xd077c1e3U,
    0x6c2bb316U, 0x99a970b9U, 0xfa119448U, 0x2247e964U,
    0xc4a8fc8cU, 0x1aa0f03fU, 0xd8567d2cU, 0xef223390U,
    0xc787494eU, 0xc1d938d1U, 0xfe8ccaa2U, 0x3698d40bU,
    0xcfa6f581U, 0x28a57adeU, 0x26dab78eU, 0xa43fadbfU,
    0xe42c3a9dU, 0x0d507892U, 0x9b6a5fccU, 0x62547e46U,
    0xc2f68d13U, 0xe890d8b8U, 0x5e2e39f7U, 0xf582c3afU,
    0xbe9f5d80U, 0x7c69d093U, 0xa96fd52dU, 0xb3cf2512U,
    0x3bc8ac99U, 0xa710187dU, 0x6ee89c63U, 0x7bdb3bbbU,
    0x09cd2678U, 0xf46e5918U, 0x01ec9ab7U, 0xa8834f9aU,
    0x65e6956eU, 0x7eaaffe6U, 0x0821bccfU, 0xe6ef15e8U,
    0xd9bae79bU, 0xce4a6f36U, 0xd4ea9f09U, 0xd629b07cU,
    0xaf31a4b2U, 0x312a3f23U, 0x30c6a594U, 0xc035a266U,
    0x37744ebcU, 0xa6fc82caU, 0xb0e090d0U, 0x1533a7d8U,
    0x4af10498U, 0xf741ecdaU, 0x0e7fcd50U, 0x2f1791f6U,
    0x8d764dd6U, 0x4d43efb0U, 0x54ccaa4dU, 0xdfe49604U,
    0xe39ed1b5U, 0x1b4c6a88U, 0xb8c12c1fU, 0x7f466551U,
    0x049d5eeaU, 0x5d018c35U, 0x73fa8774U, 0x2efb0b41U,
    0x5ab3671dU, 0x5292dbd2U, 0x33e91056U, 0x136dd647U,
    0x8c9ad761U, 0x7a37a10cU, 0x8e59f814U, 0x89eb133cU,
    0xeecea927U, 0x35b761c9U, 0xede11ce5U, 0x3c7a47b1U,
    0x599cd2dfU, 0x3f55f273U, 0x791814ceU, 0xbf73c737U,
    0xea53f7cdU, 0x5b5ffdaaU, 0x14df3d6fU, 0x867844dbU,
    0x81caaff3U, 0x3eb968c4U, 0x2c382434U, 0x5fc2a340U,
    0x72161dc3U, 0x0cbce225U, 0x8b283c49U, 0x41ff0d95U,
    0x7139a801U, 0xde080cb3U, 0x9cd8b4e4U, 0x906456c1U,
    0x617bcb84U, 0x70d532b6U, 0x74486c5cU, 0x42d0b857U,
};
__constant u32 Td2[256] = {
    0xa75051f4U, 0x65537e41U, 0xa4c31a17U, 0x5e963a27U,
    0x6bcb3babU, 0x45f11f9dU, 0x58abacfaU, 0x03934be3U,
    0xfa552030U, 0x6df6ad76U, 0x769188ccU, 0x4c25f502U,
    0xd7fc4fe5U, 0xcbd7c52aU, 0x44802635U, 0xa38fb562U,
    0x5a49deb1U, 0x1b6725baU, 0x0e9845eaU, 0xc0e15dfeU,
    0x7502c32fU, 0xf012814cU, 0x97a38d46U, 0xf9c66bd3U,
    0x5fe7038fU, 0x9c951592U, 0x7aebbf6dU, 0x59da9552U,
    0x832dd4beU, 0x21d35874U, 0x692949e0U, 0xc8448ec9U,
    0x896a75c2U, 0x7978f48eU, 0x3e6b9958U, 0x71dd27b9U,
    0x4fb6bee1U, 0xad17f088U, 0xac66c920U, 0x3ab47dceU,
    0x4a1863dfU, 0x3182e51aU, 0x33609751U, 0x7f456253U,
    0x77e0b164U, 0xae84bb6bU, 0xa01cfe81U, 0x2b94f908U,
    0x68587048U, 0xfd198f45U, 0x6c8794deU, 0xf8b7527bU,
    0xd323ab73U, 0x02e2724bU, 0x8f57e31fU, 0xab2a6655U,
    0x2807b2ebU, 0xc2032fb5U, 0x7b9a86c5U, 0x08a5d337U,
    0x87f23028U, 0xa5b223bfU, 0x6aba0203U, 0x825ced16U,
    0x1c2b8acfU, 0xb492a779U, 0xf2f0f307U, 0xe2a14e69U,
    0xf4cd65daU, 0xbed50605U, 0x621fd134U, 0xfe8ac4a6U,
    0x539d342eU, 0x55a0a2f3U, 0xe132058aU, 0xeb75a4f6U,
    0xec390b83U, 0xefaa4060U, 0x9f065e71U, 0x1051bd6eU,

    0x8af93e21U, 0x063d96ddU, 0x05aedd3eU, 0xbd464de6U,
    0x8db59154U, 0x5d0571c4U, 0xd46f0406U, 0x15ff6050U,
    0xfb241998U, 0xe997d6bdU, 0x43cc8940U, 0x9e7767d9U,
    0x42bdb0e8U, 0x8b880789U, 0x5b38e719U, 0xeedb79c8U,
    0x0a47a17cU, 0x0fe97c42U, 0x1ec9f884U, 0x00000000U,
    0x86830980U, 0xed48322bU, 0x70ac1e11U, 0x724e6c5aU,
    0xfffbfd0eU, 0x38560f85U, 0xd51e3daeU, 0x3927362dU,
    0xd9640a0fU, 0xa621685cU, 0x54d19b5bU, 0x2e3a2436U,
    0x67b10c0aU, 0xe70f9357U, 0x96d2b4eeU, 0x919e1b9bU,
    0xc54f80c0U, 0x20a261dcU, 0x4b695a77U, 0x1a161c12U,
    0xba0ae293U, 0x2ae5c0a0U, 0xe0433c22U, 0x171d121bU,
    0x0d0b0e09U, 0xc7adf28bU, 0xa8b92db6U, 0xa9c8141eU,
    0x198557f1U, 0x074caf75U, 0xddbbee99U, 0x60fda37fU,
    0x269ff701U, 0xf5bc5c72U, 0x3bc54466U, 0x7e345bfbU,
    0x29768b43U, 0xc6dccb23U, 0xfc68b6edU, 0xf163b8e4U,
    0xdccad731U, 0x85104263U, 0x22401397U, 0x112084c6U,
    0x247d854aU, 0x3df8d2bbU, 0x3211aef9U, 0xa16dc729U,
    0x2f4b1d9eU, 0x30f3dcb2U, 0x52ec0d86U, 0xe3d077c1U,
    0x166c2bb3U, 0xb999a970U, 0x48fa1194U, 0x642247e9U,
    0x8cc4a8fcU, 0x3f1aa0f0U, 0x2cd8567dU, 0x90ef2233U,
    0x4ec78749U, 0xd1c1d938U, 0xa2fe8ccaU, 0x0b3698d4U,
    0x81cfa6f5U, 0xde28a57aU, 0x8e26dab7U, 0xbfa43fadU,
    0x9de42c3aU, 0x920d5078U, 0xcc9b6a5fU, 0x4662547eU,
    0x13c2f68dU, 0xb8e890d8U, 0xf75e2e39U, 0xaff582c3U,
    0x80be9f5dU, 0x937c69d0U, 0x2da96fd5U, 0x12b3cf25U,
    0x993bc8acU, 0x7da71018U, 0x636ee89cU, 0xbb7bdb3bU,
    0x7809cd26U, 0x18f46e59U, 0xb701ec9aU, 0x9aa8834fU,
    0x6e65e695U, 0xe67eaaffU, 0xcf0821bcU, 0xe8e6ef15U,
    0x9bd9bae7U, 0x36ce4a6fU, 0x09d4ea9fU, 0x7cd629b0U,
    0xb2af31a4U, 0x23312a3fU, 0x9430c6a5U, 0x66c035a2U,
    0xbc37744eU, 0xcaa6fc82U, 0xd0b0e090U, 0xd81533a7U,
    0x984af104U, 0xdaf741ecU, 0x500e7fcdU, 0xf62f1791U,
    0xd68d764dU, 0xb04d43efU, 0x4d54ccaaU, 0x04dfe496U,
    0xb5e39ed1U, 0x881b4c6aU, 0x1fb8c12cU, 0x517f4665U,
    0xea049d5eU, 0x355d018cU, 0x7473fa87U, 0x412efb0bU,
    0x1d5ab367U, 0xd25292dbU, 0x5633e910U, 0x47136dd6U,
    0x618c9ad7U, 0x0c7a37a1U, 0x148e59f8U, 0x3c89eb13U,
    0x27eecea9U, 0xc935b761U, 0xe5ede11cU, 0xb13c7a47U,
    0xdf599cd2U, 0x733f55f2U, 0xce791814U, 0x37bf73c7U,
    0xcdea53f7U, 0xaa5b5ffdU, 0x6f14df3dU, 0xdb867844U,
    0xf381caafU, 0xc43eb968U, 0x342c3824U, 0x405fc2a3U,
    0xc372161dU, 0x250cbce2U, 0x498b283cU, 0x9541ff0dU,
    0x017139a8U, 0xb3de080cU, 0xe49cd8b4U, 0xc1906456U,
    0x84617bcbU, 0xb670d532U, 0x5c74486cU, 0x5742d0b8U,
};
__constant u32 Td3[256] = {
    0xf4a75051U, 0x4165537eU, 0x17a4c31aU, 0x275e963aU,
    0xab6bcb3bU, 0x9d45f11fU, 0xfa58abacU, 0xe303934bU,
    0x30fa5520U, 0x766df6adU, 0xcc769188U, 0x024c25f5U,
    0xe5d7fc4fU, 0x2acbd7c5U, 0x35448026U, 0x62a38fb5U,
    0xb15a49deU, 0xba1b6725U, 0xea0e9845U, 0xfec0e15dU,
    0x2f7502c3U, 0x4cf01281U, 0x4697a38dU, 0xd3f9c66bU,
    0x8f5fe703U, 0x929c9515U, 0x6d7aebbfU, 0x5259da95U,
    0xbe832dd4U, 0x7421d358U, 0xe0692949U, 0xc9c8448eU,
    0xc2896a75U, 0x8e7978f4U, 0x583e6b99U, 0xb971dd27U,
    0xe14fb6beU, 0x88ad17f0U, 0x20ac66c9U, 0xce3ab47dU,
    0xdf4a1863U, 0x1a3182e5U, 0x51336097U, 0x537f4562U,
    0x6477e0b1U, 0x6bae84bbU, 0x81a01cfeU, 0x082b94f9U,
    0x48685870U, 0x45fd198fU, 0xde6c8794U, 0x7bf8b752U,
    0x73d323abU, 0x4b02e272U, 0x1f8f57e3U, 0x55ab2a66U,
    0xeb2807b2U, 0xb5c2032fU, 0xc57b9a86U, 0x3708a5d3U,
    0x2887f230U, 0xbfa5b223U, 0x036aba02U, 0x16825cedU,
    0xcf1c2b8aU, 0x79b492a7U, 0x07f2f0f3U, 0x69e2a14eU,
    0xdaf4cd65U, 0x05bed506U, 0x34621fd1U, 0xa6fe8ac4U,
    0x2e539d34U, 0xf355a0a2U, 0x8ae13205U, 0xf6eb75a4U,
    0x83ec390bU, 0x60efaa40U, 0x719f065eU, 0x6e1051bdU,
    0x218af93eU, 0xdd063d96U, 0x3e05aeddU, 0xe6bd464dU,
    0x548db591U, 0xc45d0571U, 0x06d46f04U, 0x5015ff60U,
    0x98fb2419U, 0xbde997d6U, 0x4043cc89U, 0xd99e7767U,
    0xe842bdb0U, 0x898b8807U, 0x195b38e7U, 0xc8eedb79U,
    0x7c0a47a1U, 0x420fe97cU, 0x841ec9f8U, 0x00000000U,
    0x80868309U, 0x2bed4832U, 0x1170ac1eU, 0x5a724e6cU,
    0x0efffbfdU, 0x8538560fU, 0xaed51e3dU, 0x2d392736U,
    0x0fd9640aU, 0x5ca62168U, 0x5b54d19bU, 0x362e3a24U,
    0x0a67b10cU, 0x57e70f93U, 0xee96d2b4U, 0x9b919e1bU,
    0xc0c54f80U, 0xdc20a261U, 0x774b695aU, 0x121a161cU,
    0x93ba0ae2U, 0xa02ae5c0U, 0x22e0433cU, 0x1b171d12U,
    0x090d0b0eU, 0x8bc7adf2U, 0xb6a8b92dU, 0x1ea9c814U,
    0xf1198557U, 0x75074cafU, 0x99ddbbeeU, 0x7f60fda3U,
    0x01269ff7U, 0x72f5bc5cU, 0x663bc544U, 0xfb7e345bU,
    0x4329768bU, 0x23c6dccbU, 0xedfc68b6U, 0xe4f163b8U,
    0x31dccad7U, 0x63851042U, 0x97224013U, 0xc6112084U,
    0x4a247d85U, 0xbb3df8d2U, 0xf93211aeU, 0x29a16dc7U,
    0x9e2f4b1dU, 0xb230f3dcU, 0x8652ec0dU, 0xc1e3d077U,
    0xb3166c2bU, 0x70b999a9U, 0x9448fa11U, 0xe9642247U,
    0xfc8cc4a8U, 0xf03f1aa0U, 0x7d2cd856U, 0x3390ef22U,
    0x494ec787U, 0x38d1c1d9U, 0xcaa2fe8cU, 0xd40b3698U,
    0xf581cfa6U, 0x7ade28a5U, 0xb78e26daU, 0xadbfa43fU,
    0x3a9de42cU, 0x78920d50U, 0x5fcc9b6aU, 0x7e466254U,
    0x8d13c2f6U, 0xd8b8e890U, 0x39f75e2eU, 0xc3aff582U,
    0x5d80be9fU, 0xd0937c69U, 0xd52da96fU, 0x2512b3cfU,
    0xac993bc8U, 0x187da710U, 0x9c636ee8U, 0x3bbb7bdbU,
    0x267809cdU, 0x5918f46eU, 0x9ab701ecU, 0x4f9aa883U,
    0x956e65e6U, 0xffe67eaaU, 0xbccf0821U, 0x15e8e6efU,
    0xe79bd9baU, 0x6f36ce4aU, 0x9f09d4eaU, 0xb07cd629U,
    0xa4b2af31U, 0x3f23312aU, 0xa59430c6U, 0xa266c035U,
    0x4ebc3774U, 0x82caa6fcU, 0x90d0b0e0U, 0xa7d81533U,
    0x04984af1U, 0xecdaf741U, 0xcd500e7fU, 0x91f62f17U,
    0x4dd68d76U, 0xefb04d43U, 0xaa4d54ccU, 0x9604dfe4U,
    0xd1b5e39eU, 0x6a881b4cU, 0x2c1fb8c1U, 0x65517f46U,
    0x5eea049dU, 0x8c355d01U, 0x877473faU, 0x0b412efbU,
    0x671d5ab3U, 0xdbd25292U, 0x105633e9U, 0xd647136dU,
    0xd7618c9aU, 0xa10c7a37U, 0xf8148e59U, 0x133c89ebU,
    0xa927eeceU, 0x61c935b7U, 0x1ce5ede1U, 0x47b13c7aU,
    0xd2df599cU, 0xf2733f55U, 0x14ce7918U, 0xc737bf73U,
    0xf7cdea53U, 0xfdaa5b5fU, 0x3d6f14dfU, 0x44db8678U,
    0xaff381caU, 0x68c43eb9U, 0x24342c38U, 0xa3405fc2U,
    0x1dc37216U, 0xe2250cbcU, 0x3c498b28U, 0x0d9541ffU,
    0xa8017139U, 0x0cb3de08U, 0xb4e49cd8U, 0x56c19064U,
    0xcb84617bU, 0x32b670d5U, 0x6c5c7448U, 0xb85742d0U,
};
__constant u32 Td4[256] = {
    0x52525252U, 0x09090909U, 0x6a6a6a6aU, 0xd5d5d5d5U,
    0x30303030U, 0x36363636U, 0xa5a5a5a5U, 0x38383838U,
    0xbfbfbfbfU, 0x40404040U, 0xa3a3a3a3U, 0x9e9e9e9eU,
    0x81818181U, 0xf3f3f3f3U, 0xd7d7d7d7U, 0xfbfbfbfbU,
    0x7c7c7c7cU, 0xe3e3e3e3U, 0x39393939U, 0x82828282U,
    0x9b9b9b9bU, 0x2f2f2f2fU, 0xffffffffU, 0x87878787U,
    0x34343434U, 0x8e8e8e8eU, 0x43434343U, 0x44444444U,
    0xc4c4c4c4U, 0xdedededeU, 0xe9e9e9e9U, 0xcbcbcbcbU,
    0x54545454U, 0x7b7b7b7bU, 0x94949494U, 0x32323232U,
    0xa6a6a6a6U, 0xc2c2c2c2U, 0x23232323U, 0x3d3d3d3dU,
    0xeeeeeeeeU, 0x4c4c4c4cU, 0x95959595U, 0x0b0b0b0bU,
    0x42424242U, 0xfafafafaU, 0xc3c3c3c3U, 0x4e4e4e4eU,
    0x08080808U, 0x2e2e2e2eU, 0xa1a1a1a1U, 0x66666666U,
    0x28282828U, 0xd9d9d9d9U, 0x24242424U, 0xb2b2b2b2U,
    0x76767676U, 0x5b5b5b5bU, 0xa2a2a2a2U, 0x49494949U,
    0x6d6d6d6dU, 0x8b8b8b8bU, 0xd1d1d1d1U, 0x25252525U,
    0x72727272U, 0xf8f8f8f8U, 0xf6f6f6f6U, 0x64646464U,
    0x86868686U, 0x68686868U, 0x98989898U, 0x16161616U,
    0xd4d4d4d4U, 0xa4a4a4a4U, 0x5c5c5c5cU, 0xccccccccU,
    0x5d5d5d5dU, 0x65656565U, 0xb6b6b6b6U, 0x92929292U,
    0x6c6c6c6cU, 0x70707070U, 0x48484848U, 0x50505050U,
    0xfdfdfdfdU, 0xededededU, 0xb9b9b9b9U, 0xdadadadaU,
    0x5e5e5e5eU, 0x15151515U, 0x46464646U, 0x57575757U,
    0xa7a7a7a7U, 0x8d8d8d8dU, 0x9d9d9d9dU, 0x84848484U,
    0x90909090U, 0xd8d8d8d8U, 0xababababU, 0x00000000U,
    0x8c8c8c8cU, 0xbcbcbcbcU, 0xd3d3d3d3U, 0x0a0a0a0aU,
    0xf7f7f7f7U, 0xe4e4e4e4U, 0x58585858U, 0x05050505U,
    0xb8b8b8b8U, 0xb3b3b3b3U, 0x45454545U, 0x06060606U,
    0xd0d0d0d0U, 0x2c2c2c2cU, 0x1e1e1e1eU, 0x8f8f8f8fU,
    0xcacacacaU, 0x3f3f3f3fU, 0x0f0f0f0fU, 0x02020202U,
    0xc1c1c1c1U, 0xafafafafU, 0xbdbdbdbdU, 0x03030303U,
    0x01010101U, 0x13131313U, 0x8a8a8a8aU, 0x6b6b6b6bU,
    0x3a3a3a3aU, 0x91919191U, 0x11111111U, 0x41414141U,
    0x4f4f4f4fU, 0x67676767U, 0xdcdcdcdcU, 0xeaeaeaeaU,
    0x97979797U, 0xf2f2f2f2U, 0xcfcfcfcfU, 0xcecececeU,
    0xf0f0f0f0U, 0xb4b4b4b4U, 0xe6e6e6e6U, 0x73737373U,
    0x96969696U, 0xacacacacU, 0x74747474U, 0x22222222U,
    0xe7e7e7e7U, 0xadadadadU, 0x35353535U, 0x85858585U,
    0xe2e2e2e2U, 0xf9f9f9f9U, 0x37373737U, 0xe8e8e8e8U,
    0x1c1c1c1cU, 0x75757575U, 0xdfdfdfdfU, 0x6e6e6e6eU,
    0x47474747U, 0xf1f1f1f1U, 0x1a1a1a1aU, 0x71717171U,
    0x1d1d1d1dU, 0x29292929U, 0xc5c5c5c5U, 0x89898989U,
    0x6f6f6f6fU, 0xb7b7b7b7U, 0x62626262U, 0x0e0e0e0eU,
    0xaaaaaaaaU, 0x18181818U, 0xbebebebeU, 0x1b1b1b1bU,
    0xfcfcfcfcU, 0x56565656U, 0x3e3e3e3eU, 0x4b4b4b4bU,
    0xc6c6c6c6U, 0xd2d2d2d2U, 0x79797979U, 0x20202020U,
    0x9a9a9a9aU, 0xdbdbdbdbU, 0xc0c0c0c0U, 0xfefefefeU,
    0x78787878U, 0xcdcdcdcdU, 0x5a5a5a5aU, 0xf4f4f4f4U,
    0x1f1f1f1fU, 0xddddddddU, 0xa8a8a8a8U, 0x33333333U,
    0x88888888U, 0x07070707U, 0xc7c7c7c7U, 0x31313131U,
    0xb1b1b1b1U, 0x12121212U, 0x10101010U, 0x59595959U,
    0x27272727U, 0x80808080U, 0xececececU, 0x5f5f5f5fU,
    0x60606060U, 0x51515151U, 0x7f7f7f7fU, 0xa9a9a9a9U,
    0x19191919U, 0xb5b5b5b5U, 0x4a4a4a4aU, 0x0d0d0d0dU,
    0x2d2d2d2dU, 0xe5e5e5e5U, 0x7a7a7a7aU, 0x9f9f9f9fU,
    0x93939393U, 0xc9c9c9c9U, 0x9c9c9c9cU, 0xefefefefU,
    0xa0a0a0a0U, 0xe0e0e0e0U, 0x3b3b3b3bU, 0x4d4d4d4dU,
    0xaeaeaeaeU, 0x2a2a2a2aU, 0xf5f5f5f5U, 0xb0b0b0b0U,
    0xc8c8c8c8U, 0xebebebebU, 0xbbbbbbbbU, 0x3c3c3c3cU,
    0x83838383U, 0x53535353U, 0x99999999U, 0x61616161U,
    0x17171717U, 0x2b2b2b2bU, 0x04040404U, 0x7e7e7e7eU,
    0xbabababaU, 0x77777777U, 0xd6d6d6d6U, 0x26262626U,
    0xe1e1e1e1U, 0x69696969U, 0x14141414U, 0x63636363U,
    0x55555555U, 0x21212121U, 0x0c0c0c0cU, 0x7d7d7d7dU,
};
__constant u32 rcon[] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000, /* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
};


/**
 * Expand the cipher key into the decryption key schedule.
 */
int AES_set_decrypt_key_256(u64 rk0, u64 rk1, u64 rk2, u64 rk3, const int bits, AES_KEY* key)
{
    u32* rk;
    int i, j, status;
    u32 temp;
    u32 temp0, temp1, temp2, temp3;
    u32 temp4, temp5, temp6, temp7;

    //	key->rounds = 14;

    rk = key->rd_key + 14 * 4;
    i = 0;

    temp0 = rk[0] = rk0 >> 32;
    temp1 = rk[1] = (u32)rk0;
    temp2 = rk[2] = rk1 >> 32;
    temp3 = rk[3] = (u32)rk1;
    temp4 = rk[-4] = rk2 >> 32;
    temp5 = rk[-3] = (u32)rk2;
    temp6 = rk[-2] = rk3 >> 32;
    temp7 = rk[-1] = (u32)rk3;
    // InvMix for pre-last 4 rk
    rk[-4] =
        Td0[Te4[(temp4 >> 24)] & 0xff] ^
        Td1[Te4[(temp4 >> 16) & 0xff] & 0xff] ^
        Td2[Te4[(temp4 >> 8) & 0xff] & 0xff] ^
        Td3[Te4[(temp4) & 0xff] & 0xff];
    rk[-3] =
        Td0[Te4[(temp5 >> 24)] & 0xff] ^
        Td1[Te4[(temp5 >> 16) & 0xff] & 0xff] ^
        Td2[Te4[(temp5 >> 8) & 0xff] & 0xff] ^
        Td3[Te4[(temp5) & 0xff] & 0xff];
    rk[-2] =
        Td0[Te4[(temp6 >> 24)] & 0xff] ^
        Td1[Te4[(temp6 >> 16) & 0xff] & 0xff] ^
        Td2[Te4[(temp6 >> 8) & 0xff] & 0xff] ^
        Td3[Te4[(temp6) & 0xff] & 0xff];
    rk[-1] =
        Td0[Te4[(temp7 >> 24)] & 0xff] ^
        Td1[Te4[(temp7 >> 16) & 0xff] & 0xff] ^
        Td2[Te4[(temp7 >> 8) & 0xff] & 0xff] ^
        Td3[Te4[(temp7) & 0xff] & 0xff];

    while (1) {
        rk -= 8;
        temp0 = temp0 ^
            (Te4[(temp7 >> 16) & 0xff] & 0xff000000) ^
            (Te4[(temp7 >> 8) & 0xff] & 0x00ff0000) ^
            (Te4[(temp7) & 0xff] & 0x0000ff00) ^
            (Te4[(temp7 >> 24)] & 0x000000ff) ^
            rcon[i];

        if (i == 6) {   // last round
            rk[0] = temp0;
            rk[1] = temp1 ^ rk[0];
            rk[2] = temp2 ^ rk[1];
            rk[3] = temp3 ^ rk[2];
            return 0;
        }

        rk[0] =
            Td0[Te4[(temp0 >> 24)] & 0xff] ^
            Td1[Te4[(temp0 >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(temp0 >> 8) & 0xff] & 0xff] ^
            Td3[Te4[(temp0) & 0xff] & 0xff];

        temp1 = temp1 ^ temp0;
        rk[1] =
            Td0[Te4[(temp1 >> 24)] & 0xff] ^
            Td1[Te4[(temp1 >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(temp1 >> 8) & 0xff] & 0xff] ^
            Td3[Te4[(temp1) & 0xff] & 0xff];

        temp2 = temp2 ^ temp1;
        rk[2] =
            Td0[Te4[(temp2 >> 24)] & 0xff] ^
            Td1[Te4[(temp2 >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(temp2 >> 8) & 0xff] & 0xff] ^
            Td3[Te4[(temp2) & 0xff] & 0xff];

        temp3 = temp3 ^ temp2;
        rk[3] =
            Td0[Te4[(temp3 >> 24)] & 0xff] ^
            Td1[Te4[(temp3 >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(temp3 >> 8) & 0xff] & 0xff] ^
            Td3[Te4[(temp3) & 0xff] & 0xff];

        i++;
        temp4 = temp4 ^
            (Te4[(temp3 >> 24)] & 0xff000000) ^
            (Te4[(temp3 >> 16) & 0xff] & 0x00ff0000) ^
            (Te4[(temp3 >> 8) & 0xff] & 0x0000ff00) ^
            (Te4[(temp3) & 0xff] & 0x000000ff);
        rk[-4] =
            Td0[Te4[(temp4 >> 24)] & 0xff] ^
            Td1[Te4[(temp4 >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(temp4 >> 8) & 0xff] & 0xff] ^
            Td3[Te4[(temp4) & 0xff] & 0xff];

        temp5 = temp5 ^ temp4;
        rk[-3] =
            Td0[Te4[(temp5 >> 24)] & 0xff] ^
            Td1[Te4[(temp5 >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(temp5 >> 8) & 0xff] & 0xff] ^
            Td3[Te4[(temp5) & 0xff] & 0xff];

        temp6 = temp6 ^ temp5;
        rk[-2] =
            Td0[Te4[(temp6 >> 24)] & 0xff] ^
            Td1[Te4[(temp6 >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(temp6 >> 8) & 0xff] & 0xff] ^
            Td3[Te4[(temp6) & 0xff] & 0xff];

        temp7 = temp7 ^ temp6;
        rk[-1] =
            Td0[Te4[(temp7 >> 24)] & 0xff] ^
            Td1[Te4[(temp7 >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(temp7 >> 8) & 0xff] & 0xff] ^
            Td3[Te4[(temp7) & 0xff] & 0xff];

    }

    return 0;
}

int AES_set_decrypt_key_192(u32 rk0, u32 rk1, u32 rk2, u32 rk3,
    u32 rk4, u32 rk5, u32 rk6, u32 rk7,
    const int bits, AES_KEY* key) {

    u32* rk;
    int i, j, status;
    u32 temp;
    u32 temp0, temp1, temp2, temp3;
    u32 temp4, temp5, temp6, temp7;

    //	key->rounds = 12;

    rk = key->rd_key + 12 * 4;
    i = 0;

    temp0 = rk[0] = rk0;
    temp1 = rk[1] = rk1;
    temp2 = rk[2] = rk2;
    temp3 = rk[3] = rk3;
    temp4 = rk[-4] = rk4;
    temp5 = rk[-3] = rk5;
    // InvMix for pre-last 2 rk
    rk[-4] =
        Td0[Te4[(temp4 >> 24)] & 0xff] ^
        Td1[Te4[(temp4 >> 16) & 0xff] & 0xff] ^
        Td2[Te4[(temp4 >> 8) & 0xff] & 0xff] ^
        Td3[Te4[(temp4) & 0xff] & 0xff];
    rk[-3] =
        Td0[Te4[(temp5 >> 24)] & 0xff] ^
        Td1[Te4[(temp5 >> 16) & 0xff] & 0xff] ^
        Td2[Te4[(temp5 >> 8) & 0xff] & 0xff] ^
        Td3[Te4[(temp5) & 0xff] & 0xff];

    while (1) {
        rk -= 12;
        temp0 = temp0 ^
            (Te4[(temp5 >> 16) & 0xff] & 0xff000000) ^
            (Te4[(temp5 >> 8) & 0xff] & 0x00ff0000) ^
            (Te4[(temp5) & 0xff] & 0x0000ff00) ^
            (Te4[(temp5 >> 24)] & 0x000000ff) ^
            rcon[i];
        rk[10] =
            Td0[Te4[(temp0 >> 24)] & 0xff] ^
            Td1[Te4[(temp0 >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(temp0 >> 8) & 0xff] & 0xff] ^
            Td3[Te4[(temp0) & 0xff] & 0xff];

        temp1 = temp1 ^ temp0;
        rk[11] =
            Td0[Te4[(temp1 >> 24)] & 0xff] ^
            Td1[Te4[(temp1 >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(temp1 >> 8) & 0xff] & 0xff] ^
            Td3[Te4[(temp1) & 0xff] & 0xff];
        temp2 = temp2 ^ temp1;
        rk[4] =
            Td0[Te4[(temp2 >> 24)] & 0xff] ^
            Td1[Te4[(temp2 >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(temp2 >> 8) & 0xff] & 0xff] ^
            Td3[Te4[(temp2) & 0xff] & 0xff];

        temp3 = temp3 ^ temp2;
        rk[5] =
            Td0[Te4[(temp3 >> 24)] & 0xff] ^
            Td1[Te4[(temp3 >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(temp3 >> 8) & 0xff] & 0xff] ^
            Td3[Te4[(temp3) & 0xff] & 0xff];
        ++i;
        temp4 = temp4 ^ temp3;
        rk[6] =
            Td0[Te4[(temp4 >> 24)] & 0xff] ^
            Td1[Te4[(temp4 >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(temp4 >> 8) & 0xff] & 0xff] ^
            Td3[Te4[(temp4) & 0xff] & 0xff];

        temp5 = temp5 ^ temp4;
        rk[7] =
            Td0[Te4[(temp5 >> 24)] & 0xff] ^
            Td1[Te4[(temp5 >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(temp5 >> 8) & 0xff] & 0xff] ^
            Td3[Te4[(temp5) & 0xff] & 0xff];

        temp0 = temp0 ^
            (Te4[(temp5 >> 16) & 0xff] & 0xff000000) ^
            (Te4[(temp5 >> 8) & 0xff] & 0x00ff0000) ^
            (Te4[(temp5) & 0xff] & 0x0000ff00) ^
            (Te4[(temp5 >> 24)] & 0x000000ff) ^
            rcon[i];

        if (i == 7) { // last round
            rk[0] = temp0;
            rk[1] = temp1 ^ rk[0];
            rk[2] = temp2 ^ rk[1];
            rk[3] = temp3 ^ rk[2];
            return 0;
        }

        rk[0] =
            Td0[Te4[(temp0 >> 24)] & 0xff] ^
            Td1[Te4[(temp0 >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(temp0 >> 8) & 0xff] & 0xff] ^
            Td3[Te4[(temp0) & 0xff] & 0xff];

        temp1 = temp1 ^ temp0;
        rk[1] =
            Td0[Te4[(temp1 >> 24)] & 0xff] ^
            Td1[Te4[(temp1 >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(temp1 >> 8) & 0xff] & 0xff] ^
            Td3[Te4[(temp1) & 0xff] & 0xff];

        temp2 = temp2 ^ temp1;
        rk[2] =
            Td0[Te4[(temp2 >> 24)] & 0xff] ^
            Td1[Te4[(temp2 >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(temp2 >> 8) & 0xff] & 0xff] ^
            Td3[Te4[(temp2) & 0xff] & 0xff];

        temp3 = temp3 ^ temp2;
        rk[3] =
            Td0[Te4[(temp3 >> 24)] & 0xff] ^
            Td1[Te4[(temp3 >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(temp3 >> 8) & 0xff] & 0xff] ^
            Td3[Te4[(temp3) & 0xff] & 0xff];
        ++i;

        temp4 = temp4 ^ temp3;
        rk[-4] =
            Td0[Te4[(temp4 >> 24)] & 0xff] ^
            Td1[Te4[(temp4 >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(temp4 >> 8) & 0xff] & 0xff] ^
            Td3[Te4[(temp4) & 0xff] & 0xff];

        temp5 = temp5 ^ temp4;
        rk[-3] =
            Td0[Te4[(temp5 >> 24)] & 0xff] ^
            Td1[Te4[(temp5 >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(temp5 >> 8) & 0xff] & 0xff] ^
            Td3[Te4[(temp5) & 0xff] & 0xff];

    }

    return 0;
}


int AES_set_decrypt_key_128(u32 rk0, u32 rk1, u32 rk2, u32 rk3,
    u32 rk4, u32 rk5, u32 rk6, u32 rk7,
    const int bits, AES_KEY* key) {

    u32* rk;
    int i, j, status;
    u32 temp;
    u32 temp0, temp1, temp2, temp3;
    u32 temp4, temp5, temp6, temp7;

    //	key->rounds = 10;

    rk = key->rd_key + 10 * 4;
    i = 0;

    temp0 = rk[0] = rk0;
    temp1 = rk[1] = rk1;
    temp2 = rk[2] = rk2;
    temp3 = rk[3] = rk3;
    while (1) {
        rk -= 4;
        temp0 =
            (Te4[(temp3 >> 16) & 0xff] & 0xff000000) ^
            (Te4[(temp3 >> 8) & 0xff] & 0x00ff0000) ^
            (Te4[(temp3) & 0xff] & 0x0000ff00) ^
            (Te4[(temp3 >> 24)] & 0x000000ff) ^
            rcon[i] ^ temp0;

        if (++i == 10) {	// last round

            rk[0] = temp0;
            rk[1] = temp1 ^ rk[0];
            rk[2] = temp2 ^ rk[1];
            rk[3] = temp3 ^ rk[2];
            return 0;
        }

        rk[0] =
            Td0[Te4[(temp0 >> 24)] & 0xff] ^
            Td1[Te4[(temp0 >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(temp0 >> 8) & 0xff] & 0xff] ^
            Td3[Te4[(temp0) & 0xff] & 0xff];

        temp1 = temp1 ^ temp0;
        rk[1] =
            Td0[Te4[(temp1 >> 24)] & 0xff] ^
            Td1[Te4[(temp1 >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(temp1 >> 8) & 0xff] & 0xff] ^
            Td3[Te4[(temp1) & 0xff] & 0xff];

        temp2 = temp2 ^ temp1;
        rk[2] =
            Td0[Te4[(temp2 >> 24)] & 0xff] ^
            Td1[Te4[(temp2 >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(temp2 >> 8) & 0xff] & 0xff] ^
            Td3[Te4[(temp2) & 0xff] & 0xff];

        temp3 = temp3 ^ temp2;
        rk[3] =
            Td0[Te4[(temp3 >> 24)] & 0xff] ^
            Td1[Te4[(temp3 >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(temp3 >> 8) & 0xff] & 0xff] ^
            Td3[Te4[(temp3) & 0xff] & 0xff];
    }
    return 0;
}



void AES_decrypt(__constant unsigned int* in, u32* s0, u32* s1, u32* s2, u32* s3,
    const int bits, const AES_KEY* key) {
    const u32* rk;
    u32 /*s0, s1, s2, s3,*/ t0, t1, t2, t3;
    int rounds;

#ifndef FULL_UNROLL
    int r;
#endif /* ?FULL_UNROLL */

    //	assert(in && out && key);
    rk = key->rd_key;
    rounds = 10 + (bits - 128) / 32;


    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    (*s0) = (in[0]) ^ rk[0];
    (*s1) = (in[1]) ^ rk[1];
    (*s2) = (in[2]) ^ rk[2];
    (*s3) = (in[3]) ^ rk[3];

#ifdef FULL_UNROLL
    /* round 1: */
    t0 = Td0[(*s0) >> 24] ^ Td1[((*s3) >> 16) & 0xff] ^ Td2[((*s2) >> 8) & 0xff] ^ Td3[(*s1) & 0xff] ^ rk[4];
    t1 = Td0[(*s1) >> 24] ^ Td1[((*s0) >> 16) & 0xff] ^ Td2[((*s3) >> 8) & 0xff] ^ Td3[(*s2) & 0xff] ^ rk[5];
    t2 = Td0[(*s2) >> 24] ^ Td1[((*s1) >> 16) & 0xff] ^ Td2[((*s0) >> 8) & 0xff] ^ Td3[(*s3) & 0xff] ^ rk[6];
    t3 = Td0[(*s3) >> 24] ^ Td1[((*s2) >> 16) & 0xff] ^ Td2[((*s1) >> 8) & 0xff] ^ Td3[(*s0) & 0xff] ^ rk[7];
    /* round 2: */
    (*s0) = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[8];
    (*s1) = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[9];
    (*s2) = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[10];
    (*s3) = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[11];
    /* round 3: */
    t0 = Td0[(*s0) >> 24] ^ Td1[((*s3) >> 16) & 0xff] ^ Td2[((*s2) >> 8) & 0xff] ^ Td3[(*s1) & 0xff] ^ rk[12];
    t1 = Td0[(*s1) >> 24] ^ Td1[((*s0) >> 16) & 0xff] ^ Td2[((*s3) >> 8) & 0xff] ^ Td3[(*s2) & 0xff] ^ rk[13];
    t2 = Td0[(*s2) >> 24] ^ Td1[((*s1) >> 16) & 0xff] ^ Td2[((*s0) >> 8) & 0xff] ^ Td3[(*s3) & 0xff] ^ rk[14];
    t3 = Td0[(*s3) >> 24] ^ Td1[((*s2) >> 16) & 0xff] ^ Td2[((*s1) >> 8) & 0xff] ^ Td3[(*s0) & 0xff] ^ rk[15];
    /* round 4: */
    (*s0) = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[16];
    (*s1) = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[17];
    (*s2) = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[18];
    (*s3) = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[19];
    /* round 5: */
    t0 = Td0[(*s0) >> 24] ^ Td1[((*s3) >> 16) & 0xff] ^ Td2[((*s2) >> 8) & 0xff] ^ Td3[(*s1) & 0xff] ^ rk[20];
    t1 = Td0[(*s1) >> 24] ^ Td1[((*s0) >> 16) & 0xff] ^ Td2[((*s3) >> 8) & 0xff] ^ Td3[(*s2) & 0xff] ^ rk[21];
    t2 = Td0[(*s2) >> 24] ^ Td1[((*s1) >> 16) & 0xff] ^ Td2[((*s0) >> 8) & 0xff] ^ Td3[(*s3) & 0xff] ^ rk[22];
    t3 = Td0[(*s3) >> 24] ^ Td1[((*s2) >> 16) & 0xff] ^ Td2[((*s1) >> 8) & 0xff] ^ Td3[(*s0) & 0xff] ^ rk[23];
    /* round 6: */
    (*s0) = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[24];
    (*s1) = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[25];
    (*s2) = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[26];
    (*s3) = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[27];
    /* round 7: */
    t0 = Td0[(*s0) >> 24] ^ Td1[((*s3) >> 16) & 0xff] ^ Td2[((*s2) >> 8) & 0xff] ^ Td3[(*s1) & 0xff] ^ rk[28];
    t1 = Td0[(*s1) >> 24] ^ Td1[((*s0) >> 16) & 0xff] ^ Td2[((*s3) >> 8) & 0xff] ^ Td3[(*s2) & 0xff] ^ rk[29];
    t2 = Td0[(*s2) >> 24] ^ Td1[((*s1) >> 16) & 0xff] ^ Td2[((*s0) >> 8) & 0xff] ^ Td3[(*s3) & 0xff] ^ rk[30];
    t3 = Td0[(*s3) >> 24] ^ Td1[((*s2) >> 16) & 0xff] ^ Td2[((*s1) >> 8) & 0xff] ^ Td3[(*s0) & 0xff] ^ rk[31];
    /* round 8: */
    (*s0) = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[32];
    (*s1) = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[33];
    (*s2) = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[34];
    (*s3) = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[35];
    /* round 9: */
    t0 = Td0[(*s0) >> 24] ^ Td1[((*s3) >> 16) & 0xff] ^ Td2[((*s2) >> 8) & 0xff] ^ Td3[(*s1) & 0xff] ^ rk[36];
    t1 = Td0[(*s1) >> 24] ^ Td1[((*s0) >> 16) & 0xff] ^ Td2[((*s3) >> 8) & 0xff] ^ Td3[(*s2) & 0xff] ^ rk[37];
    t2 = Td0[(*s2) >> 24] ^ Td1[((*s1) >> 16) & 0xff] ^ Td2[((*s0) >> 8) & 0xff] ^ Td3[(*s3) & 0xff] ^ rk[38];
    t3 = Td0[(*s3) >> 24] ^ Td1[((*s2) >> 16) & 0xff] ^ Td2[((*s1) >> 8) & 0xff] ^ Td3[(*s0) & 0xff] ^ rk[39];
    if (rounds > 10) {
        /* round 10: */
        (*s0) = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[40];
        (*s1) = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[41];
        (*s2) = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[42];
        (*s3) = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[43];
        /* round 11: */
        t0 = Td0[(*s0) >> 24] ^ Td1[((*s3) >> 16) & 0xff] ^ Td2[((*s2) >> 8) & 0xff] ^ Td3[(*s1) & 0xff] ^ rk[44];
        t1 = Td0[(*s1) >> 24] ^ Td1[((*s0) >> 16) & 0xff] ^ Td2[((*s3) >> 8) & 0xff] ^ Td3[(*s2) & 0xff] ^ rk[45];
        t2 = Td0[(*s2) >> 24] ^ Td1[((*s1) >> 16) & 0xff] ^ Td2[((*s0) >> 8) & 0xff] ^ Td3[(*s3) & 0xff] ^ rk[46];
        t3 = Td0[(*s3) >> 24] ^ Td1[((*s2) >> 16) & 0xff] ^ Td2[((*s1) >> 8) & 0xff] ^ Td3[(*s0) & 0xff] ^ rk[47];
        if (rounds > 12) {
            /* round 12: */
            (*s0) = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[48];
            (*s1) = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[49];
            (*s2) = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[50];
            (*s3) = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[51];
            /* round 13: */
            t0 = Td0[(*s0) >> 24] ^ Td1[((*s3) >> 16) & 0xff] ^ Td2[((*s2) >> 8) & 0xff] ^ Td3[(*s1) & 0xff] ^ rk[52];
            t1 = Td0[(*s1) >> 24] ^ Td1[((*s0) >> 16) & 0xff] ^ Td2[((*s3) >> 8) & 0xff] ^ Td3[(*s2) & 0xff] ^ rk[53];
            t2 = Td0[(*s2) >> 24] ^ Td1[((*s1) >> 16) & 0xff] ^ Td2[((*s0) >> 8) & 0xff] ^ Td3[(*s3) & 0xff] ^ rk[54];
            t3 = Td0[(*s3) >> 24] ^ Td1[((*s2) >> 16) & 0xff] ^ Td2[((*s1) >> 8) & 0xff] ^ Td3[(*s0) & 0xff] ^ rk[55];
        }
    }
    rk += rounds << 2;
#else  /* !FULL_UNROLL */
    /*
     * Nr - 1 full rounds:
     */
    r = rounds >> 1;
    for (;;) {
        t0 =
            Td0[((*s0) >> 24)] ^
            Td1[((*s3) >> 16) & 0xff] ^
            Td2[((*s2) >> 8) & 0xff] ^
            Td3[((*s1)) & 0xff] ^
            rk[4];
        t1 =
            Td0[((*s1) >> 24)] ^
            Td1[((*s0) >> 16) & 0xff] ^
            Td2[((*s3) >> 8) & 0xff] ^
            Td3[((*s2)) & 0xff] ^
            rk[5];
        t2 =
            Td0[((*s2) >> 24)] ^
            Td1[((*s1) >> 16) & 0xff] ^
            Td2[((*s0) >> 8) & 0xff] ^
            Td3[((*s3)) & 0xff] ^
            rk[6];
        t3 =
            Td0[((*s3) >> 24)] ^
            Td1[((*s2) >> 16) & 0xff] ^
            Td2[((*s1) >> 8) & 0xff] ^
            Td3[((*s0)) & 0xff] ^
            rk[7];

        rk += 8;
        if (--r == 0) {
            break;
        }

        (*s0) =
            Td0[(t0 >> 24)] ^
            Td1[(t3 >> 16) & 0xff] ^
            Td2[(t2 >> 8) & 0xff] ^
            Td3[(t1) & 0xff] ^
            rk[0];
        (*s1) =
            Td0[(t1 >> 24)] ^
            Td1[(t0 >> 16) & 0xff] ^
            Td2[(t3 >> 8) & 0xff] ^
            Td3[(t2) & 0xff] ^
            rk[1];
        (*s2) =
            Td0[(t2 >> 24)] ^
            Td1[(t1 >> 16) & 0xff] ^
            Td2[(t0 >> 8) & 0xff] ^
            Td3[(t3) & 0xff] ^
            rk[2];
        (*s3) =
            Td0[(t3 >> 24)] ^
            Td1[(t2 >> 16) & 0xff] ^
            Td2[(t1 >> 8) & 0xff] ^
            Td3[(t0) & 0xff] ^
            rk[3];
    }
#endif /* ?FULL_UNROLL */
    /*
     * apply last round and
     * map cipher state to byte array block:
     */
    (*s0) =
        (Td4[(t0 >> 24)] & 0xff000000) ^
        (Td4[(t3 >> 16) & 0xff] & 0x00ff0000) ^
        (Td4[(t2 >> 8) & 0xff] & 0x0000ff00) ^
        (Td4[(t1) & 0xff] & 0x000000ff) ^
        rk[0];
    //	PUTU32(out     , (*s0));
    (*s1) =
        (Td4[(t1 >> 24)] & 0xff000000) ^
        (Td4[(t0 >> 16) & 0xff] & 0x00ff0000) ^
        (Td4[(t3 >> 8) & 0xff] & 0x0000ff00) ^
        (Td4[(t2) & 0xff] & 0x000000ff) ^
        rk[1];
    //	PUTU32(out +  4, (*s1));
    (*s2) =
        (Td4[(t2 >> 24)] & 0xff000000) ^
        (Td4[(t1 >> 16) & 0xff] & 0x00ff0000) ^
        (Td4[(t0 >> 8) & 0xff] & 0x0000ff00) ^
        (Td4[(t3) & 0xff] & 0x000000ff) ^
        rk[2];
    //	PUTU32(out +  8, (*s2));
    (*s3) =
        (Td4[(t3 >> 24)] & 0xff000000) ^
        (Td4[(t2 >> 16) & 0xff] & 0x00ff0000) ^
        (Td4[(t1 >> 8) & 0xff] & 0x0000ff00) ^
        (Td4[(t0) & 0xff] & 0x000000ff) ^
        rk[3];
    //	PUTU32(out + 12, (*s3));
}

