#ifndef _LEA_LOCAL_H_
#define _LEA_LOCAL_H_
#include <stdio.h>

typedef struct lea_key_st
{
	unsigned int rk[144];
	unsigned int round;
} LEA_KEY;


typedef struct lea_cmac_ctx
{
	unsigned char k1[16];
	unsigned char k2[16];
	unsigned char tbl[16];
	unsigned char last_block[16];
	LEA_KEY key;

	int nlast_block;
} LEA_CMAC_CTX;

typedef struct
{
	unsigned char key[32];
	unsigned char msg[80];
	unsigned char tag[16];
} LEA_CMAC_G;

#define XOR8x16(r, a, b)																		\
	*((unsigned int *)(r)      ) = *((unsigned int *)(a)      ) ^ *((unsigned int *)(b)      ),	\
	*((unsigned int *)(r) + 0x1) = *((unsigned int *)(a) + 0x1) ^ *((unsigned int *)(b) + 0x1),	\
	*((unsigned int *)(r) + 0x2) = *((unsigned int *)(a) + 0x2) ^ *((unsigned int *)(b) + 0x2),	\
	*((unsigned int *)(r) + 0x3) = *((unsigned int *)(a) + 0x3) ^ *((unsigned int *)(b) + 0x3)



#ifndef NO_SIMD

#if defined(__i386__) || defined(_M_IX86) || defined(_M_X64) || defined(__x86_64__)
#define ARCH_IA32
#endif

#if defined(__arm__) || defined(_M_ARM) || defined(_ARM) || defined(__arm) || defined(__aarch64__)
#define ARCH_ARM
#endif

#ifdef ARCH_IA32
#if (!defined(_MSC_VER) || _MSC_FULL_VER >= 180021114) && !defined(NO_AVX2)
#define COMPILE_AVX2
#endif

#if (!defined(_MSC_VER) || _MSC_FULL_VER >= 160040219) && !defined(NO_XOP)
#define COMPILE_XOP
#endif

#if (!defined(_MSC_VER) || _MSC_FULL_VER >= 150030729) && !defined(NO_PCLMUL)
#define COMPILE_PCLMUL
#endif

#if (!defined(_MSC_VER) || _MSC_VER >= 1250) && !defined(NO_SSE2)
#define COMPILE_SSE2
#endif 

#endif /* ARCH_IA32 */

#ifdef ARCH_ARM

#if (!defined(__GNUC__) || (__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)) && !defined(NO_NEON)
#define COMPILE_NEON
#endif
#endif /* ARCH_ARM*/

#endif /* NO_SIMD */

/*		#define USE_BUILT_IN	*/
#if (USE_BUILT_IN)
#if defined(_MSC_VER)
#include <stdlib.h>
#define ROR(W,i) _lrotr(W, i)
#define ROL(W,i) _lrotl(W, i)
#else	/*	#if defined(_MSC_VER)	*/
#define ROR(W,i) (((W) >> (i)) | ((W) << (32 - (i))))
#define ROL(W,i) (((W) << (i)) | ((W) >> (32 - (i))))
#endif	/*	#if defined(_MSC_VER)	*/
#include <string.h>
#define lea_memcpy		memcpy
#define lea_memset		memset
#define lea_memcmp		memcmp
#else	/*	#if (USE_BUILT_IN)	*/
#define ROR(W,i) (((W) >> (i)) | ((W) << (32 - (i))))
#define ROL(W,i) (((W) << (i)) | ((W) >> (32 - (i))))

#endif

/*		#define GCM_OPT_LEVEL	*/
/*	0 : 메모리를 추가적으로 사용하지 않습니다.(GCM 중 가장 느립니다.)
	1 : 4bit table을 사용합니다.(메모리를 추가로 약 0.3kb 더 사용합니다.		 0보다 약  5배 빠릅니다.)
	2 : 8bit table을 사용합니다.(메모리를 추가로 약 4.5kb 더 사용합니다.		 0보다 약 11배 빠릅니다.)
*/
#define GCM_OPT_LEVEL	2
//#define GCM_OP_LEVEL	1
//#define GCM_OP_LEVEL	0

//	endianess
#if IS_LITTLE_ENDIAN
//	little endian
#define ctow(w, c)	(*(w) = *((unsigned int *)(c)))
#define wtoc(c, w)	(*((unsigned int *)(c)) = *(w))
#define loadU32(v)	(v)

#else
//	big endian
#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#if defined(__GNUC__) && ((__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3))
#define loadU32(v)	__builtin_bswap32(v)
#define ctow(c,w)	(*(w) = __builtin_bswap32(*(unsigned int*)c))
#define wtoc(w,c)	(*(unsigned int*)(c) = __builtin_bswap32(*(w)))

#elif defined(__clang__) && defined(__has_builtin) && __has_builtin(__builtin_bswap32)

#define loadU32(v)	__builtin_bswap32(v)
#define ctow(c,w)	(*(w) = __builtin_bswap32(*(unsigned int*)c))
#define wtoc(w,c)	(*(unsigned int*)(c) = __builtin_bswap32(*(w)))

#else

#define loadU32(v)	((unsigned int)((((unsigned char*)(&v))[3]<<24)|(((unsigned char*)(&v))[2]<<16)|(((unsigned char*)(&v))[1]<<8)|(((unsigned char*)(&v))[0])))
#define ctow(c, w)	(*(w) = (((c)[3] << 24) | ((c)[2] << 16) | ((c)[1] << 8) | ((c)[0])))
#define wtoc(w, c)	((c)[0] = *(w), (c)[1] = (*(w) >> 8), (c)[2] = (*(w) >> 16), (c)[3] = (*(w) >> 24))
#endif

#endif



#define lea_assert(cond)	((cond) ? 0 : (return -1;))

void lea_set_key_generic(LEA_KEY *key, const unsigned char *mk, unsigned int mk_len);
void lea_encrypt(unsigned char *ct, const unsigned char *pt, const LEA_KEY *key);

static void lea_make_cmac_subkey(unsigned char *new_key, const unsigned char *old_key, unsigned int key_len);

void lea_cmac_init(LEA_CMAC_CTX *ctx, const unsigned char *mk, int mk_len);
void cmac_update(LEA_CMAC_CTX *ctx, const unsigned char *data, int data_len);
void cmac_final(LEA_CMAC_CTX *ctx, unsigned char *cmac, int cmac_len);
void CMAC_Enc(unsigned char* Msg, unsigned int Msg_len, unsigned char* Key, unsigned int Key_len, unsigned int Tlen, unsigned char* Tag);

void lea_encrypt_op(unsigned char *ct, const unsigned char *pt, const LEA_KEY *key);
void lea_CMAC_op(LEA_CMAC_CTX *ctx, const unsigned char *mk, int mk_len, const unsigned char *data, int data_len, unsigned char *cmac, int cmac_len);
void CMAC_Enc_op(unsigned char* Msg, unsigned int Msg_len, unsigned char* Key, unsigned int Key_len, unsigned int Tlen, unsigned char* Tag);

void HMAC_Gen_Test();
void HMAC_Ver_Test();

#endif