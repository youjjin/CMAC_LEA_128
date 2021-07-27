#define _CRT_SECURE_NO_WARNINGS
#include "CMAC_LEA_128.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
/*최적화 아이디어*/
/*전처리함수의 사용을 줄였다*/
/*for문의 사용을 줄였다.*/
/*if문의 사용을 줄였다.*/
/*전역변수의 사용을 줄인 lea_enc_op*/

void lea_encrypt_op(unsigned char *ct, const unsigned char *pt, const LEA_KEY *key)
{
	unsigned int X0, X1, X2, X3;

	const unsigned int * _pt = (const unsigned int *)pt;
	unsigned int * _ct = (unsigned int*)ct;

	X0 = ((unsigned int)((((unsigned char*)(&_pt[0]))[3] << 24) | (((unsigned char*)(&_pt[0]))[2] << 16) | (((unsigned char*)(&_pt[0]))[1] << 8) | (((unsigned char*)(&_pt[0]))[0])));
	X1 = ((unsigned int)((((unsigned char*)(&_pt[1]))[3] << 24) | (((unsigned char*)(&_pt[1]))[2] << 16) | (((unsigned char*)(&_pt[1]))[1] << 8) | (((unsigned char*)(&_pt[1]))[0])));
	X2 = ((unsigned int)((((unsigned char*)(&_pt[2]))[3] << 24) | (((unsigned char*)(&_pt[2]))[2] << 16) | (((unsigned char*)(&_pt[2]))[1] << 8) | (((unsigned char*)(&_pt[2]))[0])));
	X3 = ((unsigned int)((((unsigned char*)(&_pt[3]))[3] << 24) | (((unsigned char*)(&_pt[3]))[2] << 16) | (((unsigned char*)(&_pt[3]))[1] << 8) | (((unsigned char*)(&_pt[3]))[0])));


	X3 = ((X2 ^ key->rk[4]) + (X3 ^ key->rk[5]) >> 3) | ((X2 ^ key->rk[4]) + (X3 ^ key->rk[5]) << 29);
	X2 = ((X1 ^ key->rk[2]) + (X2 ^ key->rk[3]) >> 5) | ((X1 ^ key->rk[2]) + (X2 ^ key->rk[3]) << 27);
	X1 = ((X0 ^ key->rk[0]) + (X1 ^ key->rk[1]) << 9) | ((X0 ^ key->rk[0]) + (X1 ^ key->rk[1]) >> 23);
	X0 = ((X3 ^ key->rk[10]) + (X0 ^ key->rk[11]) >> 3) | ((X3 ^ key->rk[10]) + (X0 ^ key->rk[11]) << 29);
	X3 = ((X2 ^ key->rk[8]) + (X3 ^ key->rk[9]) >> 5) | ((X2 ^ key->rk[8]) + (X3 ^ key->rk[9]) << 27);
	X2 = ((X1 ^ key->rk[6]) + (X2 ^ key->rk[7]) << 9) | ((X1 ^ key->rk[6]) + (X2 ^ key->rk[7]) >> 23);
	X1 = ((X0 ^ key->rk[16]) + (X1 ^ key->rk[17]) >> 3) | ((X0 ^ key->rk[16]) + (X1 ^ key->rk[17]) << 29);
	X0 = ((X3 ^ key->rk[14]) + (X0 ^ key->rk[15]) >> 5) | ((X3 ^ key->rk[14]) + (X0 ^ key->rk[15]) << 27);
	X3 = ((X2 ^ key->rk[12]) + (X3 ^ key->rk[13]) << 9) | ((X2 ^ key->rk[12]) + (X3 ^ key->rk[13]) >> 23);
	X2 = ((X1 ^ key->rk[22]) + (X2 ^ key->rk[23]) >> 3) | ((X1 ^ key->rk[22]) + (X2 ^ key->rk[23]) << 29);
	X1 = ((X0 ^ key->rk[20]) + (X1 ^ key->rk[21]) >> 5) | ((X0 ^ key->rk[20]) + (X1 ^ key->rk[21]) << 27);
	X0 = ((X3 ^ key->rk[18]) + (X0 ^ key->rk[19]) << 9) | ((X3 ^ key->rk[18]) + (X0 ^ key->rk[19]) >> 23);


	X3 = ((X2 ^ key->rk[28]) + (X3 ^ key->rk[29]) >> 3) | ((X2 ^ key->rk[28]) + (X3 ^ key->rk[29]) << 29);
	X2 = ((X1 ^ key->rk[26]) + (X2 ^ key->rk[27]) >> 5) | ((X1 ^ key->rk[26]) + (X2 ^ key->rk[27]) << 27);
	X1 = ((X0 ^ key->rk[24]) + (X1 ^ key->rk[25]) << 9) | ((X0 ^ key->rk[24]) + (X1 ^ key->rk[25]) >> 23);
	X0 = ((X3 ^ key->rk[34]) + (X0 ^ key->rk[35]) >> 3) | ((X3 ^ key->rk[34]) + (X0 ^ key->rk[35]) << 29);
	X3 = ((X2 ^ key->rk[32]) + (X3 ^ key->rk[33]) >> 5) | ((X2 ^ key->rk[32]) + (X3 ^ key->rk[33]) << 27);
	X2 = ((X1 ^ key->rk[30]) + (X2 ^ key->rk[31]) << 9) | ((X1 ^ key->rk[30]) + (X2 ^ key->rk[31]) >> 23);
	X1 = ((X0 ^ key->rk[40]) + (X1 ^ key->rk[41]) >> 3) | ((X0 ^ key->rk[40]) + (X1 ^ key->rk[41]) << 29);
	X0 = ((X3 ^ key->rk[38]) + (X0 ^ key->rk[39]) >> 5) | ((X3 ^ key->rk[38]) + (X0 ^ key->rk[39]) << 27);
	X3 = ((X2 ^ key->rk[36]) + (X3 ^ key->rk[37]) << 9) | ((X2 ^ key->rk[36]) + (X3 ^ key->rk[37]) >> 23);
	X2 = ((X1 ^ key->rk[46]) + (X2 ^ key->rk[47]) >> 3) | ((X1 ^ key->rk[46]) + (X2 ^ key->rk[47]) << 29);
	X1 = ((X0 ^ key->rk[44]) + (X1 ^ key->rk[45]) >> 5) | ((X0 ^ key->rk[44]) + (X1 ^ key->rk[45]) << 27);
	X0 = ((X3 ^ key->rk[42]) + (X0 ^ key->rk[43]) << 9) | ((X3 ^ key->rk[42]) + (X0 ^ key->rk[43]) >> 23);

	X3 = ((X2 ^ key->rk[52]) + (X3 ^ key->rk[53]) >> 3) | ((X2 ^ key->rk[52]) + (X3 ^ key->rk[53]) << 29);
	X2 = ((X1 ^ key->rk[50]) + (X2 ^ key->rk[51]) >> 5) | ((X1 ^ key->rk[50]) + (X2 ^ key->rk[51]) << 27);
	X1 = ((X0 ^ key->rk[48]) + (X1 ^ key->rk[49]) << 9) | ((X0 ^ key->rk[48]) + (X1 ^ key->rk[49]) >> 23);
	X0 = ((X3 ^ key->rk[58]) + (X0 ^ key->rk[59]) >> 3) | ((X3 ^ key->rk[58]) + (X0 ^ key->rk[59]) << 29);
	X3 = ((X2 ^ key->rk[56]) + (X3 ^ key->rk[57]) >> 5) | ((X2 ^ key->rk[56]) + (X3 ^ key->rk[57]) << 27);
	X2 = ((X1 ^ key->rk[54]) + (X2 ^ key->rk[55]) << 9) | ((X1 ^ key->rk[54]) + (X2 ^ key->rk[55]) >> 23);
	X1 = ((X0 ^ key->rk[64]) + (X1 ^ key->rk[65]) >> 3) | ((X0 ^ key->rk[64]) + (X1 ^ key->rk[65]) << 29);
	X0 = ((X3 ^ key->rk[62]) + (X0 ^ key->rk[63]) >> 5) | ((X3 ^ key->rk[62]) + (X0 ^ key->rk[63]) << 27);
	X3 = ((X2 ^ key->rk[60]) + (X3 ^ key->rk[61]) << 9) | ((X2 ^ key->rk[60]) + (X3 ^ key->rk[61]) >> 23);
	X2 = ((X1 ^ key->rk[70]) + (X2 ^ key->rk[71]) >> 3) | ((X1 ^ key->rk[70]) + (X2 ^ key->rk[71]) << 29);
	X1 = ((X0 ^ key->rk[68]) + (X1 ^ key->rk[69]) >> 5) | ((X0 ^ key->rk[68]) + (X1 ^ key->rk[69]) << 27);
	X0 = ((X3 ^ key->rk[66]) + (X0 ^ key->rk[67]) << 9) | ((X3 ^ key->rk[66]) + (X0 ^ key->rk[67]) >> 23);

	X3 = ((X2 ^ key->rk[76]) + (X3 ^ key->rk[77]) >> 3) | ((X2 ^ key->rk[76]) + (X3 ^ key->rk[77]) << 29);
	X2 = ((X1 ^ key->rk[74]) + (X2 ^ key->rk[75]) >> 5) | ((X1 ^ key->rk[74]) + (X2 ^ key->rk[75]) << 27);
	X1 = ((X0 ^ key->rk[72]) + (X1 ^ key->rk[73]) << 9) | ((X0 ^ key->rk[72]) + (X1 ^ key->rk[73]) >> 23);
	X0 = ((X3 ^ key->rk[82]) + (X0 ^ key->rk[83]) >> 3) | ((X3 ^ key->rk[82]) + (X0 ^ key->rk[83]) << 29);
	X3 = ((X2 ^ key->rk[80]) + (X3 ^ key->rk[81]) >> 5) | ((X2 ^ key->rk[80]) + (X3 ^ key->rk[81]) << 27);
	X2 = ((X1 ^ key->rk[78]) + (X2 ^ key->rk[79]) << 9) | ((X1 ^ key->rk[78]) + (X2 ^ key->rk[79]) >> 23);
	X1 = ((X0 ^ key->rk[88]) + (X1 ^ key->rk[89]) >> 3) | ((X0 ^ key->rk[88]) + (X1 ^ key->rk[89]) << 29);
	X0 = ((X3 ^ key->rk[86]) + (X0 ^ key->rk[87]) >> 5) | ((X3 ^ key->rk[86]) + (X0 ^ key->rk[87]) << 27);
	X3 = ((X2 ^ key->rk[84]) + (X3 ^ key->rk[85]) << 9) | ((X2 ^ key->rk[84]) + (X3 ^ key->rk[85]) >> 23);
	X2 = ((X1 ^ key->rk[94]) + (X2 ^ key->rk[95]) >> 3) | ((X1 ^ key->rk[94]) + (X2 ^ key->rk[95]) << 29);
	X1 = ((X0 ^ key->rk[92]) + (X1 ^ key->rk[93]) >> 5) | ((X0 ^ key->rk[92]) + (X1 ^ key->rk[93]) << 27);
	X0 = ((X3 ^ key->rk[90]) + (X0 ^ key->rk[91]) << 9) | ((X3 ^ key->rk[90]) + (X0 ^ key->rk[91]) >> 23);

	X3 = ((X2 ^ key->rk[100]) + (X3 ^ key->rk[101]) >> 3) | ((X2 ^ key->rk[100]) + (X3 ^ key->rk[101]) << 29);
	X2 = ((X1 ^ key->rk[98]) + (X2 ^ key->rk[99]) >> 5) | ((X1 ^ key->rk[98]) + (X2 ^ key->rk[99]) << 27);
	X1 = ((X0 ^ key->rk[96]) + (X1 ^ key->rk[97]) << 9) | ((X0 ^ key->rk[96]) + (X1 ^ key->rk[97]) >> 23);
	X0 = ((X3 ^ key->rk[106]) + (X0 ^ key->rk[107]) >> 3) | ((X3 ^ key->rk[106]) + (X0 ^ key->rk[107]) << 29);
	X3 = ((X2 ^ key->rk[104]) + (X3 ^ key->rk[105]) >> 5) | ((X2 ^ key->rk[104]) + (X3 ^ key->rk[105]) << 27);
	X2 = ((X1 ^ key->rk[102]) + (X2 ^ key->rk[103]) << 9) | ((X1 ^ key->rk[102]) + (X2 ^ key->rk[103]) >> 23);
	X1 = ((X0 ^ key->rk[112]) + (X1 ^ key->rk[113]) >> 3) | ((X0 ^ key->rk[112]) + (X1 ^ key->rk[113]) << 29);
	X0 = ((X3 ^ key->rk[110]) + (X0 ^ key->rk[111]) >> 5) | ((X3 ^ key->rk[110]) + (X0 ^ key->rk[111]) << 27);
	X3 = ((X2 ^ key->rk[108]) + (X3 ^ key->rk[109]) << 9) | ((X2 ^ key->rk[108]) + (X3 ^ key->rk[109]) >> 23);
	X2 = ((X1 ^ key->rk[118]) + (X2 ^ key->rk[119]) >> 3) | ((X1 ^ key->rk[118]) + (X2 ^ key->rk[119]) << 29);
	X1 = ((X0 ^ key->rk[116]) + (X1 ^ key->rk[117]) >> 5) | ((X0 ^ key->rk[116]) + (X1 ^ key->rk[117]) << 27);
	X0 = ((X3 ^ key->rk[114]) + (X0 ^ key->rk[115]) << 9) | ((X3 ^ key->rk[114]) + (X0 ^ key->rk[115]) >> 23);

	X3 = ((X2 ^ key->rk[124]) + (X3 ^ key->rk[125]) >> 3) | ((X2 ^ key->rk[124]) + (X3 ^ key->rk[125]) << 29);
	X2 = ((X1 ^ key->rk[122]) + (X2 ^ key->rk[123]) >> 5) | ((X1 ^ key->rk[122]) + (X2 ^ key->rk[123]) << 27);
	X1 = ((X0 ^ key->rk[120]) + (X1 ^ key->rk[121]) << 9) | ((X0 ^ key->rk[120]) + (X1 ^ key->rk[121]) >> 23);
	X0 = ((X3 ^ key->rk[130]) + (X0 ^ key->rk[131]) >> 3) | ((X3 ^ key->rk[130]) + (X0 ^ key->rk[131]) << 29);
	X3 = ((X2 ^ key->rk[128]) + (X3 ^ key->rk[129]) >> 5) | ((X2 ^ key->rk[128]) + (X3 ^ key->rk[129]) << 27);
	X2 = ((X1 ^ key->rk[126]) + (X2 ^ key->rk[127]) << 9) | ((X1 ^ key->rk[126]) + (X2 ^ key->rk[127]) >> 23);
	X1 = ((X0 ^ key->rk[136]) + (X1 ^ key->rk[137]) >> 3) | ((X0 ^ key->rk[136]) + (X1 ^ key->rk[137]) << 29);
	X0 = ((X3 ^ key->rk[134]) + (X0 ^ key->rk[135]) >> 5) | ((X3 ^ key->rk[134]) + (X0 ^ key->rk[135]) << 27);
	X3 = ((X2 ^ key->rk[132]) + (X3 ^ key->rk[133]) << 9) | ((X2 ^ key->rk[132]) + (X3 ^ key->rk[133]) >> 23);
	X2 = ((X1 ^ key->rk[142]) + (X2 ^ key->rk[143]) >> 3) | ((X1 ^ key->rk[142]) + (X2 ^ key->rk[143]) << 29);
	X1 = ((X0 ^ key->rk[140]) + (X1 ^ key->rk[141]) >> 5) | ((X0 ^ key->rk[140]) + (X1 ^ key->rk[141]) << 27);
	X0 = ((X3 ^ key->rk[138]) + (X0 ^ key->rk[139]) << 9) | ((X3 ^ key->rk[138]) + (X0 ^ key->rk[139]) >> 23);

	_ct[0] = ((unsigned int)((((unsigned char*)(&X0))[3] << 24) | (((unsigned char*)(&X0))[2] << 16) | (((unsigned char*)(&X0))[1] << 8) | (((unsigned char*)(&X0))[0])));
	_ct[1] = ((unsigned int)((((unsigned char*)(&X1))[3] << 24) | (((unsigned char*)(&X1))[2] << 16) | (((unsigned char*)(&X1))[1] << 8) | (((unsigned char*)(&X1))[0])));
	_ct[2] = ((unsigned int)((((unsigned char*)(&X2))[3] << 24) | (((unsigned char*)(&X2))[2] << 16) | (((unsigned char*)(&X2))[1] << 8) | (((unsigned char*)(&X2))[0])));
	_ct[3] = ((unsigned int)((((unsigned char*)(&X3))[3] << 24) | (((unsigned char*)(&X3))[2] << 16) | (((unsigned char*)(&X3))[1] << 8) | (((unsigned char*)(&X3))[0])));
}

//LEA-128 블록길이:16byte / 비밀키길이:16byte / 라운드수:24라운드
void lea_CMAC_op(LEA_CMAC_CTX *ctx, const unsigned char *mk, int mk_len, const unsigned char *data, int data_len, unsigned char *cmac, int cmac_len)
{
	/*Key generation*/
	unsigned char zero[16] = { 0, };
	lea_set_key_generic(&ctx->key, mk, mk_len);//round key생성
	lea_encrypt_op(zero, zero, &ctx->key); //L생성

	/*K1*/
	unsigned int i;
	//if문이 최상위 비트가 1이면 최하위 비트가 1로 바꿔주는것을

	//if (zero[1] & 0x80) ctx->k1[0] |= 1;
	//(ctx->k1[0] ^ ((zero[1] >> 7) & 1));

	ctx->k1[0] = zero[0] << 1;	ctx->k1[0] |= ((zero[1] >> 7) & 1); ctx->k1[1] = zero[1] << 1;	ctx->k1[1] |= ((zero[2] >> 7) & 1);
	ctx->k1[2] = zero[2] << 1;	ctx->k1[2] |= ((zero[3] >> 7) & 1); ctx->k1[3] = zero[3] << 1;	ctx->k1[3] |= ((zero[4] >> 7) & 1);
	ctx->k1[4] = zero[4] << 1;	ctx->k1[4] |= ((zero[5] >> 7) & 1); ctx->k1[5] = zero[5] << 1;	ctx->k1[5] |= ((zero[6] >> 7) & 1);
	ctx->k1[6] = zero[6] << 1;	ctx->k1[6] |= ((zero[7] >> 7) & 1); ctx->k1[7] = zero[7] << 1;	ctx->k1[7] |= ((zero[8] >> 7) & 1);
	ctx->k1[8] = zero[8] << 1;  ctx->k1[8] |= ((zero[9] >> 7) & 1); ctx->k1[9] = zero[9] << 1;	ctx->k1[9] |= ((zero[10] >> 7) & 1);
	ctx->k1[10] = zero[10] << 1;  ctx->k1[10] |= ((zero[11] >> 7) & 1); ctx->k1[11] = zero[11] << 1; ctx->k1[11] |= ((zero[12] >> 7) & 1);
	ctx->k1[12] = zero[12] << 1;  ctx->k1[12] |= ((zero[13] >> 7) & 1); ctx->k1[13] = zero[13] << 1; ctx->k1[13] |= ((zero[14] >> 7) & 1);
	ctx->k1[14] = zero[14] << 1;  ctx->k1[14] |= ((zero[15] >> 7) & 1); ctx->k1[15] = zero[15] << 1;

	if (zero[0] & 0x80)
		ctx->k1[15] ^= 0x87;

	/*K2*/
	ctx->k2[0] = ctx->k1[0] << 1; ctx->k2[0] |= ((ctx->k1[1] >> 7) & 1); ctx->k2[1] = ctx->k1[1] << 1;	ctx->k2[1] |= ((ctx->k1[2] >> 7) & 1);
	ctx->k2[2] = ctx->k1[2] << 1;	 ctx->k2[2] |= ((ctx->k1[3] >> 7) & 1); ctx->k2[3] = ctx->k1[3] << 1;	 ctx->k2[3] |= ((ctx->k1[4] >> 7) & 1);
	ctx->k2[4] = ctx->k1[4] << 1;	 ctx->k2[4] |= ((ctx->k1[5] >> 7) & 1); ctx->k2[5] = ctx->k1[5] << 1;	 ctx->k2[5] |= ((ctx->k1[6] >> 7) & 1);
	ctx->k2[6] = ctx->k1[6] << 1;	 ctx->k2[6] |= ((ctx->k1[7] >> 7) & 1); ctx->k2[7] = ctx->k1[7] << 1;	 ctx->k2[7] |= ((ctx->k1[8] >> 7) & 1);
	ctx->k2[8] = ctx->k1[8] << 1;	 ctx->k2[8] |= ((ctx->k1[9] >> 7) & 1); ctx->k2[9] = ctx->k1[9] << 1;	 ctx->k2[9] |= ((ctx->k1[10] >> 7) & 1);
	ctx->k2[10] = ctx->k1[10] << 1;  ctx->k2[10] |= ((ctx->k1[11] >> 7) & 1); ctx->k2[11] = ctx->k1[11] << 1;  ctx->k2[11] |= ((ctx->k1[12] >> 7) & 1);
	ctx->k2[12] = ctx->k1[12] << 1;  ctx->k2[12] |= ((ctx->k1[13] >> 7) & 1); ctx->k2[13] = ctx->k1[13] << 1;  ctx->k2[13] |= ((ctx->k1[14] >> 7) & 1);
	ctx->k2[14] = ctx->k1[14] << 1;  ctx->k2[14] |= ((ctx->k1[15] >> 7) & 1); ctx->k2[15] = ctx->k1[15] << 1;

	if (ctx->k1[0] & 0x80)
		ctx->k2[15] ^= 0x87;

	/*Init*/
	ctx->tbl[0] = 0; ctx->tbl[1] = 0; ctx->tbl[2] = 0; ctx->tbl[3] = 0;	ctx->tbl[4] = 0; ctx->tbl[5] = 0; ctx->tbl[6] = 0; ctx->tbl[7] = 0;
	ctx->tbl[8] = 0; ctx->tbl[9] = 0; ctx->tbl[10] = 0; ctx->tbl[11] = 0; ctx->tbl[12] = 0; ctx->tbl[13] = 0; ctx->tbl[14] = 0; ctx->tbl[15] = 0;

	ctx->last_block[0] = 0; ctx->last_block[1] = 0; ctx->last_block[2] = 0; ctx->last_block[3] = 0;
	ctx->last_block[4] = 0; ctx->last_block[5] = 0; ctx->last_block[6] = 0; ctx->last_block[7] = 0;
	ctx->last_block[8] = 0; ctx->last_block[9] = 0; ctx->last_block[10] = 0; ctx->last_block[11] = 0;
	ctx->last_block[12] = 0; ctx->last_block[13] = 0; ctx->last_block[14] = 0; ctx->last_block[15] = 0;

	ctx->nlast_block = 0;

	/*Update*/
	int block_size = 16;

	if (ctx->nlast_block) //ctx->nlast_block = size of lastblock
	{
		if (data_len < 16) //16byte = 128bit 데이터 크기가 128bit보다 작으면...
			block_size = data_len; //암호화 블록사이즈를 데이터크기로..

		memcpy(ctx->last_block + ctx->nlast_block, data, block_size);

		data_len = data_len - block_size;
		data = data + block_size;
		ctx->nlast_block = ctx->nlast_block + block_size;

		//XOR8x16(ctx->tbl, ctx->tbl, ctx->last_block);
		ctx->tbl[0] = ctx->tbl[0] ^ ctx->last_block[0]; ctx->tbl[1] = ctx->tbl[1] ^ ctx->last_block[1]; 
		ctx->tbl[2] = ctx->tbl[2] ^ ctx->last_block[2]; ctx->tbl[3] = ctx->tbl[3] ^ ctx->last_block[3];
		ctx->tbl[4] = ctx->tbl[4] ^ ctx->last_block[4]; ctx->tbl[5] = ctx->tbl[5] ^ ctx->last_block[5];
		ctx->tbl[6] = ctx->tbl[6] ^ ctx->last_block[6]; ctx->tbl[7] = ctx->tbl[7] ^ ctx->last_block[7];
		ctx->tbl[8] = ctx->tbl[8] ^ ctx->last_block[8]; ctx->tbl[9] = ctx->tbl[9] ^ ctx->last_block[9];
		ctx->tbl[10] = ctx->tbl[10] ^ ctx->last_block[10]; ctx->tbl[11] = ctx->tbl[11] ^ ctx->last_block[11];
		ctx->tbl[12] = ctx->tbl[12] ^ ctx->last_block[12]; ctx->tbl[13] = ctx->tbl[13] ^ ctx->last_block[13];
		ctx->tbl[14] = ctx->tbl[14] ^ ctx->last_block[14]; ctx->tbl[15] = ctx->tbl[15] ^ ctx->last_block[15];

		lea_encrypt_op(ctx->tbl, ctx->tbl, &ctx->key);

	}

	/*128bit 단위로 lea암호화*/
	while(data_len > 16)
	{
		//XOR8x16(ctx->tbl, ctx->tbl, data);
		ctx->tbl[0] = ctx->tbl[0] ^ data[0]; ctx->tbl[1] = ctx->tbl[1] ^ data[1];
		ctx->tbl[2] = ctx->tbl[2] ^ data[2]; ctx->tbl[3] = ctx->tbl[3] ^ data[3];
		ctx->tbl[4] = ctx->tbl[4] ^ data[4]; ctx->tbl[5] = ctx->tbl[5] ^ data[5];
		ctx->tbl[6] = ctx->tbl[6] ^ data[6]; ctx->tbl[7] = ctx->tbl[7] ^ data[7];
		ctx->tbl[8] = ctx->tbl[8] ^ data[8]; ctx->tbl[9] = ctx->tbl[9] ^ data[9];
		ctx->tbl[10] = ctx->tbl[10] ^ data[10]; ctx->tbl[11] = ctx->tbl[11] ^ data[11];
		ctx->tbl[12] = ctx->tbl[12] ^ data[12]; ctx->tbl[13] = ctx->tbl[13] ^ data[13];
		ctx->tbl[14] = ctx->tbl[14] ^ data[14]; ctx->tbl[15] = ctx->tbl[15] ^ data[15];

		lea_encrypt_op(ctx->tbl, ctx->tbl, &ctx->key);
		data_len -= 0x10;
		data += 0x10;
	}

	memcpy(ctx->last_block, data, data_len);
	ctx->nlast_block = data_len;

	/*Final*/
	if (ctx->nlast_block != 16) //마지막 블록크기가 128bit가 아니면 padding이 필요
	{
		ctx->last_block[ctx->nlast_block] = 0x80;
		memset(ctx->last_block + ctx->nlast_block + 1, 0, 15 - ctx->nlast_block);

		for (ctx->nlast_block; ctx->nlast_block >= 0; ctx->nlast_block--)
			ctx->tbl[ctx->nlast_block] ^= ctx->last_block[ctx->nlast_block];

		//XOR8x16(ctx->tbl, ctx->tbl, ctx->k2);
		ctx->tbl[0] = ctx->tbl[0] ^ ctx->k2[0]; ctx->tbl[1] = ctx->tbl[1] ^ ctx->k2[1];
		ctx->tbl[2] = ctx->tbl[2] ^ ctx->k2[2]; ctx->tbl[3] = ctx->tbl[3] ^ ctx->k2[3];
		ctx->tbl[4] = ctx->tbl[4] ^ ctx->k2[4]; ctx->tbl[5] = ctx->tbl[5] ^ ctx->k2[5];
		ctx->tbl[6] = ctx->tbl[6] ^ ctx->k2[6]; ctx->tbl[7] = ctx->tbl[7] ^ ctx->k2[7];
		ctx->tbl[8] = ctx->tbl[8] ^ ctx->k2[8]; ctx->tbl[9] = ctx->tbl[9] ^ ctx->k2[9];
		ctx->tbl[10] = ctx->tbl[10] ^ ctx->k2[10]; ctx->tbl[11] = ctx->tbl[11] ^ ctx->k2[11];
		ctx->tbl[12] = ctx->tbl[12] ^ ctx->k2[12]; ctx->tbl[13] = ctx->tbl[13] ^ ctx->k2[13];
		ctx->tbl[14] = ctx->tbl[14] ^ ctx->k2[14]; ctx->tbl[15] = ctx->tbl[15] ^ ctx->k2[15];
	}
	else //마지막 블록크기가 128bit이면
	{
		//XOR8x16(ctx->tbl, ctx->tbl, ctx->last_block);
		ctx->tbl[0] = ctx->tbl[0] ^ ctx->last_block[0]; ctx->tbl[1] = ctx->tbl[1] ^ ctx->last_block[1];
		ctx->tbl[2] = ctx->tbl[2] ^ ctx->last_block[2]; ctx->tbl[3] = ctx->tbl[3] ^ ctx->last_block[3];
		ctx->tbl[4] = ctx->tbl[4] ^ ctx->last_block[4]; ctx->tbl[5] = ctx->tbl[5] ^ ctx->last_block[5];
		ctx->tbl[6] = ctx->tbl[6] ^ ctx->last_block[6]; ctx->tbl[7] = ctx->tbl[7] ^ ctx->last_block[7];
		ctx->tbl[8] = ctx->tbl[8] ^ ctx->last_block[8]; ctx->tbl[9] = ctx->tbl[9] ^ ctx->last_block[9];
		ctx->tbl[10] = ctx->tbl[10] ^ ctx->last_block[10]; ctx->tbl[11] = ctx->tbl[11] ^ ctx->last_block[11];
		ctx->tbl[12] = ctx->tbl[12] ^ ctx->last_block[12]; ctx->tbl[13] = ctx->tbl[13] ^ ctx->last_block[13];
		ctx->tbl[14] = ctx->tbl[14] ^ ctx->last_block[14]; ctx->tbl[15] = ctx->tbl[15] ^ ctx->last_block[15];
		//XOR8x16(ctx->tbl, ctx->tbl, ctx->k1);
		ctx->tbl[0] = ctx->tbl[0] ^ ctx->k1[0]; ctx->tbl[1] = ctx->tbl[1] ^ ctx->k1[1];
		ctx->tbl[2] = ctx->tbl[2] ^ ctx->k1[2]; ctx->tbl[3] = ctx->tbl[3] ^ ctx->k1[3];
		ctx->tbl[4] = ctx->tbl[4] ^ ctx->k1[4]; ctx->tbl[5] = ctx->tbl[5] ^ ctx->k1[5];
		ctx->tbl[6] = ctx->tbl[6] ^ ctx->k1[6]; ctx->tbl[7] = ctx->tbl[7] ^ ctx->k1[7];
		ctx->tbl[8] = ctx->tbl[8] ^ ctx->k1[8]; ctx->tbl[9] = ctx->tbl[9] ^ ctx->k1[9];
		ctx->tbl[10] = ctx->tbl[10] ^ ctx->k1[10]; ctx->tbl[11] = ctx->tbl[11] ^ ctx->k1[11];
		ctx->tbl[12] = ctx->tbl[12] ^ ctx->k1[12]; ctx->tbl[13] = ctx->tbl[13] ^ ctx->k1[13];
		ctx->tbl[14] = ctx->tbl[14] ^ ctx->k1[14]; ctx->tbl[15] = ctx->tbl[15] ^ ctx->k1[15];
	}

	lea_encrypt_op(ctx->tbl, ctx->tbl, &ctx->key);

	for (cmac_len--; cmac_len >= 0; cmac_len--)
		cmac[cmac_len] = ctx->tbl[cmac_len];

}


void CMAC_Enc_op(unsigned char* Msg, unsigned int Msg_len, unsigned char* Key, unsigned int Key_len, unsigned int Tlen, unsigned char* Tag)
{
	LEA_CMAC_CTX ctx;
	lea_CMAC_op(&ctx, Key, Key_len, Msg, Msg_len, Tag, 16); //k1, k2, key생성

}