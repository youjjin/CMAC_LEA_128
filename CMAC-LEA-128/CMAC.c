#define _CRT_SECURE_NO_WARNINGS
#include "CMAC_LEA_128.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

static void lea_make_cmac_subkey(unsigned char *new_key, const unsigned char *old_key, unsigned int key_len)
{
	unsigned int i;

	for (i = 0; i < key_len; i++) //key_len = 16
	{
		new_key[i] = old_key[i] << 1;
		if (i < key_len - 1 && old_key[i + 1] & 0x80)
			new_key[i] |= 1; //new_key[i]�� ������ ��Ʈ�� 1�� �������
	}
	
	if (old_key[0] & 0x80)
		new_key[key_len - 1] ^= 0x87; //������ ����
}


//LEA-128 ��ϱ���:16byte / ���Ű����:16byte / �����:24����
void lea_cmac_init(LEA_CMAC_CTX* ctx, const unsigned char *mk, int mk_len)
{
	unsigned char zero[16];

	lea_set_key_generic(&ctx->key, mk, mk_len);//round key����

	memset(zero, 0, 16);
	lea_encrypt(zero, zero, &ctx->key); //L����
	lea_make_cmac_subkey(ctx->k1, zero, 16);//K1����
	lea_make_cmac_subkey(ctx->k2, ctx->k1, 16);//K2����

	memset(ctx->tbl, 0, 16); //tbl = table
	memset(ctx->last_block, 0, 16);

	ctx->nlast_block = 0;
}

void cmac_update(LEA_CMAC_CTX *ctx, const unsigned char *data, int data_len)
{
	int empty;

	if (ctx->nlast_block) //nlast_block = size of lastblock(byte), 0�� �ƴϸ�(������ ����� 128bit���ƴϸ�..) if�� �۵�
	{
		empty = 16 - ctx->nlast_block; //16-0

		if (empty > data_len) //�޼����� ũ�Ⱑ 128bit���� ������
			empty = data_len; //����������� ũ��� 128bit���ȴ�.(16byte) : �е��� ����..
		data_len -= empty;
		data += empty;
		ctx->nlast_block += empty;

		XOR8x16(ctx->tbl, ctx->tbl, ctx->last_block);//table = table ^ ��������� => ���̺��� ����������� ����..
		lea_encrypt(ctx->tbl, ctx->tbl, &ctx->key); //�׸��� ��ȣȭ
	}

	while (data_len > 16)  //���������� ũ�Ⱑ 128bit���� ũ�� 128bit�� ��ȣȭ
	{
		XOR8x16(ctx->tbl, ctx->tbl, data); //�޼����� table�� �ִ´�.
		lea_encrypt(ctx->tbl, ctx->tbl, &ctx->key); //��ȣȭ
		data_len -= 0x10; //128��Ʈ�� ���̰�
		data += 0x10; //128��Ʈ�� �ø���.
	}

	memcpy(ctx->last_block, data, data_len);
	ctx->nlast_block = data_len;
}

void cmac_final(LEA_CMAC_CTX *ctx, unsigned char *cmac, int cmac_len)
{

	if (ctx->nlast_block != 16)
	{
		ctx->last_block[ctx->nlast_block] = 0x80;
		memset(ctx->last_block + ctx->nlast_block + 1, 0, 15 - ctx->nlast_block);

		for (ctx->nlast_block; ctx->nlast_block >= 0; ctx->nlast_block--)
			ctx->tbl[ctx->nlast_block] ^= ctx->last_block[ctx->nlast_block];

		XOR8x16(ctx->tbl, ctx->tbl, ctx->k2);
	}
	else
	{
		XOR8x16(ctx->tbl, ctx->tbl, ctx->last_block);
		XOR8x16(ctx->tbl, ctx->tbl, ctx->k1);
	}

	lea_encrypt(ctx->tbl, ctx->tbl, &ctx->key);

	for (cmac_len--; cmac_len >= 0; cmac_len--)
		cmac[cmac_len] = ctx->tbl[cmac_len];

	ctx->nlast_block = 0;
	memset(ctx->last_block, 0, 16);
	memset(ctx->tbl, 0, 16);
}


void CMAC_Enc(unsigned char* Msg, unsigned int Msg_len, unsigned char* Key, unsigned int Key_len, unsigned int Tlen, unsigned char* Tag)
{
	LEA_CMAC_CTX ctx;
	int i, j;

	lea_cmac_init(&ctx, Key, Key_len); //k1, k2, key����
	cmac_update(&ctx, Msg, Msg_len);
	cmac_final(&ctx, Tag, 16);
}