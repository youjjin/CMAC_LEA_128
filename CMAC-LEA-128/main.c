#define _CRT_SECURE_NO_WARNINGS
#include "CMAC_LEA_128.h"
#include <stdio.h>
#include <stdlib.h>

unsigned int cpucycles(void) { return __rdtsc(); }

int main()
{
	unsigned char K[16] = { 0xAD, 0x4F, 0x14, 0xF2, 0x44, 0x40, 0x66, 0xD0, 0x6B, 0xC4, 0x30, 0xB7, 0x32, 0x3B, 0xA1, 0x22 };
	unsigned char Msg[6] = { 0xF6, 0x22, 0x91, 0x9D, 0xE1, 0x8B };
	//	T = F784337ED2D1DF594FCFEC5B2DBFF58D
	unsigned char T[16] = { 0, };
	LEA_KEY key;
	key.round = 24;
	lea_set_key_generic(&key, K, 128);

	int i = 0;
	for (int i = 1; i < 145; i++)
	{
		printf("%02X ", key.rk[i]);
		if (i % 4 == 0)
			printf("\n");
	}


	//HMAC_Gen_Test();
	//HMAC_Ver_Test();

	//int i;
	//unsigned long long cycles = 0, cycles1, cycles2;
	//unsigned int loop = 10000;
	////printf("Before Optimization\n");
	//printf("After Optimization\n");
	////for loop에 들어가는 것까지 안새주려고 시간을 포루프 안에서 돌려줄것이다.
	//for (i = 0; i < loop; i++)
	//{
	//	cycles1 = cpucycles();
	//	//CMAC_Enc(Msg, 6, K, 16, 16, T);
	//	CMAC_Enc_op(Msg, 6, K, 16, 16, T);
	//	cycles2 = cpucycles();
	//	cycles += (cycles2 - cycles1);
	//}

	//printf("\n[loop = %d]cycles : %10lld\n", loop, cycles / loop);
	//cycles = 0;

	//printf("TAG = ");
	//for (i = 0; i < 16; i++)
	//	printf("%02X ", T[i]);
	//printf("\n");

	return 0;
}