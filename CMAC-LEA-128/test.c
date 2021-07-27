#define _CRT_SECURE_NO_WARNINGS
#include "CMAC_LEA_128.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>


void Change_digit(unsigned char* string, unsigned int* len, unsigned int* digit)
{
	char seps[] = "=, ,\t,\n";
	char *tok;

	int i, j;
	unsigned int result = 0, dig = 0;

	tok = strtok(string, seps);

	while (tok != NULL)
	{

		if (strstr(tok, "Tlen") == NULL)
		{
			*len = strlen(tok);
			*digit = atoi(tok);
		}
		tok = strtok(NULL, seps);
	}

}

void Ascii(char* string, unsigned char* stream, int* len)
{

	char seps[] = "=, , \t, \n";
	char *tok;

	unsigned char buf[1025] = { 0, };
	int i = 0, j = 0, cnt = 0, n = 0;
	unsigned char result = 0, six = 0;
	int tmp = 0;
	tok = strtok(string, seps);


	while (tok != NULL)
	{
		if (strstr(tok, "K") == NULL && strstr(tok, "M") == NULL && strstr(tok, "T") == NULL && strstr(tok, "Tlen") == NULL && strstr(tok, "COUNT") == NULL)
		{
			*len = strlen(tok) / 2;

			while (j < strlen(tok))
			{
				result = 0;
				six = 0;

				for (i = j; i < j + 2; i++)
				{
					if (isalpha(tok[i]))
					{
						result = toupper(tok[i]) - 55;
						six = six * 16 + result;
					}
					else
					{
						result = tok[i] - 48;
						six = six * 16 + result;
					}
				}

				buf[n] = six;
				n++;
				j = j + 2;

				tmp = 1;

			}
		}
		tok = strtok(NULL, seps);
	}

	if(tmp == 1)
		memcpy(stream, buf, *len);
	else
	{
		stream = NULL;
		*len = 0;
	}
}

void HMAC_Gen_Test()
{
	FILE *fp_req;
	FILE *fp_fax;
	LEA_CMAC_G list;
	char L_buff[100];
	char Count_buff[100];
	char KLen_buff[1000];
	char TLen_buff[1000];
	char Key_buff[1200];
	char Msg_buff[1200];
	char buf[1000];//Enter

	int i;
	unsigned int* Len_len, Msg_len, KLen_len, TLen_len, Key_len;
	unsigned int* TLen = 0;
	unsigned char Count[100] = { 0, };
	unsigned char Key[1000] = { 0, };
	unsigned char Msg[1000] = { 0, };
	unsigned char Tag[16] = { 0, };

	fp_req = fopen("CMACGenLEA128.req", "r");
	fp_fax = fopen("CMACGenLEA128.rsp", "w");

	if (fp_req == NULL || fp_fax == NULL)
	{
		printf("파일열기 실패\n");
		return;
	}


	while (fgets(Count_buff, sizeof(Count_buff), fp_req) != NULL)
	{
		/****************Count******************/
		printf("%s", Count_buff);
		fputs(Count_buff, fp_fax);
		memset(Count_buff, 0, sizeof(Count_buff));

		/****************Key******************/
		fgets(Key_buff, sizeof(Key_buff), fp_req);
		printf("%s", Key_buff);
		fputs(Key_buff, fp_fax);
		Ascii(Key_buff, Key, &Key_len);
		memset(Key_buff, 0, sizeof(Key_buff));

		/****************Msg******************/
		fgets(Msg_buff, sizeof(Msg_buff), fp_req);
		printf("%s", Msg_buff);
		fputs(Msg_buff, fp_fax);
		Ascii(Msg_buff, Msg, &Msg_len);
		memset(Msg_buff, 0, sizeof(Msg_buff));

		/****************TLen******************/ //=>요놈을 16진수에서 10진수 정수로 바꿔줘야한다는게 문제에유...
		fgets(TLen_buff, sizeof(TLen_buff), fp_req);
		printf("%s", TLen_buff);
		fputs(TLen_buff, fp_fax);
		Change_digit(TLen_buff, &TLen_len, &TLen);
		memset(TLen_buff, 0, sizeof(TLen_buff));

		/*****************Enter***************/
		fgets(buf, sizeof(buf), fp_req);
		memset(buf, 0, sizeof(buf));

		/****************HMAC***************/
		
		CMAC_Enc_op(Msg, Msg_len, Key, Key_len, 16, Tag);

		/*****************TAG***************/
		printf("T = ");
		for (i = 0; i < 16; i++)
		{
			printf("%02X", Tag[i]);
		}
		printf("\n");
		printf("\n");

		//파일에 써주기
		fprintf(fp_fax, "T = ");
		for (i = 0; i < 16; i++)
		{
			fprintf(fp_fax, "%02X", Tag[i]);
		}
		fprintf(fp_fax, "\n");
		fprintf(fp_fax, "\n");
	}
	fclose(fp_req);
	fclose(fp_fax);
}

void HMAC_Ver_Test()
{
	FILE *fp_req;
	FILE *fp_fax;
	LEA_CMAC_G list;
	char L_buff[100];
	char Count_buff[100];
	char KLen_buff[1000];
	char TLen_buff[1000];
	char Key_buff[1200];
	char Msg_buff[1200];
	char T_buff[100];
	char buf[1000];//Enter

	int i;
	unsigned int* Len_len, Msg_len, KLen_len, TLen_len, Key_len, T_len;
	unsigned int* TLen = 0;
	unsigned char Count[100] = { 0, };
	unsigned char Key[1000] = { 0, };
	unsigned char Msg[1000] = { 0, };
	unsigned char T[100] = { 0, };

	unsigned char T_tmp[100] = { 0, };
	unsigned char Tag[16] = { 0, };

	fp_req = fopen("CMACVerLEA128.req", "r");
	fp_fax = fopen("CMACVerLEA128.rsp", "w");

	if (fp_req == NULL || fp_fax == NULL)
	{
		printf("파일열기 실패\n");
		return;
	}


	while (fgets(Count_buff, sizeof(Count_buff), fp_req) != NULL)
	{
		/****************Count******************/
		printf("%s", Count_buff);
		fputs(Count_buff, fp_fax);
		memset(Count_buff, 0, sizeof(Count_buff));

		/****************Key******************/
		fgets(Key_buff, sizeof(Key_buff), fp_req);
		printf("%s", Key_buff);
		fputs(Key_buff, fp_fax);
		Ascii(Key_buff, Key, &Key_len);
		memset(Key_buff, 0, sizeof(Key_buff));

		/****************Msg******************/
		fgets(Msg_buff, sizeof(Msg_buff), fp_req);
		printf("%s", Msg_buff);
		fputs(Msg_buff, fp_fax);
		Ascii(Msg_buff, Msg, &Msg_len);
		memset(Msg_buff, 0, sizeof(Msg_buff));

		/****************TLen******************/ //=>요놈을 16진수에서 10진수 정수로 바꿔줘야한다는게 문제에유...
		fgets(TLen_buff, sizeof(TLen_buff), fp_req);
		printf("%s", TLen_buff);
		fputs(TLen_buff, fp_fax);
		Change_digit(TLen_buff, &TLen_len, &TLen);
		memset(TLen_buff, 0, sizeof(TLen_buff));

		/****************T******************/
		fgets(T_buff, sizeof(T_buff), fp_req);
		printf("%s", T_buff);
		fputs(T_buff, fp_fax);
		Ascii(T_buff, T, &T_len);
		memset(T_buff, 0, sizeof(T_buff));

		/*****************Enter***************/
		fgets(buf, sizeof(buf), fp_req);
		memset(buf, 0, sizeof(buf));

		/****************HMAC***************/

		memcpy(list.key, Key, Key_len);
		memcpy(list.msg, Msg, Msg_len);
		//void CMAC_Enc(LEA_CMAC_CTX *ctx, unsigned char* Msg, unsigned int Msg_len, unsigned char* Key, unsigned int Key_len, unsigned int Tlen, unsigned char* Tag);
		CMAC_Enc(Msg, Msg_len, Key, Key_len, 16, Tag);

		printf("TAG = ");
		for (i = 0; i < 8; i++)
		{
			printf("%02X", Tag[i]);
		}
		printf("\n");
		printf("\n");

		/*****************VALID/INVALID***************/
		int flag = 0;
		for (i = 0; i < 8; i++) //TLen 부분이 잘못된부분
		{
			if (T[i] != Tag[i])
			{
				printf("INVALID");
				fprintf(fp_fax, "INVALID");
				flag = 1;
				break;
			}
		}
		if (flag == 0)
		{
			printf("VALID");
			fprintf(fp_fax, "VALID");
		}
		printf("\n");
		printf("\n");
		fprintf(fp_fax, "\n");
		fprintf(fp_fax, "\n");

	}
	fclose(fp_req);
	fclose(fp_fax);
}