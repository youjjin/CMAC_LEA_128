#define _CRT_SECURE_NO_WARNINGS
#include "CMAC_LEA_128.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>


static const unsigned int delta[8][36] = {
	{0xc3efe9db, 0x87dfd3b7, 0x0fbfa76f, 0x1f7f4ede, 0x3efe9dbc, 0x7dfd3b78, 0xfbfa76f0, 0xf7f4ede1,
	0xefe9dbc3, 0xdfd3b787, 0xbfa76f0f, 0x7f4ede1f, 0xfe9dbc3e, 0xfd3b787d, 0xfa76f0fb, 0xf4ede1f7,
	0xe9dbc3ef, 0xd3b787df, 0xa76f0fbf, 0x4ede1f7f, 0x9dbc3efe, 0x3b787dfd, 0x76f0fbfa, 0xede1f7f4,
	0xdbc3efe9, 0xb787dfd3, 0x6f0fbfa7, 0xde1f7f4e, 0xbc3efe9d, 0x787dfd3b, 0xf0fbfa76, 0xe1f7f4eD,
	0xc3efe9db,	0x87dfd3b7, 0x0fbfa76f, 0x1f7f4ede},
	{0x44626b02, 0x88c4d604, 0x1189ac09, 0x23135812, 0x4626b024, 0x8c4d6048, 0x189ac091, 0x31358122,
	0x626b0244, 0xc4d60488, 0x89ac0911, 0x13581223, 0x26b02446, 0x4d60488c, 0x9ac09118, 0x35812231,
	0x6b024462, 0xd60488c4, 0xac091189, 0x58122313, 0xb0244626, 0x60488c4d, 0xc091189a, 0x81223135,
	0x0244626b, 0x0488c4d6, 0x091189ac, 0x12231358, 0x244626b0, 0x488c4d60, 0x91189ac0, 0x22313581,
	0x44626b02, 0x88c4d604, 0x1189ac09, 0x23135812},
	{0x79e27c8a, 0xf3c4f914, 0xe789f229, 0xcf13e453, 0x9e27c8a7, 0x3c4f914f, 0x789f229e, 0xf13e453c,
	0xe27c8a79, 0xc4f914f3, 0x89f229e7, 0x13e453cf, 0x27c8a79e, 0x4f914f3c, 0x9f229e78, 0x3e453cf1,
	0x7c8a79e2, 0xf914f3c4, 0xf229e789, 0xe453cf13, 0xc8a79e27, 0x914f3c4f, 0x229e789f, 0x453cf13e,
	0x8a79e27c, 0x14f3c4f9, 0x29e789f2, 0x53cf13e4, 0xa79e27c8, 0x4f3c4f91, 0x9e789f22, 0x3cf13e45,
	0x79e27c8a, 0xf3c4f914, 0xe789f229, 0xcf13e453},
	{0x78df30ec, 0xf1be61d8, 0xe37cc3b1, 0xc6f98763, 0x8df30ec7, 0x1be61d8f, 0x37cc3b1e, 0x6f98763c,
	0xdf30ec78, 0xbe61d8f1, 0x7cc3b1e3, 0xf98763c6, 0xf30ec78d, 0xe61d8f1b, 0xcc3b1e37, 0x98763c6f,
	0x30ec78df, 0x61d8f1be, 0xc3b1e37c, 0x8763c6f9, 0x0ec78df3, 0x1d8f1be6, 0x3b1e37cc, 0x763c6f98,
	0xec78df30, 0xd8f1be61, 0xb1e37cc3, 0x63c6f987, 0xc78df30e, 0x8f1be61d, 0x1e37cc3b, 0x3c6f9876,
	0x78df30ec,	0xf1be61d8, 0xe37cc3b1, 0xc6f98763},
	{0x715ea49e, 0xe2bd493c, 0xc57a9279, 0x8af524f3, 0x15ea49e7, 0x2bd493ce, 0x57a9279c, 0xaf524f38,
	0x5ea49e71, 0xbd493ce2, 0x7a9279c5, 0xf524f38a, 0xea49e715, 0xd493ce2b, 0xa9279c57, 0x524f38af,
	0xa49e715e, 0x493ce2bd, 0x9279c57a, 0x24f38af5, 0x49e715ea, 0x93ce2bd4, 0x279c57a9, 0x4f38af52,
	0x9e715ea4, 0x3ce2bd49, 0x79c57a92, 0xf38af524, 0xe715ea49, 0xce2bd493, 0x9c57a927, 0x38af524f,
	0x715ea49e,	0xe2bd493c, 0xc57a9279, 0x8af524f3},
	{0xc785da0a, 0x8f0bb415, 0x1e17682b, 0x3c2ed056, 0x785da0ac, 0xf0bb4158, 0xe17682b1, 0xc2ed0563,
	0x85da0ac7, 0x0bb4158f, 0x17682b1e, 0x2ed0563c, 0x5da0ac78, 0xbb4158f0, 0x7682b1e1, 0xed0563c2,
	0xda0ac785, 0xb4158f0b, 0x682b1e17, 0xd0563c2e, 0xa0ac785d, 0x4158f0bb, 0x82b1e176, 0x0563c2ed,
	0x0ac785da, 0x158f0bb4, 0x2b1e1768, 0x563c2ed0, 0xac785da0, 0x58f0bb41, 0xb1e17682, 0x63c2ed05,
	0xc785da0a, 0x8f0bb415, 0x1e17682b, 0x3c2ed056},
	{0xe04ef22a, 0xc09de455, 0x813bc8ab, 0x02779157, 0x04ef22ae, 0x09de455c, 0x13bc8ab8, 0x27791570,
	0x4ef22ae0, 0x9de455c0, 0x3bc8ab81, 0x77915702, 0xef22ae04, 0xde455c09, 0xbc8ab813, 0x79157027,
	0xf22ae04e, 0xe455c09d, 0xc8ab813b, 0x91570277, 0x22ae04ef, 0x455c09de, 0x8ab813bc, 0x15702779,
	0x2ae04ef2, 0x55c09de4, 0xab813bc8, 0x57027791, 0xae04ef22, 0x5c09de45, 0xb813bc8a, 0x70277915,
	0xe04ef22a,	0xc09de455, 0x813bc8ab, 0x02779157},
	{0xe5c40957, 0xcb8812af, 0x9710255f, 0x2e204abf, 0x5c40957e, 0xb8812afc, 0x710255f9, 0xe204abf2,
	0xc40957e5, 0x8812afcb, 0x10255f97, 0x204abf2e, 0x40957e5c, 0x812afcb8, 0x0255f971, 0x04abf2e2,
	0x0957e5c4, 0x12afcb88, 0x255f9710, 0x4abf2e20, 0x957e5c40, 0x2afcb881, 0x55f97102, 0xabf2e204,
	0x57e5c409, 0xafcb8812, 0x5f971025, 0xbf2e204a, 0x7e5c4095, 0xfcb8812a, 0xf9710255, 0xf2e204ab,
	0xe5c40957,	0xcb8812af, 0x9710255f, 0x2e204abf}
};

void lea_set_key_generic(LEA_KEY *key, const unsigned char *mk, unsigned int mk_len)
{
	if (!key)
		return;
	else if (!mk)
		return;

	const unsigned int* _mk = (const unsigned int*)mk;

	key->rk[0] = ROL(loadU32(_mk[0]) + delta[0][0], 1);
	key->rk[6] = ROL(key->rk[0] + delta[1][1], 1);
	key->rk[12] = ROL(key->rk[6] + delta[2][2], 1);
	key->rk[18] = ROL(key->rk[12] + delta[3][3], 1);
	key->rk[24] = ROL(key->rk[18] + delta[0][4], 1);
	key->rk[30] = ROL(key->rk[24] + delta[1][5], 1);
	key->rk[36] = ROL(key->rk[30] + delta[2][6], 1);
	key->rk[42] = ROL(key->rk[36] + delta[3][7], 1);
	key->rk[48] = ROL(key->rk[42] + delta[0][8], 1);
	key->rk[54] = ROL(key->rk[48] + delta[1][9], 1);
	key->rk[60] = ROL(key->rk[54] + delta[2][10], 1);
	key->rk[66] = ROL(key->rk[60] + delta[3][11], 1);
	key->rk[72] = ROL(key->rk[66] + delta[0][12], 1);
	key->rk[78] = ROL(key->rk[72] + delta[1][13], 1);
	key->rk[84] = ROL(key->rk[78] + delta[2][14], 1);
	key->rk[90] = ROL(key->rk[84] + delta[3][15], 1);
	key->rk[96] = ROL(key->rk[90] + delta[0][16], 1);
	key->rk[102] = ROL(key->rk[96] + delta[1][17], 1);
	key->rk[108] = ROL(key->rk[102] + delta[2][18], 1);
	key->rk[114] = ROL(key->rk[108] + delta[3][19], 1);
	key->rk[120] = ROL(key->rk[114] + delta[0][20], 1);
	key->rk[126] = ROL(key->rk[120] + delta[1][21], 1);
	key->rk[132] = ROL(key->rk[126] + delta[2][22], 1);
	key->rk[138] = ROL(key->rk[132] + delta[3][23], 1);

	key->rk[1] = key->rk[3] = key->rk[5] = ROL(loadU32(_mk[1]) + delta[0][1], 3);
	key->rk[7] = key->rk[9] = key->rk[11] = ROL(key->rk[1] + delta[1][2], 3);
	key->rk[13] = key->rk[15] = key->rk[17] = ROL(key->rk[7] + delta[2][3], 3);
	key->rk[19] = key->rk[21] = key->rk[23] = ROL(key->rk[13] + delta[3][4], 3);
	key->rk[25] = key->rk[27] = key->rk[29] = ROL(key->rk[19] + delta[0][5], 3);
	key->rk[31] = key->rk[33] = key->rk[35] = ROL(key->rk[25] + delta[1][6], 3);
	key->rk[37] = key->rk[39] = key->rk[41] = ROL(key->rk[31] + delta[2][7], 3);
	key->rk[43] = key->rk[45] = key->rk[47] = ROL(key->rk[37] + delta[3][8], 3);
	key->rk[49] = key->rk[51] = key->rk[53] = ROL(key->rk[43] + delta[0][9], 3);
	key->rk[55] = key->rk[57] = key->rk[59] = ROL(key->rk[49] + delta[1][10], 3);
	key->rk[61] = key->rk[63] = key->rk[65] = ROL(key->rk[55] + delta[2][11], 3);
	key->rk[67] = key->rk[69] = key->rk[71] = ROL(key->rk[61] + delta[3][12], 3);
	key->rk[73] = key->rk[75] = key->rk[77] = ROL(key->rk[67] + delta[0][13], 3);
	key->rk[79] = key->rk[81] = key->rk[83] = ROL(key->rk[73] + delta[1][14], 3);
	key->rk[85] = key->rk[87] = key->rk[89] = ROL(key->rk[79] + delta[2][15], 3);
	key->rk[91] = key->rk[93] = key->rk[95] = ROL(key->rk[85] + delta[3][16], 3);
	key->rk[97] = key->rk[99] = key->rk[101] = ROL(key->rk[91] + delta[0][17], 3);
	key->rk[103] = key->rk[105] = key->rk[107] = ROL(key->rk[97] + delta[1][18], 3);
	key->rk[109] = key->rk[111] = key->rk[113] = ROL(key->rk[103] + delta[2][19], 3);
	key->rk[115] = key->rk[117] = key->rk[119] = ROL(key->rk[109] + delta[3][20], 3);
	key->rk[121] = key->rk[123] = key->rk[125] = ROL(key->rk[115] + delta[0][21], 3);
	key->rk[127] = key->rk[129] = key->rk[131] = ROL(key->rk[121] + delta[1][22], 3);
	key->rk[133] = key->rk[135] = key->rk[137] = ROL(key->rk[127] + delta[2][23], 3);
	key->rk[139] = key->rk[141] = key->rk[143] = ROL(key->rk[133] + delta[3][24], 3);

	key->rk[2] = ROL(loadU32(_mk[2]) + delta[0][2], 6);
	key->rk[8] = ROL(key->rk[2] + delta[1][3], 6);
	key->rk[14] = ROL(key->rk[8] + delta[2][4], 6);
	key->rk[20] = ROL(key->rk[14] + delta[3][5], 6);
	key->rk[26] = ROL(key->rk[20] + delta[0][6], 6);
	key->rk[32] = ROL(key->rk[26] + delta[1][7], 6);
	key->rk[38] = ROL(key->rk[32] + delta[2][8], 6);
	key->rk[44] = ROL(key->rk[38] + delta[3][9], 6);
	key->rk[50] = ROL(key->rk[44] + delta[0][10], 6);
	key->rk[56] = ROL(key->rk[50] + delta[1][11], 6);
	key->rk[62] = ROL(key->rk[56] + delta[2][12], 6);
	key->rk[68] = ROL(key->rk[62] + delta[3][13], 6);
	key->rk[74] = ROL(key->rk[68] + delta[0][14], 6);
	key->rk[80] = ROL(key->rk[74] + delta[1][15], 6);
	key->rk[86] = ROL(key->rk[80] + delta[2][16], 6);
	key->rk[92] = ROL(key->rk[86] + delta[3][17], 6);
	key->rk[98] = ROL(key->rk[92] + delta[0][18], 6);
	key->rk[104] = ROL(key->rk[98] + delta[1][19], 6);
	key->rk[110] = ROL(key->rk[104] + delta[2][20], 6);
	key->rk[116] = ROL(key->rk[110] + delta[3][21], 6);
	key->rk[122] = ROL(key->rk[116] + delta[0][22], 6);
	key->rk[128] = ROL(key->rk[122] + delta[1][23], 6);
	key->rk[134] = ROL(key->rk[128] + delta[2][24], 6);
	key->rk[140] = ROL(key->rk[134] + delta[3][25], 6);

	key->rk[4] = ROL(loadU32(_mk[3]) + delta[0][3], 11);
	key->rk[10] = ROL(key->rk[4] + delta[1][4], 11);
	key->rk[16] = ROL(key->rk[10] + delta[2][5], 11);
	key->rk[22] = ROL(key->rk[16] + delta[3][6], 11);
	key->rk[28] = ROL(key->rk[22] + delta[0][7], 11);
	key->rk[34] = ROL(key->rk[28] + delta[1][8], 11);
	key->rk[40] = ROL(key->rk[34] + delta[2][9], 11);
	key->rk[46] = ROL(key->rk[40] + delta[3][10], 11);
	key->rk[52] = ROL(key->rk[46] + delta[0][11], 11);
	key->rk[58] = ROL(key->rk[52] + delta[1][12], 11);
	key->rk[64] = ROL(key->rk[58] + delta[2][13], 11);
	key->rk[70] = ROL(key->rk[64] + delta[3][14], 11);
	key->rk[76] = ROL(key->rk[70] + delta[0][15], 11);
	key->rk[82] = ROL(key->rk[76] + delta[1][16], 11);
	key->rk[88] = ROL(key->rk[82] + delta[2][17], 11);
	key->rk[94] = ROL(key->rk[88] + delta[3][18], 11);
	key->rk[100] = ROL(key->rk[94] + delta[0][19], 11);
	key->rk[106] = ROL(key->rk[100] + delta[1][20], 11);
	key->rk[112] = ROL(key->rk[106] + delta[2][21], 11);
	key->rk[118] = ROL(key->rk[112] + delta[3][22], 11);
	key->rk[124] = ROL(key->rk[118] + delta[0][23], 11);
	key->rk[130] = ROL(key->rk[124] + delta[1][24], 11);
	key->rk[136] = ROL(key->rk[130] + delta[2][25], 11);
	key->rk[142] = ROL(key->rk[136] + delta[3][26], 11);

	key->round = (mk_len >> 1) + 16;
}

void lea_encrypt(unsigned char *ct, const unsigned char *pt, const LEA_KEY *key)
{
	unsigned int X0, X1, X2, X3;

	const unsigned int * _pt = (const unsigned int *)pt;
	unsigned int * _ct = (unsigned int*)ct;

	X0 = loadU32(_pt[0]);
	X1 = loadU32(_pt[1]);
	X2 = loadU32(_pt[2]);
	X3 = loadU32(_pt[3]);

	X3 = ROR((X2 ^ key->rk[4]) + (X3 ^ key->rk[5]), 3);
	X2 = ROR((X1 ^ key->rk[2]) + (X2 ^ key->rk[3]), 5);
	X1 = ROL((X0 ^ key->rk[0]) + (X1 ^ key->rk[1]), 9);
	X0 = ROR((X3 ^ key->rk[10]) + (X0 ^ key->rk[11]), 3);
	X3 = ROR((X2 ^ key->rk[8]) + (X3 ^ key->rk[9]), 5);
	X2 = ROL((X1 ^ key->rk[6]) + (X2 ^ key->rk[7]), 9);
	X1 = ROR((X0 ^ key->rk[16]) + (X1 ^ key->rk[17]), 3);
	X0 = ROR((X3 ^ key->rk[14]) + (X0 ^ key->rk[15]), 5);
	X3 = ROL((X2 ^ key->rk[12]) + (X3 ^ key->rk[13]), 9);
	X2 = ROR((X1 ^ key->rk[22]) + (X2 ^ key->rk[23]), 3);
	X1 = ROR((X0 ^ key->rk[20]) + (X1 ^ key->rk[21]), 5);
	X0 = ROL((X3 ^ key->rk[18]) + (X0 ^ key->rk[19]), 9);

	X3 = ROR((X2 ^ key->rk[28]) + (X3 ^ key->rk[29]), 3);
	X2 = ROR((X1 ^ key->rk[26]) + (X2 ^ key->rk[27]), 5);
	X1 = ROL((X0 ^ key->rk[24]) + (X1 ^ key->rk[25]), 9);
	X0 = ROR((X3 ^ key->rk[34]) + (X0 ^ key->rk[35]), 3);
	X3 = ROR((X2 ^ key->rk[32]) + (X3 ^ key->rk[33]), 5);
	X2 = ROL((X1 ^ key->rk[30]) + (X2 ^ key->rk[31]), 9);
	X1 = ROR((X0 ^ key->rk[40]) + (X1 ^ key->rk[41]), 3);
	X0 = ROR((X3 ^ key->rk[38]) + (X0 ^ key->rk[39]), 5);
	X3 = ROL((X2 ^ key->rk[36]) + (X3 ^ key->rk[37]), 9);
	X2 = ROR((X1 ^ key->rk[46]) + (X2 ^ key->rk[47]), 3);
	X1 = ROR((X0 ^ key->rk[44]) + (X1 ^ key->rk[45]), 5);
	X0 = ROL((X3 ^ key->rk[42]) + (X0 ^ key->rk[43]), 9);

	X3 = ROR((X2 ^ key->rk[52]) + (X3 ^ key->rk[53]), 3);
	X2 = ROR((X1 ^ key->rk[50]) + (X2 ^ key->rk[51]), 5);
	X1 = ROL((X0 ^ key->rk[48]) + (X1 ^ key->rk[49]), 9);
	X0 = ROR((X3 ^ key->rk[58]) + (X0 ^ key->rk[59]), 3);
	X3 = ROR((X2 ^ key->rk[56]) + (X3 ^ key->rk[57]), 5);
	X2 = ROL((X1 ^ key->rk[54]) + (X2 ^ key->rk[55]), 9);
	X1 = ROR((X0 ^ key->rk[64]) + (X1 ^ key->rk[65]), 3);
	X0 = ROR((X3 ^ key->rk[62]) + (X0 ^ key->rk[63]), 5);
	X3 = ROL((X2 ^ key->rk[60]) + (X3 ^ key->rk[61]), 9);
	X2 = ROR((X1 ^ key->rk[70]) + (X2 ^ key->rk[71]), 3);
	X1 = ROR((X0 ^ key->rk[68]) + (X1 ^ key->rk[69]), 5);
	X0 = ROL((X3 ^ key->rk[66]) + (X0 ^ key->rk[67]), 9);

	X3 = ROR((X2 ^ key->rk[76]) + (X3 ^ key->rk[77]), 3);
	X2 = ROR((X1 ^ key->rk[74]) + (X2 ^ key->rk[75]), 5);
	X1 = ROL((X0 ^ key->rk[72]) + (X1 ^ key->rk[73]), 9);
	X0 = ROR((X3 ^ key->rk[82]) + (X0 ^ key->rk[83]), 3);
	X3 = ROR((X2 ^ key->rk[80]) + (X3 ^ key->rk[81]), 5);
	X2 = ROL((X1 ^ key->rk[78]) + (X2 ^ key->rk[79]), 9);
	X1 = ROR((X0 ^ key->rk[88]) + (X1 ^ key->rk[89]), 3);
	X0 = ROR((X3 ^ key->rk[86]) + (X0 ^ key->rk[87]), 5);
	X3 = ROL((X2 ^ key->rk[84]) + (X3 ^ key->rk[85]), 9);
	X2 = ROR((X1 ^ key->rk[94]) + (X2 ^ key->rk[95]), 3);
	X1 = ROR((X0 ^ key->rk[92]) + (X1 ^ key->rk[93]), 5);
	X0 = ROL((X3 ^ key->rk[90]) + (X0 ^ key->rk[91]), 9);

	X3 = ROR((X2 ^ key->rk[100]) + (X3 ^ key->rk[101]), 3);
	X2 = ROR((X1 ^ key->rk[98]) + (X2 ^ key->rk[99]), 5);
	X1 = ROL((X0 ^ key->rk[96]) + (X1 ^ key->rk[97]), 9);
	X0 = ROR((X3 ^ key->rk[106]) + (X0 ^ key->rk[107]), 3);
	X3 = ROR((X2 ^ key->rk[104]) + (X3 ^ key->rk[105]), 5);
	X2 = ROL((X1 ^ key->rk[102]) + (X2 ^ key->rk[103]), 9);
	X1 = ROR((X0 ^ key->rk[112]) + (X1 ^ key->rk[113]), 3);
	X0 = ROR((X3 ^ key->rk[110]) + (X0 ^ key->rk[111]), 5);
	X3 = ROL((X2 ^ key->rk[108]) + (X3 ^ key->rk[109]), 9);
	X2 = ROR((X1 ^ key->rk[118]) + (X2 ^ key->rk[119]), 3);
	X1 = ROR((X0 ^ key->rk[116]) + (X1 ^ key->rk[117]), 5);
	X0 = ROL((X3 ^ key->rk[114]) + (X0 ^ key->rk[115]), 9);

	X3 = ROR((X2 ^ key->rk[124]) + (X3 ^ key->rk[125]), 3);
	X2 = ROR((X1 ^ key->rk[122]) + (X2 ^ key->rk[123]), 5);
	X1 = ROL((X0 ^ key->rk[120]) + (X1 ^ key->rk[121]), 9);
	X0 = ROR((X3 ^ key->rk[130]) + (X0 ^ key->rk[131]), 3);
	X3 = ROR((X2 ^ key->rk[128]) + (X3 ^ key->rk[129]), 5);
	X2 = ROL((X1 ^ key->rk[126]) + (X2 ^ key->rk[127]), 9);
	X1 = ROR((X0 ^ key->rk[136]) + (X1 ^ key->rk[137]), 3);
	X0 = ROR((X3 ^ key->rk[134]) + (X0 ^ key->rk[135]), 5);
	X3 = ROL((X2 ^ key->rk[132]) + (X3 ^ key->rk[133]), 9);
	X2 = ROR((X1 ^ key->rk[142]) + (X2 ^ key->rk[143]), 3);
	X1 = ROR((X0 ^ key->rk[140]) + (X1 ^ key->rk[141]), 5);
	X0 = ROL((X3 ^ key->rk[138]) + (X0 ^ key->rk[139]), 9);



	_ct[0] = loadU32(X0);
	_ct[1] = loadU32(X1);
	_ct[2] = loadU32(X2);
	_ct[3] = loadU32(X3);
}