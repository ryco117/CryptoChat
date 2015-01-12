#ifndef AES_CPP
#define AES_CPP
#include "AES.h"

#ifndef ANDROID
extern "C"
{
	bool AESNI();
	void EncryptNI(const char* Text, unsigned int size, char* IV, char* Key, char* Buffer);
	int DecryptNI(const char* Cipher, unsigned int size, char* IV, char* Key, char* Buffer);
}
#endif

void ByteSplit(mpz_class& Number, mat4& Matrix);
void ByteSplit(mpz_class& Number, mat4 Matrices[2]);

void AES::Encrypt(const char* Msg, unsigned int MsgLen, mpz_class& GMPIV, mpz_class& Key, char* CipherText)
{
	#ifndef ANDROID
	if(AESNI())
	{
		size_t Size;
		char* KeyP = new char[32];
		char* IV = new char[16];
		mpz_export(KeyP, &Size, 1, 32, 1, 0, Key.get_mpz_t());
		mpz_export(IV, &Size, 1, 16, 1, 0, GMPIV.get_mpz_t());
		
		EncryptNI(Msg, MsgLen, IV, KeyP, CipherText);
		memset(KeyP, 0, 32);
		delete[] KeyP;
		memset(IV, 0, 16);
		delete[] IV;
		return;
	}
	#endif
	
	mat4 State = mat4((unsigned char)0);											//4x4 Matrix to go from original to cipher text
	mat4 CipherKey[2] = {mat4((unsigned char)0)};									//2 4x4 Matrices to hold parts 1 & 2 of the 256 bit key
	
	ByteSplit(Key, CipherKey);
	
	mat4 IV = mat4(0);
	ByteSplit(GMPIV, IV);
	
	mat4* Keys = new mat4[15];														//Will hold all 14 round keys and the initial (at pos 0)
	Keys[0] = CipherKey[0];
	Keys[1] = CipherKey[1];

	for(int i = 2; i < 15; i++)
		Keys[i] = NextRound(Keys, i);
	
	unsigned char Pad = 16 - (MsgLen % 16);
	char PaddedBlock[16];
	memcpy(PaddedBlock, &Msg[MsgLen + Pad - 16], 16 - Pad);
	memset(PaddedBlock + (16 - Pad), Pad, Pad);
	
	for(unsigned int i = 0; (i * 16) <= MsgLen; i++)									//For every 16 chars, fill the state matrix again.
	{
		if((MsgLen + Pad) - (16 * i) > 16)
		{
			for(int col = 0; col < 4; col++)
				for(int row = 0; row < 4; row++)
					State.p[col][row] = (unsigned char)Msg[(i * 16) + (4 * col) + row];	//i * 16 controls which block we're on, the rest moves through the block
		}
		else
		{
			for(int col = 0; col < 4; col++)
				for(int row = 0; row < 4; row++)
					State.p[col][row] = (unsigned char)PaddedBlock[(4 * col) + row];
		}
		
		State.AddRoundKey(IV);														//This adds more randomness to strings with repeating blocks
		State.AddRoundKey(Keys[0]);
		for(int j = 1; j < 14; j++)
		{
			State.SubBytes();
			State.ShiftRows();
			State.MixColumns();
			State.AddRoundKey(Keys[j]);
		}
		
		State.SubBytes();
		State.ShiftRows();
		
		State.AddRoundKey(Keys[14]);
		
		for(int col = 0; col < 4; col++)
			for(int row = 0; row < 4; row++)
				CipherText[(i * 16) + (4 * col) + row] = State.p[col][row];
		
		IV = State;
	}
	CipherKey[0] = 0;
	CipherKey[1] = 0;
	for(int i = 0; i < 15; i++)
		Keys[i] = 0;
	
	delete[] Keys;
	return;
}

//The same as encrypt but in reverse...
int AES::Decrypt(const char* Cipher, unsigned int CipherLen, mpz_class& GMPIV, mpz_class& Key, char* PlainText)
{
	#ifndef ANDROID
	if(AESNI())
	{
		size_t Size;
		char* KeyP = new char[32];
		char* IV = new char[16];
		mpz_export(KeyP, &Size, 1, 1, 1, 0, Key.get_mpz_t());
		mpz_export(IV, &Size, 1, 1, 1, 0, GMPIV.get_mpz_t());
		unsigned int l = DecryptNI(Cipher, CipherLen, IV, KeyP, PlainText);
		memset(KeyP, 0, 32);
		delete[] KeyP;
		memset(IV, 0, 16);
		delete[] IV;
		return l;
	}
	#endif
	
	mat4 State = mat4((unsigned char)0);
	mat4 CipherKey[2] = {mat4((unsigned char)0)};
	
	ByteSplit(Key, CipherKey);
	
	mat4 IV = mat4(0);
	ByteSplit(GMPIV, IV);
	mat4 NextIV = mat4(0);
	
	mat4* Keys = new mat4[15];
	Keys[0] = CipherKey[0];
	Keys[1] = CipherKey[1];
	for(int i = 2; i < 15; i++)
		Keys[i] = NextRound(Keys, i);
	
	for(unsigned int i = 0; (i * 16) < CipherLen; i++)
	{
		for(int col = 0; col < 4; col++)
			for(int row = 0; row < 4; row++)
				State.p[col][row] = (unsigned char)Cipher[(i * 16) + (4 * col) + row];
		
		NextIV = State;
		State.AddRoundKey(Keys[14]);
		State.RevShiftRows();
		State.RevSubBytes(); 
		
		for(int j = 13; j > 0; j--) { 
			State.AddRoundKey(Keys[j]);
			State.RevMixColumns();
			State.RevShiftRows();
			State.RevSubBytes(); 
		}
		State.AddRoundKey(Keys[0]);
		State.AddRoundKey(IV);
		
		for(int col = 0; col < 4; col++)
			for(int row = 0; row < 4; row++)
				PlainText[(i * 16) + (4 * col) + row] = State.p[col][row];

		IV = NextIV;
	}
	CipherKey[0] = 0;
	CipherKey[1] = 0;
	for(int i = 0; i < 15; i++)
		Keys[i] = 0;
	
	int len = CipherLen;
	
	int NBytes = (char)PlainText[len-1];
	bool BadPad = false;
	
	if(NBytes > 16 || NBytes == 0)
		BadPad = true;
	for(int i = 0; i < NBytes && !BadPad; i++)										//Time to do a simple integrity check
	{
		if(PlainText[len-1 - i] != NBytes)
			BadPad = true;
	}
	if(BadPad == true)
	{
		return -1;
	}
	len -= NBytes;
	PlainText[len] = 0;
	
	delete[] Keys;
	return len;
}

void ByteSplit(mpz_class& Number, mat4& Matrix)
{
	mpz_class Temp;
	mpz_class byteSplitter(255);
	for(int i = 0; i < 16; i++)														//An overly complex-looking loop that just splits the 128 bit key into 16 bytes. Places each byte into 4x4 Matrix
	{
		mpz_div_2exp(Temp.get_mpz_t(), Number.get_mpz_t(), (15-i)*8);
		mpz_and(Temp.get_mpz_t(), Temp.get_mpz_t(), byteSplitter.get_mpz_t());
		Matrix.p[i / 4][i % 4] = (unsigned char)mpz_get_ui(Temp.get_mpz_t());
	}
}

void ByteSplit(mpz_class& Number, mat4 Matrices[2])
{
	mpz_class Temp;
	mpz_class byteSplitter(255);
	for(int i = 0; i < 32; i++)														//An overly complex-looking loop that just splits the 256 bit key into 2 16 byte 4x4 Matricies
	{
		mpz_div_2exp(Temp.get_mpz_t(), Number.get_mpz_t(), (31-i)*8);
		mpz_and(Temp.get_mpz_t(), Temp.get_mpz_t(), byteSplitter.get_mpz_t());
		if(i < 16)
			Matrices[0].p[i / 4][i % 4] = (unsigned char)mpz_get_ui(Temp.get_mpz_t());
		else
			Matrices[1].p[(i-16) / 4][(i-16) % 4] = (unsigned char)mpz_get_ui(Temp.get_mpz_t());
	}
}
#endif