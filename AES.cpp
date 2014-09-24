#ifndef AES_CPP
#define AES_CPP
#include "AES.h"

void ByteSplit(mpz_class& Number, mat4& Matrix);
void ByteSplit(mpz_class& Number, mat4 Matrices[2]);

string AES::Encrypt(mpz_class Key, string Msg, mpz_class& GMPIV)
{
	mat4 State = mat4((unsigned char)0);			//4x4 Matrix to go from original to cipher text
	mat4 CipherKey[2] = {mat4((unsigned char)0)};	//2 4x4 Matrices to hold parts 1 & 2 of the 256 bit key
	string CipherText = "";
	
	ByteSplit(Key, CipherKey);
	
	mat4 IV = mat4(0);
	ByteSplit(GMPIV, IV);
	
	mat4* Keys = new mat4[15];		//Will hold all 14 round keys and the initial (at pos 0)
	Keys[0] = CipherKey[0];
	Keys[1] = CipherKey[1];

	for(int i = 2; i < 15; i++)
		Keys[i] = NextRound(Keys, i);
	
	unsigned char Pad = 16 - (Msg.length() % 16);
	for(unsigned char i = 0; i < Pad; i++)
		Msg.push_back(Pad);
	
	for(unsigned int i = 0; (i * 16) < Msg.length(); i++)		//For every 16 chars, fill the state matrix again.
	{
		for(int col = 0; col < 4; col++)
			for(int row = 0; row < 4; row++)
				State.p[col][row] = (unsigned char)Msg[(i * 16) + (4*col) + row];	//i * 16 controls which block we're on, the rest moves through the block
		
		State.AddRoundKey(IV);	//This adds more randomness to strings with repeating blocks
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
				CipherText.push_back(State.p[col][row]);
		
		IV = State;
	}
	delete[] Keys;
	return CipherText;
}

//The same as encrypt but in reverse...
string AES::Decrypt(mpz_class Key, string Cipher, mpz_class& GMPIV)
{
	mat4 State = mat4((unsigned char)0);
	mat4 CipherKey[2] = {mat4((unsigned char)0)};
	string PlainText = "";
	
	ByteSplit(Key, CipherKey);
	
	mat4 IV = mat4(0);
	ByteSplit(GMPIV, IV);
	mat4 NextIV = mat4(0);
	
	mat4* Keys = new mat4[15];
	Keys[0] = CipherKey[0];
	Keys[1] = CipherKey[1];
	for(int i = 2; i < 15; i++)
		Keys[i] = NextRound(Keys, i);
	
	for(unsigned int i = 0; (i * 16) < Cipher.length(); i++)
	{
		for(int col = 0; col < 4; col++)
			for(int row = 0; row < 4; row++)
				State.p[col][row] = (unsigned char)Cipher[(i * 16) + (4*col) + row];
		
		NextIV = State;
		State.AddRoundKey(Keys[14]);
		State.RevShiftRows();
		State.RevSubBytes(); 
		
		for(int i = 13; i > 0; i--) { 
			State.AddRoundKey(Keys[i]);
			State.RevMixColumns();
			State.RevShiftRows();
			State.RevSubBytes(); 
		}
		State.AddRoundKey(Keys[0]);
		State.AddRoundKey(IV);
		
		for(int col = 0; col < 4; col++)
		{
			for(int row = 0; row < 4; row++)
			{
				PlainText.push_back(State.p[col][row]);
			}
		}

		IV = NextIV;
	}
	int len = PlainText.length();
	unsigned int NBytes = (unsigned char)PlainText[len-1];
	bool BadPad = false;
	
	if(NBytes > 16 || NBytes == 0)
		BadPad = true;
	for(int i = 0; i < NBytes && !BadPad; i++)		//Time to do a simple integrity check
	{
		if(PlainText[len-1 - i] != NBytes)
			BadPad = true;
	}
	if(BadPad == true)
	{
		throw string("Not proper PKCS7 padding");
		return string("");
	}
	
	PlainText.resize(len - NBytes);
	delete[] Keys;
	return PlainText;
}

void ByteSplit(mpz_class& Number, mat4& Matrix)
{
	mpz_class Temp;
	mpz_class byteSplitter(255);
	for(int i = 0; i < 16; i++)			//An overly complex-looking loop that just splits the 128 bit key into 16 bytes. Places each byte into 4x4 Matrix
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
	for(int i = 0; i < 32; i++)			//An overly complex-looking loop that just splits the 256 bit key into 2 16 byte 4x4 Matricies
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
