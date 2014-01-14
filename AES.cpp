#ifndef AES_CPP
#define AES_CPP
#include "AES.h"

string AES::Encrypt(mpz_class Key, string Msg)
{
	mat4 State = mat4((unsigned char)0);		//4x4 Matrix to go from original to cipher text
	mat4 CipherKey = mat4((unsigned char)0);	//4x4 Matrix to hold key
	string CipherText = "";
	
	mpz_class Temp;
	mpz_class byteSplitter(255);
	for(int i = 0; i < 16; i++)			//An overly complex-looking loop that just splits the 128  bit key into 16 bytes. Puts each byte into 4x4 Matrix
	{
		mpz_div_2exp(Temp.get_mpz_t(), Key.get_mpz_t(), (15-i)*8);
		mpz_and(Temp.get_mpz_t(), Temp.get_mpz_t(), byteSplitter.get_mpz_t());
		CipherKey.p[i / 4][i % 4] = (unsigned char)mpz_get_ui(Temp.get_mpz_t());
	}
		
	mat4* Keys = new mat4[11];		//Will hold all the round keys and the initial
	Keys[0] = CipherKey;
	for(int i = 1; i < 11; i++)
		Keys[i] = NextRound(Keys[i-1], i-1);
	
	for(unsigned int i = 0; (i * 16) < Msg.length(); i++)		//For every 16 chars, fill the state matrix again.
	{
		if(((i+1) * 16) > Msg.length() && (Msg.length() % 16) != 0)		//What if there aren't n%16=0 chars? Fill the last matrix with extra zeros!
		{
			for(int j = 0; j < (Msg.length() % 16); j++)
				State.p[j / 4][j % 4] = (unsigned char)Msg[(i * 16) + j];
			
			for(int j = (Msg.length() % 16); j < 16; j++)
				State.p[j / 4][j % 4] = 0;
			State.p[3][3] = 16 - (Msg.length() % 16) - 1;
		}
		else
		{
			for(int col = 0; col < 4; col++)
				for(int row = 0; row < 4; row++)
					State.p[col][row] = (unsigned char)Msg[(i * 16) + (4*col) + row];	//i * 16 controls which block we're on, the rest moves through the block
		}
		
		State.AddRoundKey(Keys[0]);
		for(int j = 0; j < 9; j++)
		{
			State.SubBytes();
			State.ShiftRows();
			State.MixColumns();

			State.AddRoundKey(Keys[j+1]);
		}
		
		State.SubBytes();
		State.ShiftRows();
		
		State.AddRoundKey(Keys[10]);
		
		for(int col = 0; col < 4; col++)
			for(int row = 0; row < 4; row++)
				CipherText += State.p[col][row];
	}
	delete[] Keys;
	return CipherText;
}

//The same as encrypt but in reverse...
string AES::Decrypt(mpz_class Key, string Cipher)
{
	mat4 State = mat4((unsigned char)0);
	mat4 CipherKey = mat4((unsigned char)0);
	string PlainText = "";
	
	mpz_class Temp;
	mpz_class byteSplitter(255);
	for(int i = 0; i < 16; i++)
	{
		mpz_div_2exp(Temp.get_mpz_t(), Key.get_mpz_t(), (15-i)*8);
		mpz_and(Temp.get_mpz_t(), Temp.get_mpz_t(), byteSplitter.get_mpz_t());
		CipherKey.p[i / 4][i % 4] = (unsigned char)mpz_get_ui(Temp.get_mpz_t());
	}
		
	mat4* Keys = new mat4[11];
	Keys[0] = CipherKey;
	for(int i = 1; i < 11; i++)
		Keys[i] = NextRound(Keys[i-1], i-1);

	for(unsigned int i = 0; (i * 16) < Cipher.length(); i++)
	{
		for(int col = 0; col < 4; col++)
			for(int row = 0; row < 4; row++)
				State.p[col][row] = (unsigned char)Cipher[(i * 16) + (4*col) + row];
			
		State.AddRoundKey(Keys[10]);
		State.RevShiftRows();
		State.RevSubBytes(); 
		
		for(int i = 9; i > 0; i--) { 
			State.AddRoundKey(Keys[i]);
			State.RevMixColumns();
			State.RevShiftRows();
			State.RevSubBytes(); 
		}
		State.AddRoundKey(Keys[0]);
		
		unsigned char zeros = 0;
		for(int col = 0; col < 4; col++)
		{
			for(int row = 0; row < 4; row++)
			{
				if(State.p[col][row] != 0)
					PlainText += State.p[col][row];
				else
					zeros++;
			}
		}
		if((unsigned char)PlainText[PlainText.length() - 1] == zeros)
			PlainText[PlainText.length() -1] = '\0';
	}
	delete[] Keys;
	return PlainText;
}
#endif