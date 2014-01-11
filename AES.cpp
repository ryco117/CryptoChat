#include "AES.h"

string AES::Encrypt(mpz_class Key, string Msg)
{
	mat4 State = mat4((unsigned char)0);
	mat4 CipherKey = mat4((unsigned char)0);
	string CipherText = "";
	
	mpz_class Temp;
	mpz_class byteSplitter(255);
	for(int i = 0; i < 16; i++)
	{
		//CipherKey.p[i / 4][i % 4] = (unsigned char)((Key >> ((15-i)*8)) & 255);
		mpz_div_2exp(Temp.get_mpz_t(), Key.get_mpz_t(), (15-i)*8);
		mpz_and(Temp.get_mpz_t(), Temp.get_mpz_t(), byteSplitter.get_mpz_t());
		CipherKey.p[i / 4][i % 4] = (unsigned char)mpz_get_ui(Temp.get_mpz_t());
	}
		
	mat4* Keys = new mat4[11];
	Keys[0] = CipherKey;
	for(int i = 1; i < 11; i++)
		Keys[i] = NextRound(Keys[i-1], i-1);
	
	for(unsigned int i = 0; (i * 16) < Msg.length(); i++)
	{
		if(((i+1) * 16) > Msg.length() && (Msg.length() % 16) != 0)
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

string AES::Decrypt(mpz_class Key, string Cipher)
{
	mat4 State = mat4((unsigned char)0);
	mat4 CipherKey = mat4((unsigned char)0);
	string PlainText = "";
	
	mpz_class Temp;
	mpz_class byteSplitter(255);
	for(int i = 0; i < 16; i++)
	{
		//CipherKey.p[i / 4][i % 4] = (unsigned char)((Key >> ((15-i)*8)) & 255);
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
