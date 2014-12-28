#ifndef KEYMANAGER
#define KEYMANAGER
#include <iostream>
#include <string>
#include <sstream>
#include <gmpxx.h>
extern "C"
{
	#include <libscrypt.h>
}

#include "AES.cpp"
#include "base64.h"

/* ---------------------- Fully implementing Curve25519 keys! -------------------------- */
bool LoadCurvePublicKey(string FileLoc, uint8_t Point[32])
{
	fstream File(FileLoc.c_str(), ios::in);
	if(File.is_open())
	{
		string Line;
		getline(File, Line);
		if(Line != "crypto-key-ecc")		//Check for proper format
		{
			cout << "This key was not saved in a recognized format.\n";
			return false;
		}
		File.read((char*)Point, 32);
		File.close();
	}
	else
	{
		cout << "Error: Couldn't open " << FileLoc << endl;
		return false;
	}
	return true;
}

bool LoadCurvePrivateKey(string FileLoc, uint8_t Key[32], const char* Passwd)
{
	fstream File(FileLoc.c_str(), ios::in);
	if(File.is_open())
	{
		char Salt64[25] = {0};
		char IVStr[25] = {0};
		mpz_class IV = 0;
		char Hash[32] = {0};
		mpz_class FinalKey = 0;

		unsigned int FileLength = 0;
		File.seekg(0, File.end);
		FileLength = File.tellg();
		File.seekg(0, File.beg);
		
		if(strlen(Passwd))
		{
			File.read(Salt64, 24);
			File.read(IVStr, 24);
			char* Salt;
			int SaltLen;								//Should equal 16
			try
			{
				Salt = Base64Decode(Salt64, SaltLen);
				Import64(IVStr, IV);
			}
			catch(int e)
			{
				cout << "Error: Incorrect password or format\n";
				return false;
			}
			if(SaltLen != 16)
			{
				cout << "Error: Incorrect password or format\n";
				return false;
			}

			libscrypt_scrypt((const unsigned char*)Passwd, strlen(Passwd), (const unsigned char*)Salt, 16, 16384, 14, 2, (unsigned char*)Hash, 32);
			delete[] Salt;
			mpz_import(FinalKey.get_mpz_t(), 32, 1, 1, 0, 0, Hash);

			//Hash needs to be DELETED!
			memset(Hash, 0, 32);
		}
		
		unsigned int n = FileLength - File.tellg();
		char* Cipher = new char[n];
		File.read(Cipher, n);
		
		AES crypt;
		char* Original = new char[n];
		if(FinalKey != 0)
		{
			n = crypt.Decrypt(Cipher, n, IV, FinalKey, Original);
			if(n == -1)
			{
				cout << "Error: Incorrect password or format\n";
				memset(Original, 0, n);
				delete[] Original;
				delete[] Cipher;
				File.close();
				return false;
			}
			mpz_xor(FinalKey.get_mpz_t(), FinalKey.get_mpz_t(), FinalKey.get_mpz_t());		//Should zero out all data of our hash/sym key
		}
		else
			Original = strcpy(Original, Cipher);
		
		if(strncmp(Original, "crypto-key-ecc\n", 15))										//Check for proper format
		{
			cout << "Error: Incorrect password or format\n";
			memset(Original, 0, n);
			delete[] Original;
			delete[] Cipher;
			File.close();
			return false;
		}

		for(int i = 0; i < 32; i++)
		{
			Key[i] = Original[15 + i];
			Original[15 + i] = 0;
		}
		
		delete[] Original;
		delete[] Cipher;
		File.close();
	}
	else
	{
		cout << "Error: Couldn't open " << FileLoc << endl;
		return false;
	}
	return true;
}

void MakeCurvePublicKey(string FileLoc, uint8_t Point[32])
{
	fstream File(FileLoc.c_str(), ios::out | ios::trunc);
	if(File.is_open())
	{
		File << "crypto-key-ecc\n";
		File.write((char*)Point, 32);
		File.close();
	}
	else
		cout << "Error: Couldn't open " << FileLoc << endl;
	return;
}

void MakeCurvePrivateKey(string FileLoc, uint8_t Key[32], const char* Passwd, char* Salt, mpz_class& IV)
{
	fstream File(FileLoc.c_str(), ios::out | ios::trunc);
	if(File.is_open())
	{
		char Original[47] = {"crypto-key-ecc\n"};
		char Hash[32] = {0};
		mpz_class FinalKey = 0;
		
		if(strlen(Passwd))
		{
			libscrypt_scrypt((const unsigned char*)Passwd, strlen(Passwd), (const unsigned char*)Salt, 16, 16384, 14, 2, (unsigned char*)Hash, 32);
			mpz_import(FinalKey.get_mpz_t(), 32, 1, 1, 0, 0, Hash);

			//Hash needs to be DELETED!
			memset(Hash, 0, 32);
		}
		
		for(unsigned int i = 0; i < 32; i++)
			Original[15 + i] = (char)Key[i];
		
		AES crypt;
		if(FinalKey != 0)
		{
			char* Cipher = new char[48];
			crypt.Encrypt(Original, 47, IV, FinalKey, Cipher);
			mpz_xor(FinalKey.get_mpz_t(), FinalKey.get_mpz_t(), FinalKey.get_mpz_t());		//Should zero out all data of our AES key
			char* S = Base64Encode(Salt, 16);
			char* I = Export64(IV);
			
			File.write(S, 24);																//Write the salt in base64
			File.write(I, 24);																//Write the IV in base64
			File.write(Cipher, 48);
			
			delete[] Cipher;
			delete[] S;
			delete[] I;
		}
		else
			File.write(Original, 47);
		
		File.close();
	}
	else
		cout << "Error: Couldn't open " << FileLoc << endl;
	return;
}


/* ---------------------- RSA keys are still supported! -------------------------- */
bool LoadRSAPublicKey(string FileLoc, mpz_class& Modulus, mpz_class& Enc)
{
	fstream File(FileLoc.c_str(), ios::in);
	if(File.is_open())
	{
		string Values;
		getline(File, Values);
		if(Values != "crypto-key-rsa")				//Check for proper format
		{
			cout << "This key was not saved in a recognized format.\n";
			return false;
		}
		Values = "";
		getline(File, Values);
		try
		{
			Import64(Values.c_str(), Modulus);		//Decode Base64 Values and store into Modulus
		}
		catch(int e)
		{
			cout << "Could not load modulus from " << FileLoc << endl;
			return false;
		}
		
		Values = "";
		getline(File, Values);
		try
		{
			Import64(Values.c_str(), Enc);			//Decode Base64 Values and store into Enc
		}
		catch(int e)
		{
			cout << "Could not load encryption value from " << FileLoc << endl;
			return false;
		}
		File.close();
	}
	else
	{
		cout << "Error: Couldn't open " << FileLoc << endl;
		return false;
	}
	return true;
}

bool LoadRSAPrivateKey(string FileLoc, mpz_class& Dec, const char* Passwd)
{
	fstream File(FileLoc.c_str(), ios::in);
	if(File.is_open())
	{
		char Salt64[25] = {0};
		char IVStr[25] = {0};
		mpz_class IV = 0;
		char Hash[32] = {0};
		mpz_class FinalKey = 0;

		unsigned int FileLength = 0;
		File.seekg(0, File.end);
		FileLength = File.tellg();
		File.seekg(0, File.beg);
		
		if(strlen(Passwd))
		{
			File.read(Salt64, 24);
			File.read(IVStr, 24);
			char* Salt;
			int SaltLen;								//Should equal 16
			try
			{
				Salt = Base64Decode(Salt64, SaltLen);
				Import64(IVStr, IV);
			}
			catch(int e)
			{
				cout << "Error: Incorrect password or format\n";
				return false;
			}
			if(SaltLen != 16)
			{
				cout << "Error: Incorrect password or format\n";
				return false;
			}

			libscrypt_scrypt((const unsigned char*)Passwd, strlen(Passwd), (const unsigned char*)Salt, 16, 16384, 14, 2, (unsigned char*)Hash, 32);
			delete[] Salt;
			mpz_import(FinalKey.get_mpz_t(), 32, 1, 1, 0, 0, Hash);

			//Hash needs to be DELETED!
			memset(Hash, 0, 32);
		}

		unsigned int n = FileLength - File.tellg();
		char* Cipher = new char[n];
		File.read(Cipher, n);
		
		AES crypt;
		char* Original = new char[n+1];
		Original[n] = 0;
		if(FinalKey != 0)
		{
			n = crypt.Decrypt(Cipher, n, IV, FinalKey, Original);
			if(n == -1)
			{
				cout << "Error: Incorrect password or format\n";
				memset(Original, 0, sizeof(Original));
				delete[] Original;
				delete[] Cipher;
				File.close();
				return false;
			}
			mpz_xor(FinalKey.get_mpz_t(), FinalKey.get_mpz_t(), FinalKey.get_mpz_t());		//Should zero out all data of our hash/sym key
		}
		else
			memcpy(Original, Cipher, n);
		
		if(strncmp(Original, "crypto-key-rsa\n", 15))		//Check for proper format
		{
			cout << "Error: Incorrect password or format\n";
			memset(Original, 0, n);
			delete[] Original;
			delete[] Cipher;
			File.close();
			return false;
		}
		try
		{
			Import64(&Original[15], Dec);
		}
		catch(int e)
		{
			cout << "Error: Incorrect password or format\n";
			memset(Original, 0, n);
			delete[] Original;
			delete[] Cipher;
			File.close();
			return false;
		}
		memset(Original, 0, n);
		delete[] Original;
		delete[] Cipher;
		File.close();
	}
	else
	{
		cout << "Error: Couldn't open " << FileLoc << endl;
		return false;
	}
	return true;
}

void MakeRSAPublicKey(string FileLoc, mpz_class& Modulus, mpz_class& Enc)
{
	fstream File(FileLoc.c_str(), ios::out | ios::trunc);
	if(File.is_open())
	{
		char* ModStr = Export64(Modulus);
		char* EncStr = Export64(Enc);
		File << "crypto-key-rsa\n";
		File << ModStr << "\n";
		File << EncStr << "\n";
		delete[] ModStr;
		delete[] EncStr;
		File.close();
	}
	else
		cout << "Error: Couldn't open " << FileLoc << endl;
	return;
}

void MakeRSAPrivateKey(string FileLoc, mpz_class& Dec, const char* Passwd, char* Salt, mpz_class& IV)
{
	fstream File(FileLoc.c_str(), ios::out | ios::trunc);
	if(File.is_open())
	{
		char* Original;
		char Hash[32] = {0};
		mpz_class FinalKey = 0;
		
		if(strlen(Passwd))
		{
			libscrypt_scrypt((const unsigned char*)Passwd, strlen(Passwd), (const unsigned char*)Salt, 16, 16384, 14, 2, (unsigned char*)Hash, 32);
			mpz_import(FinalKey.get_mpz_t(), 32, 1, 1, 0, 0, Hash);

			//Hash needs to be DELETED!
			memset(Hash, 0, 32);
		}
		
		char* Dec64 = Export64(Dec);
		unsigned int Length = 15 + strlen(Dec64);
		Original = new char[Length];
		strncpy(Original, "crypto-key-rsa\n", 15);
		strncpy(&Original[15], Dec64, strlen(Dec64));
		memset(Dec64, 0, strlen(Dec64));
		delete[] Dec64;
		
		AES crypt;
		char* Cipher;
		if(FinalKey != 0)
		{
			Cipher = new char[PaddedSize(Length)];
			crypt.Encrypt(Original, Length, IV, FinalKey, Cipher);
		}
		else
			Cipher = Original;

		if(FinalKey != 0)
		{
			char* S = Base64Encode(Salt, 16);
			char* I = Export64(IV);
			mpz_xor(FinalKey.get_mpz_t(), FinalKey.get_mpz_t(), FinalKey.get_mpz_t());		//Should zero out all data of our hash/sym key
			File.write(S, 24);																//Write the salt in base64
			File.write(I, 24);																//Write the IV in base64
			delete[] S;
			delete[] I;
			File.write(Cipher, PaddedSize(Length));
			
			memset(Original, 0, Length);
			delete[] Cipher;
			delete[] Original;
		}
		else
		{
			File.write(Cipher, Length);
			delete[] Cipher;
		}
		File.close();
	}
	else
		cout << "Error: Couldn't open " << FileLoc << endl;
	return;
}
#endif