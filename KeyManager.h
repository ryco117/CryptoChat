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

bool LoadPublicKey(string FileLoc, mpz_class& Modulus, mpz_class& Enc)
{
	fstream File(FileLoc.c_str(), ios::in);
	if(File.is_open())
	{
		string Values;
		getline(File, Values);
		if(Values != "crypto-key")		//Check for proper format
		{
			cout << "This key was not saved in a recognized format.\n";
			return false;
		}
		Values = "";
		getline(File, Values);
		try
		{
			Import64(Values, Modulus);		//Decode Base64 Values and store into Modulus
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
			Import64(Values, Enc);		//Decode Base64 Values and store into Enc
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

bool LoadPrivateKey(string FileLoc, mpz_class& Dec, string* Passwd)
{
	fstream File(FileLoc.c_str(), ios::in);
	if(File.is_open())
	{
		char Salt64[24] = {0};
		char IVStr[24] = {0};
		mpz_class IV = 0;
		char Hash[32] = {0};
		mpz_class FinalKey = 0;
		int n = 0;

		unsigned int FileLength = 0;
		File.seekg(0, File.end);
		FileLength = File.tellg();
		File.seekg(0, File.beg);
		
		if(!Passwd->empty())
		{
			File.read(Salt64, 24);
			string Salt = Base64Decode(string((const char*)Salt64, 24));
			File.read(IVStr, 24);
			Import64(string((const char*)IVStr, 24), IV);

			n = libscrypt_scrypt((const unsigned char*)Passwd->c_str(), Passwd->length(), (const unsigned char*)Salt.c_str(), 16, 16384, 14, 2, (unsigned char*)Hash, 32);

			//Clear password from memory once it is no longer needed
			Passwd->replace(0, Passwd->length(), Passwd->length(), '\x0');
			Passwd->clear();

			mpz_import(FinalKey.get_mpz_t(), 32, 1, 1, 0, 0, Hash);

			//Hash needs to be DELETED!
			for(int i = 0; i < 32; i++)
				Hash[i] = 0;
		}

		n = FileLength-File.tellg();
		char* Cipher = new char[n];
		File.read(Cipher, n);
		
		AES crypt;
		string Original;
		string SCipher = "";
		for(int i = 0; i < n; i++)
			SCipher.push_back(Cipher[i]);

		if(FinalKey != 0)
		{
			try
			{
				Original = crypt.Decrypt(FinalKey, SCipher, IV);
			}
			catch(string e)
			{
				cout << "Error: Incorrect password or format\n";
				delete[] Cipher;
				File.close();
				return false;
			}
			mpz_xor(FinalKey.get_mpz_t(), FinalKey.get_mpz_t(), FinalKey.get_mpz_t());		//Should zero out all data of our hash/sym key
		}
		else
			Original = SCipher;
		
		int pos = Original.find('\n');
		if(Original.substr(0, pos) != "crypto-key")		//Check for proper format
		{
			cout << "Error: Incorrect password or format\n";
			delete[] Cipher;
			File.close();
			return false;
		}
		try
		{
			Import64(Original.substr(pos+1, string::npos), Dec);
		}
		catch(int e)
		{
			cout << "Could not load decryption value from " << FileLoc << endl;
			delete[] Cipher;
			File.close();
			return false;
		}
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

void MakePublicKey(string FileLoc, mpz_class& Modulus, mpz_class& Enc)
{
	fstream File(FileLoc.c_str(), ios::out | ios::trunc);
	if(File.is_open())
	{
		File << "crypto-key\n";
		File << Export64(Modulus) << "\n";
		File << Export64(Enc) << "\n";
		File.close();
	}
	else
		cout << "Error: Couldn't open " << FileLoc << endl;
	return;
}

void MakePrivateKey(string FileLoc, mpz_class& Dec, string* Passwd, char* Salt, mpz_class& IV)
{
	fstream File(FileLoc.c_str(), ios::out | ios::trunc);
	if(File.is_open())
	{
		string Original = "crypto-key\n";
		char Hash[32] = {0};
		mpz_class FinalKey = 0;
		int n = 0;
		
		if(!Passwd->empty())
		{
			n = libscrypt_scrypt((const unsigned char*)Passwd->c_str(), Passwd->length(), (const unsigned char*)Salt, 16, 16384, 14, 2, (unsigned char*)Hash, 32);

			//VERY IMPORTANT! Clear password from memory once it is no longer needed		
			Passwd->replace(0, Passwd->length(), Passwd->length(), '\x0');
			Passwd->clear();

			mpz_import(FinalKey.get_mpz_t(), 32, 1, 1, 0, 0, Hash);

			//Hash needs to be DELETED!
			for(int i = 0; i < 32; i++)
				Hash[i] = 0;
		}
		
		Original += Export64(Dec);
		AES crypt;
		string Cipher;
		if(FinalKey != 0)
			Cipher = crypt.Encrypt(FinalKey, Original, IV);
		else
			Cipher = Original;

		if(FinalKey != 0)
		{
			mpz_xor(FinalKey.get_mpz_t(), FinalKey.get_mpz_t(), FinalKey.get_mpz_t());		//Should zero out all data of our hash/sym key
			File.write(Base64Encode(Salt, 16).c_str(), 24);		//Write the salt in base64
			File.write(Export64(IV).c_str(), 24);			//Write the IV in base64
		}
		File.write(Cipher.c_str(), Cipher.length());			//Write all the "jibberish"
		File.close();
	}
	else
		cout << "Error: Couldn't open " << FileLoc << endl;
	return;
}
#endif
