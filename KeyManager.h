#ifndef KEYMANAGER
#define KEYMANAGER
#include <iostream>
#include <string>
#include <sstream>
#include <gmpxx.h>

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

bool LoadPrivateKey(string FileLoc, mpz_class& Dec, string Passwd)
{
	fstream File(FileLoc.c_str(), ios::in);
	if(File.is_open())
	{
		unsigned int FileLength = 0;
		File.seekg(0, File.end);
		FileLength = File.tellg();
		File.seekg(0, File.beg);
		
		char* Cipher = new char[FileLength];
		File.read(Cipher, FileLength);
		AES crypt;
		string Original;
		
		string SCipher = "";
		for(int i = 0; i < FileLength; i++)
			SCipher.push_back(Cipher[i]);
		
		if(!Passwd.empty())
			Original = crypt.Decrypt(mpz_class(Passwd, 16), SCipher);
		else
			Original = SCipher;
		
		int pos = Original.find('\n');
		if(Original.substr(0, pos) != "crypto-key")		//Check for proper format
		{
			cout << "Error: Incorrect password or format\n";
			return false;
		}
		try
		{
			Import64(Original.substr(pos+1, string::npos), Dec);
		}
		catch(int e)
		{
			cout << "Could not load decryption value from " << FileLoc << endl;
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

void MakePrivateKey(string FileLoc, mpz_class& Dec, string Passwd)
{
	fstream File(FileLoc.c_str(), ios::out | ios::trunc);
	if(File.is_open())
	{
		string Original = "crypto-key\n";
		Original += Export64(Dec);
		AES crypt;
		string Cipher;
		if(!Passwd.empty())
			Cipher = crypt.Encrypt(mpz_class(Passwd, 16), Original);
		else
			Cipher = Original;
		
		File.write(Cipher.c_str(), Cipher.length());
		File.close();
	}
	else
		cout << "Error: Couldn't open " << FileLoc << endl;
	return;
}
#endif
