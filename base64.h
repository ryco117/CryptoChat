#ifndef BASE64_H
#define BASE64_H
#include <string.h>
#include <gmpxx.h>

char BaseTable[] = {
'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
'w', 'x', 'y', 'z', '0', '1', '2', '3',
'4', '5', '6', '7', '8', '9', '+', '/'
};

char* Base64Encode(const char* DataC, unsigned int len)
{
	char* Result;
	unsigned int r = len % 3;
	unsigned char* Data = new unsigned char[len + ((3 - r) % 3)];
	memcpy(Data, DataC, len);
	
	if(r == 2)
		Data[len] = '\0';
	if(r == 1)
	{
		Data[len] = '\0';
		Data[len+1] = '\0';
	}
	unsigned int newLen = len + ((3 - r) % 3);
	newLen = (newLen / 3) * 4;
	Result = new char[newLen+1];
	Result[newLen] = 0;
	
	unsigned int k = 0;
	for(int i = 0; i < newLen / 4; i++)
	{
		k = (unsigned int)Data[i * 3] << 16;
		k += (unsigned int)Data[i * 3 + 1] << 8;
		k += (unsigned int)Data[i * 3 + 2];
		
		Result[i * 4] = BaseTable[(k & 0xFC0000) >> 18];
		Result[i * 4 + 1] = BaseTable[(k & 0x3F000) >> 12];
		Result[i * 4 + 2] = BaseTable[(k & 0xFC0) >> 6];
		Result[i * 4 + 3] = BaseTable[k & 0x3F];
	}
	
	if(r == 2)
		Result[newLen - 1] = '=';
	if(r == 1)
	{
		Result[newLen - 1] = '=';
		Result[newLen - 2] = '=';
	}
	memset(Data, 0, len + ((3 - r) % 3));
	delete[] Data;
	return Result;
}

char* Base64Decode(const char* Data, unsigned int& len)
{
	char* LookUp = new char[strlen(Data)];
	char r = 0;
	for(int i = 0; i < strlen(Data); i++)
	{
		if(Data[i] == '=')
		{
			LookUp[i] = 0;
			r++;
		}
		else if(Data[i] != '\0')
		{
			char j = 0;
			while(j < 64)
			{
				if(Data[i] == BaseTable[j])
				{
					LookUp[i] = j;
					break;
				}
				j++;
			}
			if(j == 64)
			{
				memset(LookUp, 0, strlen(Data));
				delete[] LookUp;
				throw -1;
				return (char*)0;
			}
		}
	}

	char* Result = new char[(strlen(Data) / 4) * 3 + 1];
	for(int i = 0; i * 4 < strlen(Data); i++)
	{
		int k = (unsigned int)LookUp[i * 4] << 18;
		k += (unsigned int)LookUp[i * 4 + 1] << 12;
		k += (unsigned int)LookUp[i * 4 + 2] << 6;
		k += (unsigned int)LookUp[i * 4 + 3];
		
		Result[i * 3] = char((k & 0xFF0000) >> 16);
		Result[i * 3 + 1] = char((k & 0xFF00) >> 8);
		Result[i * 3 + 2] = char(k & 0xFF);
	}
	if(&len != NULL)
	{
		len = (strlen(Data) / 4) * 3 - r;
		Result[len] = 0;
	}
	return Result;
}

void Base64Decode(const char* Data, char* Return, unsigned int maxLen)
{
	char* LookUp = new char[strlen(Data)];
	char r = 0;
	for(int i = 0; i < strlen(Data); i++)
	{
		if(Data[i] == '=')
		{
			LookUp[i] = 0;
			r++;
		}
		else if(Data[i] != '\0')
		{
			char j = 0;
			while(j < 64)
			{
				if(Data[i] == BaseTable[j])
				{
					LookUp[i] = j;
					break;
				}
				j++;
			}
			if(j == 64)
			{
				memset(LookUp, 0, strlen(Data));
				delete[] LookUp;
				throw -1;
				return;
			}
		}
	}
	
	if(((strlen(Data) / 4) * 3) - r > maxLen)
	{
		throw -2;
		return;
	}

	char* Result = new char[(strlen(Data) / 4) * 3 + 1];
	for(int i = 0; i * 4 < strlen(Data); i++)
	{
		int k = (unsigned int)LookUp[i * 4] << 18;
		k += (unsigned int)LookUp[i * 4 + 1] << 12;
		k += (unsigned int)LookUp[i * 4 + 2] << 6;
		k += (unsigned int)LookUp[i * 4 + 3];
		
		Result[i * 3] = char((k & 0xFF0000) >> 16);
		Result[i * 3 + 1] = char((k & 0xFF00) >> 8);
		Result[i * 3 + 2] = char(k & 0xFF);
	}
	unsigned int len = (strlen(Data) / 4) * 3 - r;
	memcpy(Return, Result, len);
	memset(Result, 0, len);
	return;
}

char* Export64(mpz_class& BigNum)
{
	char temp[2048] = {0};												//Big-num  max of 16384 bits
	unsigned int size = 0;
	mpz_export(temp, (size_t*)&size, 1, 1, 0, 0, BigNum.get_mpz_t());
	
	size = 1;
	mpz_class MSBFinder = 1;
	while(MSBFinder != 0)
	{
		mpz_div_2exp(MSBFinder.get_mpz_t(), BigNum.get_mpz_t(), size);
		size += 1;
	}
	size -= 1;				//1 0 0 1 1 0 0 1 0 0 1
	size = ((8 - (size % 8)) + size) / 8;
	
	char* Result;
	Result = Base64Encode(temp, size);
	memset(temp, 0, 2048);
	return Result;
}

void Import64(const char* Value, mpz_class& BigNum)
{
	unsigned int size;
	char* Decode;
	try
	{
		Decode = Base64Decode(Value, size);
	}
	catch(int e)
	{
		throw -1;
		return;
	}
	mpz_import(BigNum.get_mpz_t(), size, 1, 1, 0, 0, Decode);
	memset(Decode, 0, size);
	delete[] Decode;
	return;
}
#endif