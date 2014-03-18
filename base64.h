#ifndef BASE64_H
#define BASE64_H
#include <string>
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

std::string Base64Encode(char* DataC, int len)
{
	std::string Result;
	int r = len % 3;
	unsigned char* Data = new unsigned char[len + ((3-r)%3)];
	for(int i = 0; i < len; i++)
		Data[i] = DataC[i];
	if(r == 2)
		Data[len] = '\0';
	if(r == 1)
	{
		Data[len] = '\0';
		Data[len+1] = '\0';
	}
	len += (3-r)%3;
	
	unsigned int k = 0;
	for(int i = 0; i < len; i += 3)
	{
		k = (unsigned int)Data[i] << 16;
		k += (unsigned int)Data[i+1] << 8;
		k += (unsigned int)Data[i+2];
		
		Result.push_back(BaseTable[(k & 0xFC0000) >> 18]);
		Result.push_back(BaseTable[(k & 0x3F000) >> 12]);
		Result.push_back(BaseTable[(k & 0xFC0) >> 6]);
		Result.push_back(BaseTable[k & 0x3F]);
	}
	
	if(r == 2)
		Result[Result.length()-1] = '=';
	if(r == 1)
	{
		Result[Result.length()-1] = '=';
		Result[Result.length()-2] = '=';
	}
	
	delete[] Data;
	return Result;
}

std::string Base64Decode(std::string Data)
{
	std::string LookUp;
	char r = 0;
	for(int i = 0; i < Data.length(); i++)
	{
		if(Data[i] == '=')
		{
			LookUp.push_back(0);
			r++;
		}
		else if(Data[i] != '\0')
		{
			char j = 0;
			while(j < 64)
			{
				if(Data[i] == BaseTable[j])
				{
					LookUp.push_back(j);
					break;
				}
				j++;
			}
			if(j == 64)
			{
				std::cout << i << ", " << (int)Data[i] << std::endl;
				throw -1;
				return Data;
			}
		}
	}

	std::string Result;
	for(int i = 0; i < LookUp.length(); i += 4)
	{
		int k = (unsigned int)LookUp[i] << 18;
		k += (unsigned int)LookUp[i+1] << 12;
		k += (unsigned int)LookUp[i+2] << 6;
		k += (unsigned int)LookUp[i+3];
		
		Result.push_back(char((k & 0xFF0000) >> 16));
		Result.push_back(char((k & 0xFF00) >> 8));
		Result.push_back(char(k & 0xFF));
	}
	Result.resize(Result.length() - r);
	return Result;
}

std::string Export64(mpz_class BigNum)
{
	char temp[1024] = {0};
	int size = 0;
	mpz_export(temp, (size_t*)&size, 1, 1, 0, 0, BigNum.get_mpz_t());
	
	std::string Result;
	Result = Base64Encode(temp, size);
	return Result;
}

void Import64(std::string Value, mpz_class& BigNum)
{
	try
	{
		Value = Base64Decode(Value);
	}
	catch(int e)
	{
		throw -1;
	}
	mpz_import(BigNum.get_mpz_t(), Value.length(), 1, 1, 0, 0, Value.c_str());
	return;
}
#endif