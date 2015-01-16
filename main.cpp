#include <iostream>
#include <string>

#ifndef ANDROID
#include <ifaddrs.h>
#endif

#ifndef __bswap_64
#define	__bswap_64(x)	(((uint64_t)(x) << 56) | \
						(((uint64_t)(x) << 40) & 0xff000000000000ULL) | \
						(((uint64_t)(x) << 24) & 0xff0000000000ULL) | \
						(((uint64_t)(x) << 8)  & 0xff00000000ULL) | \
						(((uint64_t)(x) >> 8)  & 0xff000000ULL) | \
						(((uint64_t)(x) >> 24) & 0xff0000ULL) | \
						(((uint64_t)(x) >> 40) & 0xff00ULL) | \
						((uint64_t)(x)  >> 56))
#endif

#define IV64_LEN 24													//The max length an IV for AES could be (in base64)
#define FILE_PIECE_LEN 2048											//The size in bytes of the blocks used for file sending
#define RECV_SIZE (1 + IV64_LEN + 4 + FILE_PIECE_LEN + 16)			//Max size that a message could possibly be in bytes after initial setup
#define MAX_RSA_SIZE 2048
#define RSA_RECV_SIZE (16 + (MAX_RSA_SIZE + MAX_RSA_SIZE) + \
					   MAX_RSA_SIZE + (MAX_RSA_SIZE + MAX_RSA_SIZE))//Max size of RSA public key exchange (16384 bit RSA).
																	//salt, ephemeral key (2048 byte Mod, 2048 byte e value), 2048 byte signature, static key

#include "SFMT/SFMT.h"
#include "curve25519-donna.c"
#include "ecdh.h"
#include "PeerToPeer.cpp"
#include "myconio.h"
#include "KeyManager.h"

using namespace std;

void SeedAll(gmp_randclass& rng, sfmt_t& sfmt);
void PrintIP();
void GetPassword(char* buff, int buffSize);

string HelpString = \
"Secure chat program written by Ryan Andersen\n\
Contact at ryco117@gmail.com\n\n\
Arguments List\n\n\
Toggles:\n\
-dp,\t--disable-public\tdon't send our static public key at connection\n\
-r,\t--rsa\t\t\tuse RSA instead of Curve25519. Peer must do this as well (note. this effects how keys are loaded, saved)\n\
-h,\t--help\t\t\tprint this dialogue\n\n\
String Inputs:\n\
-ip,\t--ip-address\t\tspecify the ip address (or hostname) to attempt to connect to\n\
-p,\t--proxy\t\t\tspecify the address and port to use as proxy\n\
-o,\t--output\t\tsave the keys generated to files\n\
-lk,\t--load-keys\t\tspecify files to load public and private keys from\n\
-lp,\t--load-public\t\tspecify the file to load the peer's public key from\n\n\
Integer Inputs:\n\
-bp,\t--bind-port\t\tthe port number to listen on\n\
-pp,\t--peer-port\t\tthe port number to connect to\n\n\
Input Argument Examples:\n\
-ip 192.168.1.70\t\tattempt to connect to 192.168.1.70\n\
-p localhost:9050\t\tconnect through proxy at localhost on port 9050 (tor default port number)\n\
-o newKeys\t\t\tproduce \"newKeys.pub\" and \"newKeys.priv\"\n\
-lk Keys\t\t\tload the keys from the files \"Keys.pub\" and \"Keys.priv\"\n\
-lp PeerKey.pub\t\t\tload the peer's public key from \"PeerKey.pub\"\n\
-bp 4321\t\t\tlisten for connections on port 4321\n\n";

int main(int argc, char* argv[])
{
	//This will be used for all randomness for the rest of the execution... seed well
	sfmt_t sfmt;
	gmp_randclass rng(gmp_randinit_default);			//Define a gmp_randclass, initialize with default value
	SeedAll(rng, sfmt);										//Pass randclass to function to seed it for more random values
	
	PeerToPeer MyPTP;
	MyPTP.RNG = &rng;
	MyPTP.sfmt = &sfmt;
	MyPTP.BindPort = 5001;
	MyPTP.PeerPort = 5001;
	MyPTP.ProxyPort = 0;
	MyPTP.StcClientMod = 0;
	MyPTP.StcClientE = 0;
	MyPTP.Sending = 0;
	MyPTP.HasEphemeralPub = false;
	MyPTP.HasStaticPub = false;
	MyPTP.UseRSA = false;
	
	//Encryption Stuff
	RSA NewRSA;
	AES Cipher;
	sfmt_fill_small_array64(&sfmt, (uint64_t*)MyPTP.SymKey, 4);	//Create a 256 bit long random value as our key
	
	//Options
	bool SendPublic = true;
	string LoadPublic = "";
	string LoadKeys = "Keys";
	string SavePublic = "";
	string OutputFiles = "Keys";
	
	for(unsigned int i = 1; i < argc; i++)						//What arguments were we provided with? How should we handle them
	{
		string Arg = string(argv[i]);
		if((Arg == "-ip" || Arg == "--ip-address") && i+1 < argc)
		{
			MyPTP.ClntAddr = argv[i+1];
			i++;
		}
		else if((Arg == "-p" || Arg == "--proxy") && i+1 < argc)
		{
			string ProxyAddr = argv[i+1];
			MyPTP.ProxyAddr = ProxyAddr.substr(0, ProxyAddr.find(":"));
			MyPTP.ProxyPort = atoi(ProxyAddr.substr(ProxyAddr.find(":") + 1).c_str());
			i++;
		}
		else if(Arg == "-r" || Arg == "--rsa")
			MyPTP.UseRSA = true;
		else if((Arg == "-o" || Arg == "--output") && i+1 < argc)	//Write two keys files
		{
			OutputFiles = argv[i+1];
			i++;
		}
		else if((Arg == "-lk" || Arg == "--load-keys") && i+1 < argc)		//load the public and private keys we will use
		{
			LoadKeys = argv[i+1];
			i++;
		}
		else if((Arg == "-lp" || Arg == "--load-public") && i+1 < argc)		//load the peer's public key
		{
			LoadPublic = argv[i+1];
			i++;
		}
		else if((Arg == "-bp" || Arg == "--bind-port") && i+1 < argc)
		{
			MyPTP.BindPort = atoi(argv[i+1]);
			if((signed int)MyPTP.BindPort <= 0 || MyPTP.BindPort >= 65536)
			{
				cout << "Bad port number. Using default 5001\n";
				MyPTP.BindPort = 5001;
			}
			i++;
		}
		else if((Arg == "-pp" || Arg == "--peer-port") && i+1 < argc)
		{
			MyPTP.PeerPort = atoi(argv[i+1]);
			if((signed int)MyPTP.PeerPort <= 0 || MyPTP.PeerPort >= 65536)
			{
				cout << "Bad port number. Using default 5001\n";
				MyPTP.PeerPort = 5001;
			}
			i++;
		}
		else if(Arg == "-dp" || Arg == "--disable-public")
			SendPublic = false;
		else if((Arg == "-sp" || Arg == "--save-public") && i+1 < argc)
		{
			SavePublic = argv[i+1];
			i++;
		}
		else if(Arg == "-h" || Arg == "--help")
		{
			cout << HelpString;
			return 0;
		}
		else			//What the hell were they trying to do?
			cout << "warning: didn't understand " << Arg << endl;
	}
	#ifndef ANDROID
	PrintIP();
	#endif
	
	if(!LoadPublic.empty() && CanOpenFile(LoadPublic, ios_base::in))
	{
		if(MyPTP.UseRSA)
		{
			if(!LoadRSAPublicKey(LoadPublic, MyPTP.StcClientMod, MyPTP.StcClientE))
			{
				MyPTP.StcClientMod = 0;
				MyPTP.StcClientE = 0;
			}
			else
				MyPTP.HasStaticPub = true;
		}
		else
		{
			if(!LoadCurvePublicKey(LoadPublic, MyPTP.StcCurvePPeer))
				memset((char*)MyPTP.StcCurvePPeer, 0, 32);
			else
				MyPTP.HasStaticPub = true;			
		}
	}
	
	if(!CanOpenFile(LoadKeys + ".pub", ios_base::in) || !CanOpenFile(LoadKeys + ".priv", ios_base::in))		//If can't read Keys, need to output generated static keys
	{
		if(MyPTP.UseRSA)
			NewRSA.KeyGenerator(MyPTP.StcMyD, MyPTP.StcMyE, MyPTP.StcMyMod, rng);
		else
			ECC_Curve25519_Create(MyPTP.StcCurveP, MyPTP.StcCurveK, sfmt);
		
		string PubKeyName = OutputFiles + ".pub";
		string PrivKeyName = OutputFiles + ".priv";
		char* Passwd1 = new char[256];
		char* Passwd2 = new char[256];
		
		while(true)
		{
			cout << "Private Key Password To Use: ";
			fflush(stdout);
			GetPassword(Passwd1, 256);
			cout << "\nRetype Password: ";
			fflush(stdout);
			GetPassword(Passwd2, 256);
			cout << endl;
			if(strcmp(Passwd1, Passwd2) != 0)		//Mistype check
			{
				cout << "Passwords do not match. Do you want to try again [Y/n]: ";
				fflush(stdout);
				string Answer;
				getline(cin, Answer);
				if(Answer == "n" || Answer == "N")
				{
					cout << "Giving up on key creation\n\n";		//Because of a mistype? Pathetic...
					break;
				}
			}
			else
			{
				char* SaltStr = new char[16];
				sfmt_fill_small_array64(&sfmt, (uint64_t*)SaltStr, 2);
				uint8_t* TempIV = new uint8_t[16];
				sfmt_fill_small_array64(&sfmt, (uint64_t*)TempIV, 2);

				if(MyPTP.UseRSA)
				{
					MakeRSAPrivateKey(PrivKeyName, MyPTP.StcMyD, Passwd1, SaltStr, TempIV);
					MakeRSAPublicKey(PubKeyName, MyPTP.StcMyMod, MyPTP.StcMyE);
				}
				else
				{
					MakeCurvePrivateKey(PrivKeyName, MyPTP.StcCurveK, Passwd1, SaltStr, TempIV);
					MakeCurvePublicKey(PubKeyName, MyPTP.StcCurveP);
				}
				break;
			}
		}
		memset(Passwd1, 0, strlen(Passwd1));
		delete[] Passwd1;
		memset(Passwd2, 0, strlen(Passwd2));
		delete[] Passwd2;
	}
	else
	{
		string PubKeyName = LoadKeys + ".pub";
		string PrivKeyName = LoadKeys + ".priv";
		cout << "Private Key Password: ";
		fflush(stdout);
		
		char* Passwd = new char[256];
		GetPassword(Passwd, 256);
		cout << endl;
		if(MyPTP.UseRSA)
		{
			if(!LoadRSAPrivateKey(PrivKeyName, MyPTP.StcMyD, Passwd))
			{
				memset(Passwd, 0, 256);
				delete[] Passwd;
				mpz_xor(MyPTP.StcMyD.get_mpz_t(), MyPTP.StcMyD.get_mpz_t(), MyPTP.StcMyD.get_mpz_t());
				return -1;
			}
			if(!LoadRSAPublicKey(PubKeyName, MyPTP.StcMyMod, MyPTP.StcMyE))
			{
				memset(Passwd, 0, 256);
				delete[] Passwd;
				MyPTP.StcMyMod = 0;
				MyPTP.StcMyE = 0;
				mpz_xor(MyPTP.StcMyD.get_mpz_t(), MyPTP.StcMyD.get_mpz_t(), MyPTP.StcMyD.get_mpz_t());
				return -1;
			}
		}
		else
		{
			if(!LoadCurvePrivateKey(PrivKeyName, MyPTP.StcCurveK, Passwd))
			{
				memset(Passwd, 0, 256);
				delete[] Passwd;
				memset((char*)MyPTP.StcCurveK, 0, 32);
				return -1;
			}
			if(!LoadCurvePublicKey(PubKeyName, MyPTP.StcCurveP))
			{
				memset(Passwd, 0, 256);
				delete[] Passwd;
				memset((char*)MyPTP.StcCurveK, 0, 32);
				memset((char*)MyPTP.StcCurveP, 0, 32);
				return -1;
			}
		}
		memset(Passwd, 0, 256);
		delete[] Passwd;
	}
	
	char* StcPubKey64;
	if(MyPTP.UseRSA)
	{
		NewRSA.KeyGenerator(MyPTP.EphMyD, MyPTP.EphMyE, MyPTP.EphMyMod, rng);
		StcPubKey64 = Export64(MyPTP.StcMyMod);
	}
	else
	{
		ECC_Curve25519_Create(MyPTP.EphCurveP, MyPTP.EphCurveK, sfmt);
		StcPubKey64 = Base64Encode((char*)MyPTP.StcCurveP, 32);
	}

	 
	cout << "Static public key: " << StcPubKey64 << endl;
	delete[] StcPubKey64;
	cout << "All necessary Encryption values are filled\n\n";
	
	MyPTP.StartServer(1, SendPublic, SavePublic);				//Jump to the loop to handle all incoming connections and data sending
	
	//Clear critical values (and some public)
	memset(MyPTP.SymKey, 0, 32);
	if(MyPTP.UseRSA)
	{
		mpz_xor(MyPTP.EphMyE.get_mpz_t(), MyPTP.EphMyE.get_mpz_t(), MyPTP.EphMyE.get_mpz_t());
		mpz_xor(MyPTP.EphMyD.get_mpz_t(), MyPTP.EphMyD.get_mpz_t(), MyPTP.EphMyD.get_mpz_t());
		mpz_xor(MyPTP.StcMyD.get_mpz_t(), MyPTP.StcMyD.get_mpz_t(), MyPTP.StcMyD.get_mpz_t());
	}
	else
	{
		memset(MyPTP.SharedKey, 0, 32);
		memset((char*)MyPTP.EphCurveP, 0, 32);
		memset((char*)MyPTP.EphCurveK, 0, 32);
		memset((char*)MyPTP.StcCurveP, 0, 32);
		memset((char*)MyPTP.StcCurveK, 0, 32);
	}
	
	nonblock(false, true);
	cout << "Finished cleaning, Press Enter To Exit...";
	cin.get();

	return 0;
}

void SeedAll(gmp_randclass& rng, sfmt_t& sfmt)
{
	//Properly Seed rand()
	FILE* random;
	uint32_t* seed = new uint32_t[20];
	random = fopen ("/dev/urandom", "r");		//Unix provides it, why not use it
	if(random == NULL)
	{
		fprintf(stderr, "Cannot open /dev/urandom!\n"); 
		delete[] seed;
		return;
	}
	for(int i = 0; i < 20; i++)
	{
		fread(&seed[i], sizeof(uint32_t), 1, random);
		srand(seed[i]); 		//seed the default random number generator
		rng.seed(seed[i]);		//seed the GMP random number generator
	}
	sfmt_init_by_array(&sfmt, seed, 20);
	fclose(random);
}

void GetPassword(char* buff, int buffSize)
{
	int pos = 0;
	nonblock(true, false);
	while(pos < buffSize-1)
	{
		if(kbhit())
		{
			unsigned char c = getch();
			if(c == '\n')
			{
				buff[pos] = 0;
				nonblock(false, true);
				return;
			}
			else if(c == 127)	//Backspace
			{
				if(pos > 0)
				{
					pos -= 1;
					buff[pos] = 0;
				}
			}
			else if((int)c >= 32 && (int)c <= 126)
			{
				buff[pos] = c;
				pos += 1;
			}
			else
			{
				getch();
				getch();
			}
			fflush(stdout);
		}
	}
	buff[buffSize-1] = 0;
	return;
}

#ifndef ANDROID
void PrintIP()
{
	struct ifaddrs *addrs, *tmp;
	getifaddrs(&addrs);
	tmp = addrs;

	while (tmp) 
	{
		if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET)
		{
			struct sockaddr_in *pAddr = (struct sockaddr_in *)tmp->ifa_addr;
			printf("%s: %s\n", tmp->ifa_name, inet_ntoa(pAddr->sin_addr));
		}

		tmp = tmp->ifa_next;
	}
	freeifaddrs(addrs);
	return;
}
#endif
