#include <iostream>
#include <string>
#ifndef ANDROID
#include <ifaddrs.h>
#endif

#include "PeerToPeer.cpp"
#include "myconio.h"
#include "KeyManager.h"
#include "md5.h"

using namespace std;

void GMPSeed(gmp_randclass& rng);
void PrintIP();
string GetPassword();

string HelpString = \
"Arguments List\n\n\
Toggles:\n\
-p,\t--print\t\t\tprint all generated encryption values\n\
-r,\t--random\t\trandomly generate all encryption values without prompting\n\
-dp,\t--disable-public\tdon't send our public key at connection. WARNING! peer must use -lp and have our public key\n\
-h,\t--help\t\t\tprint this dialogue\n\n\
String Inputs:\n\
-ip,\t--ip-address\t\tspecify the ip address to attempt to connect to\n\
-o,\t--output\t\tsave the rsa keys generated to files which can be reused\n\
-sp,\t--save-public\t\tsave the peer's public key to a specified file\n\
-lk,\t--load-keys\t\tspecify the files to load rsa keys from (public and private) that we will use\n\
-lp,\t--load-public\t\tspecify the file to load rsa public key from that the peer has the private key to. WARNING! peer must use -dp\n\n\
Integer Inputs:\n\
-P, --ports\t\tthe port number to open and connect to\n\n\
Input Argument Examples:\n\
-ip 192.168.1.70\twill connect to 192.168.1.70\n\
-o newKeys\t\twill produce newKeys.pub and newKeys.priv\n\
-sp peerKey.pub\t\twill create the file peerKey.pub with the peer's rsa public key\n\
-lk Keys\t\twill load the rsa values from the files Keys.pub and Keys.priv\n\
-lp PeerKey.pub\t\twill load the peer's public key from PeerKey.pub\n\
-P 4321\t\twill open port number 4321 for this session, and will connect to the same number\n\n";

int main(int argc, char* argv[])
{
	//This will be used for all randomness for the rest of the execution... seed well
	gmp_randclass rng(gmp_randinit_default);
	GMPSeed(rng);
	
	PeerToPeer MyPTP;
	MyPTP.Port = 5001;
	MyPTP.ClientMod = 0;
	MyPTP.ClientE = 0;
	MyPTP.Sending = 0;
	
	RSA NewRSA;
	AES Cipher;
	mpz_class SymmetricKey = rng.get_z_bits(128);		//Create a 128 bit long random value as our key
	mpz_class Keys[2] = {0};
	mpz_class Mod = 0;
	
	bool PrintVals = false;
	bool ForceRand = false;
	bool SendPublic = true;
	string SavePublic = "";
	string OutputFiles = "";
	
	for(unsigned int i = 1; i < argc; i++)
	{
		string Arg = string(argv[i]);
		if(Arg == "-p" || Arg == "--print")
			PrintVals = true;
		else if(Arg == "-r" || Arg == "--random")
			ForceRand = true;
		else if((Arg == "-ip" || Arg == "--ip-address") && i+1 < argc)
		{
			MyPTP.ClntIP = argv[i+1];
			if(!IsIP(MyPTP.ClntIP))
			{
				cout << MyPTP.ClntIP << " is not a properly formated IPv4 address and will not be used\n";
				MyPTP.ClntIP = "";
			}
			i++;
		}
		else if((Arg == "-o" || Arg == "--output") && i+1 < argc)		//Write two keys files
		{
			OutputFiles = argv[i+1];
			i++;
		}
		else if((Arg == "-lk" || Arg == "--load-keys") && i+1 < argc)	//load the public and private keys we will use
		{
			string PubKeyName = string(argv[i+1]) + ".pub";
			string PrivKeyName = string(argv[i+1]) + ".priv";
			cout << "Private Key Password: ";
			fflush(stdout);
			string Passwd = GetPassword();
			Passwd = stringMD5(Passwd);
			if(!LoadPublicKey(PubKeyName, Mod, Keys[0]))
			{
				Mod = 0;
				Keys[0] = 0;
			}
			else		//No point trying to set the private key if the public failed
				if(!LoadPrivateKey(PrivKeyName, Keys[1], Passwd))
					Keys[1] = 0;
			
			i++;
		}
		else if((Arg == "-lp" || Arg == "--load-public") && i+1 < argc)	//load the public key that the peer can decrypt
		{
			if(!LoadPublicKey(argv[i+1], MyPTP.ClientMod, MyPTP.ClientE))
			{
				MyPTP.ClientMod = 0;
				MyPTP.ClientE = 0;
			}
			i++;
		}
		else if((Arg == "-P" || Arg == "--port") && i+1 < argc)
		{
			MyPTP.Port = atoi(argv[i+1]);
			if(MyPTP.Port <= 0)
			{
				cout << "Bad port number. Using default 5001\n";
				MyPTP.Port = 5001;
			}
		}
		else if(Arg == "-dp" || Arg == "--disable-public")				//WARNIG only if peer already has public and uses -lp
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
		else
			cout << "warning: didn't understand " << Arg << endl;
	}
	#ifndef ANDROID
	PrintIP();
	#endif

	if(PrintVals)
		cout <<"Symmetric Key: " << SymmetricKey << "\n\n";
	
	GMPSeed(rng);
	if(Mod == 0)		//If one is set, they all must be set
		NewRSA.KeyGenerator(Keys, Mod, rng, ForceRand, PrintVals);
		
	if(!OutputFiles.empty())		//So, we want to output something
	{
		string PubKeyName = OutputFiles + ".pub";
		string PrivKeyName = OutputFiles + ".priv";

		cout << "Private Key Password To Use: ";
		fflush(stdout);
		string Passwd1 = GetPassword();
		cout << "Retype Password: ";
		fflush(stdout);
		string Passwd2 = GetPassword();

		if(Passwd1 != Passwd2)
		{
			cout << "Passwords do not match. Giving up on key creation\n";
		}
		else
		{
			Passwd1 = stringMD5(Passwd1);
			MakePublicKey(PubKeyName, Mod, Keys[0]);
			MakePrivateKey(PrivKeyName, Keys[1], Passwd1);
		}
	}

	cout << "All necessary Encryption values are filled\n\n";
	MyPTP.MyMod = Mod;
	MyPTP.MyE = Keys[0];
	MyPTP.MyD = Keys[1];
	MyPTP.SymKey = SymmetricKey;

	if(MyPTP.StartServer(1, SendPublic, SavePublic) != 0)
	{
		nonblock(false, true);
		cout << "Finished cleaning, Press Enter To Exit...";
		cin.get();
		return 0;
	}
	
	nonblock(false, true);
	cout << "Finished cleaning, Press Enter To Exit...";
	cin.get();
	return 0;
}

void GMPSeed(gmp_randclass& rng)
{
	//Properly Seed rand()
	FILE* random;
	unsigned int seed;
	random = fopen ("/dev/urandom", "r");		//Unix provides it, why not use it
	if(random == NULL)
	{
		fprintf(stderr, "Cannot open /dev/urandom!\n"); 
		return;
	}
	fread(&seed, sizeof(seed), 1, random);
	srand(seed); 		// seed the default random number generator
	rng.seed(seed);	// seed the GMP random number generator
}

string GetPassword()
{
	string Passwd;
	nonblock(true, false);
	while(true)
	{
		if(kbhit())
		{
			unsigned char c = getch();
			if(c == '\n')
			{
				cout << "\n";
				nonblock(false, true);
				return Passwd;
			}
			else if(c == 127)	//Backspace
			{
				if(Passwd.length() > 0)
				{
					cout << "\b \b";
					Passwd = Passwd.substr(0, Passwd.length()-1);
				}
				else if(Passwd.length() == 1)
				{
					cout << "\b \b";
					Passwd.clear();
				}
			}
			else if((int)c >= 32 && (int)c <= 126)
			{
				Passwd += c;
				cout << "*";
			}
			else
			{
				getch();
				getch();
			}
			fflush(stdout);
		}
	}
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
