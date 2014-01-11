#include <iostream>

#include "PeerToPeer.cpp"
#include "myconio.h"

using namespace std;

void GMPSeed(gmp_randclass& rng);

int main(int argc, char* argv[])
{
	gmp_randclass rng(gmp_randinit_default);
	GMPSeed(rng);

	PeerToPeer MyPTP;
	RSA NewRSA;
	AES Cipher;
	mpz_class SymmetricKey = rng.get_z_bits(128);
	
	cout <<"Symmetric Key: " << SymmetricKey << "\n\n";

	mpz_class Keys[2];
	mpz_class Mod = 0;
	GMPSeed(rng);
	NewRSA.KeyGenerator(Keys, Mod, rng);

	cout << "All necessary Encryption values are filled\n\n";
	MyPTP.MyMod = Mod;
	MyPTP.MyE = Keys[0];
	MyPTP.MyD = Keys[1];
	MyPTP.SymKey = SymmetricKey;
	MyPTP.ClientMod = 0;
	MyPTP.ClientE = 0;
	MyPTP.Sending = 0;

	if(MyPTP.StartServer(1) != 0)
	{
		nonblock(false);
		cout << "Finished cleaning, Press Enter To Exit...";
		cin.get();
		return 0;
	}

	nonblock(false);
	cout << "Finished cleaning, Press Enter To Exit...";
	cin.get();
	return 0;
}

void GMPSeed(gmp_randclass& rng)
{
	//Properly Seed rand()
	FILE* random;
	unsigned int seed;
	random = fopen ("/dev/urandom", "r");
	if(random == NULL)
	{
		fprintf(stderr, "Cannot open /dev/urandom!\n"); 
		return;
	}
	fread(&seed, sizeof(seed), 1, random);
	srand(seed); 		// seed the default random number generator
	rng.seed(seed);	// seed the GMP random number generator
}
