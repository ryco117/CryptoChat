#include "RSA.h"
#include "base64.h"

using namespace std;

void RSA::BigPrime(mpz_class& p, gmp_randclass& rng, unsigned long sz, unsigned long c)
{
	while(true)
	{
		p = rng.get_z_bits(sz);
		if(mpz_probab_prime_p(p.get_mpz_t(), c))
			break;
	}
	return;
}

mpz_class RSA::BigEncrypt(mpz_class &Modulus, mpz_class &Key, mpz_class Msg)
{
	mpz_class Cipher;
	mpz_powm(Cipher.get_mpz_t(), Msg.get_mpz_t(), Key.get_mpz_t(), Modulus.get_mpz_t());

	return Cipher;
}

mpz_class RSA::BigDecrypt(mpz_class &Modulus, mpz_class &Key, mpz_class Cypher)
{
	mpz_class BigMsg;
	mpz_powm(BigMsg.get_mpz_t(), Cypher.get_mpz_t(), Key.get_mpz_t(), Modulus.get_mpz_t());

	return BigMsg;
}

void RSA::KeyGenerator(mpz_class Keys[], mpz_class &Mod, gmp_randclass& rng, bool ForceRand, bool PrintVals)
{
	mpz_class PrimeP = 0;
	mpz_class PrimeQ = 0;
	mpz_class EulersTot = 0;
	Mod = 0;
	string Temp;

	if(ForceRand)
		Temp = "r";
	else
	{
		cout << "Prime Number P<random>: ";
		getline(cin, Temp);
	}	
	if(Temp == "rand" || Temp == "r" || Temp == "random" || Temp.empty())
	{
		BigPrime(PrimeP, rng, 2048, 24);
		if(PrintVals)
			cout << PrimeP.get_str() << "\n\n";
	}
	else
		PrimeP = mpz_class(Temp);

	if(ForceRand)
		Temp = "r";
	else
	{
		cout << "Prime Number Q<random>: ";
		getline(cin, Temp);
	}
	if(Temp == "rand" || Temp == "r" || Temp == "random" || Temp.empty())
	{
		BigPrime(PrimeQ, rng, 2048, 24);
		if(PrintVals)
			cout << PrimeQ.get_str() << "\n\n";
	}
	else
		PrimeQ = mpz_class(Temp);

	//Set Modulus
	Mod = PrimeP * PrimeQ;
	EulersTot = (PrimeP - 1) * (PrimeQ - 1);
	
	Keys[0] = 0;
	Keys[1] = 0;
	if(PrintVals)
		cout << "The Modulus is " << Export64(Mod) << "\n\n";

	//Set Encryption Key (Public)
	if(ForceRand)
		Temp = "r";
	else
	{
		cout << "Encryption Key<65537>: ";
		getline(cin, Temp);
	}
	if(Temp == "rand" || Temp == "r" || Temp == "random")
	{
		BigPrime(Keys[0], rng, 2048, 24);
		if(PrintVals)
			cout << Export64(Keys[0]) << "\n\n";
	}
	else if(Temp.empty())
	{
		Keys[0] = mpz_class(65537);
		if(PrintVals)
			cout << "65537\n\n";
	}
	else
		Keys[0] = mpz_class(Temp);
	
	//Set Decryption Key (Private)
	mpz_invert(Keys[1].get_mpz_t(), Keys[0].get_mpz_t(), EulersTot.get_mpz_t());
	
	if(PrintVals)
	{
		cout << "Eulers Totient: " << EulersTot << "\n\n";
		cout << "D is equal to: " << Keys[1] << "\n\n";
	}
	return;
}