#include "RSA.h"

using namespace std;

void RSA::BigPrime(mpz_class& p, gmp_randclass& rng, unsigned long sz, unsigned long c)
{
	while(true)
	{
		p = rng.get_z_bits(sz);
		if(mpz_probab_prime_p(p.get_mpz_t(), c))
			break;
	}
	cout << p << "\n\n";
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

void RSA::KeyGenerator(mpz_class Keys[], mpz_class &Mod, gmp_randclass& rng)
{
	mpz_class PrimeP = 0;
	mpz_class PrimeQ = 0;
	mpz_class EulersTot = 0;
	Mod = 0;
	string Temp;

	cout << "Prime Number P: ";
	getline(cin, Temp);
	if(Temp == "rand" || Temp == "r")
		BigPrime(PrimeP, rng, 2048, 24);
	else
		PrimeP = mpz_class(Temp);

	cout << "Prime Number Q: ";
	getline(cin, Temp);
	if(Temp == "rand" || Temp == "r")
		BigPrime(PrimeQ, rng, 2048, 24);
	else
		PrimeQ = mpz_class(Temp);

	//Set Modulus
	Mod = PrimeP * PrimeQ;
	EulersTot = (PrimeP - 1) * (PrimeQ - 1);
	
	Keys[0] = 0;
	Keys[1] = 0;
	cout << "The Modulus is " << Mod << "\n\n";

	//Set Encryption Key (Public)
	cout << "Encryption Key<65537 good>: ";
	getline(cin, Temp);
	if(Temp == "rand" || Temp == "r")
		BigPrime(Keys[0], rng, 2048, 24);
	else
		Keys[0] = mpz_class(Temp);

	//Set Decryption Key (Private)
	mpz_invert(Keys[1].get_mpz_t(), Keys[0].get_mpz_t(), EulersTot.get_mpz_t());

	cout << "D is equal to: " << Keys[1] << endl << endl;

	return;
}
