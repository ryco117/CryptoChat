#ifndef RSA_CPP
#define RSA_CPP
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
	return;
}

mpz_class RSA::BigEncrypt(mpz_class& Modulus, mpz_class& Key, mpz_class& Msg)
{
	mpz_class Cipher;
	mpz_powm(Cipher.get_mpz_t(), Msg.get_mpz_t(), Key.get_mpz_t(), Modulus.get_mpz_t());

	return Cipher;
}

mpz_class RSA::BigDecrypt(mpz_class& Modulus, mpz_class& Key, mpz_class& Cipher)
{
	mpz_class BigMsg;
	mpz_powm(BigMsg.get_mpz_t(), Cipher.get_mpz_t(), Key.get_mpz_t(), Modulus.get_mpz_t());

	return BigMsg;
}

void RSA::KeyGenerator(mpz_class& Dec, mpz_class& Enc, mpz_class& Mod, gmp_randclass& rng)
{
	mpz_class PrimeP = 0;
	mpz_class PrimeQ = 0;
	mpz_class EulersTot = 0;
	Mod = 0;

	BigPrime(PrimeP, rng, 2048, 24);
	BigPrime(PrimeQ, rng, 2048, 24);

	//Set Modulus
	Mod = PrimeP * PrimeQ;
	EulersTot = (PrimeP - 1) * (PrimeQ - 1);
	mpz_xor(PrimeP.get_mpz_t(), PrimeP.get_mpz_t(), PrimeP.get_mpz_t());
	mpz_xor(PrimeQ.get_mpz_t(), PrimeQ.get_mpz_t(), PrimeQ.get_mpz_t());
	
	Enc = mpz_class(65537);
	Dec = 0;
	
	//Set Decryption Key (Private)
	mpz_invert(Dec.get_mpz_t(), Enc.get_mpz_t(), EulersTot.get_mpz_t());
	mpz_xor(EulersTot.get_mpz_t(), EulersTot.get_mpz_t(), EulersTot.get_mpz_t());
	return;
}
#endif