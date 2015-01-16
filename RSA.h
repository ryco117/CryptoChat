#ifndef MYRSA
#define MYRSA

#include <cmath>
#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include <time.h>
#include <stdlib.h>
#include <gmpxx.h>

using namespace std;

class RSA
{
public:
	void BigPrime(mpz_class& p, gmp_randclass& rng, unsigned long sz, unsigned long c);
	void KeyGenerator(mpz_class& Private, mpz_class& Public, mpz_class& Mod, gmp_randclass& rng);
	
	mpz_class BigEncrypt(mpz_class& Modulus, mpz_class& Key, mpz_class& Msg);
	mpz_class BigDecrypt(mpz_class& Modulus, mpz_class& Key, mpz_class& Cipher);
};
#endif