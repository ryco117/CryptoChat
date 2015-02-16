#ifndef ECDSA_H
#define ECDSA_H

#include <gmpxx.h>
#include "fortuna.h"
#include "curve25519-donna.c"

static const uint8_t Curve25519Base[32] = {9};

//Finite Field Math
//--------------------------------------------------------------------------------------------------------------------------------------------
mpz_class AddMod(mpz_class a, mpz_class b, mpz_class m)
{
	mpz_class r = a+b;
	mpz_mod(r.get_mpz_t(), r.get_mpz_t(), m.get_mpz_t());
	return r;
}

mpz_class SubMod(mpz_class a, mpz_class b, mpz_class m)
{
	mpz_class r = a-b;
	mpz_mod(r.get_mpz_t(), r.get_mpz_t(), m.get_mpz_t());
	return r;
}

mpz_class MultMod(mpz_class a, mpz_class b, mpz_class m)
{
	mpz_class r = a * b;
	mpz_mod(r.get_mpz_t(), r.get_mpz_t(), m.get_mpz_t());
	return r;
}

mpz_class DivMod(mpz_class a, mpz_class b, mpz_class m)
{
	mpz_class r;
	mpz_invert(r.get_mpz_t(), b.get_mpz_t(), m.get_mpz_t());
	r *= a;
	mpz_mod(r.get_mpz_t(), r.get_mpz_t(), m.get_mpz_t());
	return r;
}

mpz_class SqrMod(mpz_class x, mpz_class m)
{
	mpz_class r;
	mpz_powm(r.get_mpz_t(), x.get_mpz_t(), mpz_class(2).get_mpz_t(), m.get_mpz_t());
	return r;
}

mpz_class CubeMod(mpz_class x, mpz_class m)
{
	mpz_class r;
	mpz_powm(r.get_mpz_t(), x.get_mpz_t(), mpz_class(3).get_mpz_t(), m.get_mpz_t());
	return r;
}

//Finite Field Point Math
//----------------------------------------------------------------------------------------------------------------------------------------

//Weierstrass curve
void ECWeierAdd(mpz_class x1, mpz_class y1, mpz_class x2, mpz_class y2, mpz_class& x3, mpz_class& y3, mpz_class mod)
{
	mpz_class Lambda = DivMod(SubMod(y2, y1, mod), SubMod(x2, x1, mod), mod);
	x3 = SubMod(SubMod(SqrMod(Lambda, mod), x1, mod), x2, mod);
	y3 = SubMod(MultMod(Lambda, SubMod(x1, x3, mod), mod), y1, mod);
	return;
}

void ECWeierDouble(mpz_class x, mpz_class y, mpz_class& x3, mpz_class& y3, mpz_class a, mpz_class mod)
{
	mpz_class Lambda = DivMod(AddMod(MultMod(mpz_class(3), SqrMod(x, mod), mod), a, mod), MultMod(mpz_class(2), y, mod), mod);		// (3x^2 + a)/(2y)
	x3 = SubMod(SqrMod(Lambda, mod), MultMod(mpz_class(2), x, mod), mod);
	y3 = SubMod(MultMod(Lambda, SubMod(x, x3, mod), mod), y, mod);
	return;
}

void ECWeierMultiply(mpz_class& Gx, mpz_class& Gy, mpz_class a, mpz_class k, mpz_class mod, unsigned int m = 255)
{
	mpz_class Qx = Gx;
	mpz_class Qy = Gy;

	for(unsigned int i = m;; i--)
	{
		if(mpz_tstbit(k.get_mpz_t(), i))
		{
			m = i;
			break;
		}
	}

	for(unsigned int i = m-1;; i--)
	{
		ECWeierDouble(Qx, Qy, Qx, Qy, a, mod);
		if(mpz_tstbit(k.get_mpz_t(), i))
			ECWeierAdd(Qx, Qy, Gx, Gy, Qx, Qy, mod);
		if(i == 0)
			break;
	}

	Gx = Qx;
	Gy = Qy;
	return;
}

//Montgomery curve
/*
void ECMontAdd(mpz_class X1, mpz_class Z1, mpz_class X2, mpz_class Z2, mpz_class& X3, mpz_class& Z3, mpz_class mod)
{
	mpz_class M1 = MultMod(SubMod(X1, Z1, mod), AddMod(X2, Z2, mod), mod);						//(X_1 - Z_1)*(X_2 + Z_2)
	mpz_class M2 = MultMod(AddMod(X1, Z1, mod), SubMod(X2, Z2, mod), mod);						//(X_1 + Z_1)*(X_2 - Z_2)
	X3 = MultMod(mpz_class(1), SqrMod(AddMod(M1, M2, mod), mod), mod);							//Z_0 * (M1 + M2)^2
	Z3 = MultMod(mpz_class(9), SqrMod(SubMod(M1, M2, mod), mod), mod);							//X_0 * (M1 - M2)^2
	return;
}

void ECMontDouble(mpz_class X, mpz_class Z, mpz_class& X2, mpz_class& Z2, mpz_class a, mpz_class mod)
{
	mpz_class t = SubMod(SqrMod(AddMod(X, Z, mod), mod), SqrMod(SubMod(X, Z, mod), mod), mod);									//(X+Z)^2 - (X-Z)^2

	X2 = MultMod(MultMod(SqrMod(AddMod(X, Z, mod), mod), SqrMod(SubMod(X, Z, mod), mod), mod), mpz_class(16), mod);				//(X+Z)^2 * (X-Z)^2 * 16
	Z2 = MultMod(AddMod(MultMod(16, SqrMod(SubMod(X, Z, mod), mod), mod), MultMod(t, mpz_class(1946656), mod), mod), t, mod);	//((16 * (X-Z)^2) + (t * 1946656)) * t
	return;
}

void ECMontMultiply(mpz_class& X, mpz_class& Z, mpz_class a, mpz_class k, mpz_class mod)
{
	mpz_class R0X = X;
	mpz_class R0Z = Z;
	mpz_class R1X = X;
	mpz_class R1Z = Z;

	for(unsigned int i = 253;; i--)
	{
		if(!mpz_tstbit(k.get_mpz_t(), i))
		{
			ECMontAdd(R0X, R0Z, R1X, R1Z, R1X, R1Z, mod);
			ECMontDouble(R0X, R0Z, R0X, R0Z, a, mod);
		}
		else
		{
			ECMontAdd(R0X, R0Z, R1X, R1Z, R0X, R0Z, mod);
			ECMontDouble(R1X, R1Z, R1X, R1Z, a, mod);
		}
		if(i == 0)
			break;
	}
	return;
}
*/

//Actual ECC specific stuff
//------------------------------------------------------------------------
void ECC_CreateKeys(mpz_class& K, mpz_class& X, mpz_class& Y, mpz_class a, mpz_class mod, mpz_class n, gmp_randclass& rng, bool montgomery = false)
{
	mpz_class PubX, PubY, r;
	while(true)
	{
		while(K <= 1 || (K > n-1 && !montgomery))
		{
			K = rng.get_z_bits(256);
		}

		/*if(montgomery)
		{
			mpz_clrbit(K.get_mpz_t(), 0);
			mpz_clrbit(K.get_mpz_t(), 1);
			mpz_clrbit(K.get_mpz_t(), 2);
			mpz_clrbit(K.get_mpz_t(), 255);
			mpz_setbit(K.get_mpz_t(), 254);

			ECMontMultiply(PubX, K, Curve25519Base);
			break;
		}
		else
		{*/
			PubX = X;
			PubY = Y;
			ECWeierMultiply(PubX, PubY, a, K, mod, 255);
			mpz_mod(r.get_mpz_t(), PubX.get_mpz_t(), n.get_mpz_t());
			if(r != 0)
				break;
		//}
	}
	X = PubX;
	if(!montgomery)
		Y = PubY;

	return;
}

void ECC_Curve25519_Create(uint8_t pub[32], uint8_t k[32], FortunaPRNG& fprng)
{
	fprng.GenerateBlocks(k, 2);
	k[0] &= 248;
	k[31] &= 127;
	k[31] |= 64;

	curve25519_donna(pub, k, Curve25519Base);
	return;
}
#endif
