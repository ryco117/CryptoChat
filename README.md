CryptoSending
=============

A Secure Terminal Based Chat Program That Uses 4096 bit RSA keys to exchange a 128 bit AES key,
which is used for the rest of the chat. It uses GMP for it's large number arithmetic.

Arguments:
-p	--print		Print all generated encryption values
-r	--random		Randomly generate all encryption values without asking
-ip	--ip-address	specify the ip address to attempt to connect to

How To Build:
x86
g++ -static -O3 main.cpp -lgmpxx -lgmp -w
