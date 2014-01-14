CryptoSending
=============

A Secure Terminal Based Chat Program That Uses 4096 bit RSA keys to exchange a 128 bit AES key,
which is used for the rest of the chat. It uses GMP for it's large number arithmetic.

Arguments List

Toggles:
-p	--print			print all generated encryption values																						works
-r	--random			randomly generate all encryption values without prompting																		works
-dp	--disable-public	don't send our public key at connection. WARNING! peer must use -lp and have our public key										works
-h	--help			print this dialogue																										works

String Inputs:
-ip	--ip-address		specify the ip address to attempt to connect to																				works							
-o	--output			save the rsa keys generated to files which can be reused																		works
-sp,	--save-public		save the peers public key to a specified file
-lk	--load-keys		specify the files to load rsa keys from (public and private) that we will use														works
-lp	--load-public		specify the file to load rsa public key from that the peer has the private key to													implemented without checked

Integer Inputs:
-P, --ports		the port number to open and connect to

Input Argument Examples:
-ip 192.168.1.70	will connect to 192.168.1.70
-o newKeys		will produce newKeys.pub and newKeys.priv
-sp peerKey.pub		will create the file peerKey.pub with the peer's rsa public key
-lk Keys		will load the rsa values from the files Keys.pub and Keys.priv
-lp PeerKey.pub		will load the peer's public key from PeerKey.pub
-P 4321		will open port number 4321 for this session, and will connect to the same number

How To Build:
x86
g++ -static -O3 main.cpp -lgmpxx -lgmp -w
