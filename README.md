CryptoChat
==========

A secure, terminal based chat program that uses ECC Curve25519 or 4096 bit RSA keys to exchange a
256 bit AES key, which is used for the rest of the chat. The AES is done through the intel AES-NI instructions if they are available, else, my C++ wrapper.
GMP is for large number arithmetic. 
The public and private keys generated can be stored to files to be reused. The private key may be encrypted
with 256 bit AES using a randomly generated IV and a key derived from a password using scrypt with
a random salt. Enjoy top-notch, uber-level secure chats (most often about security, you know it's
true :P ).

Arguments List
--------------

**Toggles:**
```
-dp	--disable-public	//don't send our static public key at connection
-r  --rsa				//use RSA instead of Curve25519. Peer must do this as well (note. this effects how keys are loaded, saved)
-h	--help				//print this dialogue
```
**String Inputs:**
```
-ip	--ip-address		//specify the ip address (or hostname) to attempt to connect to
-p	--proxy				//specify the address and port to use as proxy
-o	--output			//save the keys generated to files
-lk	--load-keys			//specify files to load public and private keys from
-lp	--load-public		//specify the file to load the peer's public key from
```

**Integer Inputs:**
 ```
-bp, --bind-port		//the port number to listen on
-pp, --peer-port		//the port number to connect to
```

**Input Argument Examples:**
```
-ip 192.168.1.70		//attempt to connect to 192.168.1.70
-p localhost:9050		//connect through proxy at localhost on port 9050 (tor default port number)
-o newKeys				//produce "newKeys.pub" and "newKeys.priv"
-lk Keys				//load the keys from the files "Keys.pub" and "Keys.priv"
-lp PeerKey.pub			//load the peer's public key from "PeerKey.pub"
-bp 4321				//listen for connections on port 4321
```

How To Build
------------
**x86-64**

make


**Android**

make android
