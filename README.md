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
-m	--manual			//WARNING! this stops auto-assigning random RSA key values and is pretty much strictly for debugging
-dp	--disable-public	//don't send your public key at connection. WARNING! peer must use -lp and have your public key
-r  --rsa				//use RSA instead of Curve25519. Peer must do this aswell (note. this effects how keys are loaded, saved)
-h	--help				//print this dialogue
```
**String Inputs:**
```
-ip	--ip-address		//specify the ip address to attempt to connect to
-p	--proxy				//use proxy at IPv4 address and port
-o	--output			//save the keys generated to files which can be reused
-sp --save-public		//save the peers public key to a specified file
-lk	--load-keys			//specify the files to load keys from (public and private) to use
-lp	--load-public		//specify the file to load the peer's public key from
```

**Integer Inputs:**
 ```
-P, --ports				//the port number to open and connect to
```

**Input Argument Examples:**
```
-ip 192.168.1.70		//attempt to connect to 192.168.1.70
-p 127.0.0.1:9050		//connect through proxy at localhost on port 9050 (tor default port number)
-o newKeys				//produce newKeys.pub and newKeys.priv
-sp peerKey.pub			//create the file peerKey.pub with the peer's rsa public key
-lk Keys				//load the values from the files Keys.pub and Keys.priv
-lp PeerKey.pub			//load the peer's public key from PeerKey.pub
-P 4321					//open port number 4321 for this session, and will connect to the same number
```

How To Build
------------
**x86-64**

make


**Android**

make android
