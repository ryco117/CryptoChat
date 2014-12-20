#include "PeerToPeer.h"
#include "KeyManager.h"
#include "base64.h"
#include "PeerIO.cpp"

int PeerToPeer::StartServer(const int MAX_CLIENTS, bool SendPublic, string SavePublic)
{
	//		**-SERVER-**
	if((Serv = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) < 0)		//assign Serv to a file descriptor (socket) that uses IP addresses, TCP
	{
		close(Serv);
		return -1;
	}
	
	memset(&socketInfo, 0, sizeof(socketInfo));				//Clear data inside socketInfo to be filled with server stuff
	socketInfo.sin_family = AF_INET;					//Use IP addresses
	socketInfo.sin_addr.s_addr = htonl(INADDR_ANY);				//Allow connection from anybody
	socketInfo.sin_port = htons(Port);					//Use port Port
	
	int optval = 1;
	setsockopt(Serv, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);	//Remove Bind already used error
	if(bind(Serv, (struct sockaddr*)&socketInfo, sizeof(socketInfo)) < 0)	//Bind socketInfo to Serv
	{
		close(Serv);
		perror("Bind");
		return -2;
	}
	listen(Serv, MAX_CLIENTS);			//Listen for connections on Serv
	
	//		**-CLIENT-**
	if(ClntIP.empty())				//If we didn't set the client ip as an argument
	{
		while(!IsIP(ClntIP))			//Keep going until we enter a real ip
		{
			if(!ClntIP.empty())
				cout << "That is not a properly formated IPv4 address and will not be used\n";
			cout  << "Client's IP: ";
			getline(cin, ClntIP);
		}
	}
	
	Client = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);			//assign Client to a file descriptor (socket) that uses IP addresses, TCP
	memset(&socketInfo, 0, sizeof(socketInfo));					//Clear socketInfo to be filled with client stuff
	socketInfo.sin_family = AF_INET;							//uses IP addresses
	socketInfo.sin_addr.s_addr = inet_addr(ClntIP.c_str());		//connects to the ip we specified
	socketInfo.sin_port = htons(Port);							//uses port Port
	
	//		**-FILE DESCRIPTORS-**
	FD_ZERO(&master);											//clear data in master
	FD_SET(Serv, &master);										//set master to check file descriptor Serv
	read_fds = master;											//the read_fds will check the same FDs as master
	
	MySocks = new int[MAX_CLIENTS + 1];							//MySocks is a new array of sockets (ints) as long the max connections + 1
	MySocks[0] = Serv;											//first socket is the server FD
	for(unsigned int i = 1; i < MAX_CLIENTS + 1; i++)			//assign all the empty ones to -1 (so we know they haven't been assigned a socket)
		MySocks[i] = -1;
	timeval zero = {0, 50};										//called zero for legacy reasons... assign timeval 50 milliseconds
	fdmax = Serv;												//fdmax is the highest file descriptor to check (because they are just ints)
	
	//Progress checks
	SentStuff = 0;
	GConnected = false;											//GConnected allows us to tell if we have set all the initial values, but haven't begun the chat
	ConnectedClnt = false;
	ConnectedSrvr = false;
	ContinueLoop = true;
	
	nonblock(true, false);										//nonblocking input, disable echo
	while(ContinueLoop)
	{
		if(!GConnected && ConnectedClnt && ConnectedSrvr && SentStuff == 3)	//All values have been sent, then set, but we haven't begun! Start already!
		{
			GConnected = true;
			cout << "\r          \r";
			currntLength = 0;
			CurPos = 0;
			for(int j = 0; j < 512; j++)
				OrigText[j] = '\0';

			cout << "Message: ";
		}
		
		read_fds = master;											//assign read_fds back to the unchanged master
		if(select(fdmax+1, &read_fds, NULL, NULL, &zero) == -1)		//Check for stuff to read on sockets, up to fdmax+1.. stop check after timeval zero (50ms)
		{
			cout << "\r";
			for(int j = 0; j < currntLength + 9; j++)
				cout << " ";
			cout << "\r";
			
			perror("Select");
			return -3;
		}
		for(unsigned int i = 0; i < MAX_CLIENTS + 1; i++)			//Look through all sockets
		{
			if(MySocks[i] == -1)		//if MySocks[i] == -1 then go just continue the for loop, this part of the array hasn't been assigned a socket
				continue;
			if(FD_ISSET(MySocks[i], &read_fds))						//check read_fds to see if there is unread data in MySocks[i]
			{
				if(i == 0)		//if i = 0, then based on line 54, we know that we are looking at data on the Serv socket... This means a new connection!!
				{
					if((newSocket = accept(Serv, NULL, NULL)) < 0)	//assign socket newSocket to the person we are accepting on Serv
					{
						close(Serv);								//...unless it errors
						perror("Accept");
						return -4;
					}
					ConnectedSrvr = true;							//Passed All Tests, We Can Safely Say We Connected
					
					FD_SET(newSocket, &master); 					// add the newSocket FD to master set
					for(unsigned int j = 1; j < MAX_CLIENTS + 1; j++)	//assign an unassigned MySocks to newSocket
					{
						if(MySocks[j] == -1) 	//Not in use
						{
							MySocks[j] = newSocket;
							if(newSocket > fdmax)					//if the new file descriptor is greater than fdmax..
								fdmax = newSocket;					//change fdmax to newSocket
							break;
						}
					}
					if(UseRSA && !HasPub)					//Check if we haven't already assigned the client's public key through an arg.
					{
						char* TempVA = new char[MAX_RSA_SIZE];
						string TempVS;
						nbytes = recvr(newSocket, TempVA, MAX_RSA_SIZE, 0);
						
						for(unsigned int i = 0; i < nbytes; i++)
							TempVS.push_back(TempVA[i]);
						
						try
						{
							Import64(TempVS.substr(0, TempVS.find("|", 1)).c_str(), ClientMod);		//Modulus in Base64 in first half
							//cout << "CM: " << Export64(ClientMod) << "\n\n";
						}
						catch(int e)
						{
							cout << "The received modulus is bad\n";
							return -1;
						}
						
						try
						{
							Import64(TempVS.substr(TempVS.find("|", 1)+1).c_str(), ClientE);		//Encryption key in Base64 in second half
							//cout << "CE: " << Export64(ClientE) << "\n\n";
						}
						catch(int e)
						{
							cout << "The received RSA encryption key is bad\n";
							return -1;
						}
						if(!SavePublic.empty())														//If we set the string for where to save their public key...
							MakeRSAPublicKey(SavePublic, ClientMod, ClientE);						//SAVE THEIR PUBLIC KEY!
						
						delete[] TempVA;
					}
					else if(!UseRSA)
					{
						if(!HasPub)
						{
							nbytes = recvr(newSocket, (char*)CurvePPeer, 32, 0);
							if(!SavePublic.empty())
								MakeCurvePublicKey(SavePublic, CurvePPeer);
						}
						
						unsigned char SaltStr[16] = {'\x43','\x65','\x12','\x94','\x83','\x05','\x73','\x37','\x65','\x93','\x85','\x64','\x51','\x65','\x64','\x94'};
						unsigned char Hash[32] = {0};

						curve25519_donna(SharedKey, CurveK, CurvePPeer);						
						libscrypt_scrypt(SharedKey, 32, SaltStr, 16, 16384, 14, 2, Hash, 32);		//Use agreed upon salt
						mpz_import(SymKey.get_mpz_t(), 32, 1, 1, 0, 0, Hash);
					}
					HasPub = true;
				}
				else		//Data is on a new socket
				{
					char buf[RECV_SIZE];	//RECV_SIZE is the max possible incoming data (2048 byte file part with 24 byte iv and leading byte)
					memset(buf, 0, RECV_SIZE);
					
					if((nbytes = recvr(MySocks[i], buf, RECV_SIZE, 0)) <= 0)		//handle data from a client
					{
						// got error or connection closed by client
						if(nbytes == 0)
						{
							// connection closed
							cout << "\r";
							for(int j = 0; j < currntLength + 9; j++)
								cout << " ";
							cout << "\r";
							cout <<"Server: socket " << MySocks[i] << " hung up\n";
							return 0;
						}
						else
						{
							cout << "\r         \r";
							perror("Recv");
						}
						close(MySocks[i]); // bye!
						MySocks[i] = -1;
						FD_CLR(MySocks[i], &master); // remove from master set
						ContinueLoop = false;
					}
					else if(SentStuff == 2 && UseRSA)						//if SentStuff == 2, then we still need the symmetric key (should only get here if RSA)
					{
						string ClntKey = buf;
						mpz_class TempKey;
						try
						{
							Import64(ClntKey.c_str(), TempKey);
						}
						catch(int e)
						{
							cout << "The received symmetric key is bad\n";
						}
						SymKey += MyRSA.BigDecrypt(MyMod, MyD, TempKey);								//They sent their sym. key with our public key. Decrypt it!
						
						mpz_class LargestAllowed = 0;
						mpz_class One = 1;
						mpz_mul_2exp(LargestAllowed.get_mpz_t(), One.get_mpz_t(), 256);					//Largest allowed sym key is equal to (1 * 2^256) - 1
						mpz_mod(SymKey.get_mpz_t(), SymKey.get_mpz_t(), LargestAllowed.get_mpz_t());	//Modulus by largest 256 bit value ensures within range after adding keys!
						SentStuff = 3;
					}
					else
					{
						string Msg = "";	//lead byte for data id | Initialization Vector			| data length identifier	| main data
											//-------------------------------------------------------------------------------------------------------------------------------------
											//0 = msg				| IV64_LEN chars for encoded IV	| __int32 message length	| Enc. message
											//1 = file request		| IV64_LEN chars for encoded IV | __int32 information length| Enc. __uint64 file length & file name
											//2 = request answer 	|								| (none, always 1 byte)		| response (not encrypted because a MitM would know anyway)
											//3 = file piece		| IV64_LEN chars for encoded IV	| __int32 file piece length	| Enc. file piece
						
						if(buf[0] == 0)
						{
							nbytes = ntohl(*((__int32_t*)&buf[1 + IV64_LEN]));
							for(unsigned int i = 0; i < 1 + IV64_LEN + 4 + (unsigned int)nbytes; i++)	//If we do a simple assign, the string will stop reading at a null terminator ('\0')
								Msg.push_back(buf[i]);													//so manually push back values in array buf...
							
							try
							{
								Import64(Msg.substr(1, IV64_LEN).c_str(), PeerIV);
								Msg = Msg.substr(1 + IV64_LEN + 4);
							}
							catch(int e)
							{
								cout << "The received IV is bad (Message)\n";
								continue;
							}
							
							DropLine(Msg);
							if(Sending != 1)
								cout << "\nMessage: " << OrigText;							//Print what we already had typed (creates appearance of dropping current line)
							else
								cout << "\nFile Location: " << OrigText;
							for(int setCur = 0; setCur < currntLength - CurPos; setCur++)	//set cursor position to what it previously was (for when arrow keys are handled)
								cout << "\b";
						}
						else if(buf[0] == 1)
						{
							nbytes = ntohl(*((__int32_t*)&buf[1 + IV64_LEN]));
							for(unsigned int i = 0; i < 1 + IV64_LEN + 4 + (unsigned int)nbytes; i++)
								Msg.push_back(buf[i]);
							
							try
							{
								Import64(Msg.substr(1, IV64_LEN).c_str(), PeerIV);
								Msg = Msg.substr(1 + IV64_LEN + 4);
							}
							catch(int e)
							{
								cout << "The received IV is bad (File Request)\n";
								continue;
							}

							char* PlainText = new char[Msg.size() + 1];
							PlainText[Msg.size()] = 0;
							int PlainSize = MyAES.Decrypt(Msg.c_str(), Msg.size(), PeerIV, SymKey, PlainText);
							if(PlainSize == -1)
							{
								cout << "The received file request is bad\n";
								continue;
							}
							
							FileLength =  __bswap_64(*((__uint64_t*)PlainText));
							FileLoc = &PlainText[8];
							
							cout << "\rSave " << FileLoc << ", " << FileLength << " bytes<y/N>";
							char c = getch();
							cout << c;
							if(c == 'y' || c == 'Y')
							{
								c = 'y';
								BytesRead = 0;
								Sending = -1;		//Receive file mode
							}
							else
							{
								c = 'n';
								Sending = 0;
							}
							char* Accept = new char[RECV_SIZE];
							memset(Accept, 0, RECV_SIZE);				//Don't send over 1KB of recently freed memory over network...
							Accept[0] = 2;
							Accept[1] = c;
							send(Client, Accept, RECV_SIZE, 0);
							cout << "\nMessage: " << OrigText;
							
							memset(PlainText, 0, nbytes);
							delete[] PlainText;
							delete[] Accept;
						}
						else if(buf[0] == 2 && Sending == 2)
						{
							if(buf[1] == 'y')
							{
								Sending = 3;
								FilePos = 0;
							}
							else
							{
								Sending = 0;
								cout << "\r";
								for(int i = 0; i < currntLength + 15; i++)
									cout << " ";
								cout << "\rPeer rejected file. The transfer was cancelled.";
							}
							cout << "\nMessage: ";
							memset(OrigText, 0, 512);
							CurPos = 0;
							currntLength = 0;
						}
						else if(buf[0] == 3 && Sending == -1)
						{
							nbytes = ntohl(*((__int32_t*)&buf[1 + IV64_LEN]));
							for(unsigned int i = 0; i < 1 + IV64_LEN + 4 + (unsigned int)nbytes; i++)
								Msg.push_back(buf[i]);
							
							try
							{
								Import64(Msg.substr(1, IV64_LEN).c_str(), FileIV);
								Msg = Msg.substr(1 + IV64_LEN + 4);
							}
							catch(int e)
							{
								cout << "The received IV is bad (File Piece)\n";
								Sending = 0;
								continue;
							}
							ReceiveFile(Msg);
						}
					}
				}
			}//End FD_ISSET
		}//End For Loop for sockets
		if(kbhit())		//Check for keypress
		{
			if(GConnected && Sending != 2)													//So nothing happens until we are ready...
				ParseInput();
			else
				getch();																	//And keypresses before hand arent read when we are.
		}
		if(Sending == 3)
			SendFilePt2();
		if(!ConnectedClnt)																	//Not conected yet?!?
		{
			TryConnect(SendPublic);															//Lets try to change that
		}
		if(SentStuff == 1 && HasPub)														//We have established a connection and we have their keys!
		{
			if(UseRSA)
			{
				mpz_class Values = MyRSA.BigEncrypt(ClientMod, ClientE, SymKey);			//Encrypt The Symmetric Key With Their Public Key
				string MyValues = Export64(Values);											//Base 64
				
				//Send The Encrypted Symmetric Key
				if(send(Client, MyValues.c_str(), MyValues.length(), 0) < 0)
				{
					perror("Connect failure");
					return -5;
				}
				SentStuff = 2;																//We have given them our symmetric key
			}
			else
				SentStuff = 3;																//Have their public and they have ours... We're done setting up
		}
		fflush(stdout);																		//Not always does cout print immediately, this forces it.
	}//End While Loop

	memset(OrigText, 0, 512);
	cout << "\n";
	close(Serv);
	close(Client);
	return 0;
}

void PeerToPeer::TryConnect(bool SendPublic)
{
	if(connect(Client, (struct sockaddr*)&socketInfo, sizeof(socketInfo)) >= 0) 			//attempt to connect using socketInfo with client values
	{
		fprintf(stderr, "Connected!\n");
		if(SendPublic)
		{
			if(UseRSA)
			{
				string TempValues = "";
				string MyValues = "";

				TempValues = Export64(MyMod);												//Base64 will save digits
				MyValues = TempValues + "|";												//Pipe char to seperate keys

				TempValues = Export64(MyE);
				MyValues += TempValues;														//MyValues is equal to the string for the modulus + string for exp concatenated

				//Send My Public Key And My Modulus Because We Started The Connection
				if(send(Client, MyValues.c_str(), MyValues.length(), 0) < 0)
				{
					perror("Connect failure");
					return;
				}
			}
			else
			{
				if(send(Client, CurveP, 32, 0) < 0)
				{
					perror("Connect failure");
					return;
				}
			}
		}
		SentStuff = 1;			//We have sent our keys
			
		ConnectedClnt = true;
		fprintf(stderr, "Waiting...");
	}
	return;
}