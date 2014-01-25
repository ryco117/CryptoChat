#include "PeerToPeer.h"
#include "KeyManager.h"

int PeerToPeer::StartServer(const int MAX_CLIENTS, bool SendPublic, string SavePublic)
{
	//		**-SERVER-**
	if((Serv = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) < 0)		//assign Serv to a file descriptor (socket) that uses IP addresses, TCP
	{
		close(Serv);
		return -1;
	}
	
	memset(&socketInfo, 0, sizeof(socketInfo));			//Clear data inside socketInfo to be filled with server stuff
	socketInfo.sin_family = AF_INET;					//Use IP addresses
	socketInfo.sin_addr.s_addr = htonl(INADDR_ANY);		//Allow connection from anybody
	socketInfo.sin_port = htons(Port);					//Use port Port
	
	int optval = 1;
	setsockopt(Serv, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);		//Remove Bind already used error
	if(bind(Serv, (struct sockaddr*)&socketInfo, sizeof(socketInfo)) < 0)	//Bind socketInfo to Serv
	{
		close(Serv);
		perror("Bind");
		return -2;
	}
	listen(Serv, MAX_CLIENTS);			//Listen for connections on Serv
	
	//		**-CLIENT-**
	if(ClntIP.empty())					//If we didn't set the client ip as an argument
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
	
	nonblock(true, false);
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
		
		read_fds = master;			//assign read_fds back to the unchanged master
		if(select(fdmax+1, &read_fds, NULL, NULL, &zero) == -1)		//Check for stuff to read on sockets, up to fdmax+1.. stop check after timeval zero (50ms)
		{
			cout << "\r";
			for(int j = 0; j < currntLength + 9; j++)
				cout << " ";
			cout << "\r";
			
			perror("Select");
			return -3;
		}
		for(unsigned int i = 0; i < MAX_CLIENTS + 1; i++)		//Look through all sockets
		{
			if(MySocks[i] == -1)		//if MySocks[i] == -1 then go just continue the for loop, this part of the array hasn't been assigned a socket
				continue;
			if(FD_ISSET(MySocks[i], &read_fds))		//check read_fds to see if there is unread data in MySocks[i]
			{
				if(i == 0)		//if i = 0, then based on line 52, we know that we are looking at data on the Serv socket... This means new connection!!
				{
					if((newSocket = accept(Serv, NULL, NULL)) < 0)		//assign socket newSocket to the person we are accepting on Serv
					{
						close(Serv);				//unless it errors
						perror("Accept");
						return -4;
					}
					ConnectedSrvr = true;		//Passed All Tests, We Can Safely Say We Connected
					
					FD_SET(newSocket, &master); // add the newSocket FD to master set
					for(unsigned int j = 1; j < MAX_CLIENTS + 1; j++)	//assign an unassigned MySocks to newSocket
					{
						if(MySocks[j] == -1) 	//Not in use
						{
							MySocks[j] = newSocket;
							if(newSocket > fdmax)		//if the new file descriptor is greater than fdmax..
								fdmax = newSocket;		//change fdmax to newSocket
							break;
						}
					}
					
					if(ClientMod == 0)		//Check if we haven't already assigned the client's public key through an arg.
					{
						char TempValArray[1060] = {'\0'};
						string TempValString;
						while(TempValString.empty())		//while the string we are filling with received data is empty...
						{
							recv(newSocket, TempValArray, 1060, 0);
							TempValString = TempValArray;
						}

						ClientMod = mpz_class(TempValString.substr(0, 705), 58);	//They sent in base 58, we must read in it. Chars 0 - 704 are for the modulus
						//cout << "CM: " << ClientMod << "\n\n";
						ClientE = mpz_class(TempValString.substr(705, 355), 58);	//Chars 705 - 1059 (355 chars to read) are for the much smaller encryption value
						//cout << "CE: " << ClientE << "\n\n";
						
						if(!SavePublic.empty())		//If we set the string for where to save their public key...
							MakePublicKey(SavePublic, ClientMod, ClientE);		//SAVE THEIR PUBLIC KEY!
					}
				}
				else		//Data is on a new socket
				{
					char buf[1024] = {'\0'};
					for(unsigned int j = 0; j < 1024; j++)
						buf[j] = '\0';
					
					if((nbytes = recv(MySocks[i], buf, 1024, 0)) <= 0)		//handle data from a client
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
					else if(SentStuff == 2)		//if SentStuff == 2, then we still need the symmetric key
					{
						string ClntKey = buf;
						SymKey += MyRSA.BigDecrypt(MyMod, MyD, mpz_class(ClntKey, 58));		//They sent their sym key with our public key. Decrypt it!
						
						mpz_class LargestAllowed = 0;
						mpz_class One = 1;
						mpz_mul_2exp(LargestAllowed.get_mpz_t(), One.get_mpz_t(), 128);		//Largest allowed sym key is equal to (1 * 2^128)
						SymKey %= LargestAllowed;		//Modulus by largest 128 bit value ensures within range after adding keys!
						SentStuff = 3;
					}
					else
					{
						string Msg = "";	//1 char for type, varying extension info, actual main data
											//0 = msg        , 22 chars for IV       , 512 message chars
						for(unsigned int i = 0; i < 535; i++)			//If we do a simple assign, the string will stop reading at a null terminator ('\0')
							Msg.push_back(buf[i]);						//so manually push back all values in array buf...
						if(Msg[0] == 0)									//		^
						{												//		|
							PeerIV = mpz_class(Msg.substr(1, 22), 58);	//		|
							Msg = Msg.substr(23, 512);					//		|
							DropLine(Msg);								//		|   causes a problem which i will explain in this function.
							if(Sending == 0)
							{
								cout << "\nMessage: " << OrigText;							//Print what we already had typed (creates appearance of dropping current line)
								for(int setCur = 0; setCur < currntLength - CurPos; setCur++)	//set cursor position to what it previously was (for when arrow keys are handled)
									cout << "\b";
							}
						}
					}
				}
			}//End FD_ISSET
		}//End For Loop for sockets
		if(kbhit())		//Check for keypress
		{
			if(GConnected)		//So nothing happens until we are ready...
				ParseInput();
			else
				getch();		//And keypresses before hand arent read when we are.
		}
		
		if(!ConnectedClnt)		//Not conected yet?!?
		{
			TryConnect(SendPublic);		//Lets try to change that
		}
		if(SentStuff == 1 && ClientMod != 0 && ClientE != 0)		//We have established a connection and we have their keys!
		{
			string MyValues = (MyRSA.BigEncrypt(ClientMod, ClientE, SymKey)).get_str(58);	//Encrypt The Symmetric Key With Their Public Key, base 58
			
			//Send The Encrypted Symmetric Key
			if(send(Client, MyValues.c_str(), MyValues.length(), 0) < 0)
			{
				perror("Connect failure");
				return -5;
			}
			SentStuff = 2;			//We have given them our symmetric key
		}
		fflush(stdout);		//Not always does cout print immediately, this forces it.
	}//End While Loop
	cout << "\n";
	return 0;
}

void PeerToPeer::SendMessage()
{
	cout << "\r";		//Clear what was printed
	for(int i = 0; i < currntLength + 9; i++)
		cout << " ";
	cout << "\r";
	
	cout << "Me: " << OrigText << endl;		//print "me: " then the message
	send(Client, CypherMsg.c_str(), CypherMsg.length(), 0);	//send the client the encrypted message

	for(int i = 0; i < 1024; i++)	//clear the original text buffer
		OrigText[i] = '\0';
	CypherMsg = "";
	fprintf(stderr, "Message: ");
	CurPos = 0;
	currntLength = 0;

	return;
}

//Lots of char parsing crap...
void PeerToPeer::ParseInput()
{
	unsigned char c = getch();
	string TempValues = "";
	mpz_class IV;

	if(c == '\n')	//return
	{
		TempValues = OrigText;
		if(!TempValues.empty())
		{
			if(TempValues == "*exit*")
				ContinueLoop = false;
			else
			{
				IV = RNG->get_z_bits(128);
				CypherMsg = "x" + IV.get_str(58);
				CypherMsg[0] = 0;
				CypherMsg += MyAES.Encrypt(SymKey, TempValues, IV);
				SendMessage();
			}
		}
	}
	else if(c == 127 || c == '\b')	//Backspace
	{
		if(CurPos > 0)
		{
			cout << "\b";

			if(CurPos < currntLength)
			{
				for(int i = 0; i < currntLength - CurPos; i++)
				{
					cout << OrigText[CurPos + i];

					OrigText[CurPos + i - 1] = OrigText[CurPos + i];
				}
				OrigText[currntLength - 1] = '\0';
				cout << " ";

				for(int undo = 0; undo <= currntLength - CurPos; undo++)
					cout << "\b";
			}
			else
			{
				cout << " \b";
				OrigText[CurPos - 1] = '\0';
			}

			currntLength--;
			CurPos--;
		}
	}
	else if(c >= 32 && c <= 126)	//within range for a standard alpha-numeric-special char
	{
		cout << c;
		if(CurPos < currntLength)
		{
			for(int i = 0; i < currntLength - CurPos; i++)
				OrigText[currntLength - i] = OrigText[currntLength - i - 1];

			for(int i = 1; i <= currntLength - CurPos; i++)
				cout << OrigText[CurPos + i];

			for(int undo = 0; undo < currntLength - CurPos; undo++)
				cout << "\b";
		}

		OrigText[CurPos] = c;
		
		currntLength++;
		CurPos++;

		if(currntLength == 512)	//reached max allowed chars per message
		{
			TempValues = OrigText;
			IV = RNG->get_z_bits(128);
			CypherMsg = "x" + IV.get_str(58);
			CypherMsg[0] = 0;
			CypherMsg += MyAES.Encrypt(SymKey, TempValues, IV);
			SendMessage();
		}
	}
	else	//Some special input... These input usually also send two more chars with it, which we don't want to interpret next loop (because they are alpha-numeric)
	{
		getch();
		getch();
	}
	return;
}

void PeerToPeer::DropLine(string pBuffer)
{
	cout << "\r";	//Clear what was already printed on this line
	for(int j = 0; j < currntLength + 9; j++)
		cout << " ";
	cout << "\r";

	//We pushed back all values in the 1024 byte large array buf, but the message may have been shorter than that, so...
	int i = pBuffer.length() - 1;	//before decrypting, check how many null terminators are part of the cipher text vs were added to the back from buf, but weren't recieved
	for(; i >= 0; i--)	//This is done by iterating from the back of the buffer, looking for where the first non zero value is
	{
		if(pBuffer[i] != '\0')
			break;
	}
	while((i+1) % 16 != 0)		//Then increasing the position until it is a multiple of 16 (because AES uses blocks of 16 bytes)
		i++;
	pBuffer.erase(i+1, (pBuffer.length() - i));	//Erase Any null terminators that we don't want to decrypt, trailing zeros, from i to the end of the string
	
	cout << "Client: " << MyAES.Decrypt(SymKey, pBuffer, PeerIV);		//Print What we received
	return;
}

void PeerToPeer::TryConnect(bool SendPublic)
{
	if(connect(Client, (struct sockaddr*)&socketInfo, sizeof(socketInfo)) >= 0) 	//attempt to connect using socketInfo with client values
	{
		fprintf(stderr, "Connected!\n");
		if(SendPublic)
		{
			string TempValues = "";
			string MyValues = "";

			TempValues = MyMod.get_str(58);		//Base 58 will save digits
			while(TempValues.length() < 705)	//Make sure modulus is 705 chars long
				TempValues = "0" + TempValues;	//do this by adding leading zeros (to not change value)

			MyValues = TempValues;

			TempValues = MyE.get_str(58);
			while(TempValues.length() < 355)	//makes sure exp is 355 chars long
				TempValues = "0" + TempValues;	//do this by adding leading zeros (to not change value)
			MyValues += TempValues;				//MyValues is equal to the string for the modulus + string for exp concatenated

			//Send My Public Key And My Modulus Because We Started The Connection
			if(send(Client, MyValues.c_str(), MyValues.length(), 0) < 0)
			{
				perror("Connect failure");
				return;
			}
		}
		SentStuff = 1;			//We have sent our keys
			
		ConnectedClnt = true;
		fprintf(stderr, "Waiting...");
	}
	return;
}