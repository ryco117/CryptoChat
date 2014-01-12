#include "PeerToPeer.h"

int PeerToPeer::StartServer(const int MAX_CLIENTS)
{
	//		**-SERVER-**
	if((Serv = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) < 0)
	{
		close(Serv);
		return -1;
	}
	
	memset(&socketInfo, 0, sizeof(socketInfo));		//Used for setting up server info
	socketInfo.sin_family = AF_INET;
	socketInfo.sin_addr.s_addr = htonl(INADDR_ANY);
	socketInfo.sin_port = htons(5001);
	
	int optval = 1;
	setsockopt(Serv, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);		//Remove Bind already used error
	if(bind(Serv, (struct sockaddr*)&socketInfo, sizeof(socketInfo)) < 0)
	{
		close(Serv);
		perror("Bind");
		return -2;
	}
	listen(Serv, MAX_CLIENTS);
	
	//		**-CLIENT-**
	if(ClntIP.empty())
	{
		while(!IsIP(ClntIP))
		{
			if(!ClntIP.empty())
				cout << "That is not a properly formated IPv4 address and will not be used\n";
			cout  << "Client's IP: ";
			getline(cin, ClntIP);
		}
	}
	
	Client = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	memset(&socketInfo, 0, sizeof(socketInfo));			//Now will set up client stuff
	socketInfo.sin_family = AF_INET;
	socketInfo.sin_addr.s_addr = inet_addr(ClntIP.c_str());
	socketInfo.sin_port = htons(5001);
	
	//		**-FILE DESCRIPTORS-**
	FD_ZERO(&master);
	FD_SET(Serv, &master);
	read_fds = master;
	
	MySocks = new int[MAX_CLIENTS + 1];
	MySocks[0] = Serv;
	for(unsigned int i = 1; i < MAX_CLIENTS + 1; i++)
		MySocks[i] = -1;
	timeval zero = {0, 50};
	fdmax = Serv;
	
	//Progress checks
	SentStuff = 0;
	GConnected = false;
	ConnectedClnt = false;
	ConnectedSrvr = false;
	ContinueLoop = true;
	
	nonblock(true);
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
		
		read_fds = master;
		if(select(fdmax+1, &read_fds, NULL, NULL, &zero) == -1)		//Check for stuff to read on sockets
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
			if(MySocks[i] == -1)
				continue;
			if(FD_ISSET(MySocks[i], &read_fds))
			{
				if(i == 0)		//Connection on Serv available
				{
					if((newSocket = accept(Serv, NULL, NULL)) < 0)
					{
						close(Serv);
						perror("Accept");
						return -4;
					}
					ConnectedSrvr = true;		//Passed All Tests, We Can Say We Connected
					
					FD_SET(newSocket, &master); // add to master set
					for(unsigned int j = 1; j < MAX_CLIENTS + 1; j++)
					{
						if(MySocks[j] == -1) 	//Not in use
						{
							MySocks[j] = newSocket;
							if(newSocket > fdmax)
								fdmax = newSocket;
							break;
						}
					}
					
					char TempValArray[1060] = {'\0'};
					string TempValString;
					while(TempValString.empty())
					{
						recv(newSocket, TempValArray, 1060, 0);
						TempValString = TempValArray;
					}

					ClientMod = mpz_class(TempValString.substr(0, 705), 58);	//They sent in base 58, we must read in it
					//cout << "CM: " << ClientMod << "\n\n";
					ClientE = mpz_class(TempValString.substr(705, 355), 58);
					//cout << "CE: " << ClientE << "\n\n";
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
					else if(SentStuff == 2)
					{
						string ClntKey = buf;
						SymKey += MyRSA.BigDecrypt(MyMod, MyD, mpz_class(ClntKey, 58));		//They sent their sym key with our public key. Decrypt it!
						
						mpz_class LargestAllowed = 0;
						mpz_class One = 1;
						mpz_mul_2exp(LargestAllowed.get_mpz_t(), One.get_mpz_t(), 128);
						SymKey %= LargestAllowed;		//Modulus by largest 128 bit value ensures within range after adding!
						SentStuff = 3;
					}
					else
					{
						string Msg = "";
						for(unsigned int i = 0; i < 512; i++)
							Msg.push_back(buf[i]);
						
						DropLine(Msg);
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
			TryConnect();		//Lets try to change that
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
	
	cout << "Me: " << OrigText << endl;
	send(Client, CypherMsg.c_str(), CypherMsg.length(), 0);

	for(int i = 0; i < 1024; i++)
		OrigText[i] = '\0';		
	CypherMsg = "";
	fprintf(stderr, "Message: ");
	CurPos = 0;
	currntLength = 0;

	return;
}

void PeerToPeer::ParseInput()
{
	unsigned char c = getch();
	string TempMsg = "";

	string MyValues = "";
	string TempValues = "";

	if((int)c == '\n')	//return
	{
		TempValues = OrigText;
		if(TempValues == "*exit*")
			ContinueLoop = false;
		else
		{
			CypherMsg = MyAES.Encrypt(SymKey, TempValues);
			SendMessage();
		}
	}
	else if((int)c == 127)	//Backspace
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
	else if((int)c >= 32 && (int)c <= 126)
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

		if(currntLength == 1024)
		{
			TempValues = OrigText;
			CypherMsg = MyAES.Encrypt(SymKey, TempValues);
			SendMessage();
		}
	}
	return;
}

void PeerToPeer::DropLine(string pBuffer)
{
	cout << "\r";	//Clear what was printed
	for(int j = 0; j < currntLength + 9; j++)
		cout << " ";
	cout << "\r";

	int i = pBuffer.length() - 1;		//Before decrypting, check how many null terminators are part of the cipher text, vs were trailing in the buffer
	for(; i >= 0; i--)
		if(pBuffer[i] != '\0')
			break;
	
	if((i+1) % 16 == 0)
		pBuffer.erase(i+1, (pBuffer.length() - i));	//Erase Any null terminators that we don't want to decrypt, trailing ones
	
	cout << "Client: " << MyAES.Decrypt(SymKey, pBuffer);		//Print What we received
	cout << "\nMessage: " << OrigText;							//Print what we already had typed (creates appearance of dropping current line)
	for(int setCur = 0; setCur < currntLength - CurPos; setCur++)
		cout << "\b";

	return;
}

void PeerToPeer::TryConnect()
{
	if(connect(Client, (struct sockaddr*)&socketInfo, sizeof(socketInfo)) >= 0) //connected
	{
		fprintf(stderr, "Connected!\n");
		string TempValues = "";
		string MyValues = "";

		TempValues = MyMod.get_str(58);		//Base 58 will save digits
		while(TempValues.length() < 705)
			TempValues = "0" + TempValues;

		MyValues = TempValues;

		TempValues = MyE.get_str(58);
		while(TempValues.length() < 355)
			TempValues = "0" + TempValues;
		MyValues += TempValues;

		//Send My Public Key And My Modulus Because We Started The Connection
		if(send(Client, MyValues.c_str(), MyValues.length(), 0) < 0)
		{
			perror("Connect failure");
			return;
		}
		SentStuff = 1;			//We have sent our keys
			
		ConnectedClnt = true;
		fprintf(stderr, "Waiting...");
	}
	return;
}
