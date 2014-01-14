#ifndef PTP
#define PTP

#include <iostream>
#include <string>
#include <cstring>

#include <arpa/inet.h>		//inet_addr

#include <unistd.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>

#include "RSA.cpp"
#include "AES.cpp"
#include "myconio.h"

class PeerToPeer
{
public:
	/*Functions*/
	//Server Functions
	int StartServer(const int MAX_CLIENTS = 1, bool SendPublic = true, string SavePublic = "");
	//void ReceiveFile(std::string Msg);

	//Client Functions
	void SendMessage(void);
	void ParseInput(void);
	//void SendFilePt1(void);
	//void SendFilePt2(void);
	void TryConnect(bool SendPublic = true);
	void DropLine(std::string pBuffer);

	
	/*Vars*/
	//Server Vars
	int Serv;      //Socket holding incoming/server stuff
	int newSocket;	// newly accept()ed socket descriptor
	int addr_size;    //Address size
    int nbytes;       //Total bytes recieved
	bool ConnectedSrvr;
	std::string FileLoc;
	std::string AcceptFile;

	//Client Vars
	int Client;		//Socket for sending data
	std::string ClntIP;
	bool ConnectedClnt;
	std::string CypherMsg;
	char OrigText[1024];
	int currntLength;
	int CurPos;
	int Sending;

	//Both
	unsigned int Port;
	unsigned int SentStuff;		//an int to check which stage of the connection we are on
	bool GConnected;
	bool ContinueLoop;
	struct sockaddr_in socketInfo;

	//Encryption
	RSA MyRSA;
	AES MyAES;
	mpz_class MyMod;
	mpz_class MyE;
	mpz_class MyD;
	mpz_class ClientMod;
	mpz_class ClientE;
	mpz_class SymKey;

	//FD SET
	fd_set master;		// master file descriptor list
	fd_set read_fds;	// temp file descriptor list for select()
	int fdmax;			// highest socket descriptor number
	int* MySocks;
	
	//PThread
	//pthread_t pthand;	//Handle to the thread
};

bool IsIP(string IP)		//127.0.0.1
{
	if(IP.length() >= 7 && IP.length() <= 15)
	{
		char Periods = 0;
		char PerPos[5] = {0};	//PerPos[0] is 0, three periods, then PerPos[4] points one past the string
		for(unsigned int i = 0; i < IP.length(); i++)
		{
			if(IP[i] == '.')
			{
				Periods++;
				if(Periods <= 3 && i != 0 && i != IP.length()-1)
					PerPos[Periods] = i;
				else
					return false;
			}
			else if(IP[i] < 48 || IP[i] > 57)
				return false;
		}
		PerPos[4] = IP.length();
		int iTemp = 0;
		for(int i = 0; i < 4; i++)
		{
			if((PerPos[i+1]-1) - PerPos[i] > 0)		//Check for two side by side periods
			{
				iTemp = atoi(IP.substr(PerPos[i], PerPos[i+1] - PerPos[i]).c_str());
				if(iTemp > 255)
					return false;
			}
			else
				return false;
		}
	}
	else
		return false;
	
	return true;
}
#endif
