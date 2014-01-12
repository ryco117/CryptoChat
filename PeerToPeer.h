#ifndef PTP
#define PTP

#include <iostream>
#include <string>
#include <cstring>
//#include <pthread.h>

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
	int StartServer(const int MAX_CLIENTS = 1);
	//void ReceiveFile(std::string Msg);

	//Client Functions
	void SendMessage(void);
	void ParseInput(void);
	//void SendFilePt1(void);
	//void SendFilePt2(void);
	void TryConnect(void);
	void DropLine(std::string pBuffer);
	static void* ConnectThread(void *ptr)
	{
		reinterpret_cast<PeerToPeer*>(ptr)->TryConnect();
	}

	
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
	unsigned int SentStuff;
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
#endif
