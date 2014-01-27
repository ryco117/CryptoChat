#ifndef PTP
#define PTP

#include <iostream>
#include <string>
#include <cstring>
#include <sstream>

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
	void ReceiveFile(std::string Msg);

	//Client Functions
	void SendMessage(void);
	void ParseInput(void);
	void TryConnect(bool SendPublic = true);
	void DropLine(std::string pBuffer);
	void SendFilePt1(void);
	void SendFilePt2(void);

	
	/*Vars*/
	//Server Vars
	int Serv;      //Socket holding incoming/server stuff
	int newSocket;	// newly accept()ed socket descriptor
	int addr_size;    //Address size
    int nbytes;       //Total bytes recieved
	bool ConnectedSrvr;
	std::string FileLoc;		//string for saving file
	unsigned int FileLength;	//length of the file
	unsigned int BytesRead;		//bytes that we have received for the file
	mpz_class PeerIV;			//the initialization vector for the current message
	mpz_class FileIV;			//the IV for the current file part

	//Client Vars
	int Client;				//Socket for sending data
	std::string ClntIP;		//string holding IP to connect to
	bool ConnectedClnt;		//have we connected to them yet?
	std::string CipherMsg;	//string holding encrypted message to send
	char OrigText[512];	//unencrypted message (or file loc) that we have typed
	int currntLength;		//Length of the message we have typed in plain text
	int CurPos;				//the cursors position (isn't very useful because arrow keys don't work)
	int Sending;			//What stage are we in sending? 0 = none, positive = trying to send message, negative = receiving
	std::string FileToSend;	//String showing the file we are sending
	unsigned int FilePos;	//Position in the file we are sending

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
	gmp_randclass* RNG;

	//FD SET
	fd_set master;		// master file descriptor list
	fd_set read_fds;	// temp file descriptor list for select()
	int fdmax;			// highest socket descriptor number
	int* MySocks;
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
