#ifndef PTP
#define PTP

#include <iostream>
#include <string>
#include <cstring>
#include <sstream>

#include <arpa/inet.h>		//inet_addr

#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "RSA.cpp"
#include "AES.cpp"
#include "myconio.h"

class PeerToPeer
{
public:
	/*Functions*/
	//Server Functions
	int StartServer(const int MAX_CLIENTS = 1, bool SendPublic = true, string SavePublic = "");
	void ReceiveFile(std::string& Msg);
	void DropEncMsg(std::string pBuffer);		//Peer sent message (still encrypted) needs to be printed and current text dropped
	void DropAppMsg(std::string Msg);			//App needs to print message, drop user text below

	//Client Functions
	void SendMessage(void);
	void ParseInput(void);
	void TryConnect(bool SendPublic = true);
	void SendFilePt1(void);
	void SendFilePt2(void);

	
	/*Vars*/
	//Server Vars
	int Serv;					//Socket holding incoming/server stuff
	int newSocket;				//Newly accept()ed socket descriptor
	int addr_size;				//Address size
    int nbytes;					//Total bytes recieved
	bool ConnectedSrvr;
	std::string FileLoc;		//string for saving file
	unsigned int FileLength;	//length of the file
	unsigned int BytesRead;		//bytes that we have received for the file
	uint8_t PeerIV[16];			//the initialization vector for the current message
	uint8_t FileIV[16];			//the IV for the current file part
	bool HasEphemeralPub;		//Have received the public key (RSA or ECDH)
	bool HasStaticPub;			//Have the constant public key (RSA or ECDH)

	//Client Vars
	int Client;					//Socket for sending data
	std::string ClntAddr;		//string holding IP to connect to
	std::string ProxyAddr;		//string holding proxy IP if enabled
	uint16_t ProxyPort;			//Port of proxy if enabled
	bool ProxyRequest;			//Did we send a proxy request (without response)
	bool ConnectedClnt;			//have we connected to them yet?
	std::string CipherMsg;		//string holding encrypted message to send
	char OrigText[512];			//unencrypted message (or file loc) that we have typed
	int currntLength;			//Length of the message we have typed in plain text
	int CurPos;					//the cursors position (isn't very useful because arrow keys don't work)
	uint8_t Sending;			//What stage are we in sending? 0 = none, first bit set = typing file location, second bit set = sent request waiting for response
								//third bit set = sending file, final bit set = receiving file
	std::string FileToSend;		//String showing the file we are sending
	unsigned int FilePos;		//Position in the file we are sending

	//Both
	unsigned int PeerPort;
	unsigned int BindPort;
	unsigned int SentStuff;		//an int to check which stage of the connection we are on
	bool GConnected;
	bool ContinueLoop;
	bool UseRSA;
	struct sockaddr_in socketInfo;

	//Encryption
	RSA MyRSA;
	AES MyAES;
	uint8_t SymKey[32];
	uint8_t SharedKey[32];
	gmp_randclass* RNG;
	FortunaPRNG* fprng;
	//Ephemeral
	mpz_class EphMyMod;
	mpz_class EphMyE;
	mpz_class EphMyD;
	mpz_class EphClientMod;
	mpz_class EphClientE;
	uint8_t EphCurveK[32], EphCurveP[32], EphCurvePPeer[32];
	//Static (Signing)
	mpz_class StcMyMod;
	mpz_class StcMyE;
	mpz_class StcMyD;
	mpz_class StcClientMod;
	mpz_class StcClientE;
	uint8_t StcCurveK[32], StcCurveP[32], StcCurvePPeer[32];

	//FD SET
	fd_set master;				//master file descriptor list
	fd_set read_fds;			//temp file descriptor list for select()
	int fdmax;					//highest socket descriptor number
	int* MySocks;
};

bool IsIP(string& IP)										//127.0.0.1
{
	if(IP.length() >= 7 && IP.length() <= 15)
	{
        unsigned char Periods = 0;
        char PerPos[5] = {0};								//PerPos[0] is -1, three periods, then PerPos[4] points one past the string
		PerPos[0] = -1;
		PerPos[4] = IP.length();
		
        for(unsigned char i = 0; i < IP.length(); i++)
		{
			if(IP[i] == '.')
			{
				Periods += 1;
				if(Periods <= 3 && i != 0 && i != IP.length()-1)
					PerPos[Periods] = i;
				else
					return false;
			}
			else if(IP[i] < 48 || IP[i] > 57)
				return false;
		}
		
		int iTemp = 0;
		for(int i = 0; i < 4; i++)
		{
			if((PerPos[i+1]-1) != PerPos[i])				//Check for two side by side periods
			{
				const char* val = IP.substr(((signed char)PerPos[i]) + 1, PerPos[i+1] - (PerPos[i] + 1)).c_str();
				iTemp = atoi(val);
				if(iTemp > 255 || iTemp < 0)
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

in_addr_t Resolve(string& addr)
{
	in_addr_t IP;
	memset(&IP, 0, sizeof(in_addr_t));

	//Resolve IPv4 address from hostname
	struct addrinfo hints;
	struct addrinfo *info, *p;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	int Info;
	if((Info = getaddrinfo(addr.c_str(), NULL, &hints, &info)) != 0)
	{
		return IP;
	}
	p = info;
	while(p->ai_family != AF_INET)							//Make sure address is IPv4
	{
		p = p->ai_next;
	}
	IP = (((sockaddr_in*)p->ai_addr)->sin_addr).s_addr;
	freeaddrinfo(info);
	return IP;
}
#endif