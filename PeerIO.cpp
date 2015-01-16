#ifndef PEER_IO
#define PEER_IO
#include "PeerToPeer.h"
#include "KeyManager.h"
#include "base64.h"

int recvr(int socket, char* buffer, int length, int flags);
const char* GetName(const char* file);

void PeerToPeer::SendFilePt1()
{
	Sending &= 128;						//Clear all but don't change receive status
	Sending |= 2;						//Set request bit
	FileToSend = OrigText;
	fstream File(OrigText, ios::in);
	if(File.is_open())
	{
		char* FileRequest = new char[RECV_SIZE];
		memset(FileRequest, 0, RECV_SIZE);
		
		const char* Name = GetName(OrigText);
		File.seekg(0, File.end);
		__uint64_t Length = File.tellg();
		Length = __bswap_64(Length);

		unsigned int EncLength = 8 + strlen(Name);
		__uint32_t LenPadded = PaddedSize(EncLength);
		char* EncName = new char[LenPadded];
		memset(EncName, 0, LenPadded);
		memcpy(EncName, (void*)(&Length), 8);
		memcpy(&EncName[8], Name, strlen(Name));
		
		uint8_t IV[16];
		sfmt_fill_small_array64(sfmt, (uint64_t*)IV, 2);
		string IVStr = Base64Encode((char*)IV, 16);
		while(IVStr.size() < IV64_LEN)
			IVStr.push_back('\0');
		
		MyAES.Encrypt(EncName, EncLength, IV, SymKey, EncName);
		
		FileRequest[0] = 1;
		memcpy(&FileRequest[1], IVStr.c_str(), IV64_LEN);
		memcpy(&FileRequest[1 + IV64_LEN + 4], EncName, LenPadded);
		LenPadded = htonl(LenPadded);
		memcpy(&FileRequest[1 + IV64_LEN], &LenPadded, 4);
		
		delete[] EncName;
		if(send(Client, FileRequest, RECV_SIZE, 0) < 0)
		{
			Sending &= 128;
			perror("File request failure");
		}
		else
			cout << "\nWaiting for response...";
		
		delete[] FileRequest;
		File.close();
	}
	else
	{
		Sending &= 128;
		cout << "\r";
		for(int i = 0; i < currntLength + 15; i++)
			cout << " ";
		cout << "\rCould not open " << OrigText << ", file transfer cancelled.\n";
		cout << "Message: ";
		memset(OrigText, 0, 512);
		CurPos = 0;
		currntLength = 0;
	}
	return;
}

void PeerToPeer::SendFilePt2()
{
	fstream File(FileToSend.c_str(), ios::in | ios::binary);
	if(File.is_open())
	{
		char* FilePiece = new char[RECV_SIZE];
		memset(FilePiece, 0, RECV_SIZE);
		
		unsigned int FileLeft = 0;
		File.seekg(0, File.end);
		FileLeft = (unsigned int)File.tellg() - FilePos;
		if(FileLeft > FILE_PIECE_LEN)
			FileLeft = FILE_PIECE_LEN;
		else
		{
			Sending &= 128;				//file is done after this
			memset(OrigText, 0, 512);
			CurPos = 0;
			currntLength = 0;
			cout << "\r";
			for(int i = 0; i < currntLength + 15; i++)
				cout << " ";
			cout << "\rFinished sending " << FileToSend << ", " << (FilePos + FileLeft) << " bytes were sent";
			cout << "\nMessage: ";
		}
		
		unsigned int LenPadded = PaddedSize(FileLeft);
		char* Data = new char[LenPadded];
		
		File.seekg(FilePos, File.beg);
		File.read(Data, FileLeft);
		FilePos += FileLeft;
		
		uint8_t IV[16];
		sfmt_fill_small_array64(sfmt, (uint64_t*)IV, 2);
		string IVStr = Base64Encode((char*)IV, 16);
		while(IVStr.size() < IV64_LEN)
			IVStr.push_back('\0');
		
		MyAES.Encrypt(Data, FileLeft, IV, SymKey, Data);
		FilePiece[0] = 3;
		memcpy(&FilePiece[1], IVStr.c_str(), IV64_LEN);
		LenPadded = htonl(LenPadded);
		memcpy(&FilePiece[1 + IV64_LEN], &LenPadded, 4);
		LenPadded = htonl(LenPadded);
		memcpy(&FilePiece[1 + IV64_LEN + 4], Data, LenPadded);
		
		int n = send(Client, FilePiece, RECV_SIZE, 0);
		if(n == -1)
		{
			perror("\nSendFilePt2");
			Sending &= 128;
		}
		delete[] FilePiece;
		memset(Data, 0, LenPadded);
		delete[] Data;
		File.close();
	}
	return;
}

void PeerToPeer::ReceiveFile(string& Msg)
{
	fstream File(FileLoc.c_str(), ios::out | ios::app | ios::binary);
	if(File.is_open())
	{
		char* Data = new char[Msg.length()];
		unsigned int DataSize = 0;
		
		DataSize = MyAES.Decrypt(Msg.c_str(), Msg.length(), FileIV, SymKey, Data);
		if(DataSize == -1)
		{
			Sending &= 127;
			memset(Data, 0, DataSize);
			delete[] Data;
			cout << "There was an issue decrypting file\n";
			cout << "Message: ";
			return;
		}
		File.write(Data, DataSize);
		memset(Data, 0, DataSize);
		delete[] Data;
		
		BytesRead += DataSize;
		if(BytesRead == FileLength)
		{
			Sending &= 127;
			cout << "\r";
			for(int i = 0; i < currntLength + 15; i++)
				cout << " ";
			cout << "\rFinished saving " << FileLoc << ", " << FileLength << " bytes";
			cout << "\nMessage: " << OrigText;
			
			FileLength = 0;
		}
		File.close();
	}
	else
	{
		Sending &= 127;
		cout << "\r";
		for(int i = 0; i < currntLength + 15; i++)
			cout << " ";
		cout << "\rCould not open " << FileLoc << ", file transfer cancelled.\n";
		cout << "Message: " << OrigText;
	}
	return;
}

void PeerToPeer::DropEncMsg(string pBuffer)
{
	cout << "\r";												//Clear what was already printed on this line
	for(int j = 0; j < currntLength + 15; j++)
		cout << " ";
	cout << "\r";
	
	char* print = new char[pBuffer.length()];
	MyAES.Decrypt(pBuffer.c_str(), pBuffer.length(), PeerIV, SymKey, print);
	cout << "Client: " << print;								//Print What we received
	
	memset(print, 0, pBuffer.length());
	delete[] print;
	
	if((Sending & 1) == 0)
		cout << "\nMessage: " << OrigText;							//Print what we already had typed (creates appearance of dropping current line)
	else
		cout << "\nFile Location: " << OrigText;
	for(int setCur = 0; setCur < currntLength - CurPos; setCur++)	//set cursor position to what it previously was (for when arrow keys are handled)
		cout << "\b";
	
	return;
}

void PeerToPeer::DropAppMsg(string Msg)
{
	cout << "\r";													//Clear what was already printed on this line
	for(int j = 0; j < currntLength + 15; j++)
		cout << " ";
	cout << "\r";
	cout << Msg;													//Print What we received
	if((Sending & 1) == 0)
		cout << "\nMessage: " << OrigText;							//Print what we already had typed (creates appearance of dropping current line)
	else
		cout << "\nFile Location: " << OrigText;
	for(int setCur = 0; setCur < currntLength - CurPos; setCur++)	//set cursor position to what it previously was (for when arrow keys are handled)
		cout << "\b";
	
	return;
}

void PeerToPeer::SendMessage()
{
	cout << "\r";												//Clear what was printed
	for(int i = 0; i < currntLength + 9; i++)
		cout << " ";
	cout << "\r";
	
	cout << "Me: " << OrigText << endl;							//print "me: " then the message
	
	while(CipherMsg.size() < RECV_SIZE)
		CipherMsg.push_back('\0');
	
	send(Client, CipherMsg.c_str(), RECV_SIZE, 0);		//send the client the encrypted message

	memset(OrigText, 0, 512);
	CipherMsg = "";
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
	uint8_t IV[16];

	if(c == '\n')	//return
	{
		TempValues = OrigText;
		if(!TempValues.empty())
		{
			if(TempValues == "*exit*")
			{
				if((Sending & 1) == 0)							//We were typing messages, and want to exit
					ContinueLoop = false;
				else											//We were going to send a file, but want to cancel
				{
					Sending &= 128;
					cout << "\r";
					for(int i = 0; i < currntLength + 15; i++)
						cout << " ";
					cout << "\rMessage: ";
					memset(OrigText, 0, 512);
					CurPos = 0;
					currntLength = 0;
				}
			}
			else if(TempValues == "*file*" && (Sending & 127) == 0)		//We were typing messages, but want to send a file
			{
				Sending |= 1;
				cout << "\r";
				for(int i = 0; i < currntLength + 9; i++)
					cout << " ";
				memset(OrigText, 0, 512);
				cout << "\rFile Location: ";
				CurPos = 0;
				currntLength = 0;
			}
			else if(Sending & 1)
				SendFilePt1();
			else
			{
				sfmt_fill_small_array64(sfmt, (uint64_t*)IV, 2);
				CipherMsg = "x";
				char* IVStr = Base64Encode((char*)IV, 16);
				CipherMsg += IVStr;
				while(CipherMsg.size() < 1 + IV64_LEN)
					CipherMsg.push_back('\0');
				
				CipherMsg[0] = 0;
				unsigned int CipherSize = PaddedSize(TempValues.length());
				char* Cipher = new char[CipherSize];
				MyAES.Encrypt(TempValues.c_str(), TempValues.length(), IV, SymKey, Cipher);
				
				//Network Endian
				CipherMsg.push_back((char)((__uint32_t)CipherSize >> 24));
				CipherMsg.push_back((char)(((__uint32_t)CipherSize >> 16) & 0xFF));
				CipherMsg.push_back((char)(((__uint32_t)CipherSize >> 8) & 0xFF));
				CipherMsg.push_back((char)((__uint32_t)CipherSize & 0xFF));
				for(int i = 0; i < CipherSize; i++)
					CipherMsg.push_back(Cipher[i]);
				
				delete[] IVStr;
				delete[] Cipher;
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
			if((Sending & 1) == 0)
			{
				sfmt_fill_small_array64(sfmt, (uint64_t*)IV, 2);
				CipherMsg = "x";
				char* IVStr = Base64Encode((char*)IV, 16);
				CipherMsg += IVStr;
				while(CipherMsg.size() < 1 + IV64_LEN)
					CipherMsg.push_back('\0');
				
				CipherMsg[0] = 0;
				unsigned int CipherSize = PaddedSize(512);
				char* Cipher = new char[CipherSize];
				MyAES.Encrypt(OrigText, TempValues.length(), IV, SymKey, Cipher);
				
				//Network Endian
				CipherMsg.push_back((char)((__uint32_t)CipherSize >> 24));
				CipherMsg.push_back((char)(((__uint32_t)CipherSize >> 16) & 0xFF));
				CipherMsg.push_back((char)(((__uint32_t)CipherSize >> 8) & 0xFF));
				CipherMsg.push_back((char)((__uint32_t)CipherSize & 0xFF));
				for(int i = 0; i < CipherSize; i++)
					CipherMsg.push_back(Cipher[i]);
				
				delete[] IVStr;
				delete[] Cipher;
				SendMessage();
			}
			else
			{
				Sending &= 128;
				DropAppMsg("\rFile location is too large...");
				memset(OrigText, 0, 512);
			}
		}

	}
	else	//Some special input... These input usually also send two more chars with it, which we don't want to interpret next loop (because they are alpha-numeric)
	{
		getch();
		getch();
	}
	return;
}

int recvr(int socket, char* buffer, int length, int flags)
{
	int i = 0;
	while(i < length)
	{
		int n = recv(socket, &buffer[i], length-i, flags);
		if(n <= 0)
			return n;
		i += n;
	}
	return i;
}

const char* GetName(const char* file)
{
	const char* Name = strrchr(file, '/');
	if(Name == NULL)
		Name = file;
	else
		Name = &Name[1];
	return Name;
}
#endif