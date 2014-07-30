#ifndef PEER_IO
#define PEER_IO
#include "PeerToPeer.h"
#include "KeyManager.h"
#include "base64.h"

int sendr(int socket, const char* buffer, int length, int flags);
int recvr(int socket, char* buffer, int length, int flags);
string GetName(string file);

void PeerToPeer::SendFilePt1()
{
	Sending = 2;
	string FileRequest = OrigText;
	fstream File(FileRequest.c_str(), ios::in);
	if(File.is_open())
	{
		FileToSend = FileRequest;
		FileRequest = GetName(FileRequest);
		File.seekg(0, File.end);
		unsigned int Length = File.tellg();
		stringstream ss;
		ss << Length;

		mpz_class IV = RNG->get_z_bits(128);
		string EncName = ss.str() + "X" + FileRequest;
		while(EncName.size() < 1024)
			EncName.push_back('\0');
		EncName = MyAES.Encrypt(SymKey, EncName, IV);
		string IVStr = Export64(IV);
		while(IVStr.size() < 27)
			IVStr.push_back('\0');
		FileRequest = "x" + IVStr + EncName;
		FileRequest[0] = 1;
		
		if(sendr(Client, FileRequest.c_str(), FileRequest.length(), 0) < 0)
		{
			perror("File request failure");
			return;
		}
		else
			cout << "\nWaiting for response...";
		File.close();
	}
	else
	{
		Sending = 0;
		cout << "\r";
		for(int i = 0; i < currntLength + 15; i++)
			cout << " ";
		cout << "\rCould not open " << FileRequest << ", file transfer cancelled.\n";
		cout << "Message: ";
		for(int i = 0; i < 512; i++)
			OrigText[i] = '\0';
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
		unsigned int FileLeft = 0;
		File.seekg(0, File.end);
		FileLeft = File.tellg() - FilePos;
		if(FileLeft > 1024)
			FileLeft = 1024;
		else
		{
			Sending = 0;	//file is done after this
			cout << "\r";
			for(int i = 0; i < currntLength + 15; i++)
				cout << " ";
			cout << "\rFinished sending " << FileToSend << ", " << (FilePos + FileLeft) << " bytes were sent";
			cout << "\nMessage: ";
		}
		char* buffer = new char[1024];
		for(int i = 0; i < 1024; i++)
			buffer[i] = 0;
		
		File.seekg(FilePos, File.beg);
		File.read(buffer, FileLeft);
		FilePos += FileLeft;
		
		string Data;
		for(int i = 0; i < 1024; i++)
			Data.push_back(buffer[i]);
		
		mpz_class IV = RNG->get_z_bits(128);
		string SIV = Export64(IV);
		while(SIV.size() < 27)
			SIV.push_back('\0');
		
		string Final = "x";
		Final += SIV;
		Final += MyAES.Encrypt(SymKey, Data, IV);
		Final[0] = 3;
		
		int n = sendr(Client, Final.c_str(), Final.length(), 0);
		if(n == -1)
		{
			perror("\nSendFilePt2");
			Sending = 0;
		}
		
		delete[] buffer;
		File.close();
	}
	return;
}

void PeerToPeer::ReceiveFile(string Msg)
{
	fstream File(FileLoc.c_str(), ios::out | ios::app | ios::binary);
	if(File.is_open())
	{
		if(BytesRead + 1024 >= FileLength)
		{
			Sending = 0;
			cout << "\r";
			for(int i = 0; i < currntLength + 15; i++)
				cout << " ";
			cout << "\rFinished saving " << FileLoc << ", " << FileLength << " bytes";
			cout << "\nMessage: " << OrigText;
		}
		
		int len = 1024;
		if(Sending == 0)
			len = FileLength - BytesRead;
		File.write(MyAES.Decrypt(SymKey, Msg, FileIV).c_str(), len);
		BytesRead += 1024;
		File.close();
	}
	else
	{
		Sending = 0;
		cout << "\r";
		for(int i = 0; i < currntLength + 15; i++)
			cout << " ";
		cout << "\rCould not open " << FileLoc << ", file transfer cancelled.\n";
		cout << "Message: " << OrigText;
	}
	return;
}

void PeerToPeer::DropLine(string pBuffer)
{
	cout << "\r";	//Clear what was already printed on this line
	for(int j = 0; j < currntLength + 15; j++)
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
	pBuffer.erase(i+1);	//Erase Any null terminators that we don't want to decrypt, trailing zeros, from i to the end of the string
	string print = MyAES.Decrypt(SymKey, pBuffer, PeerIV);
	
	cout << "Client: " << print.c_str();		//Print What we received
	return;
}

void PeerToPeer::SendMessage()
{
	cout << "\r";		//Clear what was printed
	for(int i = 0; i < currntLength + 9; i++)
		cout << " ";
	cout << "\r";
	
	cout << "Me: " << OrigText << endl;		//print "me: " then the message
	while(CipherMsg.size() < 1068)
		CipherMsg.push_back('\0');
	sendr(Client, CipherMsg.c_str(), CipherMsg.length(), 0);	//send the client the encrypted message

	for(int i = 0; i < 512; i++)	//clear the original text buffer
		OrigText[i] = '\0';
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
	mpz_class IV;

	if(c == '\n')	//return
	{
		TempValues = OrigText;
		if(!TempValues.empty())
		{
			if(TempValues == "*exit*")
			{
				if(Sending == 0)	//We were typing messages, and want to exit
					ContinueLoop = false;
				else if(Sending == 1)	//We were going to send a file, but want to cancel
				{
					Sending = 0;
					cout << "\r";
					for(int i = 0; i < currntLength + 15; i++)
						cout << " ";
					cout << "\rMessage: ";
					for(int i = 0; i < 512; i++)
						OrigText[i] = '\0';
					CurPos = 0;
					currntLength = 0;
				}
			}
			else if(TempValues == "*file*" && Sending == 0)	//We were typing messages, but want to send a file
			{
				Sending = 1;
				cout << "\r";
				for(int i = 0; i < currntLength + 9; i++)
					cout << " ";
				for(int i = 0; i < 512; i++)
					OrigText[i] = '\0';
				cout << "\rFile Location: ";
				CurPos = 0;
				currntLength = 0;
			}
			else if(Sending == 1)
				SendFilePt1();
			else
			{
				IV = RNG->get_z_bits(128);
				CipherMsg = "x" + Export64(IV);
				while(CipherMsg.size() < 28)
					CipherMsg.push_back('\0');
				CipherMsg[0] = 0;
				CipherMsg += MyAES.Encrypt(SymKey, TempValues, IV);
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
			if(Sending == 0)
			{
				TempValues = OrigText;
				IV = RNG->get_z_bits(128);
				CipherMsg = "x" + Export64(IV);
				while(CipherMsg.size() < 28)
					CipherMsg.push_back('\0');
				CipherMsg[0] = 0;
				CipherMsg += MyAES.Encrypt(SymKey, TempValues, IV);
				SendMessage();
			}
			else
			{
				Sending = 0;
				cout << "\r";
				for(int i = 0; i < currntLength + 15; i++)
					cout << " ";
				cout << "\rFile location is too large...\nMessage: ";
				for(int i = 0; i < 512; i++)
					OrigText[i] = '\0';
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

int recvr(int socket, char* buffer, int  length, int flags)
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

int sendr(int socket, const char* buffer, int length, int flags)
{
	int i = 0;
	while(i < length)
	{
		int n = send(socket, &buffer[i], length-i, flags);
		if(n <= 0)
			return n;
		i += n;
	}
	return i;
}

string GetName(string file)
{
	int i = 0, j = 0;
	while(true)
	{
		if((j = file.find("/", i)) == string::npos)
			break;
		else
			i = j+1;
	}
	if(i != 0)
		file.erase(0, i);
	return file;
}
#endif
