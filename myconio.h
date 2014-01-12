#ifndef MYCONIO
#define MYCONIO

#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>

/*
 *  kbhit()  --  a keyboard lookahead monitor, returns amount of chars available to read. Allows for nonblocking input
 */
int kbhit()
{
	struct timeval tv;
	fd_set fds;
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	FD_ZERO(&fds);
	FD_SET(STDIN_FILENO, &fds); //STDIN_FILENO is 0
	select(STDIN_FILENO+1, &fds, NULL, NULL, &tv);
	return FD_ISSET(STDIN_FILENO, &fds);
}

/*
 *  nonblock(bool)  --  Change canonical mode state
 */
void nonblock(bool nb)
{
	struct termios ttystate;

	//get the terminal state
	tcgetattr(STDIN_FILENO, &ttystate);

	if(nb)
	{
		//turn off canonical mode
		ttystate.c_lflag &= ~ICANON;
		//turn echo off
		ttystate.c_lflag &= ~ECHO;
		//minimum of number input read.
		ttystate.c_cc[VMIN] = 1;
	}
	else if(!nb)
	{
		//turn on canonical mode
		ttystate.c_lflag |= ICANON;
		//turn echo on
		ttystate.c_lflag |= ECHO;
	}
	//set the terminal attributes.
	tcsetattr(STDIN_FILENO, TCSANOW, &ttystate);
}

char getch()		//Just for portability with windows
{
	char c = fgetc(stdin);
	return c;
}

#endif
