CC=g++
ACC=/usr/android-toolchain-21/bin/arm-linux-androideabi-g++
CFLAGS=-Wl,-Bstatic -lgmpxx -lgmp -lscrypt -Wl,-Bdynamic -Wno-unused-result
ACFLAGS=-I/usr/android-toolchain-21/include -L/usr/android-toolchain-21/lib -fPIE -pie -DANDROID
OUT=./bin/CryptoChat
AOUT=./bin/AndroidChat.jpg

make:
	nasm -f elf64 -o AES-NI.o AES-NI.asm
	$(CC) -o $(OUT) AES-NI.o main.cpp $(CFLAGS)

android:
	$(ACC) -o $(AOUT) main.cpp $(ACFLAGS) $(CFLAGS)

all:
	nasm -f elf64 -o AES-NI.o AES-NI.asm
	$(CC) -o $(OUT) AES-NI.o main.cpp $(CFLAGS)
	$(ACC) -o $(AOUT) main.cpp $(ACFLAGS) $(CFLAGS)
