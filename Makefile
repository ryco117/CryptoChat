CC=g++
ACC=/usr/android-toolchain/bin/arm-linux-androideabi-g++
CFLAGS=-lgmpxx -lgmp -lscrypt -static -Wno-unused-result
ACFLAGS=-I/usr/android-toolchain/include -L/usr/android-toolchain/lib -DANDROID
OUT=./bin/CryptoChat
AOUT=./bin/AndroidChat

make:
	nasm -f elf64 -o AES-NI.o AES-NI.asm
	$(CC) -o $(OUT) AES-NI.o main.cpp $(CFLAGS)

android:
	$(ACC) -o $(AOUT) main.cpp $(ACFLAGS) $(CFLAGS)

all:
	nasm -f elf64 -o AES-NI.o AES-NI.asm
	$(CC) -o $(OUT) AES-NI.o main.cpp $(CFLAGS)
	$(ACC) -o $(AOUT) main.cpp $(ACFLAGS) $(CFLAGS)
