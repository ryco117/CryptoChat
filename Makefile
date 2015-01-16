CC=g++
CFLAGS=-Wl,-Bstatic -lgmpxx -lgmp -lscrypt -Wl,-Bdynamic -Wno-unused-result -DSFMT_MEXP=19937
OUT=./bin/CryptoChat

make:
	nasm -f elf64 -o AES-NI.o AES-NI.asm
	$(CC) -o $(OUT) AES-NI.o main.cpp SFMT/SFMT.c $(CFLAGS)

all:
	nasm -f elf64 -o AES-NI.o AES-NI.asm
	$(CC) -o $(OUT) AES-NI.o main.cpp SFMT/SFMT.c $(CFLAGS)
