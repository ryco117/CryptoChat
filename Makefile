CC=g++
CFLAGS=-Wl,-Bstatic -lgmpxx -lgmp -lscrypt -Wl,-Bdynamic -Wno-unused-result -fpermissive -w
OUT=./bin/CryptoChat

make:
	nasm -f elf64 -o AES-NI.o AES-NI.asm
	$(CC) -o $(OUT) AES-NI.o main.cpp $(CFLAGS)
arm:
	$(CC) -o $(OUT) main.cpp -DARM $(CFLAGS)
