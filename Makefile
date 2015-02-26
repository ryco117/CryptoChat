CC=g++
CFLAGS=-Wl,-Bstatic -lgmpxx -lgmp -lscrypt -Wl,-Bdynamic -Wno-unused-result -fpermissive -w
OUT=./bin/CryptoChat
ACC=/usr/android-toolchain-21/bin/arm-linux-androideabi-g++
ACFLAGS=-L/usr/android-toolchain-21/lib -I/usr/android-toolchain-21/include -pie
AOUT=./bin/AndroidChat

make:
	nasm -f elf64 -o AES-NI.o AES-NI.asm
	$(CC) -o $(OUT) AES-NI.o main.cpp $(CFLAGS)
arm:
	$(CC) -o $(OUT) main.cpp -DARM $(CFLAGS)
android:
	$(ACC) -o $(AOUT) main.cpp -DARM -DANDROID $(ACFLAGS) $(CFLAGS)

