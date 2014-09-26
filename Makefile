CC=g++
ACC=/usr/android-toolchain/bin/arm-linux-androideabi-g++
CFLAGS=-O3 -lgmpxx -lgmp -lscrypt -static -Wno-unused-result
ACFLAGS=-I/usr/android-toolchain/include -L/usr/android-toolchain/lib -DANDROID
OUT=./bin/CryptoChat
AOUT=./bin/AndroidChat

make:
	$(CC) -o $(OUT) main.cpp $(CFLAGS)

android:
	$(ACC) -o $(AOUT) main.cpp $(ACFLAGS) $(CFLAGS)

all:
	$(CC) -o $(OUT) main.cpp $(CFLAGS)
	$(ACC) -o $(AOUT) main.cpp $(ACFLAGS) $(CFLAGS)
