all:
	gcc -g -lpcap -Wall aes.c cbc_aes.c sha256.c hmacsha256.c util.c mmu.c main.c -o test

clean:
	rm test
