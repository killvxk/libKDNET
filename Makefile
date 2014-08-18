all:
	gcc -g -Wall aes.c cbc_aes.c sha256.c hmacsha256.c main.c -o test

