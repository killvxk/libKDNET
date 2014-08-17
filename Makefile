all:
	gcc -g -Wall  aes.c sha256.c hmacsha256.c main.c -o test

