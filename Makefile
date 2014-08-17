all:
	gcc -g -Wall -Werror aes.c sha256.c hmacsha256.c main.c -o test

