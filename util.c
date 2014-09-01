#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <malloc.h>

#include "util.h"

void push_8(FILE* fp, uint8_t data){
	fwrite(&data, sizeof(uint8_t), 1, fp);
}

uint64_t read64(uint64_t addr, const unsigned char* memory){
	uint64_t tmp;
	memcpy(&tmp, memory+addr, 8);
	return __builtin_bswap64(tmp);
}

off_t fileSize(int fd){
	return lseek(fd, 0, SEEK_END);
}


inline uint64_t _rol64(uint64_t v, uint64_t s){
	return (v<<s)|(v>>(64-s));
}


//TODO: util.c
void printHexData(uint8_t *tmp, int len){
	int i;
	for(i=0; i<len; i++){
		printf("%02x ", tmp[i]);
		if(i%16==15){
			printf("\n");
		}
	}
	if(i%16 != 0){
		printf("\n");
	}
}

inline int roundup16(int value){
 return (value + 15) & ~15;
}
