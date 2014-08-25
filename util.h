#ifndef __UTIL_H__
#define __UTIL_H__

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

#define KB 1024
#define MB 1024*KB
#define GB 1024*MB
#define PAGE_SIZE 4096

void push_8(FILE* fp, uint8_t data);
uint64_t read64(uint64_t addr, const unsigned char* memory);
off_t fileSize(int fd);
inline uint64_t _rol64(uint64_t v, uint64_t s);

#endif //__UTIL_H__
