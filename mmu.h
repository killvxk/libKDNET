#ifndef __MMU_H__
#define __MMU_H__

#include <stdint.h>


void parsePML4E(uint64_t base, const unsigned char *memory, uint64_t memSize);
uint64_t physical_virtual(uint64_t physical_addr, uint64_t base, const unsigned char *memory, uint64_t memSize);
uint64_t virtual_physical(uint64_t virtual_addr, uint64_t PML4E_base, const unsigned char *memory, uint64_t memSize);

#endif //__MMU_H__
