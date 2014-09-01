#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

void parsePTE(uint64_t base, uint64_t virtualAddr, const unsigned char *memory, uint64_t memSize){
	uint64_t i;
	for(i=0; i<512; i++){
		uint64_t tmp = __builtin_bswap64(read64(base+(i*8), memory));
		uint64_t PPBA = tmp & 0x000FFFFFFFFFF000;
		if(PPBA && PPBA<memSize){
			printf("virtualAddr = 0x%016lX => physicalAddr = 0x%016lX\n", virtualAddr|(i<<12), PPBA&0x3FFFFFFF);
		}
	}
}

void parsePDE(uint64_t base, uint64_t virtualAddr, const unsigned char *memory, uint64_t memSize){
	uint64_t i;
	for(i=0; i<512; i++){
		uint64_t tmp = __builtin_bswap64(read64(base+(i*8), memory));
		uint64_t PTBA = tmp & 0x000FFFFFFFFFF000;
		if(PTBA && PTBA<memSize){
			parsePTE(PTBA, virtualAddr|(i<<21), memory, memSize);
		}
	}
}

void parsePDPE(uint64_t base, uint64_t virtualAddr, const unsigned char *memory, uint64_t memSize){
	uint64_t i;
	for(i=0; i<512; i++){
		uint64_t tmp = __builtin_bswap64(read64( base+(i*8), memory));
		uint64_t PDBA = tmp & 0x000FFFFFFFFFF000;
		if(PDBA && PDBA<memSize){
			parsePDE(PDBA, virtualAddr|(i<<30), memory, memSize);
		}
	}
}

void parsePML4E(uint64_t base, const unsigned char *memory, uint64_t memSize){
	uint64_t i;
	for(i=0; i<512; i++){
		uint64_t tmp = __builtin_bswap64(read64(base+(i*8), memory));
		uint64_t PDPBA = tmp & 0x000FFFFFFFFFF000;
		if(PDPBA && PDPBA<memSize){
			parsePDPE(PDPBA, i<<39, memory, memSize);
		}
	}
}

//Get potential virtual address from physical one.
uint64_t physical_virtual(uint64_t physical_addr, uint64_t base, const unsigned char *memory, uint64_t memSize){
	uint64_t offset = physical_addr & 0xFFF;
	uint64_t i;
	for(i=0; i<512; i++){
		uint64_t PDPBA = __builtin_bswap64(read64(base+(i*8), memory))&0x000FFFFFFFFFF000;
		if(PDPBA>0 && PDPBA<memSize-PAGE_SIZE){
			uint64_t j;
			for(j=0; j<512; j++){
				uint64_t PDBA = __builtin_bswap64(read64(PDPBA+(j*8), memory))& 0x000FFFFFFFFFF000;
				if(PDBA && PDBA<memSize-PAGE_SIZE){
					uint64_t k;
					for(k=0; k<512; k++){
						uint64_t PTBA = __builtin_bswap64(read64(PDBA+(k*8), memory))& 0x000FFFFFFFFFF000;
						if(PTBA && PTBA<memSize-PAGE_SIZE){
							uint64_t l;
							for(l=0; l<512; l++){
								uint64_t PPBA = __builtin_bswap64(read64(PTBA+(l*8), memory))& 0x000FFFFFFFFFF000;
								if(PPBA && PPBA<memSize-PAGE_SIZE){
									if((physical_addr&0x000FFFFFFFFFF000) == (PPBA&0x000FFFFFFFFFF000)){
										uint64_t virtual_addr = (i<<39|j<<30|k<<21|l<<12|offset);
										//printf("virtualAddr = 0x%016lX => physicalAddr = 0x%016lX\n", virtual_addr, (PPBA&0x000FFFFFFFFFF000)|offset);
										return virtual_addr;
									}
								}
							}
						}
					}
				}
			}	
		}
	}
	return 0;
}


uint64_t virtual_physical(uint64_t virtual_addr, uint64_t PML4E_base, const unsigned char *memory, uint64_t memSize){
	uint64_t PML4E_index=(virtual_addr & 0x0000FF8000000000) >> (9+9+9+12);
	uint64_t PDPE_index =(virtual_addr & 0x0000007FC0000000) >> (9+9+12);
	uint64_t PDE_index  =(virtual_addr & 0x000000003FE00000) >> (9+12);
	uint64_t PTE_index  =(virtual_addr & 0x00000000001FF000) >> (12);
	uint64_t P_offset    =(virtual_addr & 0x0000000000000FFF);
	
	uint64_t PDPE_base = __builtin_bswap64(read64(PML4E_base+(PML4E_index*8), memory))&0x0000FFFFFFFFF000;
	printf("PDPE_base %016lx\n", PDPE_base);
	if(PDPE_base == 0
	|| PDPE_base > memSize-PAGE_SIZE){
		return 0;
	}
	
	uint64_t PDE_base = __builtin_bswap64(read64(PDPE_base+(PDPE_index*8), memory))&0x0000FFFFFFFFF000;
	printf("PDE_base %016lx\n", PDE_base);
	if(PDE_base == 0
	|| PDE_base > memSize-PAGE_SIZE){
		return 0;
	}
	
	uint64_t tmp = __builtin_bswap64(read64(PDE_base+(PDE_index*8), memory));
	uint64_t PTE_base = tmp&0x0000FFFFFFFFF000;
	printf("PTE_base %016lx\n", PTE_base);
	if(PTE_base == 0
	|| PTE_base > memSize-PAGE_SIZE){
		return 0;
	}
	uint64_t is_large_page = tmp&0x0000000000000080;
	if(is_large_page){ //This page is a large one (4M) !
		return (PTE_base|(virtual_addr&0x00000000000FFFFF));
	}
	
	uint64_t P_base = __builtin_bswap64(read64(PTE_base+(PTE_index*8), memory))&0x0000FFFFFFFFF000;
	printf("P_base %016lx\n", P_base);
	if(P_base == 0
	|| P_base > memSize-PAGE_SIZE){
		return 0;
	}
	
	return (P_base|P_offset);
}

