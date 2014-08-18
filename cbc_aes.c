#include <stdint.h>
#include <malloc.h>
#include <string.h>


#include "aes.h"
#include "cbc_aes.h"

//Only 256 Bits
//TODO: no copy... bla bla bla, move it in aes.c...
BYTE* cbc_decrypt(BYTE* ciphered, int ciphered_len, WORD* w, BYTE* iv){
	BYTE current_clear_block[16];
	BYTE last_ciphered_block[16];
	BYTE current_ciphered_block[16];
	BYTE *clear;
	int i, j;
	
	clear = (BYTE*)malloc(sizeof(BYTE)*ciphered_len);
	memcpy(last_ciphered_block, iv, 16);

	/*printf("IV : ");
	for(i=0; i<16; i++){
		printf("%02x ", iv[i]);
	}
	printf("\n");
	printf("First block : ");
	for(i=0; i<16; i++){
		printf("%02x ", ciphered[i]);
	}
	printf("\n");*/

	
	for(i=0; i<ciphered_len/16; i++){
		memcpy(current_ciphered_block, ciphered+(i*16), 16);
		aes_decrypt(current_ciphered_block, current_clear_block, w, 256);
		for(j=0; j<16; j++){
			current_clear_block[j] = current_clear_block[j]^last_ciphered_block[j];
		}
		memcpy(last_ciphered_block, current_ciphered_block, 16);
		
		for(j=0; j<16; j++){
			printf("%02x ", current_clear_block[j]);
		}
		printf("\n");
		memcpy(clear+(i*16), current_clear_block, 16);
	}
	return clear;
}

//TODO: NO COPY !!!
//TODO: rename plaintext and ciphertext
BYTE* cbc_encrypt(BYTE* clear, int clear_len, WORD* w, BYTE* iv){
	BYTE* ciphered;
	BYTE last_ciphered_block[16];
	BYTE current_ciphered_block[16];
	BYTE current_clear_block[16];
	int i, j;
	
	ciphered = (BYTE*)malloc(sizeof(BYTE)*clear_len);
	memcpy(last_ciphered_block, iv, 16);
	
	for(i=0; i<clear_len/16; i++){
		memcpy(current_clear_block, clear+(i*16), 16);
		for(j=0; j<16; j++){
			current_clear_block[j] = current_clear_block[j]^last_ciphered_block[j];
		}
		aes_encrypt(current_clear_block, current_ciphered_block, w, 256);
		memcpy(last_ciphered_block, current_ciphered_block, 16);
		for(j=0; j<16; j++){
			printf("%02x ", current_ciphered_block[j]);
		}
		printf("\n");
		memcpy(ciphered+(i*16), current_ciphered_block, 16);
	}
	return ciphered;
}

/*void test_cbc(){
	WORD testcbcW[14*32];
	aes_key_setup(test_cbc_key, testcbcW, 256);

	BYTE* tmp = cbc_decrypt(test_cbc_data, sizeof(test_cbc_data), testcbcW, test_cbc_iv);
	printf("\nEncrypted ->\n");
	cbc_encrypt(tmp, sizeof(test_cbc_data), testcbcW, test_cbc_iv);
}*/
