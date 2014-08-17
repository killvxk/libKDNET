#ifndef __HMACSHA256_H__
#define __HMACSHA256_H__

#include <inttypes.h>
#include <string.h>

#include "sha256.h"

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct _hmacSHA256Context {
    SHA256Context ctx;
    SHA256Context innerCtx;
    SHA256Context outerCtx;
} hmacSHA256Context;


int hmacSHA256Init(hmacSHA256Context *ctx, const uint8_t *key, uint32_t kLength);
void hmacSHA256Update(hmacSHA256Context *ctx, const uint8_t *data, uint32_t dLength);
void hmacSHA256Final(hmacSHA256Context *ctx, uint8_t *mac);

#endif //__HMACSHA256_H__
