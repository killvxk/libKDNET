#include <inttypes.h>
#include <string.h>

#include "sha256.h"
#include "hmacsha256.h"

int hmacSHA256Init(hmacSHA256Context *ctx, const uint8_t *key, uint32_t kLength){
    int32_t i;
    uint8_t localPad[SHA256_BLOCK_SIZE] = {0};
    uint8_t localKey[SHA256_BLOCK_SIZE] = {0};

    if (key == NULL)
        return 0;

    memset(ctx, 0, sizeof(hmacSHA256Context));

    /* check key length and reduce it if necessary */
    if (kLength > SHA256_BLOCK_SIZE) {
        SHA256Init(&ctx->ctx);
        SHA256Update(&ctx->ctx, key, kLength);
        SHA256Final(&ctx->ctx, localKey);
    }
    else {
        memcpy(localKey, key, kLength);
    }
    
    /* prepare inner hash and hold the context */
    for (i = 0; i < SHA256_BLOCK_SIZE; i++)
        localPad[i] = localKey[i] ^ 0x36;

    SHA256Init(&ctx->innerCtx);
    SHA256Update(&ctx->innerCtx, localPad, SHA256_BLOCK_SIZE);

    /* prepare outer hash and hold the context */
    for (i = 0; i < SHA256_BLOCK_SIZE; i++)
        localPad[i] = localKey[i] ^ 0x5c;

    SHA256Init(&ctx->outerCtx);
    SHA256Update(&ctx->outerCtx, localPad, SHA256_BLOCK_SIZE);

    /* copy prepared inner hash to work hash - ready to process data */
    memcpy(&ctx->ctx, &ctx->innerCtx, sizeof(SHA256Context));

    memset(localKey, 0, sizeof(localKey));

    return 1;
}

void hmacSHA256Update(hmacSHA256Context *ctx, const uint8_t *data, uint32_t dLength){
    /* hash new data to work hash context */
    SHA256Update(&ctx->ctx, data, dLength);
}

void hmacSHA256Final(hmacSHA256Context *ctx, uint8_t *mac){
    uint8_t tmpDigest[SHA256_DIGEST_SIZE];

    /* finalize work hash context */
    SHA256Final(&ctx->ctx, tmpDigest);

    /* copy prepared outer hash to work hash */
    memcpy(&ctx->ctx, &ctx->outerCtx, sizeof(SHA256Context));

    /* hash inner digest to work (outer) hash context */
    SHA256Update(&ctx->ctx, tmpDigest, SHA256_DIGEST_SIZE);

    /* finalize work hash context to get the hmac*/
	SHA256Final(&ctx->ctx, mac);
}

//TODO: keyLen...
void hmachSHA256(uint8_t *data, int dataLen, uint8_t* key, uint8_t* output){
	hmacSHA256Context myHmacSHA256Context;
	hmacSHA256Init(&myHmacSHA256Context, key, 32);
	hmacSHA256Update(&myHmacSHA256Context, data, dataLen);
	hmacSHA256Final(&myHmacSHA256Context, output);
}
