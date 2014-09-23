#ifndef _CHACHAPOLY_H_
#define _CHACHAPOLY_H_

#include <nettle/chacha.h>
#include <poly1305-donna.h> 

#ifdef __cplusplus
extern "C" {
#endif

#define CHACHA_POLY1305_DIGEST_SIZE 16


typedef struct chacha_poly1305_ctx{
	uint64_t _authDataLength;
	uint64_t _dataLength;
	poly1305_context _poly;
	struct chacha_ctx _chacha;
}chacha_poly1305_ctx;

void chacha_poly1305_init(chacha_poly1305_ctx * ctx, const uint8_t key[CHACHA_KEY_SIZE], const uint8_t nonce[CHACHA_NONCE_SIZE]);
void chacha_poly1305_update(chacha_poly1305_ctx * ctx, const uint8_t *aad, size_t aadLength);
void chacha_poly1305_encrypt(chacha_poly1305_ctx * ctx, const uint8_t * source, uint64_t length, uint8_t * destination);
void chacha_poly1305_decrypt(chacha_poly1305_ctx * ctx, const uint8_t * source, uint64_t length, uint8_t * destination);
void chacha_poly1305_digest(chacha_poly1305_ctx * ctx, uint8_t authTag[CHACHA_POLY1305_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif
