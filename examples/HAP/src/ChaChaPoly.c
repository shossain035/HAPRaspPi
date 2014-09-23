#include "ChaChaPoly.h"

#define CHACHA_POLY_BLOCK_SIZE          16 

void padPoly(poly1305_context * poly, int length) 
{
	int dataRemainder = length % CHACHA_POLY_BLOCK_SIZE;

	if (dataRemainder) {
		uint8_t zeros[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

		poly1305_update(poly, zeros, CHACHA_POLY_BLOCK_SIZE - dataRemainder);
	}
}

void chacha_poly1305_init(chacha_poly1305_ctx * ctx, const uint8_t key[CHACHA_KEY_SIZE], const uint8_t nonce[CHACHA_NONCE_SIZE])
{
	chacha_set_key(&ctx->_chacha, key);

	union {
		uint32_t x[_CHACHA_STATE_LENGTH];
		uint8_t subkey[CHACHA_KEY_SIZE];
	} u;

	chacha_set_nonce(&ctx->_chacha, nonce);
	_chacha_core(u.x, ctx->_chacha.state, 20);

	poly1305_init(&ctx->_poly, u.subkey);
	ctx->_chacha.state[12] = 1;
	ctx->_dataLength = ctx->_authDataLength = 0;
}

void chacha_poly1305_update(chacha_poly1305_ctx * ctx, const uint8_t *aad, size_t aadLength)
{
	poly1305_update(&ctx->_poly, aad, aadLength);
	padPoly(&ctx->_poly, aadLength);

	ctx->_authDataLength += aadLength;
}


void chacha_poly1305_encrypt(chacha_poly1305_ctx * ctx, const uint8_t * source, uint64_t length, uint8_t * destination)
{
	ctx->_dataLength += length;
	chacha_crypt(&ctx->_chacha, length, destination, source);
	poly1305_update(&ctx->_poly, destination, length);
}


void chacha_poly1305_decrypt(chacha_poly1305_ctx * ctx, const uint8_t * source, uint64_t length, uint8_t * destination)
{
	ctx->_dataLength += length;
	poly1305_update(&ctx->_poly, source, length);
	chacha_crypt(&ctx->_chacha, length, destination, source);
}

void chacha_poly1305_digest(chacha_poly1305_ctx * ctx, uint8_t authTag[CHACHA_POLY1305_DIGEST_SIZE])
{
	padPoly(&ctx->_poly, ctx->_dataLength);

	union {
		uint64_t length;
		uint8_t lengthBuffer[8];
	} l;

	l.length = ctx->_authDataLength;
	poly1305_update(&ctx->_poly, l.lengthBuffer, 8);

	l.length = ctx->_dataLength;
	poly1305_update(&ctx->_poly, l.lengthBuffer, 8);
	
	poly1305_finish(&ctx->_poly, authTag);
}
