#include "ChaChaPoly.h"

#define CHACHA_POLY_BLOCK_SIZE          16 

ChaChaPoly::ChaChaPoly(const uint8_t key[CHACHA_KEY_SIZE], const uint8_t nonce[CHACHA_NONCE_SIZE])
{
	chacha_set_key(&_chacha, key);

	union {
		uint32_t x[_CHACHA_STATE_LENGTH];
		uint8_t subkey[CHACHA_KEY_SIZE];
	} u;

	chacha_set_nonce(&_chacha, nonce);
	_chacha_core(u.x, _chacha.state, 20);

	poly1305_init(&_poly, u.subkey);
	_chacha.state[12] = 1;
	_dataLength = _authDataLength = 0;
}

void ChaChaPoly::encrypt(const uint8_t * source, uint64_t length, uint8_t * destination)
{
	_dataLength += length;	
	chacha_crypt(&_chacha, length, destination, source);
	poly1305_update(&_poly, destination, length);
}


void ChaChaPoly::decrypt(const uint8_t * source, uint64_t length, uint8_t * destination)
{
	_dataLength += length;
	poly1305_update(&_poly, source, length);
	chacha_crypt(&_chacha, length, destination, source);
}

void ChaChaPoly::digest(uint8_t authTag[CHACHA_POLY1305_DIGEST_SIZE])
{
	int dataRemainder = _dataLength % CHACHA_POLY_BLOCK_SIZE;	
	
	if (dataRemainder) {
		uint8_t zeros[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	
		poly1305_update(&_poly, zeros, CHACHA_POLY_BLOCK_SIZE - dataRemainder);
	}

	union {
		uint64_t length;
		uint8_t lengthBuffer[8];
	} l;

	l.length = _authDataLength;
	poly1305_update(&_poly, l.lengthBuffer, 8);

	l.length = _dataLength;
	poly1305_update(&_poly, l.lengthBuffer, 8);
	
	poly1305_finish(&_poly, authTag);
}