#ifndef _CHACHAPOLY_H_
#define _CHACHAPOLY_H_

#include <nettle/chacha.h>
#include <poly1305-donna.h> 


#define CHACHA_POLY1305_DIGEST_SIZE 16

class ChaChaPoly {
public:
	ChaChaPoly(const uint8_t key[CHACHA_KEY_SIZE], const uint8_t nonce[CHACHA_NONCE_SIZE]);
	void update(const uint8_t * source, uint64_t length, uint8_t * destination);
	void digest(uint8_t authTag[CHACHA_POLY1305_DIGEST_SIZE]);
private:
	uint64_t _authDataLength;
	uint64_t _dataLength;
	poly1305_context _poly;
	chacha_ctx _chacha;
};
#endif
