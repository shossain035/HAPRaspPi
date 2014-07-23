#ifndef _HAPAUTHENTICATIONUTILITY_H_
#define _HAPAUTHENTICATIONUTILITY_H_
#include "byte_string.h"

struct chacha_poly1305_ctx;

class HAPAuthenticationUtility {
public:
	static bool computeEncryptionKeyFromSRPSharedSecret(
		const byte_string& sharedSecretKey, byte_string& encryptionKey);

	static bool decryptControllerLTPK(
		const byte_string& sharedEncryptionDecryptionKey,
		const byte_string& encryptedKey, const byte_string& authTag, byte_string& decryptedKey);
	static bool encryptAccessoryLTPK(
		const byte_string& sharedEncryptionDecryptionKey,
		const byte_string& decryptedKey, byte_string& authTag, byte_string& encryptedKey);

private: 	
	static void computeChaChaPolyAuthTag(chacha_poly1305_ctx& ctx, byte_string& authTag);
};
#endif