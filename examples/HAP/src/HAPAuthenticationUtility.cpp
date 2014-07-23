#include "HAPAuthenticationUtility.h"
#include <openssl/hmac.h>
#include <nettle/chacha-poly1305.h>
#include <nettle/sha1.h>
#include <memory>

bool 
HAPAuthenticationUtility::computeEncryptionKeyFromSRPSharedSecret(
	const byte_string& sharedSecretKey, byte_string& encryptionKey)
{
	char salt[] = "Pair-Setup-Salt";
	char info[] = "Pair-Setup-Encryption-Key";
	const unsigned int outputSize = 32;
	unsigned int pseudoRandomKeyLength = 0;
	encryptionKey.clear();

	//http://tools.ietf.org/html/rfc5869
	//HKDF Extract
	//PRK = HMAC - Hash(salt, IKM)
	unsigned char* pseudoRandomKey = HMAC(EVP_sha512(), salt, strlen(salt), 
		sharedSecretKey.data(), sharedSecretKey.size(), NULL, &pseudoRandomKeyLength);

	if (pseudoRandomKey == NULL || pseudoRandomKeyLength <= 0) return false;
	/*HKDF Expand
	
	N = ceil(L / HashLen)
	T = T(1) | T(2) | T(3) | ... | T(N)
	OKM = first L octets of T

	where:
	T(0) = empty string(zero length)
	T(1) = HMAC - Hash(PRK, T(0) | info | 0x01)
	T(2) = HMAC - Hash(PRK, T(1) | info | 0x02)
	T(3) = HMAC - Hash(PRK, T(2) | info | 0x03)
	...
	*/
	
	unsigned int N = outputSize / pseudoRandomKeyLength 
		+ (outputSize % pseudoRandomKeyLength == 0 ? 0 : 1);
	if (N > 255) return false;

	byte_string previousDigest;
	
	for (uint8_t counter = 1; counter <= N; counter++) {
		previousDigest += info;
		previousDigest += counter;

		unsigned int digestLength = 0;
		unsigned char* currentDigest = HMAC(EVP_sha512(), pseudoRandomKey, pseudoRandomKeyLength,
			previousDigest.data(), previousDigest.size(), NULL, &digestLength);

		previousDigest.assign(currentDigest, currentDigest + digestLength);
		encryptionKey.insert(encryptionKey.end(), currentDigest, currentDigest + digestLength);
		
		if (encryptionKey.size() >= outputSize) {
			encryptionKey.resize(outputSize);
			return true;
		}		
	}

	return true;
}

bool 
HAPAuthenticationUtility::decryptControllerLTPK(
	const byte_string& sharedEncryptionDecryptionKey,
	const byte_string& encryptedKey, const byte_string& authTag, byte_string& decryptedKey)
{
	chacha_poly1305_ctx ctx;
	
	chacha_poly1305_set_key(&ctx, sharedEncryptionDecryptionKey.data());
	chacha_poly1305_set_nonce(&ctx, (uint8_t *) "PS-Msg05");
	
	std::shared_ptr<unsigned char> decryptedKeybuffer(new unsigned char[encryptedKey.size()]);
	unsigned char* bufferRef = decryptedKeybuffer.get();
	chacha_poly1305_decrypt(&ctx, encryptedKey.size(), bufferRef, encryptedKey.data());	
	
	decryptedKey.assign(bufferRef, bufferRef + encryptedKey.size());	
	byte_string authTagComputed(ctx.block, ctx.block + authTag.size());

	printString(encryptedKey, "encryptedKey");
	printString(authTag, "authTag received");
	printString(decryptedKey, "decryptedKey");
	printString(authTagComputed, "authTag sent");
	
	return true;
}

bool
HAPAuthenticationUtility::encryptAccessoryLTPK(
	const byte_string& sharedEncryptionDecryptionKey,
	const byte_string& decryptedKey, byte_string& authTag, byte_string& encryptedKey)
{
	chacha_poly1305_ctx ctx;

	chacha_poly1305_set_key(&ctx, sharedEncryptionDecryptionKey.data());
	chacha_poly1305_set_nonce(&ctx, (uint8_t *) "PS-Msg05");
	//chacha_poly1305_set_nonce(&ctx, (uint8_t *) "PS-Msg06");
	
	std::shared_ptr<unsigned char> encryptedKeybuffer(new unsigned char[decryptedKey.size()]);
	unsigned char* bufferRef = encryptedKeybuffer.get();
	chacha_poly1305_encrypt(&ctx, decryptedKey.size(), bufferRef, decryptedKey.data());

	encryptedKey.assign(bufferRef, bufferRef + decryptedKey.size());
	authTag.assign(ctx.block, ctx.block + ctx.auth_size);
	
	printString(encryptedKey, "encryptedKey");
	printString(authTag, "authTag sent");

	return true;
}