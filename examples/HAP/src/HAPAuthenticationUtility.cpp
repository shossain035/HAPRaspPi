#include "HAPAuthenticationUtility.h"
#include <openssl/hmac.h>

bool 
HAPAuthenticationUtility::computeEncryptionKeyFromSRPSharedSecret(
	const byte_string& sharedSecretKey, byte_string& encryptionKey)
{
	char* salt = "Pair-Setup-Salt";
	char* info = "Pair-Setup-Encryption-Key";
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

		previousDigest.clear();
		for (unsigned int i = 0; i < digestLength; i++) {
			previousDigest += currentDigest[i];
			if (i < outputSize) {
				encryptionKey += currentDigest[i];
			}			
		}
	}
}