#include "HAPAuthenticationUtility.h"
#include <openssl/hmac.h>
#include <nettle/chacha-poly1305.h>
//#include <nettle/ecdsa.h>
#include <nettle/knuth-lfib.h>
#include "ed25519.h"
#include <memory>
#include <algorithm>
#include <fstream>
#include <iterator>


const char* HAPPairing::_pairingStorePath = "./keys/";

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
	uint8_t* pseudoRandomKey = HMAC(EVP_sha512(), salt, strlen(salt),
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
		uint8_t* currentDigest = HMAC(EVP_sha512(), pseudoRandomKey, pseudoRandomKeyLength,
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
	
	decryptedKey.resize(encryptedKey.size());
	chacha_poly1305_decrypt(&ctx, encryptedKey.size(), decryptedKey.data(), encryptedKey.data());
		
	byte_string authTagComputed;
	computeChaChaPolyAuthTag(ctx, authTagComputed);
	
	if (authTagComputed != authTag) {
		printf("auth tag mismatch\n");
		return false;
	}
	
	return true;
}

bool
HAPAuthenticationUtility::encryptAccessoryLTPK(
	const byte_string& sharedEncryptionDecryptionKey,
	const byte_string& decryptedKey, byte_string& authTag, byte_string& encryptedKey)
{
	chacha_poly1305_ctx ctx;

	chacha_poly1305_set_key(&ctx, sharedEncryptionDecryptionKey.data());
	chacha_poly1305_set_nonce(&ctx, (uint8_t *) "PS-Msg06");
	
	encryptedKey.resize(decryptedKey.size());
	chacha_poly1305_encrypt(&ctx, decryptedKey.size(), encryptedKey.data(), decryptedKey.data());

	computeChaChaPolyAuthTag(ctx, authTag);
	
	return true;
}

/*
bool 
HAPAuthenticationUtility::generateKeyPair(byte_string& publicKey, byte_string& secretKey)
{
	knuth_lfib_ctx randomCtx;
	knuth_lfib_init(&randomCtx, 4711);

	ecc_point eccPublicKey;
	ecc_scalar eccSecretKey;

	ecc_curve curve = ecc_curve->;
	struct ecc_point pub;
	struct ecc_scalar key;

	if (verbose)
		fprintf(stderr, "Curve %d\n", ecc->bit_size);

	ecc_point_init(&pub, ecc);
	ecc_scalar_init(&key, ecc);

	ecdsa_generate_keypair(&pub, &key,
		&rctx,
		(nettle_random_func *)knuth_lfib_random);

	return true;
}
*/

bool 
HAPAuthenticationUtility::generateKeyPairUsingEd25519(byte_string& publicKey, byte_string& secretKey)
{
	generateRandomBytes(secretKey, sizeof(ed25519_secret_key));
	
	publicKey.resize(sizeof(ed25519_public_key));
	ed25519_publickey(secretKey.data(), publicKey.data());
	return true;
}

void
HAPAuthenticationUtility::computeChaChaPolyAuthTag(chacha_poly1305_ctx& ctx, byte_string& authTag)
{
	authTag.resize(CHACHA_POLY1305_DIGEST_SIZE);
	chacha_poly1305_digest(&ctx, CHACHA_POLY1305_DIGEST_SIZE, authTag.data());
}


void
HAPAuthenticationUtility::generateRandomBytes(byte_string& randomBytes, size_t count)
{
	knuth_lfib_ctx randomCtx;
	knuth_lfib_init(&randomCtx, 4711);

	randomBytes.resize(count);
	knuth_lfib_random(&randomCtx, count, randomBytes.data());
}

bool
HAPPairing::savePairing()
{
	std::string path(_pairingStorePath);	
	path.append((char *)_controllerUsername.data(), _controllerUsername.size());	
	
	std::ofstream keyFile(path, std::ios::out | std::ofstream::binary);
	
	writeToFile(keyFile, _controllerUsername);
	writeToFile(keyFile, _controllerLongTermPublicKey);
	writeToFile(keyFile, _accessoryLongTermSecretKey);

	return true;
}

bool
HAPPairing::retievePairing()
{
	if (_controllerUsername.size() <= 0) return false;

	std::string path(_pairingStorePath);
	path.append((char *)_controllerUsername.data(), _controllerUsername.size());
	
	std::ifstream keyFile(path, std::ios::in | std::ofstream::binary);
	
	if (!keyFile.good()) {
		printf("no pairing found for user: %s", path.c_str());
		return false;
	}
	
	readFromFile(keyFile, _controllerUsername);
	readFromFile(keyFile, _controllerLongTermPublicKey);
	readFromFile(keyFile, _accessoryLongTermSecretKey);

	return true;
}