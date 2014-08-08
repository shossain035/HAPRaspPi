#include "HAPAuthenticationUtility.h"
#include <openssl/hmac.h>
#include <nettle/chacha-poly1305.h>
#include <nettle/knuth-lfib.h>
#include "Curve25519Donna.h"
#include "ed25519.h"

#define CURVE25519_KEY_SIZE                 32
const char* HAPPairing::_pairingStorePath = "./keys/";

bool 
HAPAuthenticationUtility::computeEncryptionKeyFromSRPSharedSecret(
	const byte_string& sharedSecretKey, byte_string& encryptionKey)
{
	return deriveKeyUsingHKDF(sharedSecretKey, "Pair-Setup-Salt", "Pair-Setup-Encryption-Key", encryptionKey);
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
	const byte_string& plainTextKey, byte_string& authTag, byte_string& encryptedKey)
{
	chacha_poly1305_ctx ctx;

	chacha_poly1305_set_key(&ctx, sharedEncryptionDecryptionKey.data());
	chacha_poly1305_set_nonce(&ctx, (uint8_t *) "PS-Msg06");
	
	encryptedKey.resize(plainTextKey.size());
	chacha_poly1305_encrypt(&ctx, plainTextKey.size(), encryptedKey.data(), plainTextKey.data());

	computeChaChaPolyAuthTag(ctx, authTag);
	
	return true;
}

//todo combine all the chacha poly encrypt
bool
HAPAuthenticationUtility::encryptHAPResponse(
	const uint8_t* encryptionKey, const uint8_t* nonce,
	const byte_string& plaintTextResponse, byte_string& authTag, byte_string& encryptedResponse)
{
	chacha_poly1305_ctx ctx;

	chacha_poly1305_set_key(&ctx, encryptionKey);
	chacha_poly1305_set_nonce(&ctx, nonce);
	
	encryptedResponse.resize(plaintTextResponse.size());
	chacha_poly1305_encrypt(&ctx, plaintTextResponse.size(), encryptedResponse.data(), plaintTextResponse.data());

	computeChaChaPolyAuthTag(ctx, authTag);
	
	return true;
}


bool 
HAPAuthenticationUtility::generateKeyPairUsingCurve25519(byte_string& publicKey, byte_string& secretKey)
{
	generateRandomBytes(secretKey, CURVE25519_KEY_SIZE);

	secretKey[0] &= 248;
	secretKey[31] &= 127;
	secretKey[31] |= 64;

	static const uint8_t basepoint[32] = { 9 };
	publicKey.resize(CURVE25519_KEY_SIZE);

	curve25519_donna(publicKey.data(), secretKey.data(), basepoint);

	return true;
}

bool 
HAPAuthenticationUtility::generateSharedSecretUsingCurve25519(
		const byte_string& controllerPublicKey,
		const byte_string& accessorySecretKey,
		byte_string& sharedSecret)
{
	sharedSecret.resize(CURVE25519_KEY_SIZE);
	curve25519_donna(sharedSecret.data(), accessorySecretKey.data(), controllerPublicKey.data());

	return true;
}


bool 
HAPAuthenticationUtility::generateAccessoryProofForSTSProtocol(
		const byte_string& stationToStationYX,
		const byte_string& accessoryLongTermPublicKey,
		const byte_string& accessoryLongTermSecretKey,		
		const byte_string& sharedSecret,
		byte_string& accessoryProof)
{
	ed25519_signature signature;
	//sign with Ed25119
	ed25519_sign(stationToStationYX.data(), stationToStationYX.size(), 
		accessoryLongTermSecretKey.data(), accessoryLongTermPublicKey.data(), signature);
	
	/*
	//derive encryption key
	byte_string encryptionKey;
	if (!deriveKeyUsingHKDF(sharedSecret, "Pair-Verify-Salt", "Pair-Verify-Encryption-Key", encryptionKey)) {
		return false;
	}

	//encrypt signature with chacha20
	chacha_ctx ctx;
	chacha_set_key(&ctx, encryptionKey.data());
	chacha_set_nonce(&ctx, (uint8_t *) "PV-Msg02");
	ctx.state[12] = 0; //block counter = 0

	accessoryProof.resize(sizeof(ed25519_signature));
	chacha_crypt(&ctx, sizeof(ed25519_signature), accessoryProof.data(), signature);
	*/

	return chacha20Crypt(sharedSecret, "PV-Msg02", sizeof(ed25519_signature), signature, accessoryProof);
}

bool 
HAPAuthenticationUtility::verifyControllerProofForSTSProtocol(
		const byte_string& stationToStationXY,
		const byte_string& controllerLongTermPublicKey,
		const byte_string& sharedSecret,
		const byte_string& controllerProof)
{
	byte_string decryptedControllerProof;
	//derive decryption key
	if (!chacha20Crypt(sharedSecret, "PV-Msg03", 
		controllerProof.size(), controllerProof.data(), decryptedControllerProof)) {
		return false;
	}

	return ed25519_sign_open(stationToStationXY.data(), stationToStationXY.size(), 
			controllerLongTermPublicKey.data(), decryptedControllerProof.data()) == 0;
}


bool 
HAPAuthenticationUtility::generateSessionKeys(const byte_string& sharedSecretForSession,
		byte_string& accessoryToControllerKey, byte_string& controllerToAccessoryKey)
{
	return deriveKeyUsingHKDF(sharedSecretForSession, "Control-Salt", "Control-Read-Info", accessoryToControllerKey)
		&& deriveKeyUsingHKDF(sharedSecretForSession, "Control-Salt", "Control-Write-Info", controllerToAccessoryKey);
}

bool 
HAPAuthenticationUtility::generateKeyPairUsingEd25519(byte_string& publicKey, byte_string& secretKey)
{
	generateRandomBytes(secretKey, sizeof(ed25519_secret_key));
	
	publicKey.resize(sizeof(ed25519_public_key));
	ed25519_publickey(secretKey.data(), publicKey.data());
	return true;
}

bool 
HAPAuthenticationUtility::deriveKeyUsingHKDF(
	const byte_string& inputKey, const char* salt, const char* info, byte_string& derivedKey)
{
	const unsigned int outputSize = 32;
	unsigned int pseudoRandomKeyLength = 0;
	derivedKey.clear();

	//http://tools.ietf.org/html/rfc5869
	//HKDF Extract
	//PRK = HMAC - Hash(salt, IKM)
	uint8_t* pseudoRandomKey = HMAC(EVP_sha512(), salt, strlen(salt),
		inputKey.data(), inputKey.size(), NULL, &pseudoRandomKeyLength);

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
		derivedKey.insert(derivedKey.end(), currentDigest, currentDigest + digestLength);

		if (derivedKey.size() >= outputSize) {
			derivedKey.resize(outputSize);
			return true;
		}
	}

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
	knuth_lfib_init(&randomCtx, rand());

	randomBytes.resize(count);
	knuth_lfib_random(&randomCtx, count, randomBytes.data());
}

bool 
HAPAuthenticationUtility::chacha20Crypt(const byte_string& sharedSecret, const char* nonce,
		int length, const uint8_t* source, byte_string& destination)
{
	//derive encryption key
	byte_string encryptionKey;
	if (!deriveKeyUsingHKDF(sharedSecret, "Pair-Verify-Salt", "Pair-Verify-Encryption-Key", encryptionKey)) {
		return false;
	}

	//crypt signature with chacha20
	chacha_ctx ctx;
	chacha_set_key(&ctx, encryptionKey.data());
	chacha_set_nonce(&ctx, (uint8_t*) nonce);
	ctx.state[12] = 0; //block counter = 0

	destination.resize(length);
	chacha_crypt(&ctx, length, destination.data(), source);

	return true;
}


bool
HAPPairing::savePairing()
{
	std::string path(_pairingStorePath);	
	path.append((char *)_controllerUsername.data(), _controllerUsername.size());	
	
	std::ofstream keyFile(path, std::ios::out | std::ofstream::binary);
	
	writeToFile(keyFile, _controllerUsername);
	writeToFile(keyFile, _controllerLongTermPublicKey);
	writeToFile(keyFile, _accessoryLongTermPublicKey);
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
		printf("no pairing found for controller: %s", path.c_str());
		return false;
	}
	
	readFromFile(keyFile, _controllerUsername);
	readFromFile(keyFile, _controllerLongTermPublicKey);
	readFromFile(keyFile, _accessoryLongTermPublicKey);
	readFromFile(keyFile, _accessoryLongTermSecretKey);

	return true;
}
