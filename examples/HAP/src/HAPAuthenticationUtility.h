#ifndef _HAPAUTHENTICATIONUTILITY_H_
#define _HAPAUTHENTICATIONUTILITY_H_
#include "byte_string.h"

struct chacha_poly1305_ctx;

class HAPPairing {
public:
	HAPPairing(const byte_string& controllerUsername) 
		: _controllerUsername(controllerUsername)
	{
	}

	HAPPairing(const byte_string& controllerUsername, 
			   const byte_string& controllerLongTermPublicKey,
			   const byte_string& accessoryLongTermPublicKey,
		       const byte_string& accessoryLongTermSecretKey)
		: _controllerUsername(controllerUsername), 
		  _controllerLongTermPublicKey(controllerLongTermPublicKey),
		  _accessoryLongTermPublicKey(accessoryLongTermPublicKey),
		  _accessoryLongTermSecretKey(accessoryLongTermSecretKey)
	{
	}

	bool savePairing();
	bool retievePairing();
	
	const byte_string& controllerUsername() { return _controllerUsername; }
	const byte_string& controllerLongTermPublicKey()  { return _controllerLongTermPublicKey; }
	const byte_string& accessoryLongTermPublicKey() { return _accessoryLongTermPublicKey; }
	const byte_string& accessoryLongTermSecretKey() { return _accessoryLongTermSecretKey; }

private:
	byte_string _controllerUsername;
	byte_string _controllerLongTermPublicKey;
	byte_string _accessoryLongTermPublicKey;
	byte_string _accessoryLongTermSecretKey;

	static const char* _pairingStorePath;
};

class HAPAuthenticationUtility {
public:
	static bool computeEncryptionKeyFromSRPSharedSecret(
		const byte_string& sharedSecretKey, byte_string& encryptionKey);

	static bool decryptControllerData(
		const byte_string& sharedEncryptionDecryptionKey,
		const byte_string& encryptedData, byte_string& decryptedData);
	static bool encryptAccessoryData(
		const byte_string& sessionKey,
		const byte_string& plainText, byte_string& cipherText);
	static bool signAccessoryInfo(
		const byte_string& sharedSecretKey, const byte_string& accessoryIdentifier,
		const byte_string& accessoryLongTermPublicKey, const byte_string& accessoryLongTermSecretKey,
		byte_string& signature);

	static bool encryptHAPResponse(
		const uint8_t* encryptionKey, const uint8_t* nonce,
		const byte_string& plaintTextResponse, byte_string& authTag, byte_string& encryptedResponse);

	static bool generateKeyPairUsingEd25519(byte_string& publicKey, byte_string& secretKey);

	static bool generateKeyPairUsingCurve25519(byte_string& publicKey, byte_string& secretKey);
	static bool generateSharedSecretUsingCurve25519(
		const byte_string& controllerPublicKey,
		const byte_string& accessorySecretKey,
		byte_string& sharedSecret);

	static bool generateAccessoryProofForSTSProtocol(
		const byte_string& stationToStationYX, 
		const byte_string& accessoryLongTermPublicKey,
		const byte_string& accessoryLongTermSecretKey, 		
		const byte_string& sharedSecret,
		byte_string& accessoryProof);

	static bool verifyControllerProofForSTSProtocol(
		const byte_string& stationToStationXY,
		const byte_string& controllerLongTermPublicKey,
		const byte_string& sharedSecret,
		const byte_string& controllerProof);


	static bool generateSessionKeys(const byte_string& sharedSecretForSession,
		byte_string& accessoryToControllerKey, byte_string& controllerToAccessoryKey);

	static void generateRandomBytes(byte_string& randomBytes, size_t count);
	
private: 	
	static bool deriveKeyUsingHKDF(
		const byte_string& inputKey, const char* salt, const char* info, byte_string& derivedKey);
	static void computeChaChaPolyAuthTag(chacha_poly1305_ctx& ctx, byte_string& authTag);

	static bool chacha20Crypt(const byte_string& sharedSecret, const char* nonce,
		int length, const uint8_t* source, byte_string& destination);
};
#endif