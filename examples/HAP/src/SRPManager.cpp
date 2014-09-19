#include "SRPManager.h"


SRPResult SRPManager::getHostPublicKeyAndSalt(
	const char * userName, const char * password,
	byte_string & hostPublicKey, byte_string & salt) {
	
	const unsigned char * saltString = 0;
	int saltLength = 0;
	
	_verifier.reset( srp_create_salted_verifier(
		SRP_SHA512, SRP_NG_3072, userName, (const unsigned char *)password, strlen(password), &saltString, &saltLength));

	salt.assign(saltString, saltString + saltLength);
	free((void*) saltString);

	return SRPResult::SRP_SUCCSESS;
}

SRPResult SRPManager::getHostProof(
	const byte_string & clientPublicKey, const  byte_string & clientProof,
	byte_string & hostProof) {
	return SRPResult::SRP_SUCCSESS;
}

SRPResult SRPManager::getSharedSecretKey(byte_string & sharedSecretKey) {
	return SRPResult::SRP_SUCCSESS;
}

void SRPManager::endSession() {
}