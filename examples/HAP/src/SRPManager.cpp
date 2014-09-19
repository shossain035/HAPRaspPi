#include "SRPManager.h"
#include <stdio.h>

SRPResult SRPManager::getHostPublicKeyAndSalt(
	const char * userName, const char * password,
	byte_string & hostPublicKey, byte_string & salt) {
	
	const unsigned char * saltString = 0, * publicKey = 0;
	int saltLength = 0, publicKeyLength = 0;
	
	_verifier.reset( srp_create_salted_verifier(
		SRP_SHA512, SRP_NG_3072, userName, (const unsigned char *)password, strlen(password), &saltString, &saltLength));

	salt.assign(saltString, saltString + saltLength);
	delete saltString;

	srp_generate_public_key(_verifier.get(), &publicKey, &publicKeyLength);

	if (!publicKeyLength) {
		printf("failed to generate public key");
				
		return errorOccured();
	}

	hostPublicKey.assign(publicKey, publicKey + publicKeyLength);
	delete publicKey;

	return SRPResult::SRP_SUCCSESS;
}

SRPResult SRPManager::getHostProof(
	const byte_string & clientPublicKey, const  byte_string & clientProof,
	byte_string & hostProof) {

	srp_compute_shared_secret(_verifier.get(), clientPublicKey.data(), clientPublicKey.size());
	const unsigned char * hostProofString = 0;

	srp_verifier_verify_session(_verifier.get(), clientProof.data(), &hostProofString);

	if (!hostProofString) {
		printf("User authentication failed!\n");
		return errorOccured();
	}

	hostProof.assign(hostProofString, hostProofString + clientProof.size());
	delete hostProofString;

	return SRPResult::SRP_SUCCSESS;
}

SRPResult SRPManager::getSharedSecretKey(byte_string & sharedSecretKey) {
	return SRPResult::SRP_SUCCSESS;
}

void SRPManager::endSession() {
	_verifier.reset();
}

SRPResult SRPManager::errorOccured() {
	endSession();
	return SRPResult::SRP_FAILURE;
}
