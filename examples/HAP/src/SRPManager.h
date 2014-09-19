#ifndef _SRPMANAGER_H_
#define _SRPMANAGER_H_

#include <memory>
#include "byte_string.h"



#include "srp.h"


enum class SRPResult {
	SRP_SUCCSESS,
	SRP_FAILURE
};


class SRPManager {
public:		

	SRPResult getHostPublicKeyAndSalt(const char * userName, const char * password, 
		byte_string & hostPublicKey, byte_string & salt);
	
	SRPResult getHostProof(const byte_string & clientPublicKey, const  byte_string & clientProof, 
		byte_string & hostProof);

	SRPResult getSharedSecretKey(byte_string & sharedSecretKey);

	void endSession();
	
private:	
	std::shared_ptr<SRPVerifier> _verifier;
};
#endif