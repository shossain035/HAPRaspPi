#ifndef _HAPAUTHENTICATIONUTILITY_H_
#define _HAPAUTHENTICATIONUTILITY_H_
#include "byte_string.h"

class HAPAuthenticationUtility {
public:
	static bool computeEncryptionKeyFromSRPSharedSecret(
		const byte_string& sharedSecretKey, byte_string& encryptionKey);
 
private: 	
};
#endif