#ifndef _HAPAUTHENTICATIONHANDLER_H_
#define _HAPAUTHENTICATIONHANDLER_H_

#include "HAPClient.h"
#include "TLV.h"

namespace HAPAuthentication
{
	enum TLVType
	{
		TLVTypeMethod = 0x00,
		TLVTypeUser = 0x01,
		TLVTypeSalt = 0x02,
		TLVTypePublicKey = 0x03,
		TLVTypeProof = 0x04,
		TLVTypeEncryptedData = 0x05,
		TLVTypeAuthTag = 0x06,
		TLVTypeState = 0x07,
		TLVTypeStatus = 0x08,
		TLVTypeRetryDelay = 0x09,
		TLVTypeCertificate = 0x0A,
		TLVTypeMFiProof = 0x0B,
		TLVTypeAdmin = 0x0C,
		TLVTypeSeparator = 0x0D
	};

	enum PairingState
	{
		M1 = 0x01,
		M2 = 0x02,
		M3 = 0x03,
		M4 = 0x04,
		M5 = 0x05,
		M6 = 0x06
	};
}

class HAPAuthenticationHandler {
public:
	HAPAuthenticationHandler();
	void setupPair(HAPClient& client);
	//void verifyPair(HAPClient& client);
	//char* decryptMessage(HAPClient& client);
	//char* encryptMessage(HAPClient& client);

	virtual ~HAPAuthenticationHandler() {}
private:
	void processSetupRequest(HAPClient& client, const TLVList& tlvList);

	void computeTLVsFromString(HAPAuthentication::TLVType tlvType, const unsigned char* inputString, int inputStringLength, TLVList& outputTLVList);
	TLV_ref getTLVForType(HAPAuthentication::TLVType tlvType, const TLVList& tlvList);
	TLV_ref createTLVForState(HAPAuthentication::PairingState state);
	void sendTLVToClient(HAPClient& client, const TLVList& tlv);

	
	void initializeSRPSession(const byte_string& userName);
	//todo: read from file
	static const char * _password;

	//caution: session variables
	struct SRPUser* _pairingUserRef;
	byte_string _pairingSalt;
};
#endif