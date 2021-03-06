#ifndef _HAPAUTHENTICATIONHANDLER_H_
#define _HAPAUTHENTICATIONHANDLER_H_

#include "HAPClient.h"
#include "TLV.h"
#include "SRPManager.h"

namespace HAPAuthentication
{
	enum TLVType
	{
		TLVTypeMethod = 0x00,
		TLVTypeIdentifier = 0x01,
		TLVTypeSalt = 0x02,
		TLVTypePublicKey = 0x03,
		TLVTypeProof = 0x04,
		TLVTypeEncryptedData = 0x05,
		TLVTypeState = 0x06,
		TLVTypeError = 0x07,
		TLVTypeRetryDelay = 0x08,
		TLVTypeCertificate = 0x09,
		TLVTypeSignature = 0x0A,
		TLVTypePermessions = 0x0B,
		TLVTypeFragmentedData = 0x0C,
		TLVTypeFragmentedList = 0x0D,
		TLVTypeSeparator = 0xFF
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
	void verifyPair(HAPClient& client);

	//char* decryptMessage(HAPClient& client);
	//char* encryptMessage(HAPClient& client);	
private:
	HAP::HAPStatus processSetupRequest(const TLVList& requestTLVList, TLVList& responseTLVList);
	HAP::HAPStatus processVerifyRequest(HAPClient& client, 
				const TLVList& requestTLVList, TLVList& responseTLVList);

	HAP::HAPStatus parseRequestBody(const HAPClient& client, TLVList& tlvList);

	void computeTLVsFromString(HAPAuthentication::TLVType tlvType, 
		const byte_string& inputString, TLVList& outputTLVList);
	void computeTLVsFromString(HAPAuthentication::TLVType tlvType, 
		const char* inputString, int inputStringLength, TLVList& outputTLVList);

	TLV_ref getTLVForType(HAPAuthentication::TLVType tlvType, const TLVList& tlvList);
	TLV_ref createTLVForState(HAPAuthentication::PairingState state);
	
	void sendTLVToClient(HAPClient& client, HAP::HAPStatus status, const TLVList& tlvList);
	
	bool prepareEncryptedAccessoryData(const byte_string& sessionKey,
		const byte_string& accessoryLongTermPublicKey, 
		const byte_string& signature, TLVList& responseTLVList);
	
	static const char * _userNameForPairSetup;
	//todo: read from file
	static const char * _password;
	static byte_string _accessoryUsername;

	SRPManager srpManager;	
};
#endif