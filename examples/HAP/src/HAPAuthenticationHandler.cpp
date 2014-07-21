#include "HAPAuthenticationHandler.h"
#include "srp.h"

#define TLV_VALUE_MAXIMUM_LENGTH          255
using namespace HAPAuthentication;

const char* HAPAuthenticationHandler::_password = "1234";

HAPAuthenticationHandler::HAPAuthenticationHandler() : _pairingUserRef(NULL)
{
}

void 
HAPAuthenticationHandler::setupPair(HAPClient& client)
{
	//todo: process 429
	byte_string bytes;
	const char* message = client.getMessage();
	int messageLength = client.getMessageLength();

	printf("length: %d\n", messageLength);
	printf("request body:\n");

	for (int i = 0; i<messageLength; i++) {
		printf("%02hhx ", static_cast<unsigned char> (message[i]));
		bytes.push_back(message[i]);
	}
	printf("\n*******************************\n");

	TLVList tlvList;		
	try {
		byte_string::iterator begin = bytes.begin();

		TLV::parseSequence(begin, bytes.end(), tlvList);
	}
	catch (const std::runtime_error& error) {
		printf("runtime_error: %s\n", error.what());
		//todo: send error
		//client.sendHeader
		return;
	}

	processSetupRequest(client, tlvList);
}


void
HAPAuthenticationHandler::processSetupRequest(HAPClient& client, const TLVList& tlvList)
{
	TLV_ref stateTLV = getTLVForType(TLVTypeState, tlvList);
	if (NULL == stateTLV) {
		printf("empty state tlv\n");
		//todo: send error
		return;
	}

	uint8_t tlvState = stateTLV->getValue().at(0);
	printf("state: %02hhx\n", tlvState);
	TLVList responseTLVList;
	
	switch (tlvState) {
		case M1:
		{	const unsigned char * bytes_v = 0;
			const unsigned char * bytes_s = 0;
			const unsigned char * bytes_A = 0;
			
			int len_v = 0;
			int len_s = 0;			
			int len_A = 0;
			
			TLV_ref userTLV = getTLVForType(TLVTypeUser, tlvList);
			if (NULL == userTLV) {
				//todo: send error
				break;
			}

			//start SRP session			
			byte_string userName = userTLV->getValue();
			userName.push_back(0);
			char* userNameString = reinterpret_cast<char*>(userName.data());
			printf("userName: %s\n", userNameString);

			//create salt
			srp_create_salted_verification_key(SRP_SHA1, SRP_NG_2048, userNameString,
				(const unsigned char *)_password,
				strlen(_password),
				&bytes_s, &len_s, &bytes_v, &len_v, 0, 0);

			_pairingSalt.clear();
			for (int j = 0; j < 4; j++) {
				for (int i = 0; i < len_s; i++) {
					_pairingSalt.push_back(bytes_s[i]);
				}
			}

			//free((char *)bytes_s);
			//free((char *)bytes_v);

			printf("creating user\n");
			//create user
			srp_user_delete(_pairingUserRef);

			_pairingUserRef = srp_user_new(SRP_SHA1, SRP_NG_2048, userNameString,
				(const unsigned char *)_password,
				strlen(_password), 0, 0);

			srp_user_start_authentication(_pairingUserRef, &bytes_A, &len_A);

			////debugging
			const unsigned char * bytes_B = 0;
			int len_B = 0;
			srp_verifier_new(SRP_SHA1, SRP_NG_2048, userNameString, _pairingSalt.data(), len_s, bytes_v, len_v,         //controller 
				bytes_A, len_A, &bytes_B, &len_B, 0, 0);

			for (int i = 0; i<len_B; i++) {
				printf("%02hhx ", (bytes_B[i]));
			}
			printf("\n*******************************\n");

			free((char *)bytes_s);
			free((char *)bytes_v);
			////debugging end


			//setting accessory's public key			
			computeTLVsFromString(TLVTypePublicKey, bytes_A, len_A, responseTLVList);			
			//setting salt
			responseTLVList.push_back(TLV_ref(new TLV(TLVTypeSalt, _pairingSalt)));			
			//setting state
			responseTLVList.push_back(createTLVForState(M2));

			sendTLVToClient(client, responseTLVList);
			
			break;
		}
		case M3:
		{
			const unsigned char * bytes_M = 0;
			int len_M = 0;

			TLV_ref controllerPublicKeyTLV = getTLVForType(TLVTypePublicKey, tlvList);
			TLV_ref controllerProofTLV = getTLVForType(TLVTypeProof, tlvList);

			if (NULL == controllerPublicKeyTLV || NULL == controllerProofTLV) {
				//todo: send error
				break;
			}
			byte_string controllerPublickKey = controllerPublicKeyTLV->getValue();

			srp_user_process_challenge(_pairingUserRef, _pairingSalt.data(),
				_pairingSalt.size(), controllerPublickKey.data(), controllerPublickKey.size(), &bytes_M, &len_M);
			
			if (!bytes_M)
			{
				printf("User SRP-6a safety check violation\n");
				//todo: send error
				break;
			}

			srp_user_verify_session(_pairingUserRef, controllerProofTLV->getValue().data());

			if (!srp_user_is_authenticated(_pairingUserRef))
			{
				printf("srp authentication failed\n");
				break;
			}

			//setting accessory's proof
			computeTLVsFromString(TLVTypePublicKey, bytes_M, len_M, responseTLVList);
			//setting state
			responseTLVList.push_back(createTLVForState(M4));

			sendTLVToClient(client, responseTLVList);

			break;
		}
		case M4:
			break;
		case M5:
			break;
		case M6:
			break;
		default:
			printf("no matching state found\n");
			//todo: send error
			break;
	}
}

void 
HAPAuthenticationHandler::sendTLVToClient(HAPClient& client, const TLVList& tlvList)
{
	byte_string messageBody;
	for (TLVList::const_iterator iter = tlvList.begin(); iter < tlvList.end(); iter++) {
		(*iter)->encode(messageBody);
	}

	printf("response body:\n");
	for (byte_string::iterator it = messageBody.begin(); it != messageBody.end(); ++it) {
		printf("%02hhx ", (*it));
	}
	printf("\n*******************************\n");

	client.sendHeader(HAP::SUCCESS, messageBody.size(), HAP::HAPMessageContentTypeTLV);
	client.printBytes(reinterpret_cast<char*>(messageBody.data()), messageBody.size());

	TLVList tlvList1;
	try {
		byte_string::iterator begin = messageBody.begin();
		TLV::parseSequence(begin, messageBody.end(), tlvList1);

		for (TLVList::const_iterator iter = tlvList1.begin(); iter < tlvList1.end(); iter++) {
			printf("T: %02hhx L:%d\n", (*iter)->getTag().at(0), (*iter)->length());
		}
	}
	catch (const std::runtime_error& error) {
		printf("runtime_error: %s\n", error.what());
		//todo: send error
		//client.sendHeader
		return;
	}
}

TLV_ref
HAPAuthenticationHandler::getTLVForType(TLVType tlvType, const TLVList& tlvList)
{
	TLVList matchedItems;

	for (TLVList::const_iterator iter = tlvList.begin(); iter < tlvList.end(); iter++) {
		if ((*iter)->getTag().at(0) == tlvType) {
			matchedItems.push_back(*iter);
		}
	}

	if (matchedItems.size() == 1) {
		return matchedItems.at(0);
	}

	if (matchedItems.size() == 0) {
		return NULL;
	}

	//combine contiguous TLVs into one
	byte_string out;
	for (TLVList::const_iterator iter = matchedItems.begin(); iter < matchedItems.end(); iter++) {
		out += (*iter)->getValue();
	}

	return TLV_ref(new TLV(tlvType, out));
}

void 
HAPAuthenticationHandler::computeTLVsFromString(
							TLVType tlvType, 
							const unsigned char* inputString, 
							int inputStringLength, 
							TLVList& outputTLVList)
{
	byte_string tlvValue;
	int tlvValueLength = 0;

	while (tlvValueLength < inputStringLength) {
		tlvValue.clear();

		for (; (tlvValueLength < inputStringLength) 
			&& (tlvValue.size() < TLV_VALUE_MAXIMUM_LENGTH); tlvValueLength++) {
			tlvValue.push_back(inputString[tlvValueLength]);
		}
		outputTLVList.push_back(TLV_ref(new TLV(tlvType, tlvValue)));
	}
}

TLV_ref
HAPAuthenticationHandler::createTLVForState(PairingState state)
{
	byte_string stateValue;
	stateValue.push_back(state);
	return TLV_ref(new TLV(TLVTypeState, stateValue));
}

void 
HAPAuthenticationHandler::initializeSRPSession(const byte_string& userName)
{
}

