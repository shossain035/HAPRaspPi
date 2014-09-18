#include "HAPAuthenticationHandler.h"
#include "HAPAuthenticationUtility.h"

extern "C"
{
#include "t_pwd.h"
}

#define TLV_VALUE_MAXIMUM_LENGTH          255
#define SRP_3072_NG_INDEX                 9
#define SALT_LENGTH                       16

using namespace HAPAuthentication;

const char* HAPAuthenticationHandler::userNameForPairSetup = "Pair-Setup";
//todo: read these from file
const char* HAPAuthenticationHandler::_password = "143-17-632";
byte_string HAPAuthenticationHandler::_accessoryUsername;

HAPAuthenticationHandler::HAPAuthenticationHandler() : _srpSessionRef(NULL)
{
	char accessoryUsername[] = "4e:06:19:0e:c0:87";
	_accessoryUsername.assign(accessoryUsername, accessoryUsername + strlen(accessoryUsername));
	SRP_initialize_library();
}

HAPAuthenticationHandler::~HAPAuthenticationHandler()
{
	//todo: put spr clean up inside a function
	SRP_free(_srpSessionRef);
	_srpSessionRef = NULL;

	SRP_finalize_library();
}

void 
HAPAuthenticationHandler::setupPair(HAPClient& client)
{
	//todo: process 429. simultaneous pairing attempts will break the system.
	TLVList requestTLVList, responseTLVList;
	HAP::HAPStatus parsingResult = parseRequestBody(client, requestTLVList);

	if (parsingResult != HAP::SUCCESS) {
		sendTLVToClient(client, parsingResult, responseTLVList);
		return;
	}

	sendTLVToClient(client, processSetupRequest(requestTLVList, responseTLVList),
						responseTLVList);		
}

void
HAPAuthenticationHandler::verifyPair(HAPClient& client)
{
	TLVList requestTLVList, responseTLVList;
	HAP::HAPStatus parsingResult = parseRequestBody(client, requestTLVList);

	if (parsingResult != HAP::SUCCESS) {
		sendTLVToClient(client, parsingResult, responseTLVList);
		return;
	}

	sendTLVToClient(client, processVerifyRequest(client, requestTLVList, responseTLVList),
		responseTLVList);
}



HAP::HAPStatus
HAPAuthenticationHandler::processSetupRequest(const TLVList& requestTLVList, TLVList& responseTLVList)
{
	TLV_ref stateTLV = getTLVForType(TLVTypeState, requestTLVList);
	if (NULL == stateTLV) {
		printf("empty state tlv\n");
		//todo: send error
		return HAP::BAD_REQUEST;
	}

	uint8_t tlvState = stateTLV->getValue().at(0);
	printf("state: %02hhx\n", tlvState);
	
	switch (tlvState) {
		case M1:
		{	
			//clear the previous session and create a new one
			//todo: reset _sessionRef after timeout. otherwise no body can pair
			if (_srpSessionRef != NULL && SRP_free(_srpSessionRef) < 0) {
				printf("failed to clear srp session\n");
				return HAP::INTERNAL_ERROR;
			}
			_srpSessionRef = SRP_new(SRP6a_server_method());
			
			//set username
			if (SRP_set_username(_srpSessionRef, userNameForPairSetup) < 0) {
				printf("failed to set username: \n");
				return HAP::INTERNAL_ERROR;
			}
			//set N, G, salt
			byte_string salt;
			HAPAuthenticationUtility::generateRandomBytes(salt, SALT_LENGTH);				
			struct t_preconf* predefinedSRPConstant = t_getpreparam(SRP_3072_NG_INDEX);

			if (SRP_set_params(
					_srpSessionRef, 
					predefinedSRPConstant->modulus.data, 
					predefinedSRPConstant->modulus.len,
					predefinedSRPConstant->generator.data, 
					predefinedSRPConstant->generator.len,
					salt.data(), 
					SALT_LENGTH) < 0) {
				printf("SRP_set_params failed\n");
				return HAP::INTERNAL_ERROR;
			}
			//set password
			if (SRP_set_auth_password(_srpSessionRef, _password) < 0) {
				printf("SRP_set_authenticator failed\n");
				return HAP::INTERNAL_ERROR;
			}

			/*if (SRP_set_authenticator(_srpSessionRef, 
					reinterpret_cast<const unsigned char*>(_password), strlen(_password)) < 0) {
				printf("SRP_set_authenticator failed\n");
				return HAP::INTERNAL_ERROR;
			}
			*/
			//generate SRP public key
			cstr* accessorySRPPublicKey = NULL;
			if (SRP_gen_pub(_srpSessionRef, &accessorySRPPublicKey) != SRP_SUCCESS) {
				printf("SRP_gen_pub failed\n");
				return HAP::INTERNAL_ERROR;
			}
			
			////setting accessory's public key			
			computeTLVsFromString(TLVTypePublicKey, 
				accessorySRPPublicKey->data, accessorySRPPublicKey->length, responseTLVList);
			////setting salt
			responseTLVList.push_back(TLV_ref(new TLV(TLVTypeSalt, salt)));
			////setting state
			responseTLVList.push_back(createTLVForState(M2));

			cstr_free(accessorySRPPublicKey);
			break;
		}
		case M3:
		{
			TLV_ref controllerSRPPublicKeyTLV = getTLVForType(TLVTypePublicKey, requestTLVList);
			TLV_ref controllerProofTLV = getTLVForType(TLVTypeProof, requestTLVList);

			if (NULL == controllerSRPPublicKeyTLV || NULL == controllerProofTLV) {
				return HAP::BAD_REQUEST;
			}

			printString(controllerSRPPublicKeyTLV->getValue(), "controllerPublicKey");
			printString(controllerProofTLV->getValue(), "controllerProof");

			byte_string controllerSRPPublicKey = controllerSRPPublicKeyTLV->getValue();
			cstr* sharedSecretKey = NULL;

			if (SRP_compute_key(_srpSessionRef, 
								&sharedSecretKey, 
								controllerSRPPublicKey.data(),
								controllerSRPPublicKey.size()) != SRP_SUCCESS) {
				printf("SRP_compute_key failed\n");
				return HAP::INTERNAL_ERROR;
			}
			
			//save shared secret session key
			_srpSessionSecretKey.assign(
				sharedSecretKey->data, 
				sharedSecretKey->data + sharedSecretKey->length);
			
			cstr_free(sharedSecretKey);
			
			
			byte_string controllerProof = controllerProofTLV->getValue();
			if (SRP_SUCCESS != SRP_verify(_srpSessionRef, controllerProof.data(), controllerProof.size())) {
				printf("SRP_verify failed\n");
				//todo: create AuthErr TLV
				return HAP::BAD_REQUEST;
			}
			

			cstr* accessoryProof = NULL;
			if (SRP_SUCCESS != SRP_respond(_srpSessionRef, &accessoryProof)) {
				printf("SRP_respond failed\n");
				return HAP::INTERNAL_ERROR;
			}

			////setting accessory's proof
			computeTLVsFromString(TLVTypeProof, 
				accessoryProof->data, accessoryProof->length, responseTLVList);
			////setting state
			responseTLVList.push_back(createTLVForState(M4));

			cstr_free(accessoryProof);			
			break;
		}
		case M5:
		{
			TLV_ref controllerEncryptedLongTermPublicKey 
				= getTLVForType(TLVTypeEncryptedData, requestTLVList);
			TLV_ref controllerAuthTag = getTLVForType(TLVTypeAuthTag, requestTLVList);

			if (controllerEncryptedLongTermPublicKey == NULL 
				|| controllerAuthTag == NULL) {
				return HAP::BAD_REQUEST;
			}
			//get the encryptionKey
			byte_string sharedEncryptionDecryptionKey;
			if (!HAPAuthenticationUtility::computeEncryptionKeyFromSRPSharedSecret(
				_srpSessionSecretKey, sharedEncryptionDecryptionKey)) {
				printf("failed to create encryptionKey\n");
				return HAP::INTERNAL_ERROR;
			}

			//decryptController LTPK
			byte_string controllerDecryptedLongTermPublicKey;
			if (!HAPAuthenticationUtility::decryptControllerLTPK(
					sharedEncryptionDecryptionKey,
					controllerEncryptedLongTermPublicKey->getValue(),
					controllerAuthTag->getValue(), 
					controllerDecryptedLongTermPublicKey)) {
				printf("failed to decrypt controller key\n");
				return HAP::BAD_REQUEST;
				//todo: create auth error tlv
			}
			//generate accessory's long term keys
			byte_string accessoryLongTermPublicKey, accessoryLongTermSecretKey;
			HAPAuthenticationUtility::generateKeyPairUsingEd25519(
				accessoryLongTermPublicKey, accessoryLongTermSecretKey);
			
			byte_string controllerUsername;
			controllerUsername.assign(_srpSessionRef->username->data, 
				_srpSessionRef->username->data + _srpSessionRef->username->length);
			//save pairing
			HAPPairing pairing(controllerUsername,
							   controllerDecryptedLongTermPublicKey,
							   accessoryLongTermPublicKey,
							   accessoryLongTermSecretKey);
			if (!pairing.savePairing()) {
				return HAP::INTERNAL_ERROR;
			}
			
			//prepare response
			if (!prepareEncryptedAccessoryData(
				sharedEncryptionDecryptionKey, accessoryLongTermPublicKey, responseTLVList)) {

				return HAP::BAD_REQUEST;
			}
			

			//srp session is over			
			SRP_free(_srpSessionRef);
			_srpSessionRef = NULL;
			break;
		}
		default:
			printf("no matching state found\n");
			//todo: send error
			return HAP::BAD_REQUEST;
	}

	return HAP::SUCCESS;
}

void 
HAPAuthenticationHandler::sendTLVToClient(
		HAPClient& client, HAP::HAPStatus status, const TLVList& tlvList)
{
	byte_string messageBody;
	for (TLV_ref tlv : tlvList) {
		tlv->encode(messageBody);
	}

	//printString(messageBody, "response");

	client.sendHeader(status, messageBody.size(), HAP::HAPMessageContentTypeTLV);
	client.printBytes(reinterpret_cast<char*>(messageBody.data()), messageBody.size());	
}

TLV_ref
HAPAuthenticationHandler::getTLVForType(TLVType tlvType, const TLVList& tlvList)
{
	TLVList matchedItems;

	for (TLV_ref tlv : tlvList) {
		if (tlv->getTag().at(0) == tlvType) {
			matchedItems.push_back(tlv);
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
	for (TLV_ref tlv : matchedItems) {
		out += tlv->getValue();
	}


	return TLV_ref(new TLV(tlvType, out));
}


HAP::HAPStatus
HAPAuthenticationHandler::processVerifyRequest(HAPClient& client, const TLVList& requestTLVList, TLVList& responseTLVList)
{
	TLV_ref stateTLV = getTLVForType(TLVTypeState, requestTLVList);
	if (NULL == stateTLV) {
		printf("empty state tlv\n");
		//todo: send error
		return HAP::BAD_REQUEST;
	}

	uint8_t tlvState = stateTLV->getValue().at(0);
	printf("state: %02hhx\n", tlvState);

	switch (tlvState) {
		case M1:
		{
			TLV_ref controllerUsername = getTLVForType(TLVTypeIdentifier, requestTLVList);
			TLV_ref controllerPublicKey = getTLVForType(TLVTypePublicKey, requestTLVList);

			if (NULL == controllerUsername || NULL == controllerPublicKey) {
				//todo: send error
				return HAP::BAD_REQUEST;
			}

			HAPPairing pairing(controllerUsername->getValue());
			if (!pairing.retievePairing()) {
				//send UnknownPeerErr
				return HAP::BAD_REQUEST;
			}
			
			byte_string accessoryPublicKey, accessorySecretKey, sharedSecret, accessoryProof;
			
			HAPAuthenticationUtility::generateKeyPairUsingCurve25519(accessoryPublicKey, accessorySecretKey);
			HAPAuthenticationUtility::
				generateSharedSecretUsingCurve25519(controllerPublicKey->getValue(), accessorySecretKey, sharedSecret);

			//Station-To-Station XY
			byte_string stationToStationXY;
			stationToStationXY += controllerPublicKey->getValue();
			stationToStationXY += accessoryPublicKey;

			client.setPairVerifyInfo(sharedSecret, 
				pairing.controllerLongTermPublicKey(), stationToStationXY);
							
			//Station-To-Station YX
			byte_string stationToStationYX;
			stationToStationYX += accessoryPublicKey;
			stationToStationYX += controllerPublicKey->getValue();

			HAPAuthenticationUtility::generateAccessoryProofForSTSProtocol(
				stationToStationYX, pairing.accessoryLongTermPublicKey(), pairing.accessoryLongTermSecretKey(),
				sharedSecret, accessoryProof);

			////setting accessory's username
			responseTLVList.push_back(TLV_ref(new TLV(TLVTypeIdentifier, _accessoryUsername)));
			////setting accessory's public key			
			computeTLVsFromString(TLVTypePublicKey, accessoryPublicKey, responseTLVList);
			computeTLVsFromString(TLVTypeProof, accessoryProof, responseTLVList);
			////setting state
			responseTLVList.push_back(createTLVForState(M2));

			break;
		}
		case M3:
		{
			TLV_ref controllerProofTLV = getTLVForType(TLVTypeProof, requestTLVList);
			if (controllerProofTLV == NULL) {
				return HAP::BAD_REQUEST;
			}

			byte_string sharedSecretForSession, controllerLongTermPublicKey, stationToStationXY;
				
			client.getPairVerifyInfo(sharedSecretForSession,
				controllerLongTermPublicKey, stationToStationXY);

			if (!HAPAuthenticationUtility::verifyControllerProofForSTSProtocol(
				stationToStationXY, controllerLongTermPublicKey, sharedSecretForSession, controllerProofTLV->getValue())) {
				//send AuthenticationErr
				printf("failed to verify session\n");
				return HAP::BAD_REQUEST;
			}
	
			byte_string accessoryToControllerKey, controllerToAccessoryKey;

			HAPAuthenticationUtility::generateSessionKeys(
				sharedSecretForSession, accessoryToControllerKey, controllerToAccessoryKey);

			client.setSessionKeys(accessoryToControllerKey, controllerToAccessoryKey);

			////setting state			
			responseTLVList.push_back(createTLVForState(M4));
			break;
		}
		default:
			printf("no matching state found\n");
			//todo: send error
			return HAP::BAD_REQUEST;
	}

	return HAP::SUCCESS;
}

HAP::HAPStatus
HAPAuthenticationHandler::parseRequestBody(const HAPClient& client, TLVList& tlvList)
{
	const char* message = client.getMessage();
	int messageLength = client.getMessageLength();

	byte_string bytes(message, message + messageLength);
	printString(bytes, "request");

	try {
		byte_string::iterator begin = bytes.begin();

		TLV::parseSequence(begin, bytes.end(), tlvList);
	}
	catch (const std::runtime_error& error) {
		printf("runtime_error: %s\n", error.what());
		return HAP::BAD_REQUEST;
	}

	return HAP::SUCCESS;
}


void
HAPAuthenticationHandler::computeTLVsFromString(TLVType tlvType,
		const byte_string& inputString, TLVList& outputTLVList)
{
	computeTLVsFromString(
		tlvType, (const char*) inputString.data(), inputString.size(), outputTLVList);
}

void 
HAPAuthenticationHandler::computeTLVsFromString(
							TLVType tlvType, 
							const char* inputString, 
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


bool
HAPAuthenticationHandler::prepareEncryptedAccessoryData(
	const byte_string& sharedEncryptionDecryptionKey, 
	const byte_string& accessoryLongTermPublicKey, 
	TLVList& responseTLVList)
{
	//create sub tlv
	TLVList subTLVList;
	subTLVList.push_back(TLV_ref(new TLV(TLVTypeIdentifier, _accessoryUsername)));
	computeTLVsFromString(TLVTypePublicKey, accessoryLongTermPublicKey, subTLVList);
	
	byte_string subTLVdata;
	for (TLV_ref tlv : subTLVList) {
		tlv->encode(subTLVdata);
	}

	//encrypt
	byte_string encryptedData, authTag;
	if (!HAPAuthenticationUtility::encryptAccessoryLTPK(
		sharedEncryptionDecryptionKey, subTLVdata, authTag, encryptedData)) {
		return false;
	}
	
	responseTLVList.push_back(TLV_ref(new TLV(TLVTypeAuthTag, authTag)));	
	computeTLVsFromString(TLVTypeEncryptedData, encryptedData, responseTLVList);
	responseTLVList.push_back(createTLVForState(M6));

	return true;
}
