#include "HAPClient.h"
#include "CivetServer.h"
#include "HAPAuthenticationUtility.h"


HAPClient::HAPClient(struct mg_connection* conn) : _conn(conn) 
{
	mg_request_info *request_info = mg_get_request_info(_conn);

	if (request_info->isSecuredSession) {
		_isSecuredConnection = true;
	}
}

HAPClient::~HAPClient()
{
	mg_request_info *request_info = mg_get_request_info(_conn);

	if (!_isSecuredConnection) {
		mg_write(_conn, _response.data(), _response.size());
		return;
	}

	//byte_string encryptedResponse, authTag;
	byte_string authTag;
	//todo: nonce based on counter. related to decrypt_request in civetweb.c
	uint8_t nonce[] = { 0, 0, 0, 0, 0, 0, 0, 0 };

	HAPAuthenticationUtility::encryptHAPResponse(request_info->accessoryToControllerKey, nonce, _response, authTag, _response);

	union {
		//warning: assumed littleendian
		uint32_t encryptedResponseLength;
		uint8_t encryptedResponseLengthBytes[4];
	};
	encryptedResponseLength = _response.size();
	printf("\n\nlength %d\n", _response.size());
	byte_string encryptedFrame;
	encryptedFrame.insert(encryptedFrame.end(), encryptedResponseLengthBytes, encryptedResponseLengthBytes + 4);
	encryptedFrame += _response;
	encryptedFrame += authTag;

	mg_write(_conn, encryptedFrame.data(), encryptedFrame.size());
}

void HAPClient::print(int i) 
{
	char value[10];

	sprintf(value, "%d", i);
	_response += value;
}

void HAPClient::print(const char * string) 
{
	_response += string;
}

void HAPClient::println(const char * string) 
{
	_response += string;
	println();
}

void HAPClient::println(int i)
{
	print(i);
	println();
}


void HAPClient::println() 
{ 
	print("\r\n");
}

void HAPClient::printBytes(const char * bytes, size_t length)
{	
	_response.insert(_response.end(), bytes, bytes + length);	
}

void HAPClient::sendHeaderWithoutBody(HAP::HAPStatus status)
{
	sendHeader(status, 0);
	println();
}

void HAPClient::sendHeader(HAP::HAPStatus status, size_t contentLength, 
						 HAP::HAPMessageContentType contentType)
{
	print("HTTP/1.1 ");

	switch (status) {
		case HAP::SUCCESS:
			println("200 OK");
			break;
		case HAP::BAD_REQUEST:
			println("400 Bad request");
			break;
		default:
			println("500 Internal Server Error");
			break;
	}

	print("Content-Type: application/");
	switch (contentType) {
		case HAP::HAPMessageContentTypeJSON:
			println("hap+json");
			break;
		case HAP::HAPMessageContentTypeTLV:
			println("pairing+tlv8");
			break;
	}

	print("Content-Length: ");
	println(contentLength);

	println();
}


void HAPClient::getPairVerifyInfo(uint8_t *sharedSecretForSession,
		uint8_t *controllerLongTermPublicKey, uint8_t *stationToStationXY)
{
	mg_request_info *request_info = mg_get_request_info(_conn);

	memcpy(sharedSecretForSession, request_info->sharedSecretForSession,
		SESSION_SECURITY_KEY_LENGTH);
	memcpy(controllerLongTermPublicKey, request_info->controllerLongTermPublicKey,
		SESSION_SECURITY_KEY_LENGTH);
	memcpy(stationToStationXY, request_info->stationToStationXY,
		2 * SESSION_SECURITY_KEY_LENGTH);
}

void HAPClient::setPairVerifyInfo(const uint8_t *sharedSecretForSession,
		const uint8_t *controllerLongTermPublicKey, const uint8_t *stationToStationXY)
{
	mg_request_info *request_info = mg_get_request_info(_conn);

	memcpy(request_info->sharedSecretForSession, sharedSecretForSession,
		SESSION_SECURITY_KEY_LENGTH);
	memcpy(request_info->controllerLongTermPublicKey, controllerLongTermPublicKey,
		SESSION_SECURITY_KEY_LENGTH);
	memcpy(request_info->stationToStationXY, stationToStationXY,
		2 * SESSION_SECURITY_KEY_LENGTH);
}

void HAPClient::setSessionKeys(
	const uint8_t *accessoryToControllerKey, 
	const uint8_t *controllerToAccessoryKey)
{
	mg_request_info *request_info = mg_get_request_info(_conn);

	request_info->isSecuredSession = 1;
	memcpy(request_info->accessoryToControllerKey,
		accessoryToControllerKey, SESSION_SECURITY_KEY_LENGTH);
	memcpy(request_info->controllerToAccessoryKey,
		controllerToAccessoryKey, SESSION_SECURITY_KEY_LENGTH);
}

const char* HAPClient::getMessage() const
{
	return CivetServer::getBody(_conn);
}

int HAPClient::getMessageLength() const
{
	return CivetServer::getContentLength(_conn);
}
