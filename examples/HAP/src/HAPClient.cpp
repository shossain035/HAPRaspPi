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
	//todo: force secure connection
	if (!_isSecuredConnection) {
		mg_write(_conn, _response.data(), _response.size());
		return;
	}

	byte_string authTag;
	
	HAPAuthenticationUtility::encryptHAPResponse(request_info->accessoryToControllerKey, 
		request_info->outgoingNonce, _response, authTag, _response);
	//todo: consider threading issues
	request_info->outgoingFrameCounter++;
	
	union {
		//warning: assumed littleendian
		uint32_t encryptedResponseLength;
		uint8_t encryptedResponseLengthBytes[4];
	};

	encryptedResponseLength = _response.size();
	
	//<4B: length of encrypted text, n>, <n: encrypted text> <16: authTag>
	_response.insert(_response.begin(), encryptedResponseLengthBytes, encryptedResponseLengthBytes + 4);
	_response += authTag;

	mg_write(_conn, _response.data(), _response.size());
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

void HAPClient::getPairVerifyInfo(byte_string& sharedSecretForSession,
		byte_string& controllerLongTermPublicKey, byte_string& stationToStationXY)
{
	mg_request_info *request_info = mg_get_request_info(_conn);
	
	sharedSecretForSession.assign(request_info->sharedSecretForSession,
		request_info->sharedSecretForSession + SESSION_SECURITY_KEY_LENGTH);
	controllerLongTermPublicKey.assign(request_info->controllerLongTermPublicKey,
		request_info->controllerLongTermPublicKey + SESSION_SECURITY_KEY_LENGTH);
	stationToStationXY.assign(request_info->stationToStationXY,
		request_info->stationToStationXY + STATION_TO_STATION_XY_LENGTH);
}

void HAPClient::setPairVerifyInfo(const byte_string& sharedSecretForSession,
	const byte_string& controllerLongTermPublicKey, const byte_string& stationToStationXY)
{
	mg_request_info *request_info = mg_get_request_info(_conn);

	memcpy(request_info->sharedSecretForSession, sharedSecretForSession.data(),
		SESSION_SECURITY_KEY_LENGTH);
	memcpy(request_info->controllerLongTermPublicKey, controllerLongTermPublicKey.data(),
		SESSION_SECURITY_KEY_LENGTH);
	memcpy(request_info->stationToStationXY, stationToStationXY.data(),
		STATION_TO_STATION_XY_LENGTH);
}

void HAPClient::setSessionKeys(
	const byte_string& accessoryToControllerKey, const byte_string& controllerToAccessoryKey)
{
	mg_request_info *request_info = mg_get_request_info(_conn);

	request_info->isSecuredSession = 1;
	memcpy(request_info->accessoryToControllerKey,
		accessoryToControllerKey.data(), SESSION_SECURITY_KEY_LENGTH);
	memcpy(request_info->controllerToAccessoryKey,
		controllerToAccessoryKey.data(), SESSION_SECURITY_KEY_LENGTH);
}

const char* HAPClient::getMessage() const
{
	return CivetServer::getBody(_conn);
}


int HAPClient::getMessageLength() const
{
	return CivetServer::getContentLength(_conn);
}
