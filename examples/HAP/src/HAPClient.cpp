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

	for (int i = 0; i < _response.size(); i++) {
		printf("%c", _response.data() [i]);
	}

	HAPAuthenticationUtility::encryptHAPResponse(request_info->accessoryToControllerKey, 
		request_info->outgoingNonce, _response, _response);
	//todo: consider threading issues
	request_info->outgoingFrameCounter++;
			
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

void HAPClient::getPairVerifyInfo(byte_string& pairVerifySharedSecret,
	byte_string& controllerPublicKey, byte_string& accessoryPublicKey)
{
	mg_request_info *request_info = mg_get_request_info(_conn);
	
	pairVerifySharedSecret.assign(request_info->pairVerifySharedSecret,
		request_info->pairVerifySharedSecret + SESSION_SECURITY_KEY_LENGTH);
	controllerPublicKey.assign(request_info->controllerPublicKey,
		request_info->controllerPublicKey + SESSION_SECURITY_KEY_LENGTH);
	accessoryPublicKey.assign(request_info->accessoryPublicKey,
		request_info->accessoryPublicKey + SESSION_SECURITY_KEY_LENGTH);
}

void HAPClient::setPairVerifyInfo(const byte_string& pairVerifySharedSecret,
	const byte_string& controllerPublicKey, const byte_string& accessoryPublicKey)
{
	mg_request_info *request_info = mg_get_request_info(_conn);

	memcpy(request_info->pairVerifySharedSecret, pairVerifySharedSecret.data(),
		SESSION_SECURITY_KEY_LENGTH);
	memcpy(request_info->controllerPublicKey, controllerPublicKey.data(),
		SESSION_SECURITY_KEY_LENGTH);
	memcpy(request_info->accessoryPublicKey, accessoryPublicKey.data(),
		SESSION_SECURITY_KEY_LENGTH);
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
