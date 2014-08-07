#include "HAPClient.h"
#include "CivetServer.h"



HAPClient::HAPClient(struct mg_connection* conn) : _conn(conn) 
{
}

void HAPClient::print(int i) 
{
	mg_printf(_conn, "%d", i);
}

void HAPClient::print(const char * string) 
{
	mg_printf(_conn, "%s", string);
}

void HAPClient::println(const char * string) 
{
	print(string);
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
	mg_write(_conn, bytes, length);
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

void HAPClient::getSharedSecretForSession(unsigned char *sharedSecretForSession)
{
	CivetServer::getSharedSecretForSession(_conn, sharedSecretForSession);
}

void HAPClient::setSharedSecretForSession(const unsigned char *sharedSecretForSession)
{
	CivetServer::setSharedSecretForSession(_conn, sharedSecretForSession);
}

void HAPClient::setSessionKeys(
	const unsigned char *accessoryToControllerKey, 
	const unsigned char *controllerToAccessoryKey)
{
	CivetServer::setSessionKeys(_conn, accessoryToControllerKey, controllerToAccessoryKey);
}

const char* HAPClient::getMessage() const
{
	return CivetServer::getBody(_conn);
}

int HAPClient::getMessageLength() const
{
	return CivetServer::getContentLength(_conn);
}
