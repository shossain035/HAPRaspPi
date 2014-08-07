#ifndef _HAPCLIENT_H_
#define _HAPCLIENT_H_

#include <stddef.h>

namespace HAP
{
	enum HAPStatus
	{
		SUCCESS           = -200,
		BAD_REQUEST       = -400,
		TOO_MANY_REQUESTS = -429,
		INTERNAL_ERROR    = -500
	};

	enum HAPMessageContentType
	{
		HAPMessageContentTypeJSON,
		HAPMessageContentTypeTLV
	};
}

class HAPClient {
public:
	HAPClient(struct mg_connection* conn);
	void print(int i);
	void print(const char * string);
	void println(int i);
	void println(const char * string);
	void println();

	void printBytes(const char * bytes, size_t length);

	const char* getMessage() const;
	int getMessageLength() const;

	void sendHeader(HAP::HAPStatus status, size_t contentLength, 
		HAP::HAPMessageContentType contentType = HAP::HAPMessageContentTypeJSON);
	void sendHeaderWithoutBody(HAP::HAPStatus status);

	void getSharedSecretForSession(unsigned char *sharedSecretForSession);
	void setSharedSecretForSession(const unsigned char *sharedSecretForSession);
	void setSessionKeys(
		const unsigned char *accessoryToControllerKey, const unsigned char *controllerToAccessoryKey);

private:
	struct mg_connection* _conn;
};
#endif