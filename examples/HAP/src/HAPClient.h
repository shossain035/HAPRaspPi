#ifndef _HAPCLIENT_H_
#define _HAPCLIENT_H_

#include <stddef.h>
#include <stdint.h>
#include "byte_string.h"

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
	~HAPClient();

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

	void getPairVerifyInfo(uint8_t *sharedSecretForSession,
		uint8_t *controllerLongTermPublicKey, uint8_t *stationToStationXY);

	void setPairVerifyInfo(const uint8_t *sharedSecretForSession,
		const uint8_t *controllerLongTermPublicKey, const uint8_t *stationToStationXY);

	void setSessionKeys(
		const uint8_t *accessoryToControllerKey, const uint8_t *controllerToAccessoryKey);

private:
	struct mg_connection* _conn;
	byte_string _response;
	bool _isSecuredConnection;
};
#endif