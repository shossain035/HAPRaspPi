#ifndef _HAPCLIENT_H_
#define _HAPCLIENT_H_

#include "CivetServer.h"

namespace HAP
{
	enum HAPStatus
	{
		SUCCESS        = -200,
		BAD_REQUEST    = -400,
		INTERNAL_ERROR = -500
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

	void sendHeader(HAP::HAPStatus status, int contentLength);
private:
	struct mg_connection* _conn;
};
#endif