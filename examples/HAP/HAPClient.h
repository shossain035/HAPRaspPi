#ifndef _HAPCLIENT_H_
#define _HAPCLIENT_H_


namespace HAP
{
	enum HAPError
	{
		BAD_REQUEST = -400,
		INTERNAL_ERROR = -500
	};
}

class HAPClient {
public:
	void print(unsigned char byte) {}
	void print(const char * string) {}
	void println(const char * string) {}
	void println() {}
};
#endif