#ifndef _HAPBASE_H_
#define _HAPBASE_H_

#include <Client.h>


namespace HAP
{
	enum HAPError
	{
		BAD_REQUEST = -400,
		INTERNAL_ERROR = -500
	};
}

class HAPBase {
public:
	HAPBase(unsigned char instanceId);
	virtual int sendToClient(Client & client) = 0;
	virtual ~HAPBase() = 0;
protected: 
	unsigned char _instanceId;
};
#endif