#ifndef _HAPBASE_H_
#define _HAPBASE_H_

#include "HAPClient.h"

class HAPBase {
public:
	HAPBase(unsigned char instanceId);
	virtual int sendToClient(HAPClient& client) = 0;
	virtual ~HAPBase() {};
protected: 
	unsigned char _instanceId;
	void printInstanceId(HAPClient & client);
};
#endif