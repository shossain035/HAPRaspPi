#ifndef _HAPBASE_H_
#define _HAPBASE_H_

#include "HAPClient.h"

class HAPBase {
public:
	HAPBase(unsigned char instanceId);
	virtual int sendToClient(HAPClient & client) = 0;
	virtual ~HAPBase() = 0;
protected: 
	unsigned char _instanceId;
};
#endif