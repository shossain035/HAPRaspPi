#ifndef _HAPBASE_H_
#define _HAPBASE_H_

#include "HAPClient.h"

class HAPBase {
public:
	HAPBase(unsigned char instanceId);
	virtual int sendToClient(HAPClient& client) = 0;
	virtual ~HAPBase() {}

	//utility functions
	template <class T> 
	static bool withinInclusiveRange(T value, T low, T high) 
	{
		return (value >= low  && value <= high);
	}
protected: 
	unsigned char _instanceId;
	void printInstanceId(HAPClient & client);
};
#endif