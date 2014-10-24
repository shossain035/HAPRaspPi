#ifndef _HAPBASE_H_
#define _HAPBASE_H_

#include "HAPClient.h"

class HAPBase {
public:
	HAPBase(unsigned int instanceId);
	virtual int sendToClient(HAPClient& client) = 0;
	virtual ~HAPBase() {}

	//utility functions
	template <class T> 
	static bool withinInclusiveRange(T value, T low, T high) 
	{
		return (value >= low  && value <= high);
	}
protected: 
	unsigned int _instanceId;
	virtual void printInstanceId(HAPClient & client);
};
#endif