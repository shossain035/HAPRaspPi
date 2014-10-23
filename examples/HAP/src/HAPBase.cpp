#include "HAPBase.h"

HAPBase::HAPBase(unsigned char instanceId)
{
	_instanceId = instanceId;
}

void HAPBase::printInstanceId(HAPClient & client)
{
	client.print("{\"iid\":");
	client.print((int)_instanceId);
}
