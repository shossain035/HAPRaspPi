#include "HAPBase.h"

HAPBase::HAPBase(unsigned char instanceId)
{
	_instanceId = instanceId;
}

void HAPBase::printInstanceId(HAPClient & client)
{
	client.print("{\"instanceID\":");
	client.print((int)_instanceId);
}
