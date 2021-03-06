#include "HAPAccessory.h"
#include <stdio.h>

HAPAccessory::HAPAccessory(unsigned int instanceId, HAPService ** const services, unsigned char servicesCount)
	:HAPBase(instanceId), _services(services), _servicesCount(servicesCount)
{
}

int HAPAccessory::sendToClient(HAPClient & client)
{
	printInstanceId(client);

	client.print(",\"services\":[");

	for (unsigned char i = 0; i < _servicesCount; i++) {
		if (i != 0) {
			client.print(",");
		}
		_services[i]->sendToClient(client);
	}

	client.print("]}");

	return 0;
}

HAPService* HAPAccessory::serviceForId(int serviceId)
{
	if (!HAPBase::withinInclusiveRange(serviceId, 1, (int)_servicesCount)) {
		printf("failed service\n");
		return NULL;
	}

	return _services[serviceId-1];
}

HAPAccessory::~HAPAccessory()
{
	for (int i = 0; i < _servicesCount; i++) {
		delete _services[i];
	}

	delete[] _services;
}

void HAPAccessory::printInstanceId(HAPClient & client)
{
	client.print("{\"aid\":");
	client.print((int)_instanceId);
}

