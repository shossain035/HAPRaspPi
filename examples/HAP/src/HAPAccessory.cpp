#include "HAPAccessory.h"


HAPAccessory::HAPAccessory(unsigned char instanceId, HAPService ** const services, unsigned char servicesCount)
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

HAPAccessory::~HAPAccessory()
{
	for (int i = 0; i < _servicesCount; i++) {
		delete _services[i];
	}

	delete[] _services;
}
