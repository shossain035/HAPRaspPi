#include "HAPService.h"
#include <stdio.h>


const char * HAPServiceTypes::accessoryInformation = "accessory-information";
const char * HAPServiceTypes::light = "lightbulb";

HAPService::HAPService(unsigned char instanceId, const char * const type, HAPCharacteristic ** const characteristics, unsigned char characteristicsCount)
	:HAPBase(instanceId),
	_type(type), 
	_characteristics(characteristics),
	_characteristicsCount(characteristicsCount)
{
}

int HAPService::sendToClient(HAPClient & client)
{
	printInstanceId(client);

	client.print(",\"type\":\"public.hap.service.");
	client.print(_type);
	client.print("\",\"characteristics\":[");

	for (unsigned char i = 0; i < _characteristicsCount; i++) {
		if (i != 0) {
			client.print(",");
		}
		_characteristics[i]->sendToClient(client);
	}

	client.print("]}");

	return HAP::BAD_REQUEST;
}

HAPCharacteristic* HAPService::characteristicForId(int characteristicId)
{
	if (!HAPBase::withinInclusiveRange(characteristicId, 1, (int)_characteristicsCount)) {
		return NULL;
	}

	return _characteristics[characteristicId - 1];
}

HAPService::~HAPService()
{
	for (int i = 0; i < _characteristicsCount; i++) {
		delete _characteristics[i];
	}

	delete[] _characteristics;
}
