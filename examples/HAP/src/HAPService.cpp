#include "HAPService.h"
#include <stdio.h>


const char * HAPServiceTypes::accessoryInformation = "3E";
const char * HAPServiceTypes::light = "43";

HAPService::HAPService(unsigned int instanceId, const char * const type, HAPCharacteristic ** const characteristics, unsigned char characteristicsCount)
	:HAPBase(instanceId),
	_type(type), 
	_characteristics(characteristics),
	_characteristicsCount(characteristicsCount)
{
}

int HAPService::sendToClient(HAPClient & client)
{
	printInstanceId(client);

	client.print(",\"type\":\"");
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
	//todo: hard coded mapping #100
	int characteristicIndex = characteristicId - _instanceId * 100;
	
	if (!HAPBase::withinInclusiveRange(characteristicIndex, 0, (int)_characteristicsCount - 1)) {
		return NULL;
	}

	return _characteristics[characteristicIndex];
}


HAPService::~HAPService()
{
	for (int i = 0; i < _characteristicsCount; i++) {
		delete _characteristics[i];
	}

	delete[] _characteristics;
}
