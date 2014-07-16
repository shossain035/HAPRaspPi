#include <HAPService.h>


const char * HAPServiceTypes::accessoryInformation = "accessory-information";
const char * HAPServiceTypes::light = "lightbulb";

HAPService::HAPService(unsigned char instanceId, const char * const type, HAPCharacteristic ** const characteristics, unsigned char characteristicsCount)
	:HAPBase(instanceId),
	_type(type), 
	_characteristics(characteristics),
	_characteristicsCount(characteristicsCount)
{
}

int HAPService::sendToClient(Client & client)
{
	client.print("{\"instanceID\":");
	client.print(_instanceId);
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

HAPService::~HAPService()
{
	for (int i = 0; i < _characteristicsCount; i++) {
		delete _characteristics[i];
	}

	delete[] _characteristics;
}
