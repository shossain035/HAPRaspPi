#include "HAPServer.h"

HAPServer::HAPServer()
{
	HAPCharacteristic ** informationCharacteristics = new HAPCharacteristic*[5];
	informationCharacteristics[0] = new HAPCharacteristic(1, HAPCharacteristicTypes::name, "Arduino Light");
	informationCharacteristics[1] = new HAPCharacteristic(2, HAPCharacteristicTypes::manufacturer, "Lithouse");
	informationCharacteristics[2] = new HAPCharacteristic(3, HAPCharacteristicTypes::model, "Light 11");
	informationCharacteristics[3] = new HAPCharacteristic(4, HAPCharacteristicTypes::serialNumber, "1CWE5F2");
	informationCharacteristics[4] = new HAPCharacteristic(5, HAPCharacteristicTypes::identify, 0);

	HAPCharacteristic ** lightBulbCharacteristics = new HAPCharacteristic*[1];
	lightBulbCharacteristics[0] = new HAPCharacteristic(1, HAPCharacteristicTypes::powerState, 0);

	HAPService ** services = new HAPService*[2];
	services[0] = new HAPService(1, HAPServiceTypes::accessoryInformation, informationCharacteristics, 5);
	services[1] = new HAPService(2, HAPServiceTypes::light, lightBulbCharacteristics, 1);
	
	_accessoryCount = 1;
	_accessories = new HAPAccessory*[_accessoryCount];
	_accessories[0] = new HAPAccessory(1, services, 2);
}

void HAPServer::getAccessories(HAPClient & client)
{
	//todo calculate length programetically
	client.sendHeader(HAP::SUCCESS, 926);
	client.print("{\"accessories\":[");

	for (unsigned char i = 0; i < _accessoryCount; i++) {
		if (i != 0) {
			client.print(",");
		}
		_accessories[i]->sendToClient(client);
	}

	client.println("]}");
}

HAPCharacteristic* HAPServer::getCharacteristic(
	int accessoryId, int serviceId, int characteristicId)
{
	if (!HAPBase::withinInclusiveRange(accessoryId, 1, _accessoryCount)) {
		return NULL;
	}

	HAPAccessory* accessory = _accessories[accessoryId - 1];
	HAPService* service = accessory->serviceForId(serviceId);

	if (NULL == service) {
		return NULL;
	}

	HAPCharacteristic* characteristic = service->characteristicForId(characteristicId);

	if (NULL == characteristic) {
		return NULL;
	}
	
	return characteristic;
}

void HAPServer::getCharacteristic(HAPClient& client,
	int accessoryId, int serviceId, int characteristicId)
{
	HAPCharacteristic* characteristic 
		= getCharacteristic(accessoryId, serviceId, characteristicId);

	if (characteristic == NULL) {
		client.sendHeaderWithoutBody(HAP::BAD_REQUEST);
		return;
	}
	//todo: length programetically
	client.sendHeader(HAP::SUCCESS, 106);
	characteristic->sendToClient(client);
}

void HAPServer::putCharacteristic(HAPClient& client,
	int accessoryId, int serviceId, int characteristicId, const char* body)
{
	HAPCharacteristic* characteristic
		= getCharacteristic(accessoryId, serviceId, characteristicId);

	if (characteristic == NULL) {
		client.sendHeaderWithoutBody(HAP::BAD_REQUEST);
		return;
	}
	
	characteristic->updateValueWithJSON(client, body);
}

HAPServer::~HAPServer()
{
	for (int i = 0; i < _accessoryCount; i++) {
		delete _accessories[i];
	}

	delete[] _accessories;
}

