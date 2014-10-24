#include "HAPServer.h"
#include <stddef.h>


HAPServer::HAPServer()
{
	//service and characteristic iids myst be unique

	std::vector<CharacteristicPermession> readPermession;
	readPermession.push_back(CharacteristicPermession::PAIRED_READ);
	std::vector<CharacteristicPermession> writePermession;
	writePermession.push_back(CharacteristicPermession::PAIRED_WRITE);
	std::vector<CharacteristicPermession> readWritePermession;
	readWritePermession.push_back(CharacteristicPermession::PAIRED_READ);
	readWritePermession.push_back(CharacteristicPermession::PAIRED_WRITE);

	HAPCharacteristic ** informationCharacteristics = new HAPCharacteristic*[5];
	informationCharacteristics[0] = new HAPCharacteristic(100, HAPCharacteristicTypes::name, "Arduino Light", readPermession);
	informationCharacteristics[1] = new HAPCharacteristic(101, HAPCharacteristicTypes::manufacturer, "Litehouse", readPermession);
	informationCharacteristics[2] = new HAPCharacteristic(102, HAPCharacteristicTypes::model, "Light 11", readPermession);
	informationCharacteristics[3] = new HAPCharacteristic(103, HAPCharacteristicTypes::serialNumber, "1CWE5F2", readPermession);
	informationCharacteristics[4] = new HAPCharacteristic(104, HAPCharacteristicTypes::identify, 0, writePermession);

	HAPCharacteristic ** lightBulbCharacteristics = new HAPCharacteristic*[1];
	lightBulbCharacteristics[0] = new HAPCharacteristic(200, HAPCharacteristicTypes::powerState, 0, readWritePermession);

	HAPService ** services = new HAPService*[2];
	services[0] = new HAPService(1, HAPServiceTypes::accessoryInformation, informationCharacteristics, 5);
	services[1] = new HAPService(2, HAPServiceTypes::light, lightBulbCharacteristics, 1);
	
	_accessoryCount = 1;
	_accessories = new HAPAccessory*[_accessoryCount];
	_accessories[0] = new HAPAccessory(1, services, 2);
}

void HAPServer::getAccessories(HAPClient & client)
{
	//todo: calculate length programetically
	client.sendHeader(HAP::SUCCESS, 467);
	client.print("{\"accessories\":[");

	for (unsigned char i = 0; i < _accessoryCount; i++) {
		if (i != 0) {
			client.print(",");
		}
		_accessories[i]->sendToClient(client);
	}

	client.print("]}");
}

HAPCharacteristic* HAPServer::getCharacteristic(
	int accessoryId, int characteristicId)
{
	if (!HAPBase::withinInclusiveRange(accessoryId, 1, _accessoryCount)) {
		return NULL;
	}

	HAPAccessory* accessory = _accessories[accessoryId - 1];
	//todo: hard coded mapping #100
	int serviceId = characteristicId / 100;
	HAPService* service = accessory->serviceForId(serviceId);

	if (NULL == service) {
		printf("no service found found\n");

		return NULL;
	}

	return service->characteristicForId(characteristicId);
}

void HAPServer::getCharacteristic(HAPClient& client,
	int accessoryId, int characteristicId)
{
	HAPCharacteristic* characteristic 
		= getCharacteristic(accessoryId, characteristicId);

	if (characteristic == NULL) {
		client.sendHeaderWithoutBody(HAP::BAD_REQUEST);
		return;
	}
	//todo: length programetically
	client.sendHeader(HAP::SUCCESS, 106);
	characteristic->sendToClient(client);
}

void HAPServer::updateCharacteristic(HAPClient& client,
	int accessoryId, int characteristicId)
{
	HAPCharacteristic* characteristic
		= getCharacteristic(accessoryId, characteristicId);

	if (characteristic == NULL) {
		printf("no characteristic found\n");
		client.sendHeaderWithoutBody(HAP::BAD_REQUEST);
		return;
	}
	
	characteristic->updateValueWithJSON(client, client.getMessage());
}

void HAPServer::setupPair(HAPClient& client)
{
	_authenticationHAndlerHandler.setupPair(client);
}

void HAPServer::verifyPair(HAPClient& client)
{
	_authenticationHAndlerHandler.verifyPair(client);
}


HAPServer::~HAPServer()
{
	for (int i = 0; i < _accessoryCount; i++) {
		delete _accessories[i];
	}

	delete[] _accessories;
}

