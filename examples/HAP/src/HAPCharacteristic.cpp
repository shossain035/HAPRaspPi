#include "HAPCharacteristic.h"
#include <string.h>
#include <stdio.h>


const char * HAPCharacteristicTypes::name = "name";
const char * HAPCharacteristicTypes::manufacturer = "manufacturer";
const char * HAPCharacteristicTypes::model = "model";
const char * HAPCharacteristicTypes::serialNumber = "serial-number";
const char * HAPCharacteristicTypes::identify = "identify";
const char * HAPCharacteristicTypes::powerState = "on";


HAPCharacteristic::HAPCharacteristic(unsigned char instanceId, const char * const type, const char * value)
	:HAPBase(instanceId), _type(type), _value(new HAPCharacteristicValue)
{
	_value->s = value;
}

HAPCharacteristic::HAPCharacteristic(unsigned char instanceId, const char * const type, int value)
	:HAPBase(instanceId), _type(type), _value(new HAPCharacteristicValue)
{
	_value->i = value;
}

int HAPCharacteristic::sendToClient(HAPClient & client)
{
	//todo: properties and meta data
	printInstanceId(client);

	client.print(",\"type\":\"public.hap.characteristic.");
	client.print(_type);

	client.print("\",\"properties\":[\"secureRead\",\"secureWrite\"],\"value\":");

	if (_type == HAPCharacteristicTypes::powerState) {
		client.print(_value->i);
	}
	else if (_type == HAPCharacteristicTypes::identify) {
		client.print("null");
	} else {
		client.print("\"");
		client.print(_value->s);
		client.print("\"");
	}

	client.print("}");

	return 0;
}

//todo: a lot!
void HAPCharacteristic::updateValueWithJSON(HAPClient& client, const char* string)
{
	if (string == NULL) {
		printf("empty message body\n");
		client.sendHeaderWithoutBody(HAP::BAD_REQUEST);
		return;
	}
	
	const char* valueTagString = strstr(string, "value");
	if (valueTagString == NULL) {
		printf("missing 'value'\n");
		client.sendHeaderWithoutBody(HAP::BAD_REQUEST);
		return;
	}

	const char* valueStringBegin = strchr(string, ':');
	if (valueTagString == NULL) {
		printf("malformed json\n");
		client.sendHeaderWithoutBody(HAP::BAD_REQUEST);
		return;
	}

	if (1 != sscanf(valueStringBegin, ":%d", &_value->i)) {
		client.sendHeaderWithoutBody(HAP::BAD_REQUEST);
		return;
	}

	printf("characteristic updated to :%d\n", _value->i);
	client.sendHeader(HAP::SUCCESS, 106);
	sendToClient(client);
}

HAPCharacteristic::~HAPCharacteristic()
{ 
	delete _value; 
}