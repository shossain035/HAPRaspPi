#include "HAPCharacteristic.h"


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
	client.print("{\"instanceID\":");
	client.print(_instanceId);

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

HAPCharacteristic::~HAPCharacteristic()
{ 
	delete _value; 
}