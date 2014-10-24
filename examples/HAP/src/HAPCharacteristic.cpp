#include "HAPCharacteristic.h"
#include <string.h>
#include <stdio.h>


const char * HAPCharacteristicTypes::name = "23";
const char * HAPCharacteristicTypes::manufacturer = "20";
const char * HAPCharacteristicTypes::model = "21";
const char * HAPCharacteristicTypes::serialNumber = "30";
const char * HAPCharacteristicTypes::identify = "14";
const char * HAPCharacteristicTypes::powerState = "25";


HAPCharacteristic::HAPCharacteristic(unsigned char instanceId, const char * const type, const char * value, 
	std::vector<CharacteristicPermession>& permissions)
	:HAPBase(instanceId), _type(type), _value(new HAPCharacteristicValue), _permessions(permissions)
{
	_value->s = value;
}

HAPCharacteristic::HAPCharacteristic(unsigned char instanceId, const char * const type, int value, 
	std::vector<CharacteristicPermession>& permissions)
	: HAPBase(instanceId), _type(type), _value(new HAPCharacteristicValue), _permessions(permissions)
{
	_value->i = value;
}

int HAPCharacteristic::sendToClient(HAPClient & client)
{
	//todo: properties and meta data
	printInstanceId(client);

	client.print(",\"type\":\"");
	client.print(_type);
	
	//todo: move into a separate function
	client.print("\",\"perms\":[");
	for (int i = 0; i < _permessions.size()-1; i++) {
		switch (_permessions[i])
		{
		case CharacteristicPermession::PAIRED_READ:
			client.print("\"pr\",");
			break;
		case CharacteristicPermession::PAIRED_WRITE:
			client.print("\"pw\",");
			break;		
		} 		
	}
	
	if (_permessions.size() > 0) {
		switch (_permessions[_permessions.size()-1])
		{
		case CharacteristicPermession::PAIRED_READ:
			client.print("\"pr\"");
			break;
		case CharacteristicPermession::PAIRED_WRITE:
			client.print("\"pw\"");
			break;
		}
	}
	
	client.print("],\"value\":");

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

	const char* valueStringBegin = strchr(valueTagString, ':');
	if (valueStringBegin == NULL) {
		printf("malformed json\n");
		client.sendHeaderWithoutBody(HAP::BAD_REQUEST);
		return;
	}
	
	if (1 != sscanf(valueStringBegin, ":%d", &_value->i)) {
		printf("not the expected integer\n");
		client.sendHeaderWithoutBody(HAP::BAD_REQUEST);
		return;
	}

	printf("characteristic updated to :%d\n", _value->i);

	client.sendHeaderWithoutBody(HAP::SUCCESS_NO_CONTENT);
}

HAPCharacteristic::~HAPCharacteristic()
{ 
	delete _value; 
}