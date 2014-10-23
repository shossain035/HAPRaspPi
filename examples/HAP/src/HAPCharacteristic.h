#ifndef _HAPCHARACTERISTICS_H_
#define _HAPCHARACTERISTICS_H_

#include "HAPBase.h"

union HAPCharacteristicValue 
{
	int i;
	float f;
	const char * s;
};

enum CharacteristicPermession
{ 
	PAIRED_READ, PAIRED_WRITE, EVENTS
};

class HAPCharacteristicTypes
{
public:
	static const char * name;
	static const char * manufacturer;
	static const char * model;
	static const char * serialNumber;
	static const char * identify;

	static const char * powerState;
};

class HAPCharacteristic : public HAPBase 
{
public:
	HAPCharacteristic(unsigned char instanceId, const char * const type, const char * value, std::vector<CharacteristicPermession>& permissions);
	HAPCharacteristic(unsigned char instanceId, const char * const type, int value, std::vector<CharacteristicPermession>& permissions);

	virtual int sendToClient(HAPClient& client);
	void updateValueWithJSON(HAPClient& client, const char* string);

	~HAPCharacteristic();
private:
	const char * const _type;
	HAPCharacteristicValue * const _value;
	const std::vector<CharacteristicPermession> _permessions;
};

#endif