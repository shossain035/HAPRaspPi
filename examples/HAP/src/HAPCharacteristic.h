#ifndef _HAPCHARACTERISTICS_H_
#define _HAPCHARACTERISTICS_H_

#include "HAPBase.h"

union HAPCharacteristicValue 
{
	int i;
	float f;
	const char * s;
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
	HAPCharacteristic(unsigned char instanceId, const char * const type, const char * value);
	HAPCharacteristic(unsigned char instanceId, const char * const type, int value);

	virtual int sendToClient(HAPClient& client);
	~HAPCharacteristic();
private:
	//void setValue(HAPCharacteristicValue * const value);
	const char * const _type;
	HAPCharacteristicValue * const _value;
};

#endif