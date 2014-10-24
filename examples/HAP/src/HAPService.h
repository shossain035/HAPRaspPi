#ifndef _HAPSERVICE_H_
#define _HAPSERVICE_H_

#include "HAPCharacteristic.h"

class HAPServiceTypes
{
public:
	static const char * accessoryInformation;
	static const char * light;
};


class HAPService : public HAPBase
{
public:
	HAPService(unsigned int instanceId, const char * const type, HAPCharacteristic ** const characteristics, unsigned char characteristicsCount);
	virtual int sendToClient(HAPClient & client);
	~HAPService();

	int characteristicsCount();
	HAPCharacteristic* characteristicForId(int characteristicId);

private:
	const char * const _type;
	HAPCharacteristic ** const _characteristics;
	unsigned char _characteristicsCount;
};



#endif