#ifndef _HAPACCESSORY_H_
#define _HAPACCESSORY_H_

#include "HAPService.h"


class HAPAccessory : public HAPBase
{
public:
	HAPAccessory(unsigned int instanceId, HAPService ** const services, unsigned char servicesCount);
	virtual int sendToClient(HAPClient& client);
	~HAPAccessory();

	HAPService* serviceForId(int serviceId);

protected:	
	virtual void printInstanceId(HAPClient & client);
private:
	HAPService ** const _services;
	unsigned char _servicesCount;
};

#endif
