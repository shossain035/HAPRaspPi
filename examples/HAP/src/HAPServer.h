#ifndef _HAPSERVER_H_
#define _HAPSERVER_H_

#include "HAPAccessory.h"
#include "HAPAuthenticationHandler.h"

class HAPServer
{
public:
	HAPServer();

	//todo: consider threading issues for all the get and put
	void getAccessories(HAPClient& client);
	void getCharacteristic(HAPClient& client, 
		int accessoryId, int serviceId, int characteristicId);
	void updateCharacteristic(HAPClient& client, 
		int accessoryId, int serviceId, int characteristicId);

	void setupPair(HAPClient& client);
	void verifyPair(HAPClient& client);

	~HAPServer();
private:
	HAPCharacteristic* getCharacteristic(
		int accessoryId, int serviceId, int characteristicId);

	HAPAccessory** _accessories;
	int _accessoryCount;

	HAPAuthenticationHandler _authenticationHAndlerHandler;
};



#endif