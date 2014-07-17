#ifndef _HAPSERVER_H_
#define _HAPSERVER_H_

#include "HAPAccessory.h"

class HAPServer
{
public:
	HAPServer();

	//todo: consider threading issues for all the get and put
	void getAccessories(HAPClient& client);

	~HAPServer();
private:
	HAPAccessory ** _accessories;
	int _accessoryCount;

};



#endif