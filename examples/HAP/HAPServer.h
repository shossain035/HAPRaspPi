#ifndef _HAPSERVER_H_
#define _HAPSERVER_H_

#include <HAPAccessory.h>

class HAPServer
{
public:
	HAPServer();
	void processRequest(Client & client);
private:
	HAPAccessory ** _accessories;
	int _accessoryCount;

};



#endif