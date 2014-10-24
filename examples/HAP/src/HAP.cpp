/* Copyright (c) 2013-2014 the Civetweb developers
* Copyright (c) 2013 No Face Press, LLC
* License http://opensource.org/licenses/mit-license.php MIT License
*/

// Simple example program on how to use Embedded C++ interface.

#include "CivetServer.h"
#include "HAPServer.h"
#include <assert.h>

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

#define PORT "8081"
#define ACCESSORIES_URI "/accessories$"
#define CHARACTERISTIC_URI "/characteristics"
#define PAIR_SETUP_URI "/pair-setup$"
#define PAIR_VERIFY_URI "/pair-verify$"

#define EXIT_URI "/exit"
bool exitNow = false;


class BaseHandler : public CivetHandler
{
public:
	BaseHandler(HAPServer& hapServer) : _hapServer(hapServer) {}
protected:
	HAPServer& _hapServer;
};

class PairSetupHandler : public BaseHandler
{
public:
	PairSetupHandler(HAPServer& hapServer) : BaseHandler(hapServer) {}
	bool handlePost(CivetServer *server, struct mg_connection *conn) {
		printf("POST pair-setup\n");
		
		HAPClient client(conn);
		_hapServer.setupPair(client);
		return true;
	}
};

class PairVerifyHandler : public BaseHandler
{
public:
	PairVerifyHandler(HAPServer& hapServer) : BaseHandler(hapServer) {}
	bool handlePost(CivetServer *server, struct mg_connection *conn) {
		printf("POST pair-verify\n");

		HAPClient client(conn);
		_hapServer.verifyPair(client);
		return true;
	}
};

class AccessoriesHandler : public BaseHandler
{
public:
	AccessoriesHandler(HAPServer& hapServer) : BaseHandler(hapServer) {}

	bool handleGet(CivetServer *server, struct mg_connection *conn) {
		HAPClient client(conn);
		printf("GET accessories\n");
		_hapServer.getAccessories(client);
		
		return true;
	}
};

class CharacteristicHandler : public BaseHandler
{
private:
	bool parseBody(struct mg_connection* conn, 
					int& accessoryId, int& characteristicId) {
		/*
		struct mg_request_info *ri = mg_get_request_info(conn);
		assert(ri != NULL);
		
		if (3 != sscanf(ri->uri, "/accessories/%d/services/%d/characteristics/%d",
			&accessoryId, &serviceId, &characteristicId)) {
			
			HAPClient client(conn);
			client.sendHeaderWithoutBody(HAP::BAD_REQUEST);
			return false;
		}
		*/

		//todo: parse body
		accessoryId = 1;
		characteristicId = 200;
		return true;
	}
public:
	CharacteristicHandler(HAPServer& hapServer) : BaseHandler(hapServer) {}

	bool handleGet(CivetServer* server, struct mg_connection* conn) {
		printf("GET characteristic\n");
		int accessoryId, characteristicId;
		if (!parseBody(conn, accessoryId, characteristicId)) {
			return true;
		}

		HAPClient client(conn);
		_hapServer.getCharacteristic(client, accessoryId, characteristicId);
		
		return true;
	}
	bool handlePut(CivetServer* server, struct mg_connection* conn) {
		printf("PUT characteristic\n");
		int accessoryId, characteristicId;
		if (!parseBody(conn, accessoryId, characteristicId)) {
			return true;
		}
			
		HAPClient client(conn);
		_hapServer.updateCharacteristic(client, accessoryId, characteristicId);

		return true;
	}
};


class ExitHandler : public CivetHandler
{
public:
	bool handleGet(CivetServer *server, struct mg_connection *conn) {
		mg_printf(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n");
		mg_printf(conn, "Bye!\n");
		exitNow = true;
		return true;
	}
};

int main(int argc, char *argv[])
{

	const char * options[] = { 
								"listening_ports", PORT, 0
							 };

	CivetServer server(options);
	HAPServer hapServer;
	
	server.addHandler(ACCESSORIES_URI, new AccessoriesHandler(hapServer));
	server.addHandler(CHARACTERISTIC_URI, new CharacteristicHandler(hapServer));
	server.addHandler(PAIR_SETUP_URI, new PairSetupHandler(hapServer));
	server.addHandler(PAIR_VERIFY_URI, new PairVerifyHandler(hapServer));

	server.addHandler(EXIT_URI, new ExitHandler());
	
	while (!exitNow) {
#ifdef _WIN32
		Sleep(1000);
#else
		sleep(1);
#endif
	}
	
	printf("Bye!\n");

	return 0;
}
