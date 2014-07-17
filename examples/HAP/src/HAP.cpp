/* Copyright (c) 2013-2014 the Civetweb developers
* Copyright (c) 2013 No Face Press, LLC
* License http://opensource.org/licenses/mit-license.php MIT License
*/

// Simple example program on how to use Embedded C++ interface.

#include "CivetServer.h"
#include "HAPServer.h"

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

#define PORT "8081"
#define ACCESSORIES_URI "/accessories$"
#define CHARACTERISTIC_URI "/accessories/**/services/**/characteristics/**$"
#define EXIT_URI "/exit"
bool exitNow = false;


class BaseHandler : public CivetHandler
{
public:
	BaseHandler(HAPServer& hapServer) : _hapServer(hapServer) {}
protected:
	HAPServer& _hapServer;
};

class AccessoriesHandler : public BaseHandler
{
public:
	AccessoriesHandler(HAPServer& hapServer) : BaseHandler(hapServer) {}

	bool handleGet(CivetServer *server, struct mg_connection *conn) {
		HAPClient client(conn);
		
		_hapServer.getAccessories(client);
		
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

class AHandler : public BaseHandler
{
private:
	bool handleAll(const char* method, CivetServer* server, struct mg_connection* conn) {
		std::string s = "";
		mg_printf(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n");
		mg_printf(conn, "<html><body>");
		mg_printf(conn, "<h2>This is the A handler for \"%s\" !</h2>", method);
		if (CivetServer::getParam(conn, "param", s)) {
			mg_printf(conn, "<p>param set to %s</p>", s.c_str());
		}
		else {
			mg_printf(conn, "<p>param not set</p>");
		}
		mg_printf(conn, "</body></html>\n");
		return true;
	}
public:
	AHandler(HAPServer& hapServer) : BaseHandler(hapServer) {}

	bool handlePut(CivetServer* server, struct mg_connection* conn) {
		mg_printf(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n");
		mg_printf(conn, "<html><body>");
		mg_printf(conn, "<h2>This is the A handler for PUT !</h2>");
		char * body = CivetServer::getBody(conn);

		if (body != NULL) {
			mg_printf(conn, "<p>body set to %s</p>", body);
		}
		else {
			mg_printf(conn, "<p>body not set</p>");
		}
		mg_printf(conn, "</body></html>\n");
		return true;
	}

	bool handleGet(CivetServer* server, struct mg_connection* conn) {
		return handleAll("GET", server, conn);
	}
	bool handlePost(CivetServer* server, struct mg_connection* conn) {
		return handleAll("POST", server, conn);
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
	server.addHandler(EXIT_URI, new ExitHandler());
	server.addHandler("/a", new AHandler(hapServer));

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
