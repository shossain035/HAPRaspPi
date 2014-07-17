#include "HAPClient.h"

HAPClient::HAPClient(struct mg_connection* conn) : _conn(conn) 
{
}

void HAPClient::print(int i) 
{
	mg_printf(_conn, "%d", i);
}

void HAPClient::print(const char * string) 
{
	mg_printf(_conn, "%s", string);
}

void HAPClient::println(const char * string) 
{
	print(string);
	println();
}

void HAPClient::println(int i)
{
	print(i);
	println();
}


void HAPClient::println() 
{ 
	print("\r\n");
}


void HAPClient::sendHeaderWithoutBody(HAP::HAPStatus status)
{
	sendHeader(status, 0);
	println();
}

void HAPClient::sendHeader(HAP::HAPStatus status, int contentLength)
{
	print("HTTP/1.1 ");

	switch (status) {
		case HAP::SUCCESS:
			println("200 OK");
			break;
		case HAP::BAD_REQUEST:
			println("400 Bad request");
			break;
		default:
			println("500 Internal Server Error");
			break;
	}

	println("Content-Type: application/hap+json");
	print("Content-Length: ");
	println(contentLength);

	println();
}
