#ifndef _SRPMANAGER_H_
#define _SRPMANAGER_H_

#include <memory>

extern "C"
{
	#include "srp.h"
}


class SRPManager {
	std::unique_ptr<SRPVerifier> _verifier;
};
#endif