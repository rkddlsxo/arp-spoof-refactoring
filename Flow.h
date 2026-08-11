#pragma once 

#include "IpAddress.h"
#include "MacAddress.h"

struct Flow
{
	IpAddress senderIp;
	MacAddress senderMac;

	IpAddress targetIp;
	MacAddress targetMac;
};