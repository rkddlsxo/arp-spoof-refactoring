#include "pch.h"
#include "EthernetHeader.h"

std::uint16_t EthernetHeader::type() const
{
    return ntohs(etherType);
}