#include "pch.h"
#include "ArpHeader.h"

std::uint16_t ArpHeader::getHardwareType() const
{
    return ntohs(hardwareType);
}

std::uint16_t ArpHeader::getProtocolType() const
{
    return ntohs(protocolType);
}

std::uint8_t ArpHeader::getHardwareLength() const
{
    return hardwareLength;
}

std::uint8_t ArpHeader::getProtocolLength() const
{
    return protocolLength;
}

std::uint16_t ArpHeader::getOperation() const
{
    return ntohs(operation);
}

MacAddress ArpHeader::getSourceMac() const
{
    return sourceMac;
}

IpAddress ArpHeader::getSourceIp() const
{
    return sourceIp;
}

MacAddress ArpHeader::getTargetMac() const
{
    return targetMac;
}

IpAddress ArpHeader::getTargetIp() const
{
    return targetIp;
}