#include "pch.h"
#include "IpAddress.h"

IpAddress::IpAddress(std::uint32_t hostOrderAddress)
    : ipAddress(htonl(hostOrderAddress))
{
}

IpAddress::IpAddress(const std::string& text)
{
    unsigned int ip1;
    unsigned int ip2;
    unsigned int ip3;
    unsigned int ip4;

    const int parsedCount = std::sscanf(
        text.c_str(),
        "%u.%u.%u.%u",
        &ip1, &ip2, &ip3, &ip4
    );

    if (parsedCount != kSize)
    {
        throw std::invalid_argument("Invalid IP address: " + text);
    }

    const std::uint32_t hostOrderAddress =
        (ip1 << 24) |
        (ip2 << 16) |
        (ip3 << 8) |
        ip4;

    ipAddress = htonl(hostOrderAddress);
}

std::uint32_t IpAddress::hostOrder() const
{
    return ntohl(ipAddress);
}