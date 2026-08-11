#include "pch.h"
#include "MacAddress.h"


MacAddress::MacAddress(const std::uint8_t* address)
{
    if (address == nullptr)
    {
        throw std::invalid_argument("MAC address pointer is null");
    }

    std::memcpy(macAddress, address, kSize);
}

MacAddress::MacAddress(const std::string& text)
{
    const int parsedCount = std::sscanf(
        text.c_str(),
        "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
        &macAddress[0],
        &macAddress[1],
        &macAddress[2],
        &macAddress[3],
        &macAddress[4],
        &macAddress[5]
    );

    if (parsedCount != kSize)
    {
        throw std::invalid_argument("Invalid MAC address: " + text);
    }
}