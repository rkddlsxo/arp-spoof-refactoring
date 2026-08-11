#pragma once

#include <cstdint>

#include "MacAddress.h"

struct EthernetHeader
{
    static constexpr int kSize = 14;

    MacAddress destinationMac;
    MacAddress sourceMac;
    std::uint16_t etherType;

    std::uint16_t type() const;

    enum : std::uint16_t
    {
        kIpv4 = 0x0800,
        kArp = 0x0806,
        kIpv6 = 0x86DD
    };
};