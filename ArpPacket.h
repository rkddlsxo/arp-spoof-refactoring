#pragma once

#include "ArpHeader.h"
#include "EthernetHeader.h"

#pragma pack(push, 1)

struct ArpPacket
{
    static constexpr int kSize =
        EthernetHeader::kSize + ArpHeader::kSize;

    EthernetHeader ethernetHeader;
    ArpHeader arpHeader;
};

#pragma pack(pop)