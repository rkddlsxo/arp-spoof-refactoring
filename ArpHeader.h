#pragma once

#include <cstdint>

#include "IpAddress.h"
#include "MacAddress.h"

#pragma pack(push, 1)

struct ArpHeader
{
    static constexpr int kSize = 28;

    std::uint16_t hardwareType{};
    std::uint16_t protocolType{};
    std::uint8_t hardwareLength{};
    std::uint8_t protocolLength{};
    std::uint16_t operation{};

    MacAddress sourceMac;
    IpAddress sourceIp;
    MacAddress targetMac;
    IpAddress targetIp;

    std::uint16_t getHardwareType() const;
    std::uint16_t getProtocolType() const;
    std::uint8_t getHardwareLength() const;
    std::uint8_t getProtocolLength() const;
    std::uint16_t getOperation() const;

    MacAddress getSourceMac() const;
    IpAddress getSourceIp() const;
    MacAddress getTargetMac() const;
    IpAddress getTargetIp() const;

    // Hardware type
    enum : std::uint16_t
    {
        kNetRom = 0,
        kEthernet = 1,
        kEEthernet = 2,
        kAx25 = 3,
        kProNet = 4,
        kChaos = 5,
        kIeee802 = 6,
        kArcNet = 7,
        kAppleTalk = 8,
        kLanStar = 9,
        kDlci = 15,
        kAtm = 19,
        kMetricom = 23,
        kIpSec = 31
    };

    // Operation
    enum : std::uint16_t
    {
        kRequest = 1,
        kReply = 2,
        kRevRequest = 3,
        kRevReply = 4,
        kInvRequest = 8,
        kInvReply = 9
    };
};

#pragma pack(pop)