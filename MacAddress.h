#pragma once

#include <cstdint>
#include <string>

struct MacAddress
{
    static constexpr int kSize = 6;
    std::uint8_t macAddress[kSize]{};

    MacAddress() = default;
    MacAddress(const MacAddress&) = default;

    explicit MacAddress(const std::uint8_t* address);
    explicit MacAddress(const std::string& text);
};