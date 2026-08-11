#pragma once

#include <cstdint>
#include <string>

struct IpAddress
{
    static constexpr int kSize = 4;

    std::uint32_t ipAddress{};

    IpAddress() = default;
    explicit IpAddress(std::uint32_t hostOrderAddress);
    explicit IpAddress(const std::string& text);

    std::uint32_t hostOrder() const;
};