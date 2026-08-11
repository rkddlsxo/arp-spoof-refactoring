cmake_minimum_required(VERSION 3.16)

project(arp-spoof LANGUAGES CXX)

add_executable(arp-spoof
    main.cpp

    MacAddress.cpp
    IpAddress.cpp
    EthernetHeader.cpp
    ArpHeader.cpp

    MacAddress.h
    IpAddress.h
    EthernetHeader.h
    ArpHeader.h
    ArpPacket.h
    Flow.h
    pch.h
 "Flow.h")

target_compile_features(arp-spoof PRIVATE cxx_std_20)

set_target_properties(arp-spoof PROPERTIES
    CXX_EXTENSIONS OFF
)

target_precompile_headers(arp-spoof PRIVATE
    pch.h
)

if(WIN32)
    target_link_libraries(arp-spoof PRIVATE
        ws2_32
        iphlpapi
        wpcap
        Packet
    )
else()
    target_link_libraries(arp-spoof PRIVATE
        pcap
    )
endif()

if(MSVC)
    target_compile_definitions(arp-spoof PRIVATE
        _CRT_SECURE_NO_WARNINGS
    )
endif()