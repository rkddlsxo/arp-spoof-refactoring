#include "pch.h"

#include "MacAddress.h"
#include "IpAddress.h"
#include "EthernetHeader.h"
#include "ArpHeader.h"
#include "ArpPacket.h"
#include "Flow.h"

using namespace std;

pcap_t* openCaptureHandle(const char* interfaceName);

MacAddress getMyMacAddress(const char* interfaceName);
IpAddress getMyIpAddress(const char* interfaceName);

ArpPacket makeArpRequestPacket(const MacAddress& myMac, const IpAddress& myIp, const IpAddress& targetIp);

void sendArpRequest(pcap_t* handle, const ArpPacket& packet);
MacAddress receiveArpReply(pcap_t* handle, const IpAddress& targetIp);

MacAddress resolveMacAddress(pcap_t* handle, const MacAddress& myMac, const IpAddress& myIp, const IpAddress& targetIp);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void usage() 
{
	printf("syntax: arp-spoof <interface> <sender ip> <target ip> [<sender ip> <target ip> ...]\n");
	printf("sample: arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
}

pcap_t* openCaptureHandle(const char* interfaceName)
{
	char errorBuffer[PCAP_ERRBUF_SIZE]{};

	pcap_t* handle = pcap_open_live(interfaceName, BUFSIZ, 1, 1, errorBuffer);
	
	if (handle == nullptr)
	{
		throw runtime_error(errorBuffer);
	}

	return handle;
}

MacAddress getMyMacAddress(const char* interfaceName) {
	int socketDescriptor = socket(AF_INET, SOCK_DGRAM, 0);
	if (socketDescriptor < 0)
	{
		throw runtime_error("socket() failed");
	}

	struct ifreq interfaceRequest {};
	strncpy(interfaceRequest.ifr_name, interfaceName, IFNAMSIZ - 1);

	if (ioctl(socketDescriptor, SIOCGIFHWADDR, &interfaceRequest) < 0)
	{
		close(socketDescriptor);
		throw runtime_error("ioctl(SIOCGIFHWADDR) failed");
	}

	close(socketDescriptor);

	return MacAddress(reinterpret_cast<uint8_t*>(interfaceRequest.ifr_hwaddr.sa_data));
}

IpAddress getMyIpAddress(const char* interfaceName)
{
	int socketDescriptor = socket(AF_INET, SOCK_DGRAM, 0);
	if (socketDescriptor < 0)
	{
		throw std::runtime_error("socket() failed");
	}

	struct ifreq interfaceRequest {};
	std::strncpy(interfaceRequest.ifr_name, interfaceName, IFNAMSIZ - 1);

	if (ioctl(socketDescriptor, SIOCGIFADDR, &interfaceRequest) < 0)
	{
		close(socketDescriptor);
		throw std::runtime_error("ioctl(SIOCGIFADDR) failed");
	}

	close(socketDescriptor);

	sockaddr_in* internetAddress = reinterpret_cast<sockaddr_in*>(&interfaceRequest.ifr_addr);

	IpAddress myIp; 
	myIp.ipAddress = internetAddress->sin_addr.s_addr;
	return myIp; 

}

ArpPacket makeArpRequestPacket(const MacAddress& myMac, const IpAddress& myIp, const IpAddress& targetIp)
{
	ArpPacket packet{};

	packet.ethernetHeader.destinationMac = MacAddress("ff:ff:ff:ff:ff:ff"); // broadcast
	packet.ethernetHeader.sourceMac = myMac;
	packet.ethernetHeader.etherType = htons(EthernetHeader::kArp);

	packet.arpHeader.hardwareType = htons(ArpHeader::kEthernet);
	packet.arpHeader.protocolType = htons(EthernetHeader::kIpv4);
	packet.arpHeader.hardwareLength = MacAddress::kSize;
	packet.arpHeader.protocolLength = IpAddress::kSize;
	packet.arpHeader.operation = htons(ArpHeader::kRequest);

	packet.arpHeader.sourceMac = myMac;
	packet.arpHeader.sourceIp = myIp;
	packet.arpHeader.targetMac = MacAddress("00:00:00:00:00:00"); // broadcast
	packet.arpHeader.targetIp = targetIp;

	return packet;
}

void sendArpRequest(pcap_t* handle, const ArpPacket& packet)
{
	const int result = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), ArpPacket::kSize);

	if (result != 0)
	{
		throw runtime_error(pcap_geterr(handle));
	}
}

MacAddress receiveArpReply(pcap_t* handle, const IpAddress& targetIp)
{
	while (true)
	{
		struct pcap_pkthdr* header = nullptr;
		const u_char* packetData = nullptr; 

		const int result = pcap_next_ex(handle, &header, &packetData);

		if (result == 0)
			continue;

		if (result < 0)
			throw runtime_error("pcap_next_ex() failed");

		const ArpPacket* packet = reinterpret_cast<const ArpPacket*>(packetData);

		if (packet->ethernetHeader.type() != EthernetHeader::kArp)
			continue;

		if (packet->arpHeader.getOperation() != ArpHeader::kReply)
			continue;

		if (packet->arpHeader.getSourceIp().ipAddress != targetIp.ipAddress)
			continue;

		return packet->arpHeader.getSourceMac();
	}
}

MacAddress resolveMacAddress(pcap_t* handle, const MacAddress& myMac, const IpAddress& myIp, const IpAddress& targetIp)
{
	ArpPacket requestPacket = makeArpRequestPacket(myMac, myIp, targetIp);
	sendArpRequest(handle, requestPacket);
	MacAddress targetMac = receiveArpReply(handle, targetIp);
	
	return targetMac;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int main(int argc, char* argv[])
{
	if (argc <= 2 || argc % 2 != 0)
	{
		usage();
		return -1; 
	}
	const char* interfaceName = argv[1];
	
	pcap_t* handle = openCaptureHandle(interfaceName);

	MacAddress myMac = getMyMacAddress(interfaceName);
	IpAddress myIp = getMyIpAddress(interfaceName);

	pcap_close(handle);
	return 0;
}