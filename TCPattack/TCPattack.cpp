/*==========================================================================
 *
 * FUZZY WIRE - Network packet capture and analysis
 *
 * Authors: Peter Bennion
 * 			Tyralyn Tran
 *
 * Version: v0.0000000000000000000001
 * http://www.binarytides.com/raw-sockets-packets-with-winpcap/
 *
 * Instructions for installing WinPcap + libs: http://www.codeproject.com/Articles/30234/Introduction-to-the-WinPcap-Networking-Libraries
 *		Don't forget to add pcap library to PATH!
 *
 * Code based on example sniffer at: https://www.winpcap.org/docs/docs_40_2/html/group__wpcap__tut3.html
 *
 *==========================================================================*/



// Stuff for WinPcap. The defines are super important for linking.
#define WPCAP
#define HAVE_REMOTE
#include "pcap.h"
//#ifndef WIN32_LEAN_AND_MEAN
//#define WIN32_LEAN_AND_MEAN
//#endif
#ifdef WIN32
#include <winsock2.h>
#endif
// Winsock includes.
#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <string.h>
//#include <netinet/in.h>
#include <windows.h>
#include <iphlpapi.h>

// Constants
#define CAPTURE_BYTES 65536 // Number of bytes to capture, per packet. Set absurdly high to capture full packet.

using namespace std;
typedef struct eth_header
{
    unsigned char dst[6];				// Destination address
    unsigned char src[6];				// Source address
    unsigned short type;				// Internet type. We're only interested in IP atm
};

// IPv4 HEADER
typedef struct ip_header
{
    unsigned char hlen:4; 				// Length of header - used to find end of optional fields
    unsigned char ver :4; 				// Ipv4 version
    unsigned char tos; 					// Congestion and differentiated services (RFCs 3168 & 2474)
    unsigned short tlen; 				// Total length of IP datagram

    unsigned short identifier;			// Unique identifier
    unsigned char frag :5; 				// Fragment offset
    unsigned char flag_more_frag :1;	// More fragments flag
    unsigned char flag_dont_frag :1;	// Don't fragment flag
    unsigned char flag_reserved :1;		// Always 0

    unsigned char frag1; 				// Fragment offset again - correcting struct length
    unsigned char ttl; 					// Time to live
    unsigned char protocol; 			// Protocol(TCP,UDP etc)
    unsigned short checksum; 			// IP checksum

    unsigned int srcaddr; 				// Source address
    unsigned int destaddr; 				// Source address
};

// TCP header
typedef struct tcp_header
{
    unsigned short sport; 				// Source port
    unsigned short dport; 				// Destination port

    unsigned int sequence; 				// Sequence number

    unsigned int acknowledge; 			// ACK number

    unsigned char ns :1; 				//Nonce sum flag (RFC 3540)
    unsigned char reserved:3;			// Reserved (0's)
    unsigned char data_offset:4; 		// Where the data begins in this fragment
    unsigned char fin :1; 				// Finish Flag
    unsigned char syn :1; 				// Synchronize Flag
    unsigned char rst :1; 				// Reset Flag
    unsigned char psh :1; 				// Push Flag
    unsigned char ack :1; 				// Acknowledgment Flag
    unsigned char urg :1; 				// Urgent Flag
    unsigned char ecn :1; 				// ECN-echo
    unsigned char cwr :1; 				// Congestion window reduced

    unsigned short window; 				// Window Size

    unsigned short checksum; 			// Checksum
    unsigned short urgent; 				// Urgent pointer
};

// Packet handler forward dec.
// To be registered as a callback function for WinPcap - called whenever a packet is captured.
void decode_packet(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

//Forward declaration of method called to construct raw header for TCP SYN packet
u_char* constructPacket();

int main(int argc, char* argv[]) {
    pcap_if_t *alldevs;	// list of all capture devices.
    char errbuf[PCAP_ERRBUF_SIZE]; // cstring used by winpcap for error messages.
	
	//string ipArg;
	//in_addr destIP;
	//destIP.s_addr=0;
	char* a;
	
	//destIp->S_un_b = (u_char) arg

    // Grab device list. Freak out if error occurs. This function doesn't like to be run from IDEs - run exe directly!
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    	{ fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf); exit(1); }

	a=alldevs->name;
    // Print info for all found devices.
    int i = 0;
    pcap_if_t *d;
    for(d= alldevs; d != NULL; d= d->next) {
    	cout<<++i<<": "<<d->name;
        if (d->description) cout<<"  - "<<d->description<<endl;
        else cout<<"  - No description."<<endl;
		cout<<"address in loop: "<<d->addresses<<endl;
    }
	cout<<"address: "<<a<<endl;

    // If no devices found (ie none were printed), exit.
    if (i == 0)
    	{ cout<<endl<<"No interfaces found! Make sure WinPcap is installed!"<<endl; return 0; }

    // Select interface for sniffing.
    int iface;
    cout<<"Enter Interface Number:";
    cin>>iface;
    if(iface<1||iface>i) // Catch invalid numbers!
    	{ cout<<endl<<"Number out of range!"<<endl; pcap_freealldevs(alldevs); exit(1); }

    // Re-traverse device list to selected adapter.
    for(d=alldevs, i=0; i< iface-1 ;d=d->next, i++);

	
	
    // Open device in WinPcap.
    pcap_t *capture;
	if ( (capture=pcap_open(d->name,            // name of the device
                        100,                // portion of the packet to capture (only the first 100 bytes)
                        PCAP_OPENFLAG_PROMISCUOUS,  // promiscuous mode
                        1000,               // read timeout
                        NULL,               // authentication on the remote machine
                        errbuf              // error buffer
                        ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        return 0;
    }

	// Free device list now that we're done with it.
	pcap_freealldevs(alldevs);

	while (pcap_sendpacket(capture, constructPacket(), sizeof(eth_header)+5*4+5*4 /* size */) != 0)
    {
		cout<<"packet sent! "<< d->name<<endl;
    }
	fprintf(stderr,"\nError sending the packet: \n");
	        return 0;
}
/*
void loadiphlpapi() {
    HINSTANCE hDll = LoadLibrary("iphlpapi.dll");

    GetAdaptersInfo = (pgetadaptersinfo)GetProcAddress(hDll,"GetAdaptersInfo");
    if(GetAdaptersInfo==NULL)
        printf("Error in iphlpapi.dll%d",GetLastError());
    SendArp = (psendarp)GetProcAddress(hDll,"SendARP");
    if(SendArp==NULL)
 printf("Error in iphlpapi.dll%d",GetLastError());
}*/

void GetMacAddress(unsigned char *mac , struct in_addr destip)
{
    DWORD ret;
    IPAddr srcip;
    ULONG MacAddr[2];
    ULONG PhyAddrLen = 6;  // default to length of six bytes 
    int i;
 
    srcip = 0;
 
    //Send an arp packet
    ret = SendARP((IPAddr) destip.S_un.S_addr , srcip , (PULONG)&MacAddr , &PhyAddrLen);
     
    //Prepare the mac address
    if(PhyAddrLen)
    {
        BYTE *bMacAddr = (BYTE *) & MacAddr;
        for (i = 0; i < (int) PhyAddrLen; i++)
        {
            mac[i] = (char)bMacAddr[i];
        }
    }
}

void GetGateway(struct in_addr ip , char *sgatewayip , int *gatewayip) {
    char pAdapterInfo[5000];
    PIP_ADAPTER_INFO  AdapterInfo;
    ULONG OutBufLen = sizeof(pAdapterInfo) ;

    GetAdaptersInfo((PIP_ADAPTER_INFO) pAdapterInfo, &OutBufLen);
    for(AdapterInfo = (PIP_ADAPTER_INFO)pAdapterInfo; AdapterInfo ; AdapterInfo = AdapterInfo->Next) {
        if(ip.s_addr == inet_addr(AdapterInfo->IpAddressList.IpAddress.String))
     strcpy(sgatewayip , AdapterInfo->GatewayList.IpAddress.String);
    }
    *gatewayip = inet_addr(sgatewayip);
}

u_char* constructPacket() {
	u_char* packet;
	eth_header* ethhdr;
	ip_header* iphdr;
	tcp_header* tcphdr;

	struct in_addr srcip, dstip;
	srcip.s_addr = inet_addr("192.168.0.7"); // hardcoded bleh

	unsigned char* s_mac, d_mac;

	packet = new u_char[sizeof(eth_header)+5*4+5*4];
	iphdr = (ip_header*)(packet + sizeof(eth_header));

// CONSTRUCT ETHERNET HEADER

	GetMacAddress(s_mac , srcip);
	GetGateway(srcip, (char*)d_mac, (int*)(dstip.S_un.S_addr));
	memcpy(ethhdr->src , s_mac , 6); //Source Mac address
	memcpy(ethhdr->dst, d_mac, 6); //Destination MAC address
	ethhdr->type = htons(0x0800); //IP Frames

// TCP HEADER AND IP HEADER
	iphdr->ver = 4;
	iphdr->hlen = 5; //In double words thats 4 bytes
	iphdr->tos = 0;
	iphdr->tlen = htons (5*4+5*4);
	iphdr->identifier = htons(2);
	iphdr->frag = 0;
	iphdr->flag_reserved=0;
	iphdr->flag_dont_frag=1;
	iphdr->flag_more_frag=0;
	iphdr->frag1 = 0;
	iphdr->ttl    = 3;
	iphdr->protocol = IPPROTO_TCP;
	iphdr->srcaddr  = inet_addr("1.2.3.4");   //srcip.s_addr;
	iphdr->destaddr = inet_addr("1.2.3.5");
	iphdr->checksum =0;
	iphdr->checksum = in_checksum((unsigned short*)iphdr, sizeof(ip_header));
	tcphdr = (tcp_header*)(packet + sizeof(eth_header) + sizeof(ip_header));

	tcphdr->sport = htons(2338);
	tcphdr->dport = htons(80);
	tcphdr->sequence=0;
	tcphdr->acknowledge=0;
	tcphdr->reserved=0;
	tcphdr->data_offset=5;
	tcphdr->fin=0;
	tcphdr->syn=1;
	tcphdr->rst=0;
	tcphdr->psh=0;
	tcphdr->ack=0;
	tcphdr->urg=0;
	tcphdr->ecn=0;
	tcphdr->cwr=0;
	tcphdr->window = htons(64240);
	tcphdr->checksum=0;
	tcphdr->urgent = 0;
	return packet;
}
