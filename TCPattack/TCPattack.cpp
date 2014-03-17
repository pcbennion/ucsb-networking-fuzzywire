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
#include <netinet/in.h>
#include <windows.h>
#include <iphlpapi.h>

// Constants
#define CAPTURE_BYTES 65536 // Number of bytes to capture, per packet. Set absurdly high to capture full packet.

using namespace std;

// Ethernet header
typedef struct eth_header{
	u_char dest[6];
	u_char source[6];
    u_short type;
}   eth_header , *PETHER_HDR , FAR * LPETHER_HDR , ETHERHeader;

// IP address
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

// IP header (v4)
typedef struct ip_header{
    u_char  hlen:4;			// header length
    u_char  ver:4;        	// version
    u_char  ecn:2;  		// explicit congestion notification (RFC 3168)
    u_char  dhcp:6;         // differentiated services code point (RFC 2474)
    u_short tlen;           // total length
    u_short id; 			// identification
    u_char fragoffset:5;   	// fragmentation offset
    u_char mfrag:1;         // more fragments
    u_char dfrag:1;   		// don't fragment
    u_char zero:1;   		// reserved flag
    u_char fragoffset1;		// fragment offset again
    u_char  ttl;            // time to live
    u_char  proto;          // protocol
    u_short crc;            // header checksum
    ip_address  src;      	// source address
    ip_address  dest;      	// destination address
}ip_header;

// UDP header
typedef struct udp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;

// TCP header
typedef struct tcp_header{
	u_short sport; 			// source port
	u_short dport; 			// destination port
    u_int sequence; 		// sequence number
    u_int acknowledge; 		// acknowledgement number
    u_char ns :1; 			// nonce sum
    u_char reserved_part1:3;// according to rfc
    u_char data_offset:4; 	// # of 32-bit words in header
    u_char fin :1; 			// Finish Flag
    u_char syn :1; 			// Synchronize Flag
    u_char rst :1; 			// Reset Flag
    u_char psh :1; 			// Push Flag
    u_char ack :1; 			// Acknowledgement Flag
    u_char urg :1; 			// Urgent Flag
    u_char ecn :1; 			// ECN-Echo Flag
    u_char cwr :1; 			// Congestion Window Reduced Flag
    u_short window; 		// window
    u_short checksum; 		// checksum
    u_short urgent_pointer; // urgent pointer
} tcp_header;

// ICMP header
typedef struct icmp_hdr
{
	u_char type; // ICMP Error type
	u_char code; // Type sub code
	u_short checksum;
	u_short id;
	u_short seq;
} icmp_hdr;

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
	u_char packet[100];
	packet[0]=1;
    packet[1]=1;
    packet[2]=1;
    packet[3]=1;
    packet[4]=1;
    packet[5]=1;
    
    /* set mac source to 2:2:2:2:2:2 */
    packet[6]=2;
    packet[7]=2;
    packet[8]=2;
    packet[9]=2;
    packet[10]=2;
    packet[11]=2;
	
	for(i=12;i<100;i++)
    {
        packet[i]=i%256;
    }

	if (pcap_sendpacket(capture, packet, 100 /* size */) != 0)
    {
        //fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		cout<<"shit don't work\n";
        return 0;
    }
	else 
		cout<<"packet sent! "<< d->name<<endl;
	//constructPacket();
	
    cout<<endl<<"Now listening on "<<d->description<<"..."<<endl;

    // Free device list now that we're done with it.
    pcap_freealldevs(alldevs);

    // Register callback and start capture loop.
    pcap_loop(capture, 0, decode_packet, NULL);

    return 0;
}

void GetMacAddress(unsigned char *mac , struct in_addr destip)
{
    DWORD ret;
    IPAddr srcip;
    ULONG MacAddr[2];
    ULONG PhyAddrLen = 6;  // default to length of six bytes 
    int i;
 
    srcip = 0;
 
    //Send an arp packet
    ret = SendARP((IPAddr) destip.S_un.S_addr , srcip , MacAddr , &PhyAddrLen);
     
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

/*u_char* constructPacket(u_char ip) {
	u_char* packet;
	packet = new u_char[65536];
	in
	GetMacAddress(s_mac , srcip);
	printf("Selected device has mac address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X",s_mac[0],s_mac[1],s_mac[2],s_mac[3],s_mac[4],s_mac[5]);
	return packet;
}*/

// Packet decoder - takes a packet and figures out protocol. Passes along to appropriate helper.
void decode_packet(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {

	// Make timestamp readable.
	time_t local = header->ts.tv_sec;
	struct tm *time = localtime(&local);
	char timestamp[16];
	strftime(timestamp, sizeof timestamp, "%H:%M:%S", time);

	// Get ip header
	ip_header *ip = (ip_header *) (pkt_data + sizeof(eth_header));

	// Figure out the protocol of the packet
	switch(ip->proto) {
		case 1: // ICMP
			break;
		case 2: // IGMP
			break;
		case 3: // IGMP
			break;
		case 4: // TCP
			break;
		case 5:// UDP
			break;
		case 6:// UDP
			break;
		default:
			break;
	}
}