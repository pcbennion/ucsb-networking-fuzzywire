/*==========================================================================
 *
 * FUZZY WIRE - Network packet capture and analysis
 *
 * Authors: Peter Bennion
 * 			Tyralyn Tran
 *
 * Version: v0.0000000000000000000001
 *
 * Instructions for installing WinPcap + libs: http://www.codeproject.com/Articles/30234/Introduction-to-the-WinPcap-Networking-Libraries
 *		Don't forget to add pcap library to PATH!
 *
 * Code based on example sniffer at: https://www.winpcap.org/docs/docs_40_2/html/group__wpcap__tut3.html
 *
 *==========================================================================*/

#include <cstdlib>
#include <cstdio>
#include <iostream>

// Stuff for WinPcap. The defines are super important for linking.
#define WPCAP
#define HAVE_REMOTE
#include "pcap.h"

// Winsock includes.
#include <Winsock2.h>
#include <windows.h>
#include <conio.h>

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

int main() {
    pcap_if_t *alldevs;	// list of all capture devices.
    char errbuf[PCAP_ERRBUF_SIZE]; // cstring used by winpcap for error messages.

    // Grab device list. Freak out if error occurs. This function doesn't like to be run from IDEs - run exe directly!
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    	{ fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf); exit(1); }

    // Print info for all found devices.
    int i = 0;
    pcap_if_t *d;
    for(d= alldevs; d != NULL; d= d->next) {
    	cout<<++i<<": "<<d->name;
        if (d->description) cout<<"  - "<<d->description<<endl;
        else cout<<"  - No description."<<endl;
    }

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
    if( (capture = pcap_open(	d->name,					// Device to be opened (selected by dname).
    							CAPTURE_BYTES,				// Bytes to capture in each packet.
    							PCAP_OPENFLAG_PROMISCUOUS,	// Set to promiscuous mode - will capture ALL traffic on network.
    							1000,						// Timeout value (ms)
    							NULL,						// Authentication info for remote capture. Unused for sniffing.
    							errbuf						// Error string.
    						 )  ) == NULL ) {
    	// Error handling - usually if adapter is incompatible.
    	fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
    	pcap_freealldevs(alldevs);
    	exit(1);
    }
    cout<<endl<<"Now listening on "<<d->description<<"..."<<endl;

    // Free device list now that we're done with it.
    pcap_freealldevs(alldevs);

    // Register callback and start capture loop.
    pcap_loop(capture, 0, decode_packet, NULL);

    return 0;
}

void print_eth_hdr(eth_header *eth){
	cout<<"\tEthernet Header :"<<endl;
	printf("\t |Dest : %.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n", eth->dest[0], eth->dest[1], eth->dest[2], eth->dest[3], eth->dest[4], eth->dest[5]);
	printf("\t |Src  : %.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n", eth->source[0], eth->source[1], eth->source[2], eth->source[3], eth->source[4], eth->source[5]);
	cout<<"\t |Proto: "<<eth->type<<endl;
}
void print_ip_hdr(ip_header *ip){
	cout<<"\tIP Header :"<<endl;
	printf("\t |Version : %d |HLEN : %d |DCSP : %d |ECN : %d |Total Length : %d\n", (u_int)ip->ver, (u_int)ip->hlen, (u_int)ip->dhcp, (u_int)ip->ecn, (u_int)ip->tlen);
	printf("\t |Identification : %d |Flags : %d%d%d | Fragmentation Offset: %d\n", ip->id, (u_int)ip->zero, (u_int)ip->dfrag, (u_int)ip->mfrag, (u_int)ip->fragoffset);
	printf("\t |Time to Live : %d |Protocol : %d |Header Checksum : %d\n", (u_int)ip->ttl, (u_int)ip->proto, ip->crc);
	printf("\t |Source : %d.%d.%d.%d\n", ip->src.byte1, ip->src.byte2, ip->src.byte3, ip->src.byte4);
	printf("\t |Destination : %d.%d.%d.%d\n", ip->dest.byte1, ip->dest.byte2, ip->dest.byte3, ip->dest.byte4);
}

// Packet decoder - takes a packet and figures out protocol. Passes along to appropriate helper.
void decode_packet(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {

	// Make timestamp readable.
	time_t local = header->ts.tv_sec;
	struct tm *time = localtime(&local);
	char timestamp[16];
	strftime(timestamp, sizeof timestamp, "%H:%M:%S", time);

	// Print capture time and length of packet.
	cout<<"Packet Captured : "<<timestamp<<" (Length : "<<header->len<<" bytes)"<<endl;

	// Get ethernet header
	eth_header *eth = (eth_header *)pkt_data;

	// Get ip header
	ip_header *ip = (ip_header *) (pkt_data + sizeof(eth_header));

	// Figure out the protocol of the packet
	switch(ip->proto) {
		case 1: // ICMP
			cout<<endl<<"ICMP PACKET : "<<endl;
			print_eth_hdr(eth);
			print_ip_hdr(ip);
			break;
		case 2: // IGMP
			cout<<endl<<"IGMP PACKET : "<<endl;
			print_eth_hdr(eth);
			print_ip_hdr(ip);
			break;
		case 6: // TCP
			cout<<endl<<"TCP PACKET : "<<endl;
			print_eth_hdr(eth);
			print_ip_hdr(ip);
			break;
		case 17:// UDP
			cout<<endl<<"UDP PACKET : "<<endl;
			print_eth_hdr(eth);
			print_ip_hdr(ip);
			break;
		default:
			cout<<ip->proto<<endl;
			break;
	}
}
