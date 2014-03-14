/*==========================================================================
 *
 * FUZZY WIRE - Network packet capture and analysis
 *
 * Authors: Peter Bennion
 * 			Tyralyn Tran
 *
 * Version: v0.01
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
#include <fstream>

// Stuff for WinPcap. Everything before the pcap.h include is super important for error-free linking.
typedef unsigned int u_int;
typedef unsigned char u_char;
typedef unsigned short u_short;
#define WPCAP
#define HAVE_REMOTE
#include <Winsock2.h>
#include <pcap.h>

// Winsock includes.
#include <windows.h>
#include <conio.h>

// Utilities.
#include <unordered_set>
#include <unordered_map>
#include "fwreconstruct.h"
#include "TcpConnection.h"

// Constants.
#define CAPTURE_BYTES 65536 // Number of bytes to capture, per packet. Set absurdly high to capture full packet.

using namespace std;

// Ethernet header
typedef struct eth_header{
	unsigned char dest[6];
	unsigned char source[6];
    unsigned short type;
}   eth_header , *PETHER_HDR , FAR * LPETHER_HDR , ETHERHeader;

// IP address
typedef struct ip_address{
    unsigned char byte1;
    unsigned char byte2;
    unsigned char byte3;
    unsigned char byte4;
    int toInt() {return (byte1<<12)+(byte2<<8)+(byte3<<4)+byte4;}
}ip_address;

// IP header (v4)
typedef struct ip_header{
    unsigned char  hlen:4;			// header length
    unsigned char  ver:4;        	// version
    unsigned char  ecn:2;  		// explicit congestion notification (RFC 3168)
    unsigned char  dhcp:6;         // differentiated services code point (RFC 2474)
    unsigned short tlen;           // total length
    unsigned short id; 			// identification
    unsigned char fragoffset:5;   	// fragmentation offset
    unsigned char mfrag:1;         // more fragments
    unsigned char dfrag:1;   		// don't fragment
    unsigned char zero:1;   		// reserved flag
    unsigned char fragoffset1;		// fragment offset again
    unsigned char  ttl;            // time to live
    unsigned char  proto;          // protocol
    unsigned short crc;            // header checksum
    ip_address  src;      	// source address
    ip_address  dest;      	// destination address
}ip_header;

// UDP header
typedef struct udp_header{
    unsigned short sport;          // Source port
    unsigned short dport;          // Destination port
    unsigned short len;            // Datagram length
    unsigned short crc;            // Checksum
}udp_header;

// TCP header
typedef struct tcp_header{
	unsigned short sport; 			// source port
	unsigned short dport; 			// destination port
    unsigned int sequence; 		// sequence number
    unsigned int acknowledge; 		// acknowledgement number
    unsigned char ns :1; 			// nonce sum
    unsigned char reserved_part1:3;// according to rfc
    unsigned char data_offset:4; 	// # of 32-bit words in header
    unsigned char fin :1; 			// Finish Flag
    unsigned char syn :1; 			// Synchronize Flag
    unsigned char rst :1; 			// Reset Flag
    unsigned char psh :1; 			// Push Flag
    unsigned char ack :1; 			// Acknowledgement Flag
    unsigned char urg :1; 			// Urgent Flag
    unsigned char ecn :1; 			// ECN-Echo Flag
    unsigned char cwr :1; 			// Congestion Window Reduced Flag
    unsigned short window; 		// window
    unsigned short checksum; 		// checksum
    unsigned short urgent_pointer; // urgent pointer
} tcp_header;

// ICMP header
typedef struct icmp_hdr
{
	unsigned char type; // ICMP Error type
	unsigned char code; // Type sub code
	unsigned short checksum;
	unsigned short id;
	unsigned short seq;
} icmp_hdr;

// Packet handler forward dec.
// To be registered as a callback function for WinPcap - called whenever a packet is captured.
void decode_packet(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *pkt_data);

typedef unordered_map<double, TcpConnection*> connMap;
connMap connections;
typedef pair<double, TcpConnection*> connPair;

FILE *fp;


int main() {
    pcap_if_t *alldevs;	// list of all capture devices.
    char errbuf[PCAP_ERRBUF_SIZE]; // cstring used by winpcap for error messages.

    // Grab device list. Freak out if error occurs. This function doesn't like to be run from IDEs - run exe directly!
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, (char*)errbuf) == -1)
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

    // Open an output file for cleaner console output.
    fp=fopen("output.txt", "w");
    if(fp==NULL) { cout<<"Error opening output file."<<endl; exit(1);}
    cout<<"Output will be saved to 'output.txt'."<<endl;

    // Free device list now that we're done with it.
    pcap_freealldevs(alldevs);

    // Register callback and start capture loop.
    pcap_loop(capture, 0, decode_packet, NULL);

    return 0;
}

void print_eth_hdr(eth_header *eth){
	fprintf(fp,"\tEthernet Header :\n");
	fprintf(fp, "\t |Dest : %.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n", eth->dest[0], eth->dest[1], eth->dest[2], eth->dest[3], eth->dest[4], eth->dest[5]);
	fprintf(fp, "\t |Src  : %.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n", eth->source[0], eth->source[1], eth->source[2], eth->source[3], eth->source[4], eth->source[5]);
	fprintf(fp, "\t |Proto: %d\n", eth->type);
}
void print_ip_hdr(ip_header *ip){
	fprintf(fp,"\tIP Header :\n");
	fprintf(fp,"\t |Version : %d |HLEN : %d |DCSP : %d |ECN : %d |Total Length : %d\n", (unsigned int)ip->ver, (unsigned int)ip->hlen, (unsigned int)ip->dhcp, (unsigned int)ip->ecn, (unsigned int)ip->tlen);
	fprintf(fp,"\t |Identification : %d |Flags : %d%d%d | Fragmentation Offset: %d\n", ip->id, (unsigned int)ip->zero, (unsigned int)ip->dfrag, (unsigned int)ip->mfrag, (unsigned int)ip->fragoffset);
	fprintf(fp,"\t |Time to Live : %d |Protocol : %d |Header Checksum : %d\n", (unsigned int)ip->ttl, (unsigned int)ip->proto, ip->crc);
	fprintf(fp,"\t |Source : %d.%d.%d.%d\n", ip->src.byte1, ip->src.byte2, ip->src.byte3, ip->src.byte4);
	fprintf(fp,"\t |Destination : %d.%d.%d.%d\n", ip->dest.byte1, ip->dest.byte2, ip->dest.byte3, ip->dest.byte4);
}

void ICMPhelper(const unsigned char *data, int len){

}

void TCPhelper(const unsigned char *data, int len){
	// Grab TCP header
	ip_header* ip = (ip_header*)(data+sizeof(eth_header));
	tcp_header* tcp = (tcp_header*)(data+sizeof(eth_header)+sizeof(ip));

	// Print header here

	// Generate necessary values
	unsigned short dport = ntohs(tcp->dport), sport = ntohs(tcp->sport);
	unsigned int dstip=ip->dest.toInt(), srcip=ip->src.toInt();
	fprintf(stdout,"S: %d.%d.%d.%d, D:%d.%d.%d.%d\n ", ip->dest.byte1, ip->dest.byte2, ip->dest.byte3, ip->dest.byte4, ip->src.byte1, ip->src.byte2, ip->src.byte3, ip->src.byte4);
	double key1 = (((int)srcip)*2) + (int)dstip;
	double key2 = (((int)dstip)*2) + (int)srcip;
	cout<<"\tip1="<<srcip<<", ip2="<<dstip<<", key1="<<key1<<", key2="<<key2<<endl;

	// Get connection between hosts, if it exists. Otherwise, make and register a new one
	TcpConnection* c;
	connPair p;
	connMap::iterator i;
	i=connections.find(key1);
	if(i!=connections.end()) {p=(connPair)*i; c=p.second;} // Check for connection as-is
	else {
		i=connections.find(key2);
		if(i!=connections.end()) { // Check for the reverse connection. Reverse source and dest values if found
			p=(connPair)*i;
			c=p.second;
			int temp=srcip; srcip=dstip; dstip=temp;
			short tempprt=sport; sport=dport; dport=tempprt;
		} else { // If not found, insert new connection as-is
			c = new TcpConnection(srcip, dstip);
			connections.insert({key1, c});
			cout<<"New connection registered\n";
		}
	}

	// What to do in cases of various flag sets
	//HtmlSession* session = new HtmlSession(ip->src.toInt(), sport, ip->dest.toInt(), dport);
	// Case of syn
	if(tcp->syn!=0 && tcp->ack==0) {
		/*
		cout<<"\tSession Created.\n";
		session_table.insert(session);*/
	}
	// Case of syn, ack
	else if(tcp->syn!=0 && tcp->ack!=0) {

	}
	// Case of body message (no rst, syn, fin, ack)
	else if(tcp->syn==0 && tcp->ack==0 && tcp->fin==0 && tcp->rst==0) {/*
		unordered_set<HtmlSession*>::iterator i;
		i = session_table.find(session);
		if(i != session_table.end()) {
			delete session;
			session = (HtmlSession*)*i;
			cout<<"Adding packet to session.\n";
			int offset = sizeof(eth_header)+sizeof(ip)+sizeof(tcp);
			int seq = ntohs(tcp->sequence);
			int datalen = len-offset;
			session->addPacket(new HtmlConstruct(data+offset, datalen, seq, seq+datalen));
		} */
	}
	// Case of closure (rst, fin)
	else if(tcp->rst!=0 || tcp->fin !=0) {/*
		unordered_set<HtmlSession*>::iterator i;
		i = session_table.find(session);
		if(i != session_table.end()) {
			delete session;
			session = (HtmlSession*)*i;
			session->dumpData();
		}*/
	}
}

void UDPhelper(const unsigned char *data, int len){

}



// Packet decoder - takes a packet and figures out protocol. Passes along to appropriate helper.
void decode_packet(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *pkt_data) {

	// Make timestamp readable.
	time_t local = header->ts.tv_sec;
	struct tm *time = localtime(&local);
	char timestamp[16];
	strftime(timestamp, sizeof timestamp, "%H:%M:%S", time);

	// Print capture time and length of packet.
	fprintf(fp,"Packet Captured : %s (Length: %d bytes)\n",timestamp, header->len);

	// Get ethernet header
	eth_header *eth = (eth_header *)pkt_data;

	// Get ip header
	ip_header *ip = (ip_header *) (pkt_data + sizeof(eth_header));

	// Figure out the protocol of the packet
	switch(ip->proto) {
		case 1: // ICMP
			fprintf(fp, "ICMP PACKET :\n");
			print_eth_hdr(eth);
			print_ip_hdr(ip);
			break;
		case 2: // IGMP
			fprintf(fp, "IGMP PACKET :\n");
			print_eth_hdr(eth);
			print_ip_hdr(ip);
			break;
		case 6: // TCP
			fprintf(fp, "TCP PACKET :\n");
			print_eth_hdr(eth);
			print_ip_hdr(ip);
			TCPhelper(pkt_data, header->len);
			break;
		case 17:// UDP
			fprintf(fp, "UDP PACKET :\n");
			print_eth_hdr(eth);
			print_ip_hdr(ip);
			break;
		default:
			fprintf(fp,"%d\n",ip->proto);
			break;
	}
}
