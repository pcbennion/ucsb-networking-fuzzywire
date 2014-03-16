/*==========================================================================
 *
 * FUZZY WIRE - Network packet capture, HTML reconstruction, security analysis
 *
 * Authors: Peter Bennion
 * 			Tyralyn Tran
 *
 * Version: v0.5
 *
 * Instructions for installing WinPcap + libs: http://www.codeproject.com/Articles/30234/Introduction-to-the-WinPcap-Networking-Libraries
 *		Don't forget to add pcap library to PATH!
 *
 * Code based on example sniffers at:	https://www.winpcap.org/docs/docs_40_2/html/group__wpcap__tut3.html
 *										http://www.binarytides.com/code-packet-sniffer-c-winpcap/
 *
 *==========================================================================*/

// Std Utilities.
#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <unordered_map>

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

// Other headers in fuzzywire.
#include "TcpConnection.h"

// Globals.
typedef std::unordered_map<double, TcpConnection*> connMap;
typedef std::pair<double, TcpConnection*> connPair;
connMap* connections;
FILE *fp;
eth_header *ethhdr;			// These are for ease of use.
ip_header *iphdr;
tcp_header *tcpheader;
udp_header *udpheader;
icmp_header *icmpheader;

// Constants.
#define CAPTURE_BYTES 65536 // Number of bytes to capture, per packet. Set absurdly high to capture full packet.

// Forward declarations.
void ProcessPacket(u_char* Buffer, int Size);

using namespace std;

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

    connections = new connMap();

    // Read packets in a loop
    unsigned int res;
    struct pcap_pkthdr* header;
    unsigned char* data;
	while((res = pcap_next_ex( capture, &header, (const unsigned char**)&data)) >= 0)
	{
		if(res == 0){continue;} // No packet this run through

		// Make timestamp readable.
		time_t local = header->ts.tv_sec;
		struct tm *time = localtime(&local);
		char timestamp[16];
		strftime(timestamp, sizeof timestamp, "%H:%M:%S", time);

		// Print basic packet info
		//fprintf(logfile , "\nNext Packet : %ld:%ld (Packet Length : %ld bytes) " , header->ts.tv_sec, header->ts.tv_usec, header->len);
		//fprintf(logfile , "\nNext Packet : %s.%ld (Packet Length : %ld bytes) " , buffer , header->ts.tv_usec, header->len);
		ProcessPacket(data , header->caplen); // call processing function
	}
	return 0;
}

/**********************************************************************
 *	PRINT HELPER FUNCTIONS
 *********************************************************************/
void print_eth_hdr(eth_header *eth){
	fprintf(fp,"\tEthernet Header :\n");
	fprintf(fp, "\t |Dest : %.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n", eth->dst[0], eth->dst[1], eth->dst[2], eth->dst[3], eth->dst[4], eth->dst[5]);
	fprintf(fp, "\t |Src  : %.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n", eth->src[0], eth->src[1], eth->src[2], eth->src[3], eth->src[4], eth->src[5]);
	fprintf(fp, "\t |Proto: %d\n", ntohs(eth->type));
}
void print_ip_hdr(ip_header *ip){
	struct sockaddr_in source,dest;
	source.sin_addr.s_addr = iphdr->srcaddr;
	dest.sin_addr.s_addr = iphdr->destaddr;
	fprintf(fp,"\tIP Header :\n");
	fprintf(fp,"\t |Version : %d |HLEN : %d |Total Length : %d Bytes\n", (unsigned int)ip->ver, (unsigned int)ip->hlen, ntohs(iphdr->tlen));
	fprintf(fp,"\t |Time to Live : %d |Protocol : %d |Header Checksum : %d\n", (unsigned int)ip->ttl, (unsigned int)ip->protocol, ntohs(iphdr->checksum));
	fprintf(fp,"\t |Source : %s\n", inet_ntoa(source.sin_addr));
	fprintf(fp,"\t |Destination : %s\n",inet_ntoa(dest.sin_addr));
}
void print_tcp_hdr(tcp_header *tcp){
	fprintf(fp,"\tTCP Header :\n");
	fprintf(fp,"\t |Source Port : %d |Dest Port : %d\n", (tcpheader->sport), (tcpheader->dport));
	fprintf(fp,"\t |Sequence Number: %d\n", (unsigned int)tcpheader->sequence);
	fprintf(fp,"\t |Acknowledge Number : %d \n", (unsigned int)tcpheader->acknowledge);
	fprintf(fp,"\t |Flags(SYN,ACK,FIN,RST): %d%d%d%d\n", (unsigned int)tcpheader->syn, (unsigned int)tcpheader->ack, (unsigned int)tcpheader->fin, (unsigned int)tcpheader->rst);
}

/**********************************************************************
 *	REGISTRY FOR TCP CONNECTIONS
 *********************************************************************/
void TCPReg(ip_header* ip, tcp_header* tcp, const unsigned char *data, int len){

	// Generate necessary values
	unsigned short dport = (tcp->sport), sport =  (tcp->dport);
	unsigned int dstip=ip->destaddr, srcip=ip->srcaddr;
	double key1 = (((int)srcip)*2) + (int)dstip;
	double key2 = (((int)dstip)*2) + (int)srcip;
	//cout<<sport<<", "<<dport<<", "<<len<<endl;

	// Get connection between hosts, if it exists. Otherwise, make and register a new one
	TcpConnection* c;
	connPair p;
	connMap::iterator i;
	i=connections->find(key1);
	if(i!=connections->end()) {p=(connPair)*i; c=p.second;} // Check for connection as-is
	else {
		i=connections->find(key2);
		if(i!=connections->end()) { // Check for the reverse connection. Reverse source and dest values if found
			p=(connPair)*i;
			c=p.second;
			int temp=srcip; srcip=dstip; dstip=temp;
			short tempprt=sport; sport=dport; dport=tempprt;
		} else { // If not found, insert new connection as-is
			c = new TcpConnection(srcip, dstip);
			connections->insert({key1, c});
			//cout<<"New connection registered\n";
		}
	}

	// What to do in cases of common various flag sets
	// Case of syn
	if(tcp->syn!=0 && tcp->ack==0) {
		c->addSyn(sport, dport);
	}
	// Case of syn, ack
	else if(tcp->syn!=0 && tcp->ack!=0) {

	}
	// Case of body message (no rst, syn, fin, len>0)
	else if(tcp->syn==0 && tcp->fin==0 && tcp->rst==0 && len>0) {
		c->addData(tcp, data, len);
	}
	// Case of closure (rst, fin)
	else if(tcp->rst != 0 || tcp->fin !=0) {
		c->addFin(sport, dport);
	}
}
/*********************************************************************/

void ProcessPacket(u_char* Buffer, int Size)
{
    // Get and print Ethernet header
	ethhdr = (eth_header *)Buffer;
    //print_eth_hdr(ethhdr);

    // Operate on IP packets only
    if(ntohs(ethhdr->type) == 0x0800)
    {
        // Get and print IPv4 header
    	iphdr = (ip_header *)(Buffer + sizeof(eth_header));
        unsigned short iphdrlen = iphdr->hlen*4;
        int nexthdrlen;
        //print_ip_hdr(iphdr);

        switch (iphdr->protocol)
        {
            case 1: //ICMP
            	break;
            case 2: //IGMP
            	break;
            case 6: //TCP
            	tcpheader = (tcp_header*)( Buffer + iphdrlen + sizeof(eth_header) );
            	tcpheader->sport = ntohs(tcpheader->sport); tcpheader->dport = ntohs(tcpheader->dport);
            	tcpheader->sequence = (unsigned int)ntohl(tcpheader->sequence);
            	tcpheader->acknowledge = (unsigned int)ntohl(tcpheader->acknowledge);
            	nexthdrlen = tcpheader->data_offset*4;
            	print_eth_hdr(ethhdr);
            	print_ip_hdr(iphdr);
            	print_tcp_hdr(tcpheader);
            	TCPReg(iphdr, tcpheader, (Buffer+sizeof(eth_header)+iphdrlen+nexthdrlen), Size-sizeof(eth_header)-iphdrlen-nexthdrlen);
            	break;
            case 17: //UDP
            	//udpheader = (udp_header*)( Buffer + iphdrlen + sizeof(eth_header) );
            	break;
            default:
            	break;
        }
    }
}
