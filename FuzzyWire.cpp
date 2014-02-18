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

// Constants
#define CAPTURE_BYTES 65536 // Number of bytes to capture, per packet. Set absurdly high to capture full packet.

using namespace std;

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


// Packet decoder - takes a packet and prints basic information
void decode_packet(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {

	// Make timestamp readable.
	time_t local = header->ts.tv_sec;
	struct tm *time = localtime(&local);
	char timestamp[16];
	strftime(timestamp, sizeof timestamp, "%H:%M:%S", time);

	// Print capture time and length of packet.
	printf("%s,%.6d len:%d\n", timestamp, header->ts.tv_usec, header->len);
}
