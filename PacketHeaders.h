#ifndef PACKETHEADERS_H_
#define PACKETHEADERS_H_

// ETHERNET HEADER
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

// UDP header
typedef struct udp_header
{
    unsigned short sport; 				// Source port
    unsigned short dport; 				// Destination port
    unsigned short len; 				// Packet length
    unsigned short checksum; 			// Optional checksum
};

// ICMP HEADER
typedef struct icmp_header
{
    unsigned char type; 				// Error type
    unsigned char code; 				// Sub code
    unsigned short checksum;
    unsigned short id;
    unsigned short seq;
};

#endif /* PACKETHEADERS_H_ */
