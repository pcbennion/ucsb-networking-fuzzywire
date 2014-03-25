ucsb-networking-fuzzywire
=========================

Packet capture, analysis, and visualization program created for CS176b. Uses WinPcap libraries.

Authors:
  Peter Bennion
  Tyralyn Tran
  
This is a very barebones packet analysis program. It uses winpcap for sniffing network traffic, then analyzes TCP traffic to ressemble the contents of HTML packets. Reassembled HTML sessions are displayed in the command line as plaintext when the connection to the host ends. Generally, this means that only command and error packets will be displayed immediately - connections that include page contents will be closed much later.

A wireshark-like breakdown of TCP packets is pushed to 'output.txt'. This includes all relevant information about Ethernet addresses, IP addresses, port numbers, TCP flags, etc. Due to a small bug in the output, port numbers are displayed as signed ints.

The program works by keeping a map-of-a-map that represents all connections between IP addresses and all port connections within that connection. This allows the number of SYNs vs the number of data packets to be tracked. This tracking was intended to be used for security mechanisms that have their frameworks present, but were not fully implemented due to time cosntraints. The TCPAttack class was supposed to simulate a SYN attack to take advantage of these mechanisms, but it is also unfinished.
