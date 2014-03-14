/*
 * TcpConnection.cpp
 *
 *  Created on: Mar 13, 2014
 *      Author: Peter
 */

#include "TcpConnection.h"
#include "fwReconstruct.h"

using namespace std;

/****************************************************
 * TcpConnection Class:
 * 		Registry of a TCP exchange between hosts.
 * 		Keeps track of ports that have been used.
 * 		Builds HtmlSessions for port 80 traffic.
 ***************************************************/
// constructor
TcpConnection::TcpConnection(unsigned int ip1, unsigned int ip2) {
	this->srcip=ip1; this->dstip=ip2;
	this->synCount=0;
	this->key=srcip*2+dstip;
}

/*
 * Find a session between ports, if it exists.
 */
TcpSession* TcpConnection::findConnection(int key) {
	TcpSession* session = NULL;
	sessionPair pair;
	sessionMap::iterator i;
	i=map.find(key);
	if(i!=map.end()) {pair= (sessionPair)*i; session = pair.second;}
	return session;
}

/*
 * Register flag states with the connection
 */
void TcpConnection::addSyn(unsigned short prt1, unsigned short prt2) {
	// for now, just increment the number  of syns. We'll see how that works out later
	synCount++;
}
void TcpConnection::addData(unsigned short prt1, unsigned short prt2, const char* data) {
	// Generate key and try to find session
	int prtkey = prt1*2+prt2;
	TcpSession* session = findConnection(prtkey);
	// Check port numbers to see if this is an HTML exchange
	if(prt1==80||prt2==80) {
		// If session is null, add new session and decrement synCount (a new data session has started)
		if(session==NULL) {session = (TcpSession*) new HtmlSession(prt1, prt2); map.insert({prtkey, session}); synCount--;}
		// TODO Insert data into session
	} else {
		// If session is null, add new session and decrement synCount (a new data session has started)
		if(session==NULL) {session = new TcpSession(prt1, prt2, DEF); map.insert({prtkey, session}); synCount--;}
	}
}
void TcpConnection::addFin(unsigned short prt1, unsigned short prt2) {

}
