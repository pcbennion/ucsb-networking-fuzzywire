#ifndef TCPCONNECTION_H_
#define TCPCONNECTION_H_

#include <cstdlib>
#include <unordered_map>
#include "PacketHeaders.h"

class TcpSession; class HtmlSession;

typedef std::unordered_map<int, TcpSession*> sessionMap;
enum SessionType {DEF, HTML};
typedef std::pair<int, TcpSession*> sessionPair;

class TcpSession {
private:
	unsigned short srcprt, dstprt;
	SessionType t;
protected:
public:
	TcpSession(unsigned short prt1, unsigned short prt2, SessionType type) {srcprt=prt1, dstprt=prt2; t=type;}
	SessionType getType() {return t;}
};

class TcpConnection {
private:
	sessionMap* map;
	unsigned int srcip, dstip;
	int synCount;
	double key;
protected:
public:
	TcpConnection(unsigned int ip1, unsigned int ip2);
	TcpSession* findConnection(int key);
	double getKeyVal() {return key;}
	void addSyn(unsigned short prt1, unsigned short prt2);
	void addData(tcp_header* header, const unsigned char* data, int len);
	void addFin(unsigned short prt1, unsigned short prt2);
};

#endif /* TCPCONNECTION_H_ */
