#ifndef FWRECONSTRUCT_H_
#define FWRECONSTRUCT_H_

#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <list>

#include "TcpConnection.h"

class HtmlConstruct{

private:
	unsigned char *data;
	int len;
	int seq;
	int nextseq;
protected:
public:
	HtmlConstruct(const unsigned char* data, int len, int seq, int nextseq);
	int combine(HtmlConstruct* c);
	unsigned char *getData();
	int getLen();
	int getSeq();
	int getNext();
};

class HtmlSession : TcpSession {
private:
	std::list<HtmlConstruct*>* packets;
protected:
public:
	HtmlSession(unsigned short srcprt, unsigned short dstprt);
	void addPacket(HtmlConstruct* c);
	std::string dumpData();
};

#endif /* FWRECONSTRUCT_H_ */
