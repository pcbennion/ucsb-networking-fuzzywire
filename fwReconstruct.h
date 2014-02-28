#ifndef FWRECONSTRUCT_H_
#define FWRECONSTRUCT_H_

#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <list>

class HtmlConstruct{
public:
	HtmlConstruct(unsigned char* data, int len, int seq, int nextseq);
	int combine(HtmlConstruct* c);
	unsigned char *getData();
	int getLen();
	int getSeq();
	int getNext();
protected:
private:
	unsigned char *data;
	int len;
	int seq;
	int nextseq;
};

class HtmlSession{
public:
	HtmlSession(int srcip, int srcprt, int dstip, int dstprt);
	void addPacket(HtmlConstruct* c);
	std::string dumpData();
protected:
private:
	int srcip, srcprt;
	int dstip, dstprt;
	std::list<HtmlConstruct*>* packets;
};

#endif /* FWRECONSTRUCT_H_ */
