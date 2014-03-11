#ifndef FWRECONSTRUCT_H_
#define FWRECONSTRUCT_H_

#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <list>

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

class HtmlSession{
private:
	int srcip, dstip;
	short srcprt, dstprt;
	std::list<HtmlConstruct*>* packets;
protected:
public:
	HtmlSession(int srcip, short srcprt, int dstip, short dstprt);
	void addPacket(HtmlConstruct* c);
	std::string getHashString();
	std::string dumpData();/*
	bool operator==(HtmlSession x){return (	this->srcip==x.srcip && this->srcprt==x.srcprt &&
											this->dstip==x.dstip && this->dstprt==x.dstprt		); }*/
};

#endif /* FWRECONSTRUCT_H_ */
