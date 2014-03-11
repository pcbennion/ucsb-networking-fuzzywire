// needed for test main
//#include <vector>
//#include <random>

#include "fwReconstruct.h"

using namespace std;

/****************************************************
 * HtmlConstruct Class:
 * 		Represents a packet of contiguous html data.
 ***************************************************/
// constructor
HtmlConstruct::HtmlConstruct(const unsigned char* data, int len, int seq, int nextseq){
this->data=new unsigned char[len];
for(int i=0; i<len; i++) this->data[i]=data[i]; // copys over data in unsigned char
this->len=len; this->seq=seq; this->nextseq=nextseq;
}

// Appends data in c to this object
int HtmlConstruct::combine(HtmlConstruct* c){
if(c->getSeq()!=nextseq) return 0; //Exit if not a valid combine. Redundant, but safe.

// Grab necessary vars from c.
unsigned char *data2 = c->getData();
int len2 = c->getLen();

// Allocate a new data set from the two data fields. Discard old data.
unsigned char *newdata = new unsigned char[len+len2];
int i;
for(i=0; i<len; i++) newdata[i]=data[i]; // this's (this'? this?) data
for(i=0; i<len2; i++) newdata[i+len]=data2[i]; // c's data
delete data;

// Update members.
data = newdata;
len += len2;
nextseq = c->getNext();

// Return 1 if successful.
// DON'T FORGET TO DELETE C OR MEMORY WILL LEAK!!!
return 1;
}

// Accessors. Yay.
unsigned char *HtmlConstruct::getData(){return data;}
int HtmlConstruct::getLen(){return len;}
int HtmlConstruct::getSeq(){return seq;}
int HtmlConstruct::getNext(){return nextseq;}

/****************************************************
 * HtmlSession Class:
 * 		Best-effort reconstruction of an HTML session
 * 		from provided HtmlConstructs.
 ***************************************************/
// Constructor
HtmlSession::HtmlSession(int srcip, short srcprt, int dstip, short dstprt){
	this->srcip=srcip; this->srcprt=srcprt; this->dstip=dstip; this->dstprt=dstprt;
	packets = new list<HtmlConstruct*>();
}

// Adds a packet to the member list of constructs.
// If it can be combined with any current elements, function recurses with resulting combo.
// If no possible combinations (or list is empty), adds to end of list.
void HtmlSession::addPacket(HtmlConstruct* c){
	// DEBUG: uncomment couts for debug messages
	//cout<<"Inserting packet "<<c->getData()<<" - ";
	if(packets->empty()) {packets->push_front(c); /*cout<<"added to end"<<endl;*/ return;}
	list<HtmlConstruct*>::iterator i;
	HtmlConstruct* elem;
	for(i=packets->begin(); i!=packets->end(); ++i){
		elem = *i;
		if(c->getNext()==elem->getSeq()){
			//cout<<"comes before "<<elem->getData()<<endl;
			c->combine(elem);
			packets->erase(i);
			delete elem;
			this->addPacket(c);
			return;
		} else if(elem->getNext()==c->getSeq()){
			//cout<<"comes after "<<elem->getData()<<endl;
			elem->combine(c);
			packets->erase(i);
			delete c;
			this->addPacket(elem);
			return;
		}
	}
	//cout<<"added to end"<<endl;
	packets->push_back(c);
}

string HtmlSession::getHashString(){
	stringstream ss;
	ss.fill('0'); ss.width(sizeof(int));
	ss<<srcip<<dstip;
	ss.width(sizeof(short));
	ss<<srcprt<<dstprt;
	return ss.str();
}

// Dumps all data from packets in member list.
// TODO: fix so it returns properly instead of dumping to cout.
string HtmlSession::dumpData(){
	stringstream ss;
	if(packets->empty()) return "";
	list<HtmlConstruct*>::iterator i;
	HtmlConstruct* elem;
	for(i=packets->begin(); i!=packets->end(); ++i){
		elem = *i;
		cout << elem->getData();
		cout<<"|";
	}
	cout<<endl;
	return ss.str();
}

//Testing Function. unsigned char* conversion will output weird chars in debug. Don't panic - result is all that matters.
// Randomly assembles chunks of the alphabet. Outputs in-order alphabet.
/*
int main()
{
	int i;
	HtmlConstruct* construct[26];
	HtmlSession session(0,0,0,0);

	vector<int> v;

	int index=0;
	construct[index++]=new HtmlConstruct((unsigned char*)"abcd ", 	4, 0 , 4);
	construct[index++]=new HtmlConstruct((unsigned char*)"efg ", 	3, 4 , 7);
	construct[index++]=new HtmlConstruct((unsigned char*)"hijkl ", 	5, 7 ,12);
	construct[index++]=new HtmlConstruct((unsigned char*)"m ", 		1, 12,13);
	construct[index++]=new HtmlConstruct((unsigned char*)"nop ", 	3, 13,16);
	construct[index++]=new HtmlConstruct((unsigned char*)"qrstuv ", 6, 16,22);
	construct[index++]=new HtmlConstruct((unsigned char*)"wx ", 	2, 22,24);
	construct[index++]=new HtmlConstruct((unsigned char*)"y ", 		1, 24,25);
	construct[index++]=new HtmlConstruct((unsigned char*)"z ", 		1, 25,26);
	for(i=0; i<index;i++){
		v.push_back(i);
	}

	random_shuffle(v.begin(), v.end());

	for(i=0;i<index;i++){session.addPacket(construct[v[i]]); session.dumpData();}

	return 0;
}*/


