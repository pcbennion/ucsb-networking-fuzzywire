CC		=	g++
CFLAGS 	=	-O2 -g -Wall -fmessage-length=0 -std=c++11
LFLAGS 	=	-lwpcap -lwsock32

TARGET 	=	FuzzyWire.exe

SRC 	=	FuzzyWire.cpp fwReconstruct.cpp TcpConnection.cpp
OBJS 	=	$(SRC:.cpp=.o)

all:	$(SRC) $(TARGET) attack

$(OBJS) : $(SRC)
	$(CC) $(CFLAGS) -c $(SRC)

$(TARGET):	$(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(LFLAGS)
	
attack: TCPattack/TCPattack.cpp 
	g++ TCPattack/TCPattack.cpp -o TCPattack/TCPattack.exe -lwpcap -liphlpapi -O2 -g -Wall -fmessage-length=0

clean:
	rm -f *.o $(TARGET)
