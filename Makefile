CC		=	g++
CFLAGS 	=	-O2 -g -Wall -fmessage-length=0 -std=c++11
LFLAGS 	=	-lwpcap -lwsock32

TARGET 	=	FuzzyWire.exe

SRC 	=	FuzzyWire.cpp fwReconstruct.cpp TcpConnection.cpp
OBJS 	=	$(SRC:.cpp=.o)

$(OBJS) : $(SRC)
	$(CC) $(CFLAGS) -c $(SRC)

$(TARGET):	$(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(LFLAGS)

all:	$(SRC) $(TARGET)

clean:
	rm -f *.o $(TARGET)
