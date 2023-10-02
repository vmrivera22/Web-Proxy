CFLAGS = -g -Wall
CC=g++ $(CFLAGS)
LDFLAGS= -pthread -lpthread -lssl -lcrypto

DDIR = ./bin
all		:	myproxy myproxy.o
.PHONY	:	all
myproxy	:	myproxy.o
	$(CC) -o $(DDIR)/myproxy $(LDFLAGS) myproxy.o $(LDFLAGS)
myproxy.o	:	./src/myproxy.cpp
	$(CC) -c ./src/myproxy.cpp
clean	:
	rm -rf $(DDIR)/myproxy myproxy.o infer-out
infer	:	clean
	infer-capture -- make
	infer-analyze -- make