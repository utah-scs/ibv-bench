CXXFLAGS := -std=c++14 -O3 -Idocopt.cpp -Wall -Werror
#CXXFLAGS := -std=c++14 -O0 -g -Idocopt.cpp -Wall -Werror
LDFLAGS := -libverbs -lpthread

SRCS := $(filter-out nosend.cc, $(wildcard *.cc))
OBJS := $(patsubst %.cc, %.o, $(SRCS)) docopt.o

ibv-bench: $(OBJS)
	$(CXX) $^ -o ibv-bench $(LDFLAGS)

docopt.o : docopt.cpp/docopt.cpp
	$(CXX) $(CXXFLAGS) -Wno-unknown-pragmas -c $<

%.o : %.cpp
	$(CXX) $(CXXFLAGS) -c $<

%.o : %.cc
	$(CXX) $(CXXFLAGS) -c $<

nosend : nosend.o IpAddress.o Common.o Cycles.o SpinLock.o LargeBlockOfMemory.o docopt.o
	g++ IpAddress.o Common.o Cycles.o SpinLock.o LargeBlockOfMemory.o docopt.o nosend.o -o nosend -libverbs -lpthread

.PHONY: clean
clean:
	-rm *.o ibv-bench nosend

all: ibv-bench nosend 

