CXXFLAGS := -std=c++14 -O3 -Idocopt.cpp -Wall -Werror
LDFLAGS := -libverbs -lpthread

SRCS := $(wildcard *.cc)
OBJS := $(patsubst %.cc, %.o, $(SRCS)) docopt.o

ibv-bench: $(OBJS)
	$(CXX) $^ -o ibv-bench $(LDFLAGS)

docopt.o : docopt.cpp/docopt.cpp
	$(CXX) $(CXXFLAGS) -Wno-unknown-pragmas -c $<

%.o : %.cpp
	$(CXX) $(CXXFLAGS) -c $<

%.o : %.cc
	$(CXX) $(CXXFLAGS) -c $<

.PHONY: clean
clean:
	-rm *.o ibv-bench

all: ibv-bench

