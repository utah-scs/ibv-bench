CXXFLAGS := -std=c++14 -O3 -Idocopt.cpp

ibv-bench: Main.o IpAddress.o LargeBlockOfMemory.o Common.o docopt.o
	g++ $^ -o ibv-bench -libverbs -lpthread

docopt.o: docopt.cpp/docopt.cpp
	g++ $(CXXFLAGS) -c $<

Common.o: Common.cc
	g++ $(CXXFLAGS) -c Common.cc

IpAddress.o: IpAddress.cc
	g++ $(CXXFLAGS) -c IpAddress.cc

LargeBlockOfMemory.o: LargeBlockOfMemory.cc
	g++ $(CXXFLAGS) -c LargeBlockOfMemory.cc

Main.o: Main.cc
	g++ $(CXXFLAGS) -c Main.cc


.PHONY: clean
clean:
	-rm *.o ibv-bench
