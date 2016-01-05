CXXFLAGS := -std=c++14 -O3

main: Main.o IpAddress.o LargeBlockOfMemory.o Common.o
	g++ $^ -o main -libverbs -lpthread

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
	-rm *.o main
