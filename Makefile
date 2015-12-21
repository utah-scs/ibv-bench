CXXFLAGS := -std=c++14

main: Main.o IpAddress.o
	g++ $^ -o main -libverbs -lpthread

IpAddress.o: IpAddress.cc
	g++ $(CXXFLAGS) -c IpAddress.cc

Main.o: Main.cc
	g++ $(CXXFLAGS) -c Main.cc

.PHONY: clean
clean:
	-rm *.o main
