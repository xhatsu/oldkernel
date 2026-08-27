# Build targets for the native old-kernel capture path.
# GCC 4.4 / CentOS 6 compatible: C++03, no third-party libraries.
CXX ?= g++
CXXFLAGS ?= -O2 -Wall -Wextra -std=gnu++03

.PHONY: all cpp cpp-ship cpp-debug fixture clean

all: cpp cpp-ship

cpp:
	$(CXX) $(CXXFLAGS) nt-sniff-cpp.cpp -o nt-sniff-cpp

cpp-ship:
	$(CXX) $(CXXFLAGS) nt-ship-cpp.cpp -o nt-ship-cpp

cpp-debug:
	$(CXX) -O0 -g -Wall -Wextra -std=gnu++03 nt-sniff-cpp.cpp -o nt-sniff-cpp-debug

fixture: cpp
	./nt-sniff-cpp --fixture

clean:
	rm -f nt-sniff-cpp nt-sniff-cpp-debug nt-ship-cpp
