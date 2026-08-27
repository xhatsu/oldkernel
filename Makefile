# GCC 4.4 / CentOS 6 compatible: C++03, gnu++03 or gnu++98.
CXX ?= g++
CXXSTD ?= $(shell $(CXX) -std=gnu++03 -x c++ -E /dev/null >/dev/null 2>&1 && echo -std=gnu++03 || echo -std=gnu++98)
CXXFLAGS ?= -O2 -Wall -Wextra $(CXXSTD)

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
