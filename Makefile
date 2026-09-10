# GCC 4.4 / CentOS 6 compatible: C++03, gnu++03 or gnu++98.
CXX ?= g++
CXXSTD ?= $(shell $(CXX) -std=gnu++03 -x c++ -E /dev/null >/dev/null 2>&1 && echo -std=gnu++03 || echo -std=gnu++98)
CXXFLAGS ?= -O2 -Wall -Wextra $(CXXSTD) -pthread
LDLIBS ?= -pthread -lrt

.PHONY: all cpp cpp-ship cpp-debug fixture pcap-fixture clean

all: cpp cpp-ship

cpp:
	$(CXX) $(CXXFLAGS) nt-sniff-cpp.cpp $(LDLIBS) -o nt-sniff-cpp

cpp-ship:
	$(CXX) $(CXXFLAGS) nt-ship-cpp.cpp $(LDLIBS) -o nt-ship-cpp

cpp-debug:
	$(CXX) -O0 -g -Wall -Wextra -std=gnu++03 nt-sniff-cpp.cpp $(LDLIBS) -o nt-sniff-cpp-debug

fixture: cpp
	./nt-sniff-cpp --fixture
	./nt-sniff-cpp --ring-fixture
	./nt-sniff-cpp --ship-rate-fixture
	./nt-sniff-cpp --stats-fixture

pcap-fixture: pcap_test_cpp

pcap_test_cpp: pcap_test_cpp.cpp nt-sniff-cpp.cpp
	$(CXX) $(CXXFLAGS) pcap_test_cpp.cpp $(LDLIBS) -o pcap_test_cpp

clean:
	rm -f nt-sniff-cpp nt-sniff-cpp-debug nt-ship-cpp pcap_test_cpp
