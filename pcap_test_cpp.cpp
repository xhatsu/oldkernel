#define main main_unused
#include "nt-sniff-cpp.cpp"
#undef main

#include <iostream>
#include <fstream>
#include <vector>
#include <stdint.h>
#include <sys/time.h>

struct PcapFileHeader {
  uint32_t magic;
  uint16_t version_major;
  uint16_t version_minor;
  int32_t thiszone;
  uint32_t sigfigs;
  uint32_t snaplen;
  uint32_t linktype;
};

struct PcapPacketHeader {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t incl_len;
  uint32_t orig_len;
};

int main(int argc, char **argv) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <pcap_file> [ports...]\n";
    return 1;
  }
  const char *pcap_file = argv[1];
  std::vector<unsigned> ports;
  g_wsse_body_bytes = 16384;
  for (int i = 2; i < argc; ++i) {
    if (!strcmp(argv[i], "--wsse-body-bytes") && i + 1 < argc) {
      g_wsse_body_bytes = (size_t)atoi(argv[++i]);
      continue;
    }
    unsigned p = (unsigned)atoi(argv[i]);
    if (valid_port(p)) ports.push_back(p);
  }
  if (ports.empty()) {
    ports.push_back(8001);
  }

  init_rng();
  memset(g_monitored_ports, 0, sizeof(g_monitored_ports));
  for (size_t k = 0; k < ports.size(); ++k) {
    if (ports[k] < 65536) g_monitored_ports[ports[k]] = true;
  }
  g_endpoint = "";

  std::ifstream f(pcap_file, std::ios::binary);
  if (!f.is_open()) {
    std::cerr << "Cannot open " << pcap_file << "\n";
    return 1;
  }

  PcapFileHeader fh;
  if (!f.read((char *)&fh, sizeof(fh))) return 1;

  bool swap = (fh.magic == 0xd4c3b2a1);
  uint32_t linktype = fh.linktype;
  if (swap) {
    linktype = ((linktype >> 24) & 0xff) | ((linktype >> 8) & 0xff00) |
               ((linktype << 8) & 0xff0000) | ((linktype << 24) & 0xff000000);
  }

  std::map<ConnectionKey, Connection> connections;
  std::list<ConnectionKey> conn_lru;
  std::string node = "cpp-pcap-test";

  std::vector<unsigned char> raw_buf;
  std::vector<unsigned char> eth_buf;
  size_t pkt_count = 0;

  while (f) {
    PcapPacketHeader ph;
    if (!f.read((char *)&ph, sizeof(ph))) break;
    uint32_t incl_len = ph.incl_len;
    if (swap) {
      incl_len = ((incl_len >> 24) & 0xff) | ((incl_len >> 8) & 0xff00) |
                 ((incl_len << 8) & 0xff0000) | ((incl_len << 24) & 0xff000000);
    }
    raw_buf.resize(incl_len);
    if (!f.read((char *)&raw_buf[0], incl_len)) break;
    ++pkt_count;

    const unsigned char *pkt_ptr = &raw_buf[0];
    size_t pkt_len = incl_len;

    if (linktype == 113) {
      if (pkt_len < 16) continue;
      eth_buf.resize(14 + pkt_len - 16);
      memset(&eth_buf[0], 0, 12);
      eth_buf[12] = raw_buf[14];
      eth_buf[13] = raw_buf[15];
      memcpy(&eth_buf[14], &raw_buf[16], pkt_len - 16);
      pkt_ptr = &eth_buf[0];
      pkt_len = eth_buf.size();
    }

    time_t pcap_now = (time_t)ph.ts_sec;
    long long pcap_mono_now = (long long)ph.ts_sec * 1000LL + (long long)ph.ts_usec / 1000LL;
    sweep(connections, conn_lru, pcap_now, g_pending_ttl_sec, pcap_mono_now);
    handle_packet(pkt_ptr, pkt_len, node, ports, connections, conn_lru, pcap_now, pcap_mono_now);
  }

  flush_incomplete_wsse(connections);
  flush_all_pending(connections);
  std::cout.flush();
  return 0;
}
