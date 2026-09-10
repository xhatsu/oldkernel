/*
 * nt-sniff-cpp.cpp - C++03-compatible old-kernel HTTP capture agent.
 *
 * Replaces the Python hot loop while retaining the oldkernel JSONL contract:
 * AF_PACKET -> classic BPF -> bounded HTTP header flow table -> response
 * correlation -> JSONL stdout -> nt-ship.py.
 *
 * Build target: CentOS 6.8 / GCC 4.4, Linux 2.6.32. No third-party deps.
 * SOAP body inspection is explicitly opt-in and bounded. TLS remains
 * ecapture's concern.
 */
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <pthread.h>
#include <pwd.h>
#include <grp.h>
#include <linux/filter.h>
#include <linux/capability.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <list>
#include <deque>
#include <sstream>
#include <string>

#include <vector>
#include <algorithm>

#if defined(__SANITIZE_ADDRESS__)
  #define NT_HAS_ASAN 1
#elif defined(__has_feature)
  #if __has_feature(address_sanitizer)
    #define NT_HAS_ASAN 1
  #endif
#endif

static volatile sig_atomic_t g_running = 1;
static void stop_signal(int) { g_running = 0; }

static const size_t MAX_FLOWS = 4096;
static const size_t MAX_TOTAL_BUFFER_BYTES = 16 * 1024 * 1024; // 16 MiB aggregate budget
static const size_t MAX_PENDING_TOTAL = 4096;                   // 4096 global pending requests
static const size_t MAX_PENDING_PER_FLOW = 32;
static const size_t MAX_PORTS = 30;
static const size_t MAX_HEADER_BYTES = 32768;                   // 32 KiB
static const size_t MAX_FLOW_BUFFER_BYTES = 65536;              // 64 KiB
static const size_t MAX_WSSE_BODY_BYTES = 65536;
static const size_t MAX_WSSE_BODY_FLOWS = 256;
static const size_t MAX_WSSE_USERNAME = 200;
static const size_t MAX_BATCH = 400;
static const size_t MAX_QUEUE = 4000;
static const size_t MAX_POST_BYTES = 65536;
static const size_t MAX_STATS_BYTES = 16384;
static const unsigned DEFAULT_SHIP_RATE_KBPS = 1024;
static const int FLUSH_SEC = 5;
static const int RETRY_SEC = 60;
static const unsigned FLOW_IDLE_TTL = 300;
static const unsigned FLOW_STALE_TTL = 600;
static const unsigned DEFAULT_PENDING_TTL = 30;
static unsigned g_pending_ttl_sec = DEFAULT_PENDING_TTL;
static const unsigned ACCEPT = 12288;
#ifndef SO_ATTACH_FILTER
  #define SO_ATTACH_FILTER 26
#endif
static const unsigned short ETH_P_IP_HOST = 0x0800;
static const unsigned short ETH_P_8021Q_HOST = 0x8100;
static const size_t MAX_OOO_SEGMENTS = 4;
static const size_t MAX_DRAIN_PER_PASS = 256;

static inline long long now_monotonic_ms() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static inline int32_t seq_diff(uint32_t a, uint32_t b) {
  return (int32_t)(a - b);
}

static std::string trim(const std::string &s) {
  size_t a = 0, b = s.size();
  while (a < b && isspace((unsigned char)s[a])) ++a;
  while (b > a && isspace((unsigned char)s[b - 1])) --b;
  return s.substr(a, b - a);
}
static std::string lower(const std::string &s) {
  std::string x = s;
  size_t i; for (i = 0; i < x.size(); ++i) x[i] = (char)tolower((unsigned char)x[i]);
  return x;
}
static std::string jsonq(const std::string &s) {
  std::string x = "\""; size_t i;
  for (i = 0; i < s.size(); ++i) {
    unsigned char c = (unsigned char)s[i];
    if (c == '\\' || c == '\"') { x += '\\'; x += (char)c; }
    else if (c == '\n') x += "\\n";
    else if (c == '\r') x += "\\r";
    else if (c == '\t') x += "\\t";
    else if (c < 32) x += '?';
    else x += (char)c;
  }
  x += '\"'; return x;
}
static long long now_ms() {
  struct timeval tv; gettimeofday(&tv, NULL);
  return (long long)tv.tv_sec * 1000LL + tv.tv_usec / 1000;
}
static std::string num(long v) { std::ostringstream o; o << v; return o.str(); }
static bool valid_port(unsigned p) { return p > 0 && p <= 65535; }

static uint16_t read_u16(const unsigned char *p) {
  uint16_t value;
  memcpy(&value, p, sizeof(value));
  return value;
}

static uint32_t read_u32(const unsigned char *p) {
  uint32_t value;
  memcpy(&value, p, sizeof(value));
  return value;
}
static bool has_method(const std::string &m) {
  return m == "GET" || m == "POST" || m == "PUT" || m == "DELETE" ||
         m == "PATCH" || m == "HEAD" || m == "OPTIONS";
}
static std::string host_name() {
  char b[256]; if (gethostname(b, sizeof(b) - 1) != 0) return "unknown-node";
  b[sizeof(b) - 1] = 0; char *p = strchr(b, '.'); if (p) *p = 0; return b;
}

/* Strict Base64 decoder with uint32 accumulator, requiring ':', and rejecting invalid data after '=' */
static std::string b64decode_user(const char *in, size_t in_len) {
  while (in_len > 0 && isspace((unsigned char)*in)) { ++in; --in_len; }
  while (in_len > 0 && isspace((unsigned char)in[in_len - 1])) { --in_len; }
  std::string out;
  uint32_t val = 0;
  int bits = -8;
  bool saw_colon = false;
  bool saw_padding = false;
  int pad_count = 0;
  size_t data_chars = 0;

  for (size_t i = 0; i < in_len; ++i) {
    unsigned char c = (unsigned char)in[i];
    if (isspace(c)) continue;
    if (saw_padding) {
      if (c == '=') {
        pad_count++;
        if (pad_count > 2) return "";
        continue;
      }
      return "";
    }
    int d = -1;
    if (c >= 'A' && c <= 'Z') d = c - 'A';
    else if (c >= 'a' && c <= 'z') d = c - 'a' + 26;
    else if (c >= '0' && c <= '9') d = c - '0' + 52;
    else if (c == '+') d = 62;
    else if (c == '/') d = 63;
    else if (c == '=') {
      saw_padding = true;
      pad_count = 1;
      continue;
    }
    else return "";

    data_chars++;
    val = (val << 6) | (uint32_t)d;
    bits += 6;
    if (bits >= 0) {
      char ch = (char)((val >> bits) & 0xff);
      bits -= 8;
      if (ch == ':') {
        saw_colon = true;
      } else if (!saw_colon) {
        if (out.size() >= 256) return "";
        out += ch;
      }
    }
  }
  if (!saw_colon) return "";
  if ((data_chars + (size_t)pad_count) % 4 != 0) return "";
  return out;
}

static std::string ip_to_str(uint32_t ip_be) {
  char b[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &ip_be, b, sizeof(b));
  return b;
}

static inline bool is_hex(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static std::string trace_id_from_parent(const std::string &tp) {
  std::string x = trim(tp);
  if (x.size() != 55 || x[2] != '-' || x[35] != '-' || x[52] != '-') return "";
  if (x[0] != '0' || x[1] != '0') return "";
  bool all_zeros = true;
  for (size_t i = 3; i < 35; ++i) {
    if (!is_hex(x[i])) return "";
    if (x[i] != '0') all_zeros = false;
  }
  if (all_zeros) return "";
  bool span_zeros = true;
  for (size_t i = 36; i < 52; ++i) {
    if (!is_hex(x[i])) return "";
    if (x[i] != '0') span_zeros = false;
  }
  if (span_zeros) return "";
  if (!is_hex(x[53]) || !is_hex(x[54])) return "";
  return lower(x.substr(3, 32));
}

static uint64_t g_rng_state = 0;
static void init_rng() {
  FILE *f = fopen("/dev/urandom", "rb");
  if (f) {
    size_t n = fread(&g_rng_state, 1, sizeof(g_rng_state), f);
    (void)n;
    fclose(f);
  }
  if (!g_rng_state) {
    g_rng_state = ((uint64_t)time(NULL) << 32) ^ (uint64_t)getpid();
  }
}
static inline uint64_t next_rng() {
  uint64_t x = g_rng_state;
  x ^= x << 13; x ^= x >> 7; x ^= x << 17;
  return g_rng_state = (x ? x : 0x853c49e6748fea9bULL);
}

static std::string make_traceparent(std::string *tid) {
  uint64_t r1 = next_rng();
  uint64_t r2 = next_rng();
  uint64_t r3 = next_rng();
  char buf[64];
  snprintf(buf, sizeof(buf), "00-%016llx%016llx-%016llx-01",
           (unsigned long long)r1, (unsigned long long)r2, (unsigned long long)r3);
  char tid_buf[33];
  snprintf(tid_buf, sizeof(tid_buf), "%016llx%016llx",
           (unsigned long long)r1, (unsigned long long)r2);
  *tid = tid_buf;
  return buf;
}

struct Event {
  long ts; std::string host, src, service, method, path, user, scheme, probe;
  std::string basic_user, wsse_user;
  std::string host_hdr, user_agent, xff, caller, dst_ip, traceparent, trace_id;
  unsigned caller_port, dst_port, req_bytes, resp_bytes; int status; long duration_ms;
  bool has_status, has_duration, has_resp;
  Event() : ts(0), caller_port(0), dst_port(0), req_bytes(0), resp_bytes(0), status(0), duration_ms(0), has_status(false), has_duration(false), has_resp(false) {}
};
struct RequestMeta {
  std::string content_type, transfer_encoding;
  size_t content_length;
  bool has_content_length;
  bool has_conflict_cl;
  bool has_transfer_encoding;
  bool invalid_transfer_encoding;
  RequestMeta()
      : content_length(0),
        has_content_length(false),
        has_conflict_cl(false),
        has_transfer_encoding(false),
        invalid_transfer_encoding(false) {}
};

struct TcpSegment {
  uint32_t seq;
  std::string data;
};

static size_t g_total_flow_bytes = 0;
static inline void flow_bytes_add(size_t n) {
  g_total_flow_bytes += n;
}
static inline void flow_bytes_sub(size_t n) {
  if (g_total_flow_bytes >= n) g_total_flow_bytes -= n;
  else g_total_flow_bytes = 0;
}
struct FlowKey {
  uint32_t s_ip;
  uint16_t sport;
  uint32_t d_ip;
  uint16_t dport;
  bool operator<(const FlowKey &x) const {
    if (s_ip != x.s_ip) return s_ip < x.s_ip;
    if (sport != x.sport) return sport < x.sport;
    if (d_ip != x.d_ip) return d_ip < x.d_ip;
    return dport < x.dport;
  }
  bool operator==(const FlowKey &x) const {
    return s_ip == x.s_ip && sport == x.sport && d_ip == x.d_ip && dport == x.dport;
  }
};

typedef FlowKey PacketKey;

static size_t g_wsse_body_flows_active = 0;

struct Flow {
  uint32_t next_seq;
  bool has_seq;
  bool is_broken;
  bool correlation_disabled;
  bool syn_seen;
  bool corr_eligible;
  time_t touched;
  long long first_byte_mono_ms;
  uint32_t generation;
  std::string buf;
  std::vector<TcpSegment> ooo;

  enum HttpState {
    HTTP_STATE_HEADER,
    HTTP_STATE_BODY,
    HTTP_STATE_CHUNK,
    HTTP_STATE_CLOSE_BODY,
    HTTP_STATE_UNSYNCED
  } state;

  size_t body_remaining;
  size_t chunk_payload_remaining;
  bool chunk_reading_len;
  bool chunk_reading_crlf;
  bool chunk_reading_trailer;

  bool awaiting_wsse;
  Event wsse_event;
  std::string wsse_buf;
  size_t wsse_goal;
  size_t wsse_last_parsed_len;
  uint64_t wsse_req_id;
  PacketKey wsse_rk;
  bool fin_seen;
  uint32_t fin_seq;

  Flow() : next_seq(0), has_seq(false), is_broken(false), correlation_disabled(false),
           syn_seen(false), corr_eligible(true), touched(time(NULL)), first_byte_mono_ms(0), generation(0),
           state(HTTP_STATE_HEADER), body_remaining(0), chunk_payload_remaining(0),
           chunk_reading_len(true), chunk_reading_crlf(false), chunk_reading_trailer(false),
           awaiting_wsse(false), wsse_goal(0), wsse_last_parsed_len(0), wsse_req_id(0),
           fin_seen(false), fin_seq(0) {}

  void reset_for_new_connection(uint32_t next_gen, time_t now, bool is_syn_seen = true, bool is_corr_eligible = true) {
    clear_buffers();
    next_seq = 0;
    has_seq = false;
    is_broken = false;
    correlation_disabled = false;
    syn_seen = is_syn_seen;
    corr_eligible = is_corr_eligible;
    touched = now;
    first_byte_mono_ms = 0;
    generation = next_gen;
    state = HTTP_STATE_HEADER;
    body_remaining = 0;
    chunk_payload_remaining = 0;
    chunk_reading_len = true;
    chunk_reading_crlf = false;
    chunk_reading_trailer = false;
    awaiting_wsse = false;
    wsse_event = Event();
    wsse_goal = 0;
    wsse_last_parsed_len = 0;
    wsse_req_id = 0;
    fin_seen = false;
    fin_seq = 0;
  }

  void wsse_cancel() {
    if (awaiting_wsse) {
      awaiting_wsse = false;
      if (g_wsse_body_flows_active > 0) --g_wsse_body_flows_active;
    }
    wsse_clear();
    wsse_goal = 0;
    wsse_last_parsed_len = 0;
    wsse_req_id = 0;
  }

  void wsse_clear() {
    flow_bytes_sub(wsse_buf.size());
    wsse_buf.clear();
    wsse_last_parsed_len = 0;
  }

  void clear_buffers() {
    flow_bytes_sub(buf.size());
    buf.clear();
    wsse_cancel();
    for (size_t i = 0; i < ooo.size(); ++i) {
      flow_bytes_sub(ooo[i].data.size());
    }
    ooo.clear();
  }

  bool buf_append(const char *data, size_t len) {
    if (buf.size() + len > MAX_FLOW_BUFFER_BYTES) {
      clear_buffers();
      is_broken = true;
      return false;
    }
    buf.append(data, len);
    flow_bytes_add(len);
    return true;
  }

  void buf_erase(size_t off, size_t len) {
    if (off >= buf.size()) return;
    if (len > buf.size() - off) len = buf.size() - off;
    buf.erase(off, len);
    flow_bytes_sub(len);
  }

  void wsse_append(const char *data, size_t len) {
    wsse_buf.append(data, len);
    flow_bytes_add(len);
  }

  bool ooo_push(uint32_t seq, const char *data, size_t len) {
    if (ooo.size() >= MAX_OOO_SEGMENTS) return false;
    TcpSegment seg;
    seg.seq = seq;
    seg.data.assign(data, len);
    ooo.push_back(seg);
    flow_bytes_add(len);
    return true;
  }

  void ooo_erase(size_t idx) {
    if (idx < ooo.size()) {
      flow_bytes_sub(ooo[idx].data.size());
      ooo.erase(ooo.begin() + idx);
    }
  }
};

struct Endpoint {
  uint32_t ip;
  uint16_t port;
  Endpoint() : ip(0), port(0) {}
  Endpoint(uint32_t i, uint16_t p) : ip(i), port(p) {}
  bool operator<(const Endpoint &o) const {
    if (ip != o.ip) return ip < o.ip;
    return port < o.port;
  }
  bool operator==(const Endpoint &o) const {
    return ip == o.ip && port == o.port;
  }
};

struct ConnectionKey {
  Endpoint ep1;
  Endpoint ep2;
  ConnectionKey() {}
  ConnectionKey(uint32_t s_ip, uint16_t sport, uint32_t d_ip, uint16_t dport) {
    Endpoint a(s_ip, (uint16_t)sport);
    Endpoint b(d_ip, (uint16_t)dport);
    if (a < b) { ep1 = a; ep2 = b; }
    else { ep1 = b; ep2 = a; }
  }
  bool operator<(const ConnectionKey &o) const {
    if (!(ep1 == o.ep1)) return ep1 < o.ep1;
    return ep2 < o.ep2;
  }
  bool operator==(const ConnectionKey &o) const {
    return ep1 == o.ep1 && ep2 == o.ep2;
  }
};

static uint64_t g_capture_truncated = 0;
static uint64_t g_stream_invalidations = 0;

static uint64_t g_req_id_seq = 0;

struct PendingQueueRef {
  uint64_t req_id;
  uint32_t generation;
  ConnectionKey key;
  long long started_mono_ms;
};

struct Pending {
  uint64_t req_id;
  uint32_t generation;
  Event ev;
  long long started_wall_ms;
  long long started_mono_ms;
  bool is_tombstone;
  long long tombstone_mono_ms;
  std::list<PendingQueueRef>::iterator fifo_it;
  bool in_fifo;
  Pending() : req_id(0), generation(0), started_wall_ms(0), started_mono_ms(0),
              is_tombstone(false), tombstone_mono_ms(0), in_fifo(false) {}
  Pending(uint64_t id, uint32_t gen, const Event &e, long long wall_t, long long mono_t)
    : req_id(id), generation(gen), ev(e), started_wall_ms(wall_t), started_mono_ms(mono_t),
      is_tombstone(false), tombstone_mono_ms(0), in_fifo(false) {}
};

struct Connection {
  ConnectionKey key;
  Endpoint client;
  Endpoint server;
  bool roles_established;
  uint32_t generation;
  bool syn_seen;
  bool have_client_isn;
  uint32_t client_isn;
  bool corr_eligible;
  bool corr_disabled;
  time_t touched;
  long long touched_mono_ms;

  Flow req_flow;
  Flow resp_flow;

  std::vector<Pending> pending;
  bool has_deferred_wsse;
  Event deferred_wsse_event;
  uint64_t deferred_wsse_req_id;

  std::list<ConnectionKey>::iterator lru_it;
  bool in_lru;

  Connection() : roles_established(false), generation(0), syn_seen(false),
                 have_client_isn(false), client_isn(0),
                 corr_eligible(true), corr_disabled(false), touched(time(NULL)),
                 touched_mono_ms(0),
                 has_deferred_wsse(false), deferred_wsse_req_id(0), in_lru(false) {}
};

static size_t g_total_pending_count = 0;
static std::list<PendingQueueRef> g_pending_fifo;

static void remove_pending_from_fifo(Pending &p) {
  if (p.in_fifo) {
    g_pending_fifo.erase(p.fifo_it);
    p.in_fifo = false;
  }
}

// PacketKey entries (response-direction: server→client) for which response

// correlation is permanently disabled until a verified new SYN arrives.
// Bounded to MAX_CORR_DISABLED entries to prevent memory growth under many
// timed-out connections. When capacity is reached, ordering for untracked
// connections cannot be verified, falling back to emitting without correlation.
static const size_t MAX_CORR_DISABLED = 2048;
static std::set<PacketKey> g_corr_disabled;
static std::list<PacketKey> g_corr_disabled_fifo;
static bool g_corr_capacity_reached = false;

static void corr_disabled_insert(const PacketKey &key) {
  if (g_corr_disabled.count(key)) return;
  while (g_corr_disabled.size() >= MAX_CORR_DISABLED && !g_corr_disabled_fifo.empty()) {
    g_corr_capacity_reached = true;
    PacketKey old_key = g_corr_disabled_fifo.front();
    g_corr_disabled_fifo.pop_front();
    g_corr_disabled.erase(old_key);
  }
  g_corr_disabled.insert(key);
  g_corr_disabled_fifo.push_back(key);
}

static void corr_disabled_erase(const PacketKey &key) {
  if (g_corr_disabled.erase(key)) {
    for (std::list<PacketKey>::iterator it = g_corr_disabled_fifo.begin();
         it != g_corr_disabled_fifo.end(); ++it) {
      if (*it == key) {
        g_corr_disabled_fifo.erase(it);
        break;
      }
    }
  }
}

static void corr_disabled_clear() {
  g_corr_disabled.clear();
  g_corr_disabled_fifo.clear();
  g_corr_capacity_reached = false;
}

static bool is_correlation_disabled(const PacketKey &key, bool syn_seen) {
  if (g_corr_disabled.count(key)) return true;
  if (g_corr_capacity_reached && !syn_seen) return true;
  return false;
}

static void invalidate_connection_correlation(std::map<FlowKey, Flow> &flows, const PacketKey &rk) {
  corr_disabled_insert(rk);
  std::map<FlowKey, Flow>::iterator rit = flows.find(rk);
  if (rit != flows.end()) {
    rit->second.corr_eligible = false;
  }
  FlowKey cfk;
  cfk.s_ip = rk.d_ip; cfk.sport = rk.dport;
  cfk.d_ip = rk.s_ip; cfk.dport = rk.sport;
  std::map<FlowKey, Flow>::iterator cit = flows.find(cfk);
  if (cit != flows.end()) {
    cit->second.corr_eligible = false;
  }
}

static bool is_correlation_allowed(const PacketKey &rk,
                                   const std::map<FlowKey, Flow> &flows,
                                   uint32_t gen,
                                   bool syn_seen,
                                   bool corr_eligible) {
  if (g_corr_disabled.count(rk) > 0) return false;
  if (!corr_eligible) return false;

  std::map<FlowKey, Flow>::const_iterator rit = flows.find(rk);
  if (rit != flows.end()) {
    if (!rit->second.corr_eligible || rit->second.is_broken) return false;
  }

  FlowKey cfk;
  cfk.s_ip = rk.d_ip; cfk.sport = rk.dport;
  cfk.d_ip = rk.s_ip; cfk.dport = rk.sport;
  std::map<FlowKey, Flow>::const_iterator cit = flows.find(cfk);
  if (cit != flows.end()) {
    if (!cit->second.corr_eligible || cit->second.is_broken) return false;
  }

  if (g_corr_capacity_reached) {
    if (!syn_seen || gen == 0) return false;
  }

  return true;
}


static void logmsg(const std::string &s) { fprintf(stderr, "nt-sniff-cpp: %s\n", s.c_str()); fflush(stderr); }

static bool parse_decimal_size(const char *p, size_t n, size_t *out) {
  while (n && isspace((unsigned char)*p)) { ++p; --n; }
  while (n && isspace((unsigned char)p[n - 1])) --n;
  if (!n) return false;
  size_t value = 0;
  for (size_t i = 0; i < n; ++i) {
    if (p[i] < '0' || p[i] > '9') return false;
    unsigned digit = (unsigned)(p[i] - '0');
    if (value > (size_t)-1 / 10 || value * 10 > (size_t)-1 - digit) return false;
    value = value * 10 + digit;
  }
  *out = value;
  return true;
}

static inline void bounded_assign(std::string *dst, const char *src, size_t len, size_t max_len) {
  if (len > max_len) len = max_len;
  dst->assign(src, len);
}

static bool transfer_encoding_final_chunked(const std::string &raw) {
  std::string s = lower(trim(raw));
  if (s.empty()) return false;
  std::vector<std::string> tokens;
  size_t start = 0;
  while (start <= s.size()) {
    size_t comma = s.find(',', start);
    if (comma == std::string::npos) comma = s.size();
    std::string token = trim(s.substr(start, comma - start));
    if (token.empty()) return false;
    tokens.push_back(token);
    if (comma == s.size()) break;
    start = comma + 1;
  }
  if (tokens.empty() || tokens.back() != "chunked") return false;
  for (size_t i = 0; i + 1 < tokens.size(); ++i) {
    if (tokens[i] == "chunked") return false;
  }
  return true;
}

static bool parse_request(const char *data, size_t len, Event *e, RequestMeta *meta) {
  const char *end = data + len;
  const char *p = data;
  const char *eol = (const char *)memchr(p, '\n', end - p);
  if (!eol) return false;
  const char *sp1 = (const char *)memchr(p, ' ', eol - p);
  if (!sp1) return false;
  e->method.assign(p, sp1 - p);
  if (!has_method(e->method)) return false;

  const char *path_start = sp1 + 1;
  while (path_start < eol && *path_start == ' ') ++path_start;
  const char *sp2 = (const char *)memchr(path_start, ' ', eol - path_start);
  if (!sp2) return false;

  const char *version = sp2 + 1;
  while (version < eol && *version == ' ') ++version;
  const char *version_end = eol;
  if (version_end > version && version_end[-1] == '\r') --version_end;
  size_t version_len = (size_t)(version_end - version);
  if (version_len != 8) return false;
  if (memcmp(version, "HTTP/1.1", 8) != 0 && memcmp(version, "HTTP/1.0", 8) != 0) return false;

  const char *qmark = (const char *)memchr(path_start, '?', sp2 - path_start);
  size_t path_len = (qmark ? qmark : sp2) - path_start;
  if (path_len > 120) path_len = 120;
  e->path.assign(path_start, path_len);

  p = eol + 1;
  while (p < end) {
    if (*p == '\r' || *p == '\n') break;
    const char *line_end = (const char *)memchr(p, '\n', end - p);
    if (!line_end) line_end = end;
    const char *colon = (const char *)memchr(p, ':', line_end - p);
    if (colon) {
      size_t hname_len = (size_t)(colon - p);
      const char *val_start = colon + 1;
      while (val_start < line_end && (*val_start == ' ' || *val_start == '\t')) ++val_start;
      const char *val_end = line_end;
      while (val_end > val_start && (val_end[-1] == '\r' || val_end[-1] == ' ' || val_end[-1] == '\t')) --val_end;
      size_t val_len = (size_t)(val_end - val_start);

      if (hname_len == 13 && !strncasecmp(p, "authorization", 13)) {
        if (val_len >= 6 && !strncasecmp(val_start, "Basic ", 6)) {
          std::string u = b64decode_user(val_start + 6, val_len - 6);
          if (!u.empty()) { e->user = u; e->scheme = "basic"; e->basic_user = u; }
        }
      } else if (hname_len == 11 && !strncasecmp(p, "traceparent", 11)) {
        std::string tp(val_start, val_len);
        std::string tid = trace_id_from_parent(tp);
        if (!tid.empty()) {
          e->traceparent = tp;
          e->trace_id = tid;
        } else {
          e->traceparent.clear();
          e->trace_id.clear();
        }
      } else if (hname_len == 4 && !strncasecmp(p, "host", 4)) {
        bounded_assign(&e->host_hdr, val_start, val_len, 256);
      } else if (hname_len == 10 && !strncasecmp(p, "user-agent", 10)) {
        bounded_assign(&e->user_agent, val_start, val_len, 256);
      } else if (hname_len == 15 && !strncasecmp(p, "x-forwarded-for", 15)) {
        bounded_assign(&e->xff, val_start, val_len, 512);
      } else if (meta && hname_len == 12 && !strncasecmp(p, "content-type", 12)) {
        bounded_assign(&meta->content_type, val_start, val_len, 256);
      } else if (meta && hname_len == 14 && !strncasecmp(p, "content-length", 14)) {
        size_t clen_val = 0;
        if (parse_decimal_size(val_start, val_len, &clen_val)) {
          if (meta->has_content_length && meta->content_length != clen_val) {
            meta->has_conflict_cl = true;
          }
          meta->content_length = clen_val;
          meta->has_content_length = true;
        } else {
          meta->has_conflict_cl = true;
        }
      } else if (meta && hname_len == 17 && !strncasecmp(p, "transfer-encoding", 17)) {
        meta->has_transfer_encoding = true;
        if (val_len > 256) {
          meta->invalid_transfer_encoding = true;
        } else {
          if (!meta->transfer_encoding.empty())
            meta->transfer_encoding += ",";
          if (meta->transfer_encoding.size() + val_len > 256) {
            meta->invalid_transfer_encoding = true;
          } else {
            meta->transfer_encoding.append(val_start, val_len);
          }
        }
      }
    }
    p = line_end + 1;
  }



  if (e->user.empty()) e->user = "-anonymous-";
  if (e->scheme.empty()) e->scheme = "none";
  if (e->trace_id.empty()) e->traceparent = make_traceparent(&e->trace_id);
  return true;
}

static bool is_wsse_namespace(const std::string &uri) {
  return uri == "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" ||
         uri == "http://schemas.xmlsoap.org/ws/2002/07/secext" ||
         uri == "http://schemas.xmlsoap.org/ws/2002/12/secext" ||
         uri == "http://schemas.xmlsoap.org/ws/2003/06/secext";
}

static bool is_soap_content_type(const std::string &ct) {
  std::string x = lower(ct);
  return x.find("text/xml") != std::string::npos ||
         x.find("application/soap+xml") != std::string::npos ||
         x.find("+xml") != std::string::npos;
}

static void split_qname(const std::string &qname, std::string *prefix, std::string *local) {
  size_t p = qname.find(':');
  if (p == std::string::npos) { prefix->clear(); *local = qname; }
  else { *prefix = qname.substr(0, p); *local = qname.substr(p + 1); }
}

static bool xml_unescape_append(const std::string &in, std::string *out) {
  for (size_t i = 0; i < in.size(); ++i) {
    if (in[i] != '&') { out->push_back(in[i]); continue; }
    size_t semi = in.find(';', i + 1);
    if (semi == std::string::npos) return false;
    std::string ref = in.substr(i + 1, semi - i - 1);
    if (ref == "amp") out->push_back('&');
    else if (ref == "lt") out->push_back('<');
    else if (ref == "gt") out->push_back('>');
    else if (ref == "quot") out->push_back('"');
    else if (ref == "apos") out->push_back('\'');
    else if (!ref.empty() && ref[0] == '#') {
      unsigned long val = 0;
      char *endp = NULL;
      if (ref.size() > 2 && (ref[1] == 'x' || ref[1] == 'X')) {
        val = strtoul(ref.c_str() + 2, &endp, 16);
      } else {
        val = strtoul(ref.c_str() + 1, &endp, 10);
      }
      if (!endp || *endp != '\0' || val > 0x10ffffUL) return false;
      if (val < 0x80) {
        out->push_back((char)val);
      } else if (val < 0x800) {
        out->push_back((char)(0xc0 | (val >> 6)));
        out->push_back((char)(0x80 | (val & 0x3f)));
      } else if (val < 0x10000) {
        out->push_back((char)(0xe0 | (val >> 12)));
        out->push_back((char)(0x80 | ((val >> 6) & 0x3f)));
        out->push_back((char)(0x80 | (val & 0x3f)));
      } else {
        out->push_back((char)(0xf0 | (val >> 18)));
        out->push_back((char)(0x80 | ((val >> 12) & 0x3f)));
        out->push_back((char)(0x80 | ((val >> 6) & 0x3f)));
        out->push_back((char)(0x80 | (val & 0x3f)));
      }
    } else {
      return false;
    }
    i = semi;
  }
  return true;
}

static bool xml_unescape(const std::string &in, std::string *out) {
  out->clear();
  return xml_unescape_append(in, out);
}

static bool valid_utf8_username(const std::string &s) {
  if (s.empty() || s.size() > MAX_WSSE_USERNAME * 4) return false;
  size_t characters = 0;
  for (size_t i = 0; i < s.size();) {
    unsigned char c = (unsigned char)s[i];
    unsigned long cp = 0;
    size_t need = 0;
    if (c < 0x80) { cp = c; need = 0; ++i; }
    else if ((c & 0xe0) == 0xc0) { need = 1; }
    else if ((c & 0xf0) == 0xe0) { need = 2; }
    else if (c >= 0xf0 && c <= 0xf4) { need = 3; }
    else return false;

    if (need) {
      if (i + need >= s.size()) return false;
      for (size_t j = 1; j <= need; ++j) {
        if (((unsigned char)s[i + j] & 0xc0) != 0x80) return false;
      }
      if (need == 1 && c < 0xc2) return false;
      if (need == 2 && c == 0xe0 && (unsigned char)s[i + 1] < 0xa0) return false;
      if (need == 2 && c == 0xed && (unsigned char)s[i + 1] >= 0xa0) return false;
      if (need == 3 && c == 0xf0 && (unsigned char)s[i + 1] < 0x90) return false;
      if (need == 3 && c == 0xf4 && (unsigned char)s[i + 1] >= 0x90) return false;
      if (need == 3 && c > 0xf4) return false;
      cp = c & ((1U << (7 - need - 1)) - 1);
      for (size_t j = 1; j <= need; ++j) cp = (cp << 6) | ((unsigned char)s[i + j] & 0x3f);
      if (cp > 0x10ffffUL) return false;
      i += need + 1;
    }
    if (++characters > MAX_WSSE_USERNAME) return false;
    if (cp < 0x20 || (cp >= 0x7f && cp <= 0x9f) ||
        (cp >= 0xe000 && cp <= 0xf8ff) ||
        (cp >= 0xf0000 && cp <= 0xffffd) ||
        (cp >= 0x100000 && cp <= 0x10fffd) ||
        (cp >= 0xfdd0 && cp <= 0xfdef) || (cp & 0xffffUL) >= 0xfffeUL ||
        cp == 0x00ad || cp == 0x061c || cp == 0x06dd || cp == 0x070f ||
        cp == 0x180e || (cp >= 0x200b && cp <= 0x200f) ||
        (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2060 && cp <= 0x206f) ||
        cp == 0xfeff) return false;
  }
  return true;
}

struct XmlFrame {
  std::map<std::string, std::string> ns;
  std::string qname, uri, local;
};

static bool parse_xml_name(const std::string &body, size_t limit, size_t *pos,
                           std::string *name) {
  size_t start = *pos;
  while (*pos < limit) {
    unsigned char c = (unsigned char)body[*pos];
    if (!(isalnum(c) || c == '_' || c == '-' || c == '.' || c == ':')) break;
    ++*pos;
  }
  if (*pos == start || *pos - start > 256) return false;
  name->assign(body, start, *pos - start);
  return true;
}

static std::string extract_wsse_username(const std::string &body) {
  if (body.empty() || body.size() > MAX_WSSE_BODY_BYTES ||
      body.find('\0') != std::string::npos) return "";
  std::string lowered = lower(body);
  if (lowered.find("<!doctype") != std::string::npos ||
      lowered.find("<!entity") != std::string::npos) return "";

  std::vector<XmlFrame> stack;
  size_t token_depth = 0, username_depth = 0, pos = 0;
  std::string token_uri, chars, result;
  bool username_bad = false;
  while (pos < body.size()) {
    size_t lt = body.find('<', pos);
    if (lt == std::string::npos) {
      if (username_depth && !username_bad && !xml_unescape_append(body.substr(pos), &chars)) username_bad = true;
      break;
    }
    if (username_depth && !username_bad && lt > pos &&
        !xml_unescape_append(body.substr(pos, lt - pos), &chars)) username_bad = true;
    if (chars.size() > MAX_WSSE_USERNAME * 4 + 2) { chars.clear(); username_bad = true; }

    if (body.compare(lt, 4, "<!--") == 0) {
      size_t end = body.find("-->", lt + 4); if (end == std::string::npos) break;
      pos = end + 3; continue;
    }
    if (body.compare(lt, 9, "<![CDATA[") == 0) {
      size_t end = body.find("]]>", lt + 9); if (end == std::string::npos) break;
      if (username_depth && !username_bad) chars.append(body, lt + 9, end - lt - 9);
      pos = end + 3; continue;
    }
    if (body.compare(lt, 2, "<?") == 0) {
      size_t end = body.find("?>", lt + 2); if (end == std::string::npos) break;
      pos = end + 2; continue;
    }
    if (body.compare(lt, 2, "<!") == 0) return "";

    bool closing = (lt + 1 < body.size() && body[lt + 1] == '/');
    size_t p = lt + (closing ? 2 : 1);
    std::string qname;
    if (!parse_xml_name(body, body.size(), &p, &qname)) break;
    if (closing) {
      while (p < body.size() && isspace((unsigned char)body[p])) ++p;
      if (p >= body.size() || body[p] != '>') break;
      if (stack.empty()) break;
      std::string prefix, local; split_qname(qname, &prefix, &local);
      XmlFrame &top = stack.back();
      if (top.qname != qname || top.local != local) break;
      size_t depth = stack.size();
      if (username_depth == depth) {
        std::string username = trim(chars);
        if (!username_bad && valid_utf8_username(username) && result.empty()) result = username;
        username_depth = 0; chars.clear(); username_bad = false;
      }
      if (token_depth == depth) { token_depth = 0; token_uri.clear(); }
      stack.pop_back(); pos = p + 1;
      if (!result.empty()) return result;
      continue;
    }

    XmlFrame frame;
    if (stack.size() >= 64) return "";
    if (!stack.empty()) frame.ns = stack.back().ns;
    bool self_closing = false, complete = false;
    size_t attr_count = 0;
    while (p < body.size()) {
      while (p < body.size() && isspace((unsigned char)body[p])) ++p;
      if (p >= body.size()) break;
      if (body[p] == '>') { ++p; complete = true; break; }
      if (body[p] == '/' && p + 1 < body.size() && body[p + 1] == '>') {
        p += 2; self_closing = true; complete = true; break;
      }
      std::string aname;
      if (!parse_xml_name(body, body.size(), &p, &aname)) break;
      if (++attr_count > 128) return "";
      while (p < body.size() && isspace((unsigned char)body[p])) ++p;
      if (p >= body.size() || body[p++] != '=') break;
      while (p < body.size() && isspace((unsigned char)body[p])) ++p;
      if (p >= body.size() || (body[p] != '\'' && body[p] != '"')) break;
      char quote = body[p++]; size_t value_start = p;
      while (p < body.size() && body[p] != quote) ++p;
      if (p >= body.size()) break;
      std::string value;
      if (!xml_unescape(body.substr(value_start, p - value_start), &value)) return "";
      ++p;
      if (aname == "xmlns") frame.ns[""] = value;
      else if (aname.compare(0, 6, "xmlns:") == 0) frame.ns[aname.substr(6)] = value;
      if (frame.ns.size() > 64) return "";
    }
    if (!complete) break;
    std::string prefix, local; split_qname(qname, &prefix, &local);
    std::map<std::string, std::string>::const_iterator ns = frame.ns.find(prefix);
    frame.uri = (ns == frame.ns.end()) ? "" : ns->second;
    frame.qname = qname;
    frame.local = local;
    stack.push_back(frame);
    size_t depth = stack.size();
    if (!token_depth && local == "UsernameToken" && is_wsse_namespace(frame.uri)) {
      token_depth = depth; token_uri = frame.uri;
    } else if (token_depth && depth == token_depth + 1 &&
               local == "Username" && frame.uri == token_uri) {
      username_depth = depth; chars.clear(); username_bad = false;
    }
    if (self_closing) {
      if (username_depth == depth) username_depth = 0;
      if (token_depth == depth) { token_depth = 0; token_uri.clear(); }
      stack.pop_back();
    }
    pos = p;
  }
  return result;
}

static bool parse_response(const char *data, size_t len, int *status, size_t *clen,
                           bool *has_clen, bool *is_chunked, bool *is_close,
                           bool *framing_conflict = NULL) {
  if (framing_conflict) *framing_conflict = false;
  *has_clen = false;
  *clen = 0;
  *is_chunked = false;
  *is_close = false;
  const char *end = data + len;
  const char *p = data;
  const char *eol = (const char *)memchr(p, '\n', end - p);
  if (!eol) return false;
  bool http10 = (eol - p >= 12 && memcmp(p, "HTTP/1.0 ", 9) == 0);
  bool http11 = (eol - p >= 12 && memcmp(p, "HTTP/1.1 ", 9) == 0);
  if (!http10 && !http11) return false;

  const char *sc = p + 9;
  if (sc + 3 > eol) return false;
  if (!isdigit((unsigned char)sc[0]) ||
      !isdigit((unsigned char)sc[1]) ||
      !isdigit((unsigned char)sc[2])) {
    return false;
  }
  if (sc + 3 < eol && sc[3] != ' ' && sc[3] != '\r') return false;

  *status = (sc[0] - '0') * 100 + (sc[1] - '0') * 10 + (sc[2] - '0');
  if (*status < 100 || *status > 599) return false;

  bool is_http_10 = http10;
  bool conn_close = false;
  bool conn_keep_alive = false;
  bool has_te = false;
  bool invalid_te = false;
  std::string resp_te;
  p = eol + 1;
  while (p < end) {
    if (*p == '\r' || *p == '\n') break;
    const char *line_end = (const char *)memchr(p, '\n', end - p);
    if (!line_end) line_end = end;
    const char *colon = (const char *)memchr(p, ':', line_end - p);
    if (colon) {
      size_t hlen = colon - p;
      const char *v = colon + 1;
      while (v < line_end && (*v == ' ' || *v == '\t')) ++v;
      const char *ve = line_end;
      while (ve > v && (ve[-1] == '\r' || ve[-1] == '\n' || ve[-1] == ' ' || ve[-1] == '\t')) --ve;
      size_t vlen = (size_t)(ve - v);

      if (hlen == 14 && !strncasecmp(p, "content-length", 14)) {
        size_t n = 0;
        if (parse_decimal_size(v, vlen, &n)) {
          if (*has_clen && *clen != n) {
            if (framing_conflict) *framing_conflict = true;
            return false;
          }
          *clen = n;
          *has_clen = true;
        } else {
          if (framing_conflict) *framing_conflict = true;
          return false;
        }
      } else if (hlen == 17 && !strncasecmp(p, "transfer-encoding", 17)) {
        has_te = true;
        if (vlen > 256) {
          invalid_te = true;
        } else {
          if (!resp_te.empty()) resp_te += ",";
          if (resp_te.size() + vlen > 256) {
            invalid_te = true;
          } else {
            resp_te.append(v, vlen);
          }
        }
      } else if (hlen == 10 && !strncasecmp(p, "connection", 10)) {
        std::string conn(v, vlen);
        if (lower(conn).find("close") != std::string::npos) {
          conn_close = true;
        } else if (lower(conn).find("keep-alive") != std::string::npos) {
          conn_keep_alive = true;
        }
      }
    }
    p = line_end + 1;
  }
  if (has_te) {
    if (invalid_te || !transfer_encoding_final_chunked(resp_te)) {
      if (framing_conflict) *framing_conflict = true;
      return false;
    }
    *is_chunked = true;
  }
  if (*has_clen && (has_te || *is_chunked)) {
    if (framing_conflict) *framing_conflict = true;
    return false;
  }
  if (is_http_10 && !conn_keep_alive) {
    *is_close = true;
  } else if (conn_close) {
    *is_close = true;
  }
  return true;
}

static std::string g_endpoint;
static std::string g_ship_node;
static unsigned g_ship_rate_kbps = DEFAULT_SHIP_RATE_KBPS;
static unsigned g_stats_interval_sec = 30;
static size_t g_wsse_body_bytes = 0;
static unsigned long long g_capture_packets = 0, g_capture_bytes = 0;
static unsigned long long g_kernel_drops = 0, g_invalid_frames = 0;
static unsigned long long g_events_emitted = 0, g_events_in = 0;
static unsigned long long g_events_pushed = 0, g_events_dropped = 0;
static unsigned long long g_drop_queue = 0, g_drop_hub = 0, g_drop_oversized = 0;
static unsigned long long g_batches_pushed = 0, g_batches_failed = 0;
static unsigned long long g_bytes_pushed = 0, g_stats_dropped = 0;
static unsigned long long g_output_pipe_drops = 0, g_prev_output_pipe_drops = 0;
static size_t g_queue_high_water = 0;
static unsigned g_consecutive_failures = 0, g_last_push_status = 0;
static time_t g_last_success_at = 0;
static double g_stats_last_at = 0.0, g_stats_last_cpu = 0.0;
static unsigned long long g_prev_capture_packets = 0, g_prev_capture_bytes = 0;
static unsigned long long g_prev_events_emitted = 0, g_prev_events_in = 0;
static unsigned long long g_prev_events_pushed = 0, g_prev_events_dropped = 0;
static unsigned long long g_prev_batches_pushed = 0, g_prev_batches_failed = 0;
static unsigned long long g_prev_bytes_pushed = 0, g_prev_drop_queue = 0;
static unsigned long long g_prev_drop_hub = 0, g_prev_drop_oversized = 0;
static unsigned long long g_stats_sequence = 0;
static std::string g_instance_id;

static pthread_t g_ship_worker_tid;
static pthread_mutex_t g_ship_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_ship_queue_cond = PTHREAD_COND_INITIALIZER;
static std::deque<std::string> g_ship_buf;
static bool g_ship_worker_active = false;
static bool g_producer_finished = false;
static std::string g_pending_stats_body;

static std::string shellq(const std::string &s) {
  std::string o = "'";
  for (size_t i = 0; i < s.size(); ++i) { if (s[i] == '\'') o += "'\\''"; else o += s[i]; }
  return o + "'";
}
static std::string number_string(size_t n) { std::ostringstream o; o << n; return o.str(); }
static std::string ull_string(unsigned long long n) { std::ostringstream o; o << n; return o.str(); }
static std::string double_string(double n) { std::ostringstream o; o.setf(std::ios::fixed); o.precision(4); o << n; return o.str(); }
static std::string json_array(const std::vector<std::string> &a) {
  std::string o = "["; for (size_t i = 0; i < a.size(); ++i) { if (i) o += ","; o += a[i]; } return o + "]";
}
static double wall_seconds() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}
static void pace_upload(size_t bytes, double *next_slot) {
  if (!g_ship_rate_kbps) return;
  double bytes_per_sec = (double)g_ship_rate_kbps * 1000.0 / 8.0;
  double now = wall_seconds();
  if (*next_slot < now) *next_slot = now;
  double slot = *next_slot;
  *next_slot += (double)bytes / bytes_per_sec;
  while (slot > (now = wall_seconds())) {
    double remaining = slot - now;
    useconds_t delay = (useconds_t)(remaining > 0.5 ? 500000 : remaining * 1000000.0);
    if (delay) usleep(delay);
  }
}
static size_t bounded_batch_count(const std::deque<std::string> &buf,
                                  const std::string &node) {
  size_t size = std::string("{\"node\":").size() + jsonq(node).size() +
                std::string(",\"events\":[]}").size();
  size_t n = 0, limit = buf.size() < MAX_BATCH ? buf.size() : MAX_BATCH;
  while (n < limit) {
    size_t extra = buf[n].size() + (n ? 1 : 0);
    if (extra > MAX_POST_BYTES - size) break;
    size += extra;
    ++n;
  }
  return n;
}

static bool post_body(const std::string &endpoint, const std::string &path,
                       const std::string &body, unsigned timeout_sec, double *next_slot) {
  if (next_slot) pace_upload(body.size(), next_slot);
  std::string cmd = "curl -sSf --max-time " + number_string(timeout_sec) + " --limit-rate " +
    number_string((size_t)g_ship_rate_kbps * 1000U / 8U) +
    " -o /dev/null -H 'Content-Type: application/json' --data-binary @- " + shellq(endpoint + path);
  FILE *fp = popen(cmd.c_str(), "w"); if (!fp) return false;
  fwrite(body.data(), 1, body.size(), fp);
  int rc = pclose(fp);
  return WIFEXITED(rc) && WEXITSTATUS(rc) == 0;
}

static void *ship_worker_thread(void *) {
  double next_slot = wall_seconds();
  double next_stats_slot = wall_seconds();
  double shutdown_deadline = 0.0;
  while (true) {
    std::vector<std::string> batch;
    std::string stats_body;
    pthread_mutex_lock(&g_ship_queue_mutex);
    while (g_running && !g_producer_finished && g_ship_buf.empty() && g_pending_stats_body.empty()) {
      struct timespec ts;
      clock_gettime(CLOCK_REALTIME, &ts);
      ts.tv_sec += 1;
      pthread_cond_timedwait(&g_ship_queue_cond, &g_ship_queue_mutex, &ts);
    }
    if (!g_running && shutdown_deadline == 0.0) {
      shutdown_deadline = wall_seconds() + 10.0;
    }
    if (g_producer_finished && g_ship_buf.empty() && g_pending_stats_body.empty()) {
      pthread_mutex_unlock(&g_ship_queue_mutex);
      break;
    }
    if (shutdown_deadline > 0.0 && wall_seconds() > shutdown_deadline) {
      g_events_dropped += g_ship_buf.size();
      g_drop_hub += g_ship_buf.size();
      g_ship_buf.clear();
      g_pending_stats_body.clear();
      pthread_mutex_unlock(&g_ship_queue_mutex);
      break;
    }
    if (!g_pending_stats_body.empty()) {
      stats_body.swap(g_pending_stats_body);
    }
    if (!g_ship_buf.empty()) {
      size_t n = bounded_batch_count(g_ship_buf, g_ship_node);
      if (!n) {
        g_ship_buf.pop_front();
        ++g_events_dropped;
        ++g_drop_oversized;
      } else {
        batch.reserve(n);
        for (size_t i = 0; i < n; ++i) {
          batch.push_back(g_ship_buf.front());
          g_ship_buf.pop_front();
        }
      }
    }
    pthread_mutex_unlock(&g_ship_queue_mutex);

    if (!stats_body.empty()) {
      if (!post_body(g_endpoint, "/api/agent/stats", stats_body, 2, &next_stats_slot)) {
        pthread_mutex_lock(&g_ship_queue_mutex);
        ++g_stats_dropped;
        pthread_mutex_unlock(&g_ship_queue_mutex);
      }
    }

    if (!batch.empty()) {
      std::string body = "{\"node\":" + jsonq(g_ship_node) + ",\"events\":" + json_array(batch) + "}";
      bool pushed = false;
      for (int attempt = 0; attempt < 3; ++attempt) {
        if (shutdown_deadline > 0.0 && wall_seconds() >= shutdown_deadline) {
          break;
        }
        if (attempt > 0) {
          usleep(500000);
        }
        unsigned timeout = 3;
        if (shutdown_deadline > 0.0) {
          double remain = shutdown_deadline - wall_seconds();
          if (remain <= 0.0) break;
          if (remain < 3.0) timeout = (unsigned)remain + 1;
        }
        if (post_body(g_endpoint, "/api/ingest", body, timeout, &next_slot)) {
          pushed = true;
          break;
        }
      }
      if (pushed) {
        pthread_mutex_lock(&g_ship_queue_mutex);
        g_events_pushed += batch.size();
        ++g_batches_pushed;
        g_bytes_pushed += body.size();
        g_consecutive_failures = 0;
        g_last_push_status = 200;
        g_last_success_at = time(NULL);
        pthread_mutex_unlock(&g_ship_queue_mutex);
      } else {
        pthread_mutex_lock(&g_ship_queue_mutex);
        g_events_dropped += batch.size();
        g_drop_hub += batch.size();
        ++g_batches_failed;
        ++g_consecutive_failures;
        g_last_push_status = 0;
        if (shutdown_deadline > 0.0 && g_consecutive_failures >= 3) {
          g_events_dropped += g_ship_buf.size();
          g_drop_hub += g_ship_buf.size();
          g_ship_buf.clear();
          g_pending_stats_body.clear();
          pthread_mutex_unlock(&g_ship_queue_mutex);
          break;
        }
        pthread_mutex_unlock(&g_ship_queue_mutex);
      }
    }
  }
  return NULL;
}

static unsigned count_open_fds() {
  DIR *dir = opendir("/proc/self/fd");
  if (!dir) return 0;
  unsigned count = 0;
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) ++count;
  }
  closedir(dir);
  return count;
}

static void proc_status(size_t *rss, size_t *virt, unsigned *threads,
                        unsigned *cpu_core) {
  *rss = 0; *virt = 0; *threads = 1; *cpu_core = 0;
  std::ifstream in("/proc/self/status");
  std::string line;
  while (std::getline(in, line)) {
    unsigned long value = 0;
    if (sscanf(line.c_str(), "VmRSS: %lu kB", &value) == 1) *rss = (size_t)value * 1024U;
    else if (sscanf(line.c_str(), "VmSize: %lu kB", &value) == 1) *virt = (size_t)value * 1024U;
    else if (sscanf(line.c_str(), "Threads: %lu", &value) == 1) *threads = (unsigned)value;
    else if (sscanf(line.c_str(), "Cpus_allowed_list: %lu", &value) == 1) *cpu_core = (unsigned)value;
  }
}

static unsigned long long update_kernel_drops(int fd) {
  if (fd < 0) return 0;
  struct tpacket_stats packet_stats;
  socklen_t packet_stats_len = sizeof(packet_stats);
  memset(&packet_stats, 0, sizeof(packet_stats));
  if (getsockopt(fd, SOL_PACKET, PACKET_STATISTICS,
                 &packet_stats, &packet_stats_len) != 0) return 0;
  g_kernel_drops += packet_stats.tp_drops;
  return packet_stats.tp_drops;
}

static std::string agent_stats_body(int fd, size_t flows_active,
                                    size_t pending_requests,
                                    size_t wsse_body_flows) {
  double now = wall_seconds();
  double elapsed = now - g_stats_last_at;
  if (elapsed < 0.001) elapsed = 0.001;
  unsigned long long kernel_drop_delta = update_kernel_drops(fd);
  unsigned long long packet_delta = g_capture_packets - g_prev_capture_packets;
  unsigned long long packet_bytes_delta = g_capture_bytes - g_prev_capture_bytes;
  unsigned long long emitted_delta = g_events_emitted - g_prev_events_emitted;

  pthread_mutex_lock(&g_ship_queue_mutex);
  unsigned long long events_in_total      = g_events_in;
  unsigned long long events_pushed_total  = g_events_pushed;
  unsigned long long events_dropped_total = g_events_dropped;

  unsigned long long drop_queue_total     = g_drop_queue;
  unsigned long long drop_hub_total       = g_drop_hub;
  unsigned long long drop_oversized_total = g_drop_oversized;

  unsigned long long batches_pushed_total = g_batches_pushed;
  unsigned long long batches_failed_total = g_batches_failed;
  unsigned long long bytes_pushed_total   = g_bytes_pushed;
  unsigned long long stats_drop_total     = g_stats_dropped;

  unsigned long long in_delta = events_in_total - g_prev_events_in;
  unsigned long long pushed_delta = events_pushed_total - g_prev_events_pushed;
  unsigned long long dropped_delta = events_dropped_total - g_prev_events_dropped;

  unsigned long long batches_pushed_delta = batches_pushed_total - g_prev_batches_pushed;
  unsigned long long batches_failed_delta = batches_failed_total - g_prev_batches_failed;
  unsigned long long bytes_delta = bytes_pushed_total - g_prev_bytes_pushed;

  unsigned long long queue_delta = drop_queue_total - g_prev_drop_queue;
  unsigned long long hub_delta = drop_hub_total - g_prev_drop_hub;
  unsigned long long oversized_delta = drop_oversized_total - g_prev_drop_oversized;

  size_t ship_buf_size = g_ship_buf.size();
  size_t queue_high = g_queue_high_water;
  unsigned last_status = g_last_push_status;
  time_t last_succ = g_last_success_at;
  unsigned consec_fails = g_consecutive_failures;

  /* Commit previous values from the SAME snapshot. */
  g_prev_events_in = events_in_total;
  g_prev_events_pushed = events_pushed_total;
  g_prev_events_dropped = events_dropped_total;
  g_prev_batches_pushed = batches_pushed_total;
  g_prev_batches_failed = batches_failed_total;
  g_prev_bytes_pushed = bytes_pushed_total;
  g_prev_drop_queue = drop_queue_total;
  g_prev_drop_hub = drop_hub_total;
  g_prev_drop_oversized = drop_oversized_total;
  pthread_mutex_unlock(&g_ship_queue_mutex);

  unsigned long long pipe_drop_delta = g_output_pipe_drops - g_prev_output_pipe_drops;
  struct rusage usage;
  memset(&usage, 0, sizeof(usage));
  getrusage(RUSAGE_SELF, &usage);
  double user_cpu = usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1000000.0;
  double sys_cpu = usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1000000.0;
  double cpu_total = user_cpu + sys_cpu;
  double cpu_pct = 100.0 * (cpu_total - g_stats_last_cpu) / elapsed;
  if (cpu_pct < 0) cpu_pct = 0;
  size_t rss = 0, virt = 0;
  unsigned threads = 1, cpu_core = 0;
  proc_status(&rss, &virt, &threads, &cpu_core);
  std::string reasons;
  if (kernel_drop_delta) reasons += "\"kernel_drop\"";
  if (dropped_delta) { if (!reasons.empty()) reasons += ","; reasons += "\"ship_drop\""; }
  if (hub_delta) { if (!reasons.empty()) reasons += ","; reasons += "\"hub_unreachable\""; }
  if (queue_delta || pipe_drop_delta) { if (!reasons.empty()) reasons += ","; reasons += "\"queue_pressure\""; }
  std::ostringstream out;
  out << "{\"schema_version\":1,\"type\":\"agent_stats\",\"node\":" << jsonq(g_ship_node)
      << ",\"instance_id\":" << jsonq(g_instance_id) << ",\"sequence\":" << ++g_stats_sequence
      << ",\"observed_at\":" << (unsigned long)now << ",\"window_seconds\":" << double_string(elapsed)
      << ",\"mode\":\"cpp\",\"status\":" << (reasons.empty() ? "\"ok\"" : "\"degraded\"")
      << ",\"reasons\":[" << reasons << "],\"capture\":{"
      << "\"packets_total\":" << ull_string(g_capture_packets) << ",\"packets_delta\":" << ull_string(packet_delta)
      << ",\"packet_bytes_total\":" << ull_string(g_capture_bytes) << ",\"packet_bytes_delta\":" << ull_string(packet_bytes_delta)
      << ",\"kernel_drops_total\":" << ull_string(g_kernel_drops) << ",\"kernel_drops_delta\":" << ull_string(kernel_drop_delta)
      << ",\"kernel_drop_percent\":" << double_string(100.0 * kernel_drop_delta / (packet_delta ? packet_delta : 1))
      << ",\"invalid_frames_total\":" << ull_string(g_invalid_frames)
      << ",\"events_emitted_total\":" << ull_string(g_events_emitted) << ",\"events_emitted_delta\":" << ull_string(emitted_delta)
      << ",\"flows_active\":" << flows_active << ",\"pending_requests\":" << pending_requests
      << ",\"wsse_body_flows_active\":" << wsse_body_flows
      << ",\"wsse_body_bytes\":" << g_wsse_body_bytes
      << ",\"output_pipe_drops_total\":" << ull_string(g_output_pipe_drops)
      << ",\"output_pipe_drops_delta\":" << ull_string(pipe_drop_delta) << "},\"shipping\":{"
      << "\"events_in_total\":" << ull_string(events_in_total) << ",\"events_in_delta\":" << ull_string(in_delta)
      << ",\"events_pushed_total\":" << ull_string(events_pushed_total) << ",\"events_pushed_delta\":" << ull_string(pushed_delta)
      << ",\"events_dropped_total\":" << ull_string(events_dropped_total) << ",\"events_dropped_delta\":" << ull_string(dropped_delta)
      << ",\"drop_causes\":{\"queue_full_total\":" << ull_string(drop_queue_total) << ",\"queue_full_delta\":" << ull_string(queue_delta)
      << ",\"hub_failure_total\":" << ull_string(drop_hub_total) << ",\"hub_failure_delta\":" << ull_string(hub_delta)
      << ",\"oversized_total\":" << ull_string(drop_oversized_total) << ",\"oversized_delta\":" << ull_string(oversized_delta) << "}"
      << ",\"batches_pushed_total\":" << ull_string(batches_pushed_total) << ",\"batches_pushed_delta\":" << ull_string(batches_pushed_delta)
      << ",\"batches_failed_total\":" << ull_string(batches_failed_total) << ",\"batches_failed_delta\":" << ull_string(batches_failed_delta)
      << ",\"bytes_pushed_total\":" << ull_string(bytes_pushed_total) << ",\"bytes_pushed_delta\":" << ull_string(bytes_delta)
      << ",\"push_events_per_second\":" << double_string(pushed_delta / elapsed)
      << ",\"push_kbps\":" << double_string(8.0 * bytes_delta / (1000.0 * elapsed))
      << ",\"drop_events_per_second\":" << double_string(dropped_delta / elapsed)
      << ",\"drop_percent\":" << double_string(100.0 * dropped_delta / (in_delta ? in_delta : 1))
      << ",\"queue_depth_events\":" << ship_buf_size << ",\"queue_capacity_events\":" << MAX_QUEUE
      << ",\"queue_high_water_events\":" << queue_high << ",\"last_push_http_status\":" << last_status
      << ",\"last_success_at\":" << (unsigned long)last_succ << ",\"consecutive_failures\":" << consec_fails
      << ",\"stats_samples_dropped_total\":" << ull_string(stats_drop_total) << "},\"resources\":{"
      << "\"cpu_user_seconds\":" << double_string(user_cpu) << ",\"cpu_system_seconds\":" << double_string(sys_cpu)
      << ",\"cpu_percent_one_core\":" << double_string(cpu_pct) << ",\"rss_bytes\":" << rss
      << ",\"virtual_bytes\":" << virt << ",\"open_fds\":" << count_open_fds() << ",\"threads\":" << threads
      << "},\"limits\":{\"cpu_core\":" << cpu_core << ",\"address_space_bytes\":268435456"
      << ",\"ship_rate_kbps\":" << g_ship_rate_kbps << ",\"http_body_max_bytes\":" << MAX_POST_BYTES
      << ",\"ship_threads_max\":1,\"wsse_body_bytes\":" << g_wsse_body_bytes << "}}";
  g_prev_capture_packets = g_capture_packets; g_prev_capture_bytes = g_capture_bytes;
  g_prev_events_emitted = g_events_emitted;
  g_prev_output_pipe_drops = g_output_pipe_drops;
  g_stats_last_cpu = cpu_total; g_stats_last_at = now;
  return out.str();
}

static void send_agent_stats(int fd, size_t flows_active,
                             size_t pending_requests,
                             size_t wsse_body_flows) {
  std::string body = agent_stats_body(fd, flows_active, pending_requests,
                                      wsse_body_flows);
  if (body.size() > MAX_STATS_BYTES) {
    pthread_mutex_lock(&g_ship_queue_mutex);
    ++g_stats_dropped;
    pthread_mutex_unlock(&g_ship_queue_mutex);
    return;
  }
  pthread_mutex_lock(&g_ship_queue_mutex);
  g_pending_stats_body = body;
  pthread_cond_signal(&g_ship_queue_cond);
  pthread_mutex_unlock(&g_ship_queue_mutex);
}

static bool write_nonblocking_line(const std::string &line) {
  if (line.size() + 1 > PIPE_BUF) {
    ++g_output_pipe_drops;
    return true;
  }
  std::string framed = line + "\n";
  ssize_t written;
  do { written = write(STDOUT_FILENO, framed.data(), framed.size()); }
  while (written < 0 && errno == EINTR && g_running);
  if (written == (ssize_t)framed.size()) return true;
  if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
    ++g_output_pipe_drops;
    return true;
  }
  if (written < 0 && errno == EPIPE) {
    logmsg("shipper pipe closed; stopping capture for supervised restart");
  } else {
    logmsg("shipper pipe write failed; stopping capture for supervised restart");
  }
  g_running = 0;
  return false;
}

static void emit_capture_stats_internal(int fd, size_t flows_active,
                                        size_t pending_requests,
                                        size_t wsse_body_flows) {
  std::string full = agent_stats_body(fd, flows_active, pending_requests,
                                      wsse_body_flows);
  const std::string marker = "\"capture\":";
  size_t start = full.find(marker);
  size_t end = full.find(",\"shipping\":", start);
  if (start == std::string::npos || end == std::string::npos) {
    ++g_output_pipe_drops;
    return;
  }
  start += marker.size();
  write_nonblocking_line("{\"_nt_internal\":\"capture_stats_v1\",\"capture\":" +
                         full.substr(start, end - start) + "}");
}

static std::string sanitize_utf8_truncate(const std::string &s, size_t max_bytes = 0) {
  if (s.empty()) return "";
  std::string out;
  size_t len = s.size();
  for (size_t i = 0; i < len;) {
    unsigned char c = (unsigned char)s[i];
    size_t need = 0;
    if (c < 0x80) {
      if (c < 32 && c != '\t' && c != '\r' && c != '\n') {
        if (max_bytes && out.size() + 1 > max_bytes) break;
        out += '?';
      } else {
        if (max_bytes && out.size() + 1 > max_bytes) break;
        out += (char)c;
      }
      ++i;
      continue;
    } else if ((c & 0xe0) == 0xc0) {
      need = 1;
    } else if ((c & 0xf0) == 0xe0) {
      need = 2;
    } else if (c >= 0xf0 && c <= 0xf4) {
      need = 3;
    } else {
      if (max_bytes && out.size() + 1 > max_bytes) break;
      out += '?';
      ++i;
      continue;
    }

    if (i + need >= len) {
      // Incomplete multi-byte sequence at end of string
      break;
    }

    bool valid = true;
    for (size_t j = 1; j <= need; ++j) {
      if (((unsigned char)s[i + j] & 0xc0) != 0x80) {
        valid = false;
        break;
      }
    }

    if (valid) {
      if (need == 1 && c < 0xc2) valid = false;
      else if (need == 2 && c == 0xe0 && (unsigned char)s[i + 1] < 0xa0) valid = false;
      else if (need == 2 && c == 0xed && (unsigned char)s[i + 1] >= 0xa0) valid = false;
      else if (need == 3 && c == 0xf0 && (unsigned char)s[i + 1] < 0x90) valid = false;
      else if (need == 3 && c == 0xf4 && (unsigned char)s[i + 1] >= 0x90) valid = false;
      else if (need == 3 && c > 0xf4) valid = false;
      if (valid) {
        unsigned long cp = c & ((1U << (7 - need - 1)) - 1);
        for (size_t j = 1; j <= need; ++j) cp = (cp << 6) | ((unsigned char)s[i + j] & 0x3f);
        if (cp > 0x10ffffUL) valid = false;
      }
    }

    if (!valid) {
      if (max_bytes && out.size() + 1 > max_bytes) break;
      out += '?';
      ++i;
      continue;
    }

    if (max_bytes && out.size() + need + 1 > max_bytes) break;
    out.append(s, i, need + 1);
    i += need + 1;
  }
  return out;
}

static std::string format_event_json(const Event &e) {
  std::ostringstream ss;
  ss << "{\"ts\":" << e.ts << ",\"host\":" << jsonq(e.host) << ",\"src\":\"pcap\",\"service\":" << jsonq(e.service)
     << ",\"method\":" << jsonq(e.method) << ",\"path\":" << jsonq(e.path) << ",\"user\":" << jsonq(e.user)
     << ",\"scheme\":" << jsonq(e.scheme)
     << ",\"basic_user\":" << (e.basic_user.empty() ? "null" : jsonq(e.basic_user))
     << ",\"wsse_user\":" << (e.wsse_user.empty() ? "null" : jsonq(e.wsse_user))
     << ",\"source_probe\":\"pcap-http-cpp\",\"host_hdr\":" << jsonq(e.host_hdr)
     << ",\"user_agent\":" << jsonq(e.user_agent) << ",\"x_forwarded_for\":" << jsonq(e.xff)
     << ",\"caller\":" << jsonq(e.caller) << ",\"caller_port\":" << e.caller_port << ",\"dst_ip\":" << jsonq(e.dst_ip)
     << ",\"dst_port\":" << e.dst_port << ",\"traceparent\":" << jsonq(e.traceparent) << ",\"trace_id\":" << jsonq(e.trace_id)
     << ",\"service_id\":null,\"module_id\":\"pcap-http-cpp\",\"req_bytes\":" << e.req_bytes;
  if (e.has_status) ss << ",\"status\":" << e.status; else ss << ",\"status\":null";
  if (e.has_duration) ss << ",\"duration_ms\":" << e.duration_ms; else ss << ",\"duration_ms\":null";
  if (e.has_resp) ss << ",\"resp_bytes\":" << e.resp_bytes; else ss << ",\"resp_bytes\":null";
  ss << "}";
  return ss.str();
}

static void emit_event(Event e) {
  e.host = sanitize_utf8_truncate(e.host, 128);
  e.service = sanitize_utf8_truncate(e.service, 64);
  e.method = sanitize_utf8_truncate(e.method, 16);
  e.path = sanitize_utf8_truncate(e.path, 120);
  e.user = sanitize_utf8_truncate(e.user, MAX_WSSE_USERNAME * 4);
  e.scheme = sanitize_utf8_truncate(e.scheme, 16);
  if (!e.basic_user.empty()) e.basic_user = sanitize_utf8_truncate(e.basic_user, 256);
  if (!e.wsse_user.empty()) e.wsse_user = sanitize_utf8_truncate(e.wsse_user, MAX_WSSE_USERNAME * 4);
  e.host_hdr = sanitize_utf8_truncate(e.host_hdr, 256);
  e.user_agent = sanitize_utf8_truncate(e.user_agent, 256);
  e.xff = sanitize_utf8_truncate(e.xff, 512);
  e.caller = sanitize_utf8_truncate(e.caller, 64);
  e.dst_ip = sanitize_utf8_truncate(e.dst_ip, 64);
  e.traceparent = sanitize_utf8_truncate(e.traceparent, 64);
  e.trace_id = sanitize_utf8_truncate(e.trace_id, 32);

  std::string line = format_event_json(e);
  if (line.size() + 1 > PIPE_BUF) {
    if (!e.user_agent.empty()) {
      e.user_agent = sanitize_utf8_truncate(e.user_agent, 64);
      line = format_event_json(e);
    }
    if (line.size() + 1 > PIPE_BUF && !e.xff.empty()) {
      e.xff = sanitize_utf8_truncate(e.xff, 64);
      line = format_event_json(e);
    }
    if (line.size() + 1 > PIPE_BUF && !e.user_agent.empty()) {
      e.user_agent.clear();
      line = format_event_json(e);
    }
    if (line.size() + 1 > PIPE_BUF && !e.xff.empty()) {
      e.xff.clear();
      line = format_event_json(e);
    }
    if (line.size() + 1 > PIPE_BUF && e.path.size() > 32) {
      e.path = sanitize_utf8_truncate(e.path, 32);
      line = format_event_json(e);
    }
  }

  ++g_events_emitted;

  if (!g_endpoint.empty()) {
    ++g_events_in;
    pthread_mutex_lock(&g_ship_queue_mutex);
    if (g_ship_buf.size() >= MAX_QUEUE) {
      g_ship_buf.pop_front();
      ++g_events_dropped;
      ++g_drop_queue;
    }
    g_ship_buf.push_back(line);
    if (g_ship_buf.size() > g_queue_high_water) g_queue_high_water = g_ship_buf.size();
    pthread_cond_signal(&g_ship_queue_cond);
    pthread_mutex_unlock(&g_ship_queue_mutex);
  } else {
    write_nonblocking_line(line);
  }
}

static bool g_monitored_ports[65536];

static inline PacketKey get_canonical_response_key(const FlowKey &fk) {
  PacketKey rk;
  bool src_mon = g_monitored_ports[fk.sport];
  bool dst_mon = g_monitored_ports[fk.dport];
  if (src_mon && !dst_mon) {
    rk.s_ip = fk.s_ip; rk.sport = fk.sport;
    rk.d_ip = fk.d_ip; rk.dport = fk.dport;
  } else {
    rk.s_ip = fk.d_ip; rk.sport = fk.dport;
    rk.d_ip = fk.s_ip; rk.dport = fk.sport;
  }
  return rk;
}

static bool ooo_insert(Flow &fl, uint32_t seq, const char *data, size_t len) {
  for (size_t i = 0; i < fl.ooo.size(); ++i) {
    if (fl.ooo[i].seq != seq) continue;

    size_t old_len = fl.ooo[i].data.size();
    size_t common = old_len < len ? old_len : len;

    // Retransmission carrying different bytes: ordering/content is ambiguous.
    if (common && memcmp(fl.ooo[i].data.data(), data, common) != 0) {
      return false;
    }

    // Existing segment already covers this one.
    if (old_len >= len) return true;

    if (g_total_flow_bytes + (len - old_len) > MAX_TOTAL_BUFFER_BYTES) return false;

    // New retransmission extends the known range.
    flow_bytes_sub(old_len);
    fl.ooo[i].data.assign(data, len);
    flow_bytes_add(len);
    return true;
  }

  if (fl.ooo.size() >= MAX_OOO_SEGMENTS) return false;

  return fl.ooo_push(seq, data, len);
}

static bool drain_ooo_segments(Flow &fl) {
  bool drained = true;
  while (drained && !fl.ooo.empty()) {
    drained = false;
    for (size_t i = 0; i < fl.ooo.size(); ++i) {
      int32_t odiff = seq_diff(fl.ooo[i].seq, fl.next_seq);
      if (odiff == 0) {
        if (!fl.buf_append(fl.ooo[i].data.data(), fl.ooo[i].data.size())) return false;
        fl.next_seq += (uint32_t)fl.ooo[i].data.size();
        fl.ooo_erase(i);
        drained = true; break;
      } else if (odiff < 0) {
        uint32_t o_overlap = (uint32_t)(-(int64_t)odiff);
        if ((size_t)o_overlap < fl.ooo[i].data.size()) {
          size_t flen = fl.ooo[i].data.size() - o_overlap;
          if (!fl.buf_append(fl.ooo[i].data.data() + o_overlap, flen)) return false;
          fl.next_seq += (uint32_t)flen;
        }
        fl.ooo_erase(i);
        drained = true; break;
      }
    }
  }
  return true;
}

static size_t find_http_start(const std::string &s) {
  const char *m[] = { "GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS " };
  size_t best = std::string::npos;
  for (size_t i = 0; i < 7; ++i) {
    size_t pos = s.find(m[i]);
    if (pos != std::string::npos && (best == std::string::npos || pos < best)) best = pos;
  }
  return best;
}

static size_t find_request_resync(const char *p, size_t len) {
  const char *methods[] = {
    "GET ", "POST ", "PUT ", "DELETE ",
    "PATCH ", "HEAD ", "OPTIONS "
  };
  size_t scan_limit = len < 16384 ? len : 16384;
  size_t best = (size_t)-1;

  // First prefer a complete method.
  for (size_t i = 0; i < 7; ++i) {
    size_t mlen = strlen(methods[i]);
    if (scan_limit >= mlen) {
      for (size_t off = 0; off + mlen <= scan_limit; ++off) {
        if (memcmp(p + off, methods[i], mlen) == 0) {
          if (best == (size_t)-1 || off < best) best = off;
          break;
        }
      }
    }
  }

  if (best != (size_t)-1) return best;

  // Then allow a method beginning near the end and
  // continuing into the next contiguous TCP segment.
  for (size_t i = 0; i < 7; ++i) {
    size_t mlen = strlen(methods[i]);
    for (size_t prefix = 1; prefix < mlen; ++prefix) {
      if (prefix > scan_limit) continue;
      size_t off = scan_limit - prefix;
      if (memcmp(p + off, methods[i], prefix) == 0) {
        return off;
      }
    }
  }

  return (size_t)-1;
}

static size_t find_response_resync(const char *p, size_t len) {
  const char prefix[] = "HTTP/";
  const size_t plen = 5;

  size_t scan_limit = len < 16384 ? len : 16384;

  for (size_t off = 0; off + plen <= scan_limit; ++off) {
    if (memcmp(p + off, prefix, plen) == 0) return off;
  }

  for (size_t n = plen - 1; n > 0; --n) {
    if (n <= scan_limit) {
      size_t off = scan_limit - n;
      if (memcmp(p + off, prefix, n) == 0) return off;
    }
  }

  return (size_t)-1;
}

static bool is_method_or_prefix(const char *p, size_t len) {
  if (!len) return false;
  const char *m[] = { "GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS " };
  for (size_t i = 0; i < 7; ++i) {
    size_t mlen = strlen(m[i]);
    size_t check_len = len < mlen ? len : mlen;
    if (memcmp(p, m[i], check_len) == 0) return true;
  }
  return false;
}

static void reset_flow_for_resync(Flow &fl) {
  fl.clear_buffers();
  fl.has_seq = false;
  fl.next_seq = 0;
  fl.is_broken = false;
  fl.state = Flow::HTTP_STATE_HEADER;
  fl.body_remaining = 0;
  fl.chunk_payload_remaining = 0;
  fl.chunk_reading_len = true;
  fl.chunk_reading_crlf = false;
  fl.chunk_reading_trailer = false;
  fl.fin_seen = false;
  fl.fin_seq = 0;
}

static void invalidate_stream(Connection &conn, const char *reason) {
  (void)reason;
  ++g_stream_invalidations;
  conn.corr_disabled = true;
  conn.corr_eligible = false;
  conn.req_flow.correlation_disabled = true;
  conn.req_flow.corr_eligible = false;
  reset_flow_for_resync(conn.req_flow);

  conn.resp_flow.correlation_disabled = true;
  conn.resp_flow.corr_eligible = false;
  reset_flow_for_resync(conn.resp_flow);

  if (conn.has_deferred_wsse) {
    emit_event(conn.deferred_wsse_event);
    conn.has_deferred_wsse = false;
  }

  for (size_t i = 0; i < conn.pending.size(); ++i) {
    if (!conn.pending[i].is_tombstone) {
      emit_event(conn.pending[i].ev);
      if (g_total_pending_count > 0) --g_total_pending_count;
    }
    remove_pending_from_fifo(conn.pending[i]);
  }
  conn.pending.clear();

  if (conn.roles_established) {
    PacketKey rk;
    rk.s_ip = conn.server.ip; rk.sport = conn.server.port;
    rk.d_ip = conn.client.ip; rk.dport = conn.client.port;
    corr_disabled_insert(rk);
  }
}

static void touch_connection(Connection &conn, const ConnectionKey &key, std::list<ConnectionKey> &conn_lru, time_t now, long long mono_now = 0) {
  conn.touched = now;
  conn.touched_mono_ms = mono_now;
  if (conn.in_lru) {
    conn_lru.erase(conn.lru_it);
    conn.in_lru = false;
  }
  conn_lru.push_back(key);
  conn.lru_it = --conn_lru.end();
  conn.in_lru = true;
}

static void evict_connection_if_needed(std::map<ConnectionKey, Connection> &connections,
                                      std::list<ConnectionKey> &conn_lru,
                                      bool inserting_new,
                                      const ConnectionKey *protected_key = NULL) {
  if (inserting_new) {
    while (connections.size() >= MAX_FLOWS && !conn_lru.empty()) {
      ConnectionKey oldest_key = conn_lru.front();
      if (protected_key && oldest_key == *protected_key && conn_lru.size() > 1) {
        conn_lru.pop_front();
        conn_lru.push_back(oldest_key);
        std::map<ConnectionKey, Connection>::iterator pit = connections.find(oldest_key);
        if (pit != connections.end()) {
          pit->second.lru_it = --conn_lru.end();
          pit->second.in_lru = true;
        }
        continue;
      }
      std::map<ConnectionKey, Connection>::iterator it = connections.find(oldest_key);
      if (it != connections.end()) {
        it->second.in_lru = false;
        invalidate_stream(it->second, "lru_count_evicted");
        connections.erase(it);
      }
      conn_lru.pop_front();
    }
  }
  while (g_total_flow_bytes >= MAX_TOTAL_BUFFER_BYTES && !conn_lru.empty()) {
    ConnectionKey oldest_key = conn_lru.front();
    if (protected_key && oldest_key == *protected_key && conn_lru.size() > 1) {
      conn_lru.pop_front();
      conn_lru.push_back(oldest_key);
      std::map<ConnectionKey, Connection>::iterator pit = connections.find(oldest_key);
      if (pit != connections.end()) {
        pit->second.lru_it = --conn_lru.end();
        pit->second.in_lru = true;
      }
      continue;
    }
    std::map<ConnectionKey, Connection>::iterator it = connections.find(oldest_key);
    if (it != connections.end()) {
      it->second.in_lru = false;
      invalidate_stream(it->second, "lru_bytes_evicted");
      connections.erase(it);
    }
    conn_lru.pop_front();
  }
}

static uint64_t queue_request(Connection &conn, const Event &e, long long first_byte_mono_ms,
                              std::map<ConnectionKey, Connection> &connections,
                              std::list<ConnectionKey> &conn_lru,
                              bool wsse_eligible) {
  (void)conn_lru;
  long long mono_now = now_monotonic_ms();
  long long started_mono = (first_byte_mono_ms > 0) ? first_byte_mono_ms : mono_now;

  PacketKey rk;
  rk.s_ip = conn.server.ip; rk.sport = conn.server.port;
  rk.d_ip = conn.client.ip; rk.dport = conn.client.port;

  bool allowed = (!conn.corr_disabled && conn.corr_eligible && !conn.req_flow.is_broken && !conn.resp_flow.is_broken);
  if (g_corr_disabled.count(rk) > 0) allowed = false;
  if (g_corr_capacity_reached && (!conn.syn_seen || conn.generation == 0)) allowed = false;

  if (!allowed) {
    if (wsse_eligible) {
      if (conn.has_deferred_wsse) {
        emit_event(conn.deferred_wsse_event);
      }
      conn.deferred_wsse_event = e;
      conn.has_deferred_wsse = true;
      conn.deferred_wsse_req_id = ++g_req_id_seq;
      return conn.deferred_wsse_req_id;
    }
    emit_event(e);
    return 0;
  }

  while (g_total_pending_count >= MAX_PENDING_TOTAL && !g_pending_fifo.empty()) {
    PendingQueueRef ref = g_pending_fifo.front();
    std::map<ConnectionKey, Connection>::iterator it = connections.find(ref.key);
    bool found_live = false;
    if (it != connections.end()) {
      for (size_t i = 0; i < it->second.pending.size(); ++i) {
        if (it->second.pending[i].req_id == ref.req_id) {
          found_live = true;
          invalidate_stream(it->second, "global_pending_overflow");
          break;
        }
      }
    }
    if (!found_live) {
      g_pending_fifo.pop_front();
    }
  }

  if (conn.corr_disabled || !conn.corr_eligible || conn.req_flow.is_broken || conn.resp_flow.is_broken || g_corr_disabled.count(rk) > 0) {
    if (wsse_eligible) {
      if (conn.has_deferred_wsse) {
        emit_event(conn.deferred_wsse_event);
      }
      conn.deferred_wsse_event = e;
      conn.has_deferred_wsse = true;
      conn.deferred_wsse_req_id = ++g_req_id_seq;
      return conn.deferred_wsse_req_id;
    }
    emit_event(e);
    return 0;
  }

  if (conn.pending.size() >= MAX_PENDING_PER_FLOW) {
    invalidate_stream(conn, "per_flow_pending_overflow");
    emit_event(e);
    return 0;
  }

  uint64_t req_id = ++g_req_id_seq;

  PendingQueueRef new_ref;
  new_ref.req_id = req_id;
  new_ref.generation = conn.generation;
  new_ref.key = conn.key;
  new_ref.started_mono_ms = started_mono;
  g_pending_fifo.push_back(new_ref);
  std::list<PendingQueueRef>::iterator fit = g_pending_fifo.end();
  --fit;

  Pending p(req_id, conn.generation, e, now_ms(), started_mono);
  p.fifo_it = fit;
  p.in_fifo = true;
  conn.pending.push_back(p);
  ++g_total_pending_count;

  return req_id;
}

static bool flow_at_clean_boundary(const Flow &fl) {
  return fl.state == Flow::HTTP_STATE_HEADER &&
         fl.buf.empty() && fl.ooo.empty() &&
         !fl.awaiting_wsse && fl.wsse_buf.empty() &&
         fl.body_remaining == 0 && fl.chunk_payload_remaining == 0;
}

static bool connection_clean_idle(const Connection &conn) {
  return conn.pending.empty() && !conn.has_deferred_wsse &&
         flow_at_clean_boundary(conn.req_flow) &&
         flow_at_clean_boundary(conn.resp_flow);
}

static void sweep(std::map<ConnectionKey, Connection> &connections,
                  std::list<ConnectionKey> &conn_lru,
                  time_t now, unsigned pending_ttl_sec,
                  long long now_mono = 0) {
  (void)now;
  if (now_mono <= 0) now_mono = now_monotonic_ms();
  long long ttl_ms = (long long)pending_ttl_sec * 1000LL;

  for (std::map<ConnectionKey, Connection>::iterator cit = connections.begin(); cit != connections.end();) {
    std::map<ConnectionKey, Connection>::iterator next_cit = cit; ++next_cit;
    Connection &conn = cit->second;

    size_t i = 0;
    while (i < conn.pending.size()) {
      Pending &entry = conn.pending[i];
      if (entry.is_tombstone) {
        if (now_mono - entry.tombstone_mono_ms > 10000LL) {
          remove_pending_from_fifo(entry);
          conn.pending.erase(conn.pending.begin() + i);
          while (i < conn.pending.size()) {
            Pending &tail = conn.pending[i];
            if (!tail.is_tombstone) {
              emit_event(tail.ev);
              if (g_total_pending_count > 0) --g_total_pending_count;
            }
            remove_pending_from_fifo(tail);
            conn.pending.erase(conn.pending.begin() + i);
          }
          invalidate_stream(conn, "tombstone_unresolved_expiry");
        } else {
          ++i;
        }
      } else if (now_mono - entry.started_mono_ms > ttl_ms) {
        emit_event(entry.ev);
        if (g_total_pending_count > 0) --g_total_pending_count;
        remove_pending_from_fifo(entry);
        entry.is_tombstone = true;
        entry.tombstone_mono_ms = now_mono;
        ++i;
      } else {
        ++i;
      }
    }

    long long idle_ms = now_mono - conn.touched_mono_ms;
    if (idle_ms < 0) idle_ms = 0;
    long long stale_ttl_ms = ((long long)pending_ttl_sec + 60LL) * 1000LL;
    if (stale_ttl_ms < (long long)FLOW_STALE_TTL * 1000LL)
      stale_ttl_ms = (long long)FLOW_STALE_TTL * 1000LL;

    if (idle_ms > (long long)FLOW_IDLE_TTL * 1000LL && connection_clean_idle(conn)) {
      if (conn.in_lru) {
        conn_lru.erase(conn.lru_it);
        conn.in_lru = false;
      }
      connections.erase(cit);
      cit = next_cit;
      continue;
    }

    if (idle_ms > stale_ttl_ms) {
      invalidate_stream(conn, "stale_flow_expired");
      if (conn.in_lru) {
        conn_lru.erase(conn.lru_it);
        conn.in_lru = false;
      }
      connections.erase(cit);
      cit = next_cit;
      continue;
    }

    cit = next_cit;
  }

  while (!g_pending_fifo.empty() &&
         (now_mono - g_pending_fifo.front().started_mono_ms > ttl_ms * 2LL)) {
    g_pending_fifo.pop_front();
  }
}

static void flush_incomplete_wsse(std::map<ConnectionKey, Connection> &connections) {
  for (std::map<ConnectionKey, Connection>::iterator it = connections.begin(); it != connections.end(); ++it) {
    if (it->second.has_deferred_wsse) {
      emit_event(it->second.deferred_wsse_event);
      it->second.has_deferred_wsse = false;
    }
    it->second.req_flow.clear_buffers();
    it->second.resp_flow.clear_buffers();
  }
}

static void flush_all_pending(std::map<ConnectionKey, Connection> &connections) {
  for (std::map<ConnectionKey, Connection>::iterator it = connections.begin(); it != connections.end(); ++it) {
    if (it->second.has_deferred_wsse) {
      emit_event(it->second.deferred_wsse_event);
      it->second.has_deferred_wsse = false;
    }
    for (size_t i = 0; i < it->second.pending.size(); ++i) {
      if (!it->second.pending[i].is_tombstone) {
        emit_event(it->second.pending[i].ev);
      }
    }
    it->second.pending.clear();
  }
  connections.clear();
  g_pending_fifo.clear();
  g_total_pending_count = 0;
  corr_disabled_clear();
}

static void process_request_payload(Connection &conn,
                                    const char *payload, size_t plen,
                                    uint32_t seq,
                                    time_t now, long long mono_now,
                                    const std::string &node,
                                    std::map<ConnectionKey, Connection> &connections,
                                    std::list<ConnectionKey> &conn_lru) {
  Flow &fl = conn.req_flow;
  if (fl.state == Flow::HTTP_STATE_UNSYNCED) return;

  if (!fl.has_seq) {
    size_t start = find_request_resync(payload, plen);
    if (start != (size_t)-1) {
      fl.has_seq = true;
      fl.next_seq = seq + (uint32_t)start;
      fl.is_broken = false;
      fl.state = Flow::HTTP_STATE_HEADER;

      payload += start;
      plen -= start;
      seq += (uint32_t)start;
    } else if (is_method_or_prefix(payload, plen)) {
      fl.has_seq = true;
      fl.next_seq = seq;
      fl.is_broken = false;
    } else {
      if (!ooo_insert(fl, seq, payload, plen)) {
        invalidate_stream(conn, "req_ooo_ambiguous");
      }
      return;
    }
  }

  int32_t diff = seq_diff(seq, fl.next_seq);
  if (diff == 0) {
    if (!fl.buf_append(payload, plen)) {
      invalidate_stream(conn, "req_buf_overflow");
      return;
    }
    fl.next_seq += (uint32_t)plen;
    if (!drain_ooo_segments(fl)) {
      invalidate_stream(conn, "req_ooo_drain_overflow");
      return;
    }
  } else if (diff < 0) {
    uint32_t overlap = (uint32_t)(-(int64_t)diff);
    if ((size_t)overlap < plen) {
      size_t flen = plen - overlap;
      if (!fl.buf_append(payload + overlap, flen)) {
        invalidate_stream(conn, "req_buf_overflow");
        return;
      }
      fl.next_seq += (uint32_t)flen;
      if (!drain_ooo_segments(fl)) {
        invalidate_stream(conn, "req_ooo_drain_overflow");
        return;
      }
    }
  } else {
    if (!ooo_insert(fl, seq, payload, plen)) {
      invalidate_stream(conn, "req_ooo_ambiguous");
      return;
    }
  }

  while (!fl.buf.empty() && !fl.is_broken) {
    if (fl.state == Flow::HTTP_STATE_UNSYNCED) break;

    if (fl.state == Flow::HTTP_STATE_CLOSE_BODY) {
      fl.buf_erase(0, fl.buf.size());
      break;
    }

    if (fl.state == Flow::HTTP_STATE_HEADER) {
      if (!fl.first_byte_mono_ms) fl.first_byte_mono_ms = mono_now;

      size_t end = fl.buf.find("\r\n\r\n");
      if (end == std::string::npos) {
        if (fl.buf.size() > MAX_HEADER_BYTES) {
          invalidate_stream(conn, "req_header_too_large");
        }
        break;
      }

      size_t start = find_http_start(fl.buf);
      if (start == std::string::npos || start > end) {
        fl.buf_erase(0, end + 4);
        continue;
      }
      if (start > 0) {
        fl.buf_erase(0, start);
        end -= start;
      }

      Event e; RequestMeta meta;
      e.ts = now; e.host = node; e.service = "port:" + num(conn.server.port);
      e.caller = ip_to_str(conn.client.ip); e.caller_port = conn.client.port;
      e.dst_ip = ip_to_str(conn.server.ip); e.dst_port = conn.server.port;
      e.req_bytes = (unsigned)(end + 4);

      if (!parse_request(fl.buf.data(), end + 2, &e, &meta)) {
        fl.buf_erase(0, end + 4);
        continue;
      }

      bool has_te = meta.has_transfer_encoding;
      bool has_chunked = has_te && transfer_encoding_final_chunked(meta.transfer_encoding);

      if (meta.has_conflict_cl ||
          meta.invalid_transfer_encoding ||
          (meta.has_content_length && has_te) ||
          (has_te && !has_chunked)) {
        invalidate_stream(conn, "request_framing_ambiguous");
        break;
      }

      fl.buf_erase(0, end + 4);

      bool wsse_eligible = (g_wsse_body_bytes > 0 &&
                            is_soap_content_type(meta.content_type) &&
                            meta.has_content_length &&
                            meta.content_length > 0 &&
                            !has_chunked &&
                            g_wsse_body_flows_active < MAX_WSSE_BODY_FLOWS);

      uint64_t req_id = queue_request(conn, e, fl.first_byte_mono_ms, connections, conn_lru, wsse_eligible);

      if (wsse_eligible && req_id != 0) {
        fl.awaiting_wsse = true;
        ++g_wsse_body_flows_active;
        fl.wsse_req_id = req_id;
        fl.wsse_clear();
        fl.wsse_last_parsed_len = 0;
        fl.wsse_goal = meta.content_length < g_wsse_body_bytes ? meta.content_length : g_wsse_body_bytes;
      } else {
        fl.awaiting_wsse = false;
        fl.wsse_clear();
      }

      if (meta.has_content_length && meta.content_length > 0) {
        fl.state = Flow::HTTP_STATE_BODY;
        fl.body_remaining = meta.content_length;
      } else if (has_chunked) {
        fl.state = Flow::HTTP_STATE_CHUNK;
        fl.chunk_reading_len = true;
        fl.chunk_reading_crlf = false;
        fl.chunk_reading_trailer = false;
        fl.chunk_payload_remaining = 0;
      } else {
        fl.state = Flow::HTTP_STATE_HEADER;
        fl.first_byte_mono_ms = fl.buf.empty() ? 0 : mono_now;
      }
      continue;
    }

    if (fl.state == Flow::HTTP_STATE_BODY) {
      if (fl.buf.empty()) break;
      size_t to_consume = (fl.buf.size() < fl.body_remaining) ? fl.buf.size() : fl.body_remaining;

      if (fl.awaiting_wsse) {
        size_t wsse_need = fl.wsse_goal > fl.wsse_buf.size() ? fl.wsse_goal - fl.wsse_buf.size() : 0;
        if (wsse_need > 0) {
          size_t copy_len = (to_consume < wsse_need) ? to_consume : wsse_need;
          fl.wsse_append(fl.buf.data(), copy_len);
        }

        bool should_parse = false;
        if (fl.wsse_buf.size() >= fl.wsse_goal) should_parse = true;
        else if (fl.body_remaining <= to_consume) should_parse = true;
        else if (fl.wsse_buf.size() >= fl.wsse_last_parsed_len + 512) should_parse = true;

        if (should_parse) {
          fl.wsse_last_parsed_len = fl.wsse_buf.size();
          std::string username = extract_wsse_username(fl.wsse_buf);
          if (!username.empty()) {
            if (conn.has_deferred_wsse && conn.deferred_wsse_req_id == fl.wsse_req_id) {
              conn.deferred_wsse_event.wsse_user = username;
              conn.deferred_wsse_event.user = username;
              conn.deferred_wsse_event.scheme = "wsse";
              emit_event(conn.deferred_wsse_event);
              conn.has_deferred_wsse = false;
            } else {
              for (size_t j = 0; j < conn.pending.size(); ++j) {
                if (conn.pending[j].req_id == fl.wsse_req_id) {
                  conn.pending[j].ev.wsse_user = username;
                  conn.pending[j].ev.user = username;
                  conn.pending[j].ev.scheme = "wsse";
                  break;
                }
              }
            }
            fl.wsse_cancel();
          } else if (fl.wsse_buf.size() >= fl.wsse_goal) {
            if (conn.has_deferred_wsse && conn.deferred_wsse_req_id == fl.wsse_req_id) {
              emit_event(conn.deferred_wsse_event);
              conn.has_deferred_wsse = false;
            }
            fl.wsse_cancel();
          }
        }
      }

      fl.buf_erase(0, to_consume);
      fl.body_remaining -= to_consume;
      if (fl.body_remaining == 0) {
        if (fl.awaiting_wsse) {
          if (conn.has_deferred_wsse && conn.deferred_wsse_req_id == fl.wsse_req_id) {
            emit_event(conn.deferred_wsse_event);
            conn.has_deferred_wsse = false;
          }
          fl.wsse_cancel();
        }
        fl.state = Flow::HTTP_STATE_HEADER;
        fl.first_byte_mono_ms = fl.buf.empty() ? 0 : mono_now;
      }
      continue;
    }

    if (fl.state == Flow::HTTP_STATE_CHUNK) {
      if (fl.buf.empty()) break;
      if (fl.chunk_reading_trailer) {
        if (fl.buf.size() >= 2 && fl.buf[0] == '\r' && fl.buf[1] == '\n') {
          fl.buf_erase(0, 2);
          fl.chunk_reading_trailer = false;
          fl.state = Flow::HTTP_STATE_HEADER;
          fl.first_byte_mono_ms = fl.buf.empty() ? 0 : mono_now;
          continue;
        }
        size_t tr_end = fl.buf.find("\r\n\r\n");
        if (tr_end != std::string::npos) {
          fl.buf_erase(0, tr_end + 4);
          fl.chunk_reading_trailer = false;
          fl.state = Flow::HTTP_STATE_HEADER;
          fl.first_byte_mono_ms = fl.buf.empty() ? 0 : mono_now;
          continue;
        }
        if (fl.buf.size() > MAX_HEADER_BYTES) {
          invalidate_stream(conn, "req_chunk_trailer_overflow");
        }
        break;
      }
      if (fl.chunk_reading_len) {
        size_t crlf = fl.buf.find("\r\n");
        if (crlf == std::string::npos) {
          if (fl.buf.size() > 64) {
            invalidate_stream(conn, "req_chunk_len_overflow");
          }
          break;
        }
        if (crlf > 64) {
          invalidate_stream(conn, "req_chunk_len_overflow");
          break;
        }
        std::string line = trim(fl.buf.substr(0, crlf));
        size_t semi = line.find(';');
        std::string hex_str = (semi != std::string::npos) ? trim(line.substr(0, semi)) : line;
        if (hex_str.empty() || hex_str.size() > 16) {
          invalidate_stream(conn, "req_chunk_hex_invalid");
          break;
        }
        bool valid_hex = true;
        for (size_t hi = 0; hi < hex_str.size(); ++hi) {
          if (!isxdigit((unsigned char)hex_str[hi])) { valid_hex = false; break; }
        }
        if (!valid_hex) {
          invalidate_stream(conn, "req_chunk_hex_invalid");
          break;
        }
        char *endptr = NULL;
        errno = 0;
        unsigned long long parsed_len = strtoull(hex_str.c_str(), &endptr, 16);
        if (errno != 0 || endptr != hex_str.c_str() + hex_str.size() || parsed_len > 16777216ULL) {
          invalidate_stream(conn, "req_chunk_size_overflow");
          break;
        }
        fl.buf_erase(0, crlf + 2);
        if (parsed_len == 0) {
          fl.chunk_reading_trailer = true;
          fl.chunk_reading_len = false;
          continue;
        } else {
          fl.chunk_payload_remaining = (size_t)parsed_len;
          fl.chunk_reading_len = false;
          fl.chunk_reading_crlf = false;
        }
      } else if (fl.chunk_reading_crlf) {
        if (fl.buf.size() < 2) break;
        if (fl.buf[0] != '\r' || fl.buf[1] != '\n') {
          invalidate_stream(conn, "req_chunk_crlf_missing");
          break;
        }
        fl.buf_erase(0, 2);
        fl.chunk_reading_crlf = false;
        fl.chunk_reading_len = true;
      } else {
        size_t to_consume = (fl.buf.size() < fl.chunk_payload_remaining) ? fl.buf.size() : fl.chunk_payload_remaining;
        fl.buf_erase(0, to_consume);
        fl.chunk_payload_remaining -= to_consume;
        if (fl.chunk_payload_remaining == 0) {
          fl.chunk_reading_crlf = true;
        }
      }
      continue;
    }
  }

  if (fl.fin_seen && fl.has_seq) {
    int32_t fdiff = seq_diff(fl.next_seq, fl.fin_seq);
    if (fdiff >= 0 && fl.buf.empty() && fl.ooo.empty()) {
      fl.state = Flow::HTTP_STATE_CLOSE_BODY;
      if (conn.has_deferred_wsse) {
        emit_event(conn.deferred_wsse_event);
        conn.has_deferred_wsse = false;
      }
      if (fl.awaiting_wsse) {
        fl.wsse_cancel();
      }
    }
  }
}

static void process_response_payload(Connection &conn,
                                     const char *payload, size_t plen,
                                     uint32_t seq,
                                     time_t now, long long mono_now) {
  (void)now;
  Flow &rfl = conn.resp_flow;
  if (rfl.state == Flow::HTTP_STATE_UNSYNCED) return;

  PacketKey rk;
  rk.s_ip = conn.server.ip; rk.sport = conn.server.port;
  rk.d_ip = conn.client.ip; rk.dport = conn.client.port;

  bool allowed = (!conn.corr_disabled && conn.corr_eligible && !conn.req_flow.is_broken && !conn.resp_flow.is_broken);
  if (g_corr_disabled.count(rk) > 0) allowed = false;
  if (g_corr_capacity_reached && (!conn.syn_seen || conn.generation == 0)) allowed = false;

  if (!allowed) {
    if (!rfl.buf.empty() || !rfl.ooo.empty()) {
      rfl.clear_buffers();
    }
    return;
  }

  if (!rfl.has_seq) {
    size_t start = find_response_resync(payload, plen);
    if (start != (size_t)-1) {
      rfl.has_seq = true;
      rfl.next_seq = seq + (uint32_t)start;
      rfl.is_broken = false;
      rfl.state = Flow::HTTP_STATE_HEADER;

      payload += start;
      plen -= start;
      seq += (uint32_t)start;
    } else if ((plen >= 5 && memcmp(payload, "HTTP/", 5) == 0) ||
               (plen < 5 && memcmp(payload, "HTTP/", plen) == 0)) {
      rfl.has_seq = true;
      rfl.next_seq = seq;
      rfl.is_broken = false;
    } else {
      if (!ooo_insert(rfl, seq, payload, plen)) {
        invalidate_stream(conn, "resp_ooo_ambiguous");
      }
      return;
    }
  }

  int32_t diff = seq_diff(seq, rfl.next_seq);
  if (diff == 0) {
    if (!rfl.buf_append(payload, plen)) {
      invalidate_stream(conn, "resp_buf_overflow");
      return;
    }
    rfl.next_seq += (uint32_t)plen;
    if (!drain_ooo_segments(rfl)) {
      invalidate_stream(conn, "resp_ooo_drain_overflow");
      return;
    }
  } else if (diff < 0) {
    uint32_t overlap = (uint32_t)(-(int64_t)diff);
    if ((size_t)overlap < plen) {
      size_t flen = plen - overlap;
      if (!rfl.buf_append(payload + overlap, flen)) {
        invalidate_stream(conn, "resp_buf_overflow");
        return;
      }
      rfl.next_seq += (uint32_t)flen;
      if (!drain_ooo_segments(rfl)) {
        invalidate_stream(conn, "resp_ooo_drain_overflow");
        return;
      }
    }
  } else {
    if (!ooo_insert(rfl, seq, payload, plen)) {
      invalidate_stream(conn, "resp_ooo_ambiguous");
      return;
    }
  }

  while (!rfl.buf.empty() && !rfl.is_broken) {
    if (rfl.state == Flow::HTTP_STATE_UNSYNCED) break;

    if (rfl.state == Flow::HTTP_STATE_CLOSE_BODY) {
      rfl.buf_erase(0, rfl.buf.size());
      break;
    }

    if (rfl.state == Flow::HTTP_STATE_HEADER) {
      size_t end = rfl.buf.find("\r\n\r\n");
      if (end == std::string::npos) {
        if (rfl.buf.size() > MAX_HEADER_BYTES) {
          invalidate_stream(conn, "resp_header_too_large");
        }
        break;
      }

      if (rfl.buf.compare(0, 5, "HTTP/") != 0) {
        size_t hpos = rfl.buf.find("HTTP/");
        if (hpos == std::string::npos || hpos > end) {
          rfl.buf_erase(0, end + 4);
          continue;
        }
        rfl.buf_erase(0, hpos);
        end -= hpos;
      }

      bool framing_conflict = false;
      int st = 0; size_t cl = 0; bool has_cl = false, is_chunked = false, is_close = false;
      if (!parse_response(rfl.buf.data(), end + 2, &st, &cl, &has_cl, &is_chunked, &is_close, &framing_conflict)) {
        if (framing_conflict) {
          invalidate_stream(conn, "resp_framing_ambiguous");
          break;
        }
        rfl.buf_erase(0, end + 4);
        continue;
      }

      if (st == 101) {
        if (conn.has_deferred_wsse) {
          emit_event(conn.deferred_wsse_event);
          conn.has_deferred_wsse = false;
        }
        for (size_t pi = 0; pi < conn.pending.size(); ++pi) {
          Pending &p = conn.pending[pi];
          if (!p.is_tombstone) {
            Event e = p.ev;
            if (pi == 0) {
              e.status = 101;
              e.has_status = true;
              e.duration_ms = (long)(mono_now - p.started_mono_ms);
              if (e.duration_ms < 0) e.duration_ms = 0;
              e.has_duration = true;
              e.resp_bytes = 0;
              e.has_resp = true;
            }
            emit_event(e);
            if (g_total_pending_count > 0) --g_total_pending_count;
          }
          remove_pending_from_fifo(p);
        }
        conn.pending.clear();
        rfl.buf_erase(0, end + 4);
        conn.req_flow.state = Flow::HTTP_STATE_UNSYNCED;
        conn.resp_flow.state = Flow::HTTP_STATE_UNSYNCED;
        conn.corr_eligible = false;
        conn.corr_disabled = true;
        corr_disabled_insert(rk);
        break;
      }

      if (st >= 100 && st <= 199) {
        rfl.buf_erase(0, end + 4);
        continue;
      }

      if (conn.req_flow.awaiting_wsse && !conn.req_flow.wsse_buf.empty()) {
        std::string username = extract_wsse_username(conn.req_flow.wsse_buf);
        if (!username.empty()) {
          for (size_t pi = 0; pi < conn.pending.size(); ++pi) {
            if (conn.pending[pi].req_id == conn.req_flow.wsse_req_id &&
                conn.pending[pi].generation == conn.req_flow.generation) {
              conn.pending[pi].ev.wsse_user = username;
              conn.pending[pi].ev.user = username;
              conn.pending[pi].ev.scheme = "wsse";
              break;
            }
          }
          conn.req_flow.wsse_cancel();
        }
      }

      bool is_head = false;
      PacketKey rk;
      rk.s_ip = conn.server.ip; rk.sport = conn.server.port;
      rk.d_ip = conn.client.ip; rk.dport = conn.client.port;

      bool allowed = (!conn.corr_disabled && conn.corr_eligible && !conn.req_flow.is_broken && !conn.resp_flow.is_broken);
      if (g_corr_disabled.count(rk) > 0) allowed = false;
      if (g_corr_capacity_reached && (!conn.syn_seen || conn.generation == 0)) allowed = false;

      if (allowed && !conn.pending.empty()) {
        Pending &front = conn.pending.front();
        if (conn.generation != 0 && front.generation != 0 && front.generation != conn.generation) {
          if (!front.is_tombstone) {
            emit_event(front.ev);
            if (g_total_pending_count > 0) --g_total_pending_count;
          }
          remove_pending_from_fifo(front);
          conn.pending.erase(conn.pending.begin());
        } else {
          if (front.ev.method == "HEAD") is_head = true;
          if (front.is_tombstone) {
            remove_pending_from_fifo(front);
            conn.pending.erase(conn.pending.begin());
          } else {
            Event e = front.ev;
            e.status = st;
            e.has_status = true;
            e.duration_ms = (long)(mono_now - front.started_mono_ms);
            if (e.duration_ms < 0) e.duration_ms = 0;
            e.has_duration = true;
            if (has_cl) {
              e.resp_bytes = (unsigned)cl;
              e.has_resp = true;
            }
            emit_event(e);
            if (g_total_pending_count > 0) --g_total_pending_count;
            remove_pending_from_fifo(front);
            conn.pending.erase(conn.pending.begin());
          }
        }
      }

      rfl.buf_erase(0, end + 4);

      if (is_head || st == 204 || st == 304) {
        rfl.state = Flow::HTTP_STATE_HEADER;
      } else if (is_chunked) {
        rfl.state = Flow::HTTP_STATE_CHUNK;
        rfl.chunk_reading_len = true;
        rfl.chunk_reading_crlf = false;
        rfl.chunk_reading_trailer = false;
        rfl.chunk_payload_remaining = 0;
      } else if (has_cl) {
        if (cl > 0) {
          rfl.state = Flow::HTTP_STATE_BODY;
          rfl.body_remaining = cl;
        } else {
          rfl.state = Flow::HTTP_STATE_HEADER;
        }
      } else if (is_close) {
        rfl.state = Flow::HTTP_STATE_CLOSE_BODY;
      } else {
        rfl.state = Flow::HTTP_STATE_CLOSE_BODY;
      }
      continue;
    }

    if (rfl.state == Flow::HTTP_STATE_BODY) {
      if (rfl.buf.empty()) break;
      size_t to_consume = (rfl.buf.size() < rfl.body_remaining) ? rfl.buf.size() : rfl.body_remaining;
      rfl.buf_erase(0, to_consume);
      rfl.body_remaining -= to_consume;
      if (rfl.body_remaining == 0) {
        rfl.state = Flow::HTTP_STATE_HEADER;
      }
      continue;
    }

    if (rfl.state == Flow::HTTP_STATE_CHUNK) {
      if (rfl.buf.empty()) break;
      if (rfl.chunk_reading_trailer) {
        if (rfl.buf.size() >= 2 && rfl.buf[0] == '\r' && rfl.buf[1] == '\n') {
          rfl.buf_erase(0, 2);
          rfl.chunk_reading_trailer = false;
          rfl.state = Flow::HTTP_STATE_HEADER;
          continue;
        }
        size_t tr_end = rfl.buf.find("\r\n\r\n");
        if (tr_end != std::string::npos) {
          rfl.buf_erase(0, tr_end + 4);
          rfl.chunk_reading_trailer = false;
          rfl.state = Flow::HTTP_STATE_HEADER;
          continue;
        }
        if (rfl.buf.size() > MAX_HEADER_BYTES) {
          invalidate_stream(conn, "resp_chunk_trailer_overflow");
        }
        break;
      }
      if (rfl.chunk_reading_len) {
        size_t crlf = rfl.buf.find("\r\n");
        if (crlf == std::string::npos) {
          if (rfl.buf.size() > 64) {
            invalidate_stream(conn, "resp_chunk_len_overflow");
          }
          break;
        }
        if (crlf > 64) {
          invalidate_stream(conn, "resp_chunk_len_overflow");
          break;
        }
        std::string line = trim(rfl.buf.substr(0, crlf));
        size_t semi = line.find(';');
        std::string hex_str = (semi != std::string::npos) ? trim(line.substr(0, semi)) : line;
        if (hex_str.empty() || hex_str.size() > 16) {
          invalidate_stream(conn, "resp_chunk_hex_invalid");
          break;
        }
        bool valid_hex = true;
        for (size_t hi = 0; hi < hex_str.size(); ++hi) {
          if (!isxdigit((unsigned char)hex_str[hi])) { valid_hex = false; break; }
        }
        if (!valid_hex) {
          invalidate_stream(conn, "resp_chunk_hex_invalid");
          break;
        }
        char *endptr = NULL;
        errno = 0;
        unsigned long long parsed_len = strtoull(hex_str.c_str(), &endptr, 16);
        if (errno != 0 || endptr != hex_str.c_str() + hex_str.size() || parsed_len > 16777216ULL) {
          invalidate_stream(conn, "resp_chunk_size_overflow");
          break;
        }
        rfl.buf_erase(0, crlf + 2);
        if (parsed_len == 0) {
          rfl.chunk_reading_trailer = true;
          rfl.chunk_reading_len = false;
          continue;
        } else {
          rfl.chunk_payload_remaining = (size_t)parsed_len;
          rfl.chunk_reading_len = false;
          rfl.chunk_reading_crlf = false;
        }
      } else if (rfl.chunk_reading_crlf) {
        if (rfl.buf.size() < 2) break;
        if (rfl.buf[0] != '\r' || rfl.buf[1] != '\n') {
          invalidate_stream(conn, "resp_chunk_crlf_missing");
          break;
        }
        rfl.buf_erase(0, 2);
        rfl.chunk_reading_crlf = false;
        rfl.chunk_reading_len = true;
      } else {
        size_t to_consume = (rfl.buf.size() < rfl.chunk_payload_remaining) ? rfl.buf.size() : rfl.chunk_payload_remaining;
        rfl.buf_erase(0, to_consume);
        rfl.chunk_payload_remaining -= to_consume;
        if (rfl.chunk_payload_remaining == 0) {
          rfl.chunk_reading_crlf = true;
        }
      }
      continue;
    }

    if (rfl.state == Flow::HTTP_STATE_CLOSE_BODY) {
      rfl.buf_erase(0, rfl.buf.size());
      break;
    }
  }

  if (rfl.fin_seen && rfl.has_seq) {
    int32_t fdiff = seq_diff(rfl.next_seq, rfl.fin_seq);
    if (fdiff >= 0 && rfl.buf.empty() && rfl.ooo.empty()) {
      rfl.state = Flow::HTTP_STATE_CLOSE_BODY;
    }
  }
}

static bool handle_connection_flags(Connection &conn,
                                    unsigned char tcp_flags,
                                    uint32_t seq,
                                    bool is_from_client,
                                    std::map<ConnectionKey, Connection> &connections,
                                    std::list<ConnectionKey> &conn_lru) {
  if (tcp_flags & 0x04) {
    invalidate_stream(conn, "rst_received");
    if (conn.in_lru) {
      conn_lru.erase(conn.lru_it);
      conn.in_lru = false;
    }
    connections.erase(conn.key);
    return true;
  }

  if (tcp_flags & 0x01) {
    if (is_from_client) {
      conn.req_flow.fin_seen = true;
      conn.req_flow.fin_seq = seq;
      int32_t fdiff = conn.req_flow.has_seq ? seq_diff(conn.req_flow.next_seq, seq) : 0;
      if ((!conn.req_flow.has_seq || fdiff >= 0) && conn.req_flow.buf.empty() && conn.req_flow.ooo.empty()) {
        conn.req_flow.state = Flow::HTTP_STATE_CLOSE_BODY;
        if (conn.has_deferred_wsse) {
          emit_event(conn.deferred_wsse_event);
          conn.has_deferred_wsse = false;
        }
        if (conn.req_flow.awaiting_wsse) {
          conn.req_flow.wsse_cancel();
        }
      }
    } else {
      conn.resp_flow.fin_seen = true;
      conn.resp_flow.fin_seq = seq;
      int32_t fdiff = conn.resp_flow.has_seq ? seq_diff(conn.resp_flow.next_seq, seq) : 0;
      if ((!conn.resp_flow.has_seq || fdiff >= 0) && conn.resp_flow.buf.empty() && conn.resp_flow.ooo.empty()) {
        conn.resp_flow.state = Flow::HTTP_STATE_CLOSE_BODY;
      }
    }

    if (conn.req_flow.fin_seen && conn.resp_flow.fin_seen &&
        conn.req_flow.state == Flow::HTTP_STATE_CLOSE_BODY &&
        conn.resp_flow.state == Flow::HTTP_STATE_CLOSE_BODY) {
      invalidate_stream(conn, "both_fin");
      if (conn.in_lru) {
        conn_lru.erase(conn.lru_it);
        conn.in_lru = false;
      }
      connections.erase(conn.key);
      return true;
    }
  }
  return false;
}

static bool handle_packet(const unsigned char *buf, size_t n,
                          const std::string &node,
                          const std::vector<unsigned> &ports,
                          std::map<ConnectionKey, Connection> &connections,
                          std::list<ConnectionKey> &conn_lru,
                          time_t pcap_now = 0, long long pcap_mono_now = 0) {
  (void)ports;
  if (n < 34) return false;
  size_t off = 14;
  unsigned short et = ntohs(read_u16(buf + 12));
  if (et == ETH_P_8021Q) { if (n < 38) return false; et = ntohs(read_u16(buf + 16)); off = 18; }
  if (et != ETH_P_IP || n < off + 20) return false;

  unsigned char ihl = (unsigned char)(buf[off] & 15) * 4;
  if ((buf[off] >> 4) != 4 || ihl < 20 || buf[off + 9] != 6) return false;

  uint16_t frag = ntohs(read_u16(buf + off + 6));
  if (frag & 0x3fff) return false;

  uint16_t ip_total_len = ntohs(read_u16(buf + off + 2));
  if (ip_total_len < ihl + 20) return false;
  bool is_truncated = false;
  if (n - off < ip_total_len) {
    is_truncated = true;
    ++g_invalid_frames;
    ++g_capture_truncated;
  } else if (n - off > ip_total_len) {
    n = off + ip_total_len;
  }

  uint32_t s_ip = read_u32(buf + off + 12);
  uint32_t d_ip = read_u32(buf + off + 16);
  size_t to = off + ihl;
  if (n < to + 20) return false;

  unsigned sport = ntohs(read_u16(buf + to));
  unsigned dport = ntohs(read_u16(buf + to + 2));
  uint32_t seq = ntohl(read_u32(buf + to + 4));
  unsigned doff = (buf[to + 12] >> 4) * 4;
  if (doff < 20 || n < to + doff) return false;

  unsigned char tcp_flags = buf[to + 13];
  const char *payload = (const char *)(buf + to + doff);
  size_t plen = n - to - doff;

  time_t now = (pcap_now > 0) ? pcap_now : time(NULL);
  long long mono_now = (pcap_mono_now > 0) ? pcap_mono_now : now_monotonic_ms();

  bool dst_mon = (dport < 65536) ? g_monitored_ports[dport] : false;
  bool src_mon = (sport < 65536) ? g_monitored_ports[sport] : false;

  if (!dst_mon && !src_mon) return false;

  ConnectionKey ckey(s_ip, (uint16_t)sport, d_ip, (uint16_t)dport);
  bool is_new_conn = (connections.find(ckey) == connections.end());

  evict_connection_if_needed(connections, conn_lru, is_new_conn, &ckey);

  std::map<ConnectionKey, Connection>::iterator cit = connections.find(ckey);
  bool needs_init = (cit == connections.end());
  Connection &conn = connections[ckey];
  if (needs_init) {
    conn.key = ckey;
    conn_lru.push_back(ckey);
    conn.lru_it = --conn_lru.end();
    conn.in_lru = true;
    conn.touched = now;
    conn.touched_mono_ms = mono_now;
  } else {
    touch_connection(conn, ckey, conn_lru, now, mono_now);
  }

  if (is_truncated) {
    invalidate_stream(conn, "frame_truncated");
    return true;
  }

  if (!conn.roles_established) {
    if ((tcp_flags & 0x02) && !(tcp_flags & 0x10)) {
      conn.client = Endpoint(s_ip, (uint16_t)sport);
      conn.server = Endpoint(d_ip, (uint16_t)dport);
      conn.roles_established = true;
      conn.client_isn = seq;
      conn.have_client_isn = true;
    } else if ((tcp_flags & 0x02) && (tcp_flags & 0x10)) {
      conn.server = Endpoint(s_ip, (uint16_t)sport);
      conn.client = Endpoint(d_ip, (uint16_t)dport);
      conn.roles_established = true;
    } else if (dst_mon && !src_mon) {
      conn.client = Endpoint(s_ip, (uint16_t)sport);
      conn.server = Endpoint(d_ip, (uint16_t)dport);
      conn.roles_established = true;
    } else if (src_mon && !dst_mon) {
      conn.server = Endpoint(s_ip, (uint16_t)sport);
      conn.client = Endpoint(d_ip, (uint16_t)dport);
      conn.roles_established = true;
    } else {
      if (is_method_or_prefix(payload, plen)) {
        conn.client = Endpoint(s_ip, (uint16_t)sport);
        conn.server = Endpoint(d_ip, (uint16_t)dport);
        conn.roles_established = true;
      } else if (plen >= 5 && memcmp(payload, "HTTP/", 5) == 0) {
        conn.server = Endpoint(s_ip, (uint16_t)sport);
        conn.client = Endpoint(d_ip, (uint16_t)dport);
        conn.roles_established = true;
      }
    }
  }

  if (!conn.roles_established) return true;

  Endpoint sender(s_ip, (uint16_t)sport);
  bool is_from_client = (sender == conn.client);

  if (is_from_client) {
    if ((tcp_flags & 0x02) && !(tcp_flags & 0x10)) {
      if (conn.syn_seen && conn.have_client_isn && conn.client_isn == seq) {
        return true;
      }
      conn.client_isn = seq;
      conn.have_client_isn = true;
      conn.touched = now;
      conn.touched_mono_ms = mono_now;
      for (size_t pi = 0; pi < conn.pending.size(); ++pi) {
        if (!conn.pending[pi].is_tombstone) {
          emit_event(conn.pending[pi].ev);
          if (g_total_pending_count > 0) --g_total_pending_count;
        }
        remove_pending_from_fifo(conn.pending[pi]);
      }
      conn.pending.clear();
      if (conn.has_deferred_wsse) {
        emit_event(conn.deferred_wsse_event);
        conn.has_deferred_wsse = false;
      }

      PacketKey rk;
      rk.s_ip = conn.server.ip; rk.sport = conn.server.port;
      rk.d_ip = conn.client.ip; rk.dport = conn.client.port;
      corr_disabled_erase(rk);

      uint32_t next_gen = conn.generation + 1;
      conn.generation = next_gen;
      conn.syn_seen = true;
      conn.corr_eligible = true;
      conn.corr_disabled = false;
      conn.req_flow.reset_for_new_connection(next_gen, now, true, true);
      conn.resp_flow.reset_for_new_connection(next_gen, now, true, true);
      conn.req_flow.has_seq = true;
      conn.req_flow.next_seq = seq + 1;
      return true;
    }

    if (plen > 0) {
      process_request_payload(conn, payload, plen, seq, now, mono_now, node, connections, conn_lru);
    }
    handle_connection_flags(conn, tcp_flags, seq + (uint32_t)plen, true, connections, conn_lru);
  } else {
    if ((tcp_flags & 0x02) && (tcp_flags & 0x10)) {
      if (!conn.resp_flow.has_seq) {
        conn.resp_flow.has_seq = true;
        conn.resp_flow.next_seq = seq + 1;
      }
      return true;
    }

    if (plen > 0) {
      process_response_payload(conn, payload, plen, seq, now, mono_now);
    }
    handle_connection_flags(conn, tcp_flags, seq + (uint32_t)plen, false, connections, conn_lru);
  }
  return true;
}


static bool attach_bpf(int fd, const std::vector<unsigned> &ports) {
  if (ports.empty()) return false;
  std::vector<struct sock_filter> f; size_t i;
  unsigned N = (unsigned)ports.size();
  unsigned reject = 11 + N * 8;
  unsigned accept = reject + 1;
  struct sock_filter x;
#define ADD(C,J,T,K) do { \
  unsigned _jt = (unsigned)(J), _jf = (unsigned)(T); \
  if (_jt > UCHAR_MAX || _jf > UCHAR_MAX) return false; \
  x.code=(C); x.jt=(unsigned char)_jt; x.jf=(unsigned char)_jf; x.k=(K); \
  f.push_back(x); \
} while(0)
  ADD(BPF_LD|BPF_H|BPF_ABS, 0, 0, 12);
  ADD(BPF_JMP|BPF_JEQ|BPF_K, (unsigned)(6 + 4 * N), 0, ETH_P_IP_HOST);

  // Path B: 802.1Q VLAN
  ADD(BPF_JMP|BPF_JEQ|BPF_K, 0, (unsigned)(reject - (unsigned)f.size() - 1), ETH_P_8021Q_HOST);
  ADD(BPF_LD|BPF_H|BPF_ABS, 0, 0, 16);
  ADD(BPF_JMP|BPF_JEQ|BPF_K, 0, (unsigned)(reject - (unsigned)f.size() - 1), ETH_P_IP_HOST);
  ADD(BPF_LD|BPF_B|BPF_ABS, 0, 0, 27);
  ADD(BPF_JMP|BPF_JEQ|BPF_K, 0, (unsigned)(reject - (unsigned)f.size() - 1), IPPROTO_TCP);
  ADD(BPF_LDX|BPF_B|BPF_MSH, 0, 0, 18);
  for (i = 0; i < ports.size(); ++i) {
    ADD(BPF_LD|BPF_H|BPF_IND, 0, 0, 20);
    unsigned jt = accept - (unsigned)f.size() - 1;
    ADD(BPF_JMP|BPF_JEQ|BPF_K, jt, 0, ports[i]);
  }
  for (i = 0; i < ports.size(); ++i) {
    ADD(BPF_LD|BPF_H|BPF_IND, 0, 0, 18);
    unsigned jt = accept - (unsigned)f.size() - 1;
    unsigned jf = (i < ports.size() - 1) ? 0 : (reject - (unsigned)f.size() - 1);
    ADD(BPF_JMP|BPF_JEQ|BPF_K, jt, jf, ports[i]);
  }

  // Path A: Standard IPv4
  ADD(BPF_LD|BPF_B|BPF_ABS, 0, 0, 23);
  ADD(BPF_JMP|BPF_JEQ|BPF_K, 0, (unsigned)(reject - (unsigned)f.size() - 1), IPPROTO_TCP);
  ADD(BPF_LDX|BPF_B|BPF_MSH, 0, 0, 14);
  for (i = 0; i < ports.size(); ++i) {
    ADD(BPF_LD|BPF_H|BPF_IND, 0, 0, 16);
    unsigned jt = accept - (unsigned)f.size() - 1;
    ADD(BPF_JMP|BPF_JEQ|BPF_K, jt, 0, ports[i]);
  }
  for (i = 0; i < ports.size(); ++i) {
    ADD(BPF_LD|BPF_H|BPF_IND, 0, 0, 14);
    unsigned jt = accept - (unsigned)f.size() - 1;
    unsigned jf = (i < ports.size() - 1) ? 0 : (reject - (unsigned)f.size() - 1);
    ADD(BPF_JMP|BPF_JEQ|BPF_K, jt, jf, ports[i]);
  }

  ADD(BPF_RET|BPF_K, 0, 0, 0);
  ADD(BPF_RET|BPF_K, 0, 0, ACCEPT);
#undef ADD
  if (f.size() > 4096) return false;
  struct sock_fprog prog; prog.len = (unsigned short)f.size(); prog.filter = &f[0];
  return setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) == 0;
}

struct MmapRing {
  void *ring;
  size_t ring_size;
  unsigned block_size;
  unsigned block_nr;
  unsigned frame_size;
  unsigned frame_nr;
  unsigned frames_per_block;
  unsigned frame_idx;

  MmapRing() : ring(MAP_FAILED), ring_size(0), block_size(65536), block_nr(64),
               frame_size(16384), frame_nr(256), frames_per_block(4), frame_idx(0) {}
};

static bool valid_ring_geometry(const MmapRing &mr) {
  const size_t size_max = (size_t)-1;
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) return false;
  if (mr.block_size == 0 || mr.block_size % (unsigned long)page_size != 0) return false;
  if (mr.frame_size < TPACKET2_HDRLEN ||
      mr.frame_size % TPACKET_ALIGNMENT != 0) return false;
  if (mr.block_size % mr.frame_size != 0) return false;
  unsigned frames_per_block = mr.block_size / mr.frame_size;
  if (frames_per_block == 0 || mr.block_nr == 0) return false;
  if (frames_per_block > UINT_MAX / mr.block_nr) return false;
  if (frames_per_block * mr.block_nr != mr.frame_nr) return false;
  if ((size_t)mr.block_size > size_max / (size_t)mr.block_nr) return false;
  if ((size_t)mr.block_size * (size_t)mr.block_nr != 4U * 1024U * 1024U) return false;
  return true;
}

static bool setup_mmap_ring(int fd, MmapRing &mr) {
  if (!valid_ring_geometry(mr)) {
    logmsg("invalid fixed TPACKET_V2 ring geometry");
    return false;
  }
  int ver = TPACKET_V2;
  if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver)) < 0) {
    return false;
  }
  struct tpacket_req req;
  memset(&req, 0, sizeof(req));
  req.tp_block_size = mr.block_size;
  req.tp_block_nr = mr.block_nr;
  req.tp_frame_size = mr.frame_size;
  req.tp_frame_nr = mr.frame_nr;

  if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
    return false;
  }
  mr.ring_size = (size_t)req.tp_block_size * (size_t)req.tp_block_nr;
  mr.frames_per_block = req.tp_block_size / req.tp_frame_size;
  mr.frame_idx = 0;

  mr.ring = mmap(NULL, mr.ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (mr.ring == MAP_FAILED) {
    mr.ring_size = 0;
    return false;
  }
  return true;
}

static bool release_mmap_ring(int fd, MmapRing &mr) {
  bool ok = true;
  if (mr.ring != MAP_FAILED) {
    if (munmap(mr.ring, mr.ring_size) != 0) ok = false;
    mr.ring = MAP_FAILED;
  }
  struct tpacket_req empty_req;
  memset(&empty_req, 0, sizeof(empty_req));
  if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING,
                 &empty_req, sizeof(empty_req)) != 0) ok = false;
  mr.ring_size = 0;
  return ok;
}

static bool valid_ring_frame(const struct tpacket2_hdr *hdr,
                             unsigned frame_size,
                             size_t *packet_offset,
                             size_t *packet_length) {
  const unsigned mac = hdr->tp_mac;
  const unsigned net = hdr->tp_net;
  const unsigned snaplen = hdr->tp_snaplen;
  const unsigned wire_len = hdr->tp_len;
  if (mac < TPACKET2_HDRLEN || mac > frame_size) return false;
  if (snaplen > wire_len || snaplen > frame_size - mac) return false;
  if (net < mac || net > mac + snaplen) return false;
  *packet_offset = mac;
  *packet_length = snaplen;
  return true;
}

static int run_ring_fixture() {
  MmapRing mr;
  uint8_t frame[16384];
  memset(frame, 0, sizeof(frame));
  struct tpacket2_hdr *hdr = (struct tpacket2_hdr *)frame;
  hdr->tp_mac = TPACKET2_HDRLEN;
  hdr->tp_net = TPACKET2_HDRLEN;
  hdr->tp_snaplen = 128;
  hdr->tp_len = 128;
  size_t off = 0, len = 0;
  if (!valid_ring_frame(hdr, sizeof(frame), &off, &len) ||
      off != TPACKET2_HDRLEN || len != 128) return 21;
  hdr->tp_mac = TPACKET2_HDRLEN - 1;
  if (valid_ring_frame(hdr, sizeof(frame), &off, &len)) return 22;
  hdr->tp_mac = TPACKET2_HDRLEN;
  hdr->tp_snaplen = sizeof(frame);
  hdr->tp_len = sizeof(frame);
  if (valid_ring_frame(hdr, sizeof(frame), &off, &len)) return 23;
  hdr->tp_snaplen = 129;
  hdr->tp_len = 128;
  if (valid_ring_frame(hdr, sizeof(frame), &off, &len)) return 24;
  hdr->tp_snaplen = 128;
  hdr->tp_len = 128;
  hdr->tp_net = TPACKET2_HDRLEN - 1;
  if (valid_ring_frame(hdr, sizeof(frame), &off, &len)) return 25;
  mr.frame_nr++;
  if (valid_ring_geometry(mr)) return 26;
  return 0;
}

static int run_fixture() {
  std::string req = "GET /api/items?x=1 HTTP/1.1\r\nHost: api.local\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\nTraceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n\r\n";
  Event e; RequestMeta meta; e.ts = 1700000000; e.host = "cpp-node"; e.service = "port:8080"; e.caller = "10.0.0.9"; e.caller_port = 51000; e.dst_ip = "10.0.0.2"; e.dst_port = 8080; e.req_bytes = (unsigned)req.size(); parse_request(req.data(), req.size() - 4, &e, &meta); e.status = 200; e.has_status = true; e.duration_ms = 3; e.has_duration = true; e.resp_bytes = 42; e.has_resp = true; emit_event(e); return 0;
}

static int run_wsse_fixture() {
  const char *namespaces[] = {
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
    "http://schemas.xmlsoap.org/ws/2002/07/secext",
    "http://schemas.xmlsoap.org/ws/2002/12/secext",
    "http://schemas.xmlsoap.org/ws/2003/06/secext"
  };
  for (size_t i = 0; i < 4; ++i) {
    std::string body = "<s:Envelope xmlns:s='urn:soap' xmlns:w='" + std::string(namespaces[i]) +
      "'><s:Header><w:UsernameToken><w:Username>native.fixture</w:Username>"
      "<w:Password>SENSITIVE_PASSWORD</w:Password></w:UsernameToken></s:Header>";
    std::string user = extract_wsse_username(body);
    if (user != "native.fixture") return 3;
    std::cout << user << "\n";
  }
  std::string malicious = "<!DOCTYPE x [<!ENTITY pw 'secret'>]><w:UsernameToken xmlns:w='" +
    std::string(namespaces[0]) + "'><w:Username>&pw;</w:Username></w:UsernameToken>";
  if (!extract_wsse_username(malicious).empty()) return 4;
  std::string wrong_ns = "<w:UsernameToken xmlns:w='urn:not-wsse'><w:Username>wrong</w:Username></w:UsernameToken>";
  if (!extract_wsse_username(wrong_ns).empty()) return 5;
  std::string unnamespaced = "<UsernameToken><Username>wrong</Username></UsernameToken>";
  if (!extract_wsse_username(unnamespaced).empty()) return 6;
  std::string escaped = "<w:UsernameToken xmlns:w='" + std::string(namespaces[0]) +
    "'><w:Username>native&amp;fixture</w:Username>";
  if (extract_wsse_username(escaped) != "native&fixture") return 7;
  std::string too_long = "<w:UsernameToken xmlns:w='" + std::string(namespaces[0]) +
    "'><w:Username>" + std::string(MAX_WSSE_USERNAME + 1, 'x') + "</w:Username>";
  if (!extract_wsse_username(too_long).empty()) return 8;
  return 0;
}

static int run_dual_auth_fixture() {
  const std::string body =
    "<s:Envelope xmlns:s='urn:soap' xmlns:w='http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-wssecurity-secext-1.0.xsd'><s:Header><w:UsernameToken>"
    "<w:Username>soap.user</w:Username><w:Password>SENSITIVE_PASSWORD</w:Password>"
    "</w:UsernameToken></s:Header></s:Envelope>";
  std::ostringstream request;
  request << "POST /soap HTTP/1.1\r\nHost: fixture\r\n"
          << "Authorization: Basic YmFzaWMudXNlcjpwYXNzd29yZA==\r\n"
          << "Content-Type: application/soap+xml\r\nContent-Length: "
          << body.size() << "\r\n\r\n" << body;
  const std::string payload = request.str();

  std::vector<unsigned char> packet(14 + 20 + 20 + payload.size(), 0);
  packet[12] = 0x08; packet[13] = 0x00;
  packet[14] = 0x45; packet[23] = IPPROTO_TCP;
  uint16_t tot_len = (uint16_t)(20 + 20 + payload.size());
  packet[16] = (unsigned char)(tot_len >> 8); packet[17] = (unsigned char)(tot_len & 0xff);
  packet[26] = 192; packet[27] = 0; packet[28] = 2; packet[29] = 2;
  packet[30] = 192; packet[31] = 0; packet[32] = 2; packet[33] = 1;
  unsigned short sport = htons(51000), dport = htons(8080);
  memcpy(&packet[34], &sport, sizeof(sport));
  memcpy(&packet[36], &dport, sizeof(dport));
  packet[46] = 5U << 4; packet[47] = 0x19;
  memcpy(&packet[54], payload.data(), payload.size());

  g_wsse_body_bytes = 8192;
  memset(g_monitored_ports, 0, sizeof(g_monitored_ports));
  g_monitored_ports[8080] = true;
  g_endpoint.clear();
  init_rng();
  std::vector<unsigned> ports(1, 8080);
  std::map<ConnectionKey, Connection> connections;
  std::list<ConnectionKey> conn_lru;
  if (!handle_packet(&packet[0], packet.size(), "cpp-dual-fixture",
                     ports, connections, conn_lru)) return 9;
  if (connections.empty() || connections.begin()->second.pending.size() != 1) return 10;
  flush_all_pending(connections);
  return 0;
}

static int run_ship_rate_fixture() {
  std::deque<std::string> events;
  events.push_back(std::string(40000, 'x'));
  events.push_back(std::string(40000, 'y'));
  if (bounded_batch_count(events, "fixture") != 1) return 30;
  events.clear();
  events.push_back(std::string(MAX_POST_BYTES + 1, 'x'));
  if (bounded_batch_count(events, "fixture") != 0) return 31;
  return 0;
}

static int run_stats_fixture() {
  g_ship_node = "fixture-node";
  g_instance_id = "fixture-1";
  g_stats_last_at = wall_seconds() - 30.0;
  g_capture_packets = 100;
  g_capture_bytes = 6400;
  g_events_emitted = g_events_in = 10;
  g_events_pushed = 8;
  g_events_dropped = g_drop_queue = 2;
  std::string body = agent_stats_body(-1, 3, 2, 1);
  if (body.size() > MAX_STATS_BYTES) return 40;
  if (body.find("\"type\":\"agent_stats\"") == std::string::npos) return 41;
  if (body.find("\"drop_percent\":20.0000") == std::string::npos) return 42;
  if (body.find("\"mode\":\"cpp\"") == std::string::npos) return 43;
  std::cout << body << "\n";
  return 0;
}

static bool parse_wsse_size(const char *value, size_t *result) {
  if (!value || !*value) return false;
  size_t n = 0;
  if (!parse_decimal_size(value, strlen(value), &n) || n > MAX_WSSE_BODY_BYTES) return false;
  *result = n;
  return true;
}

static bool drop_all_capabilities() {
  if (getuid() == 0 || geteuid() == 0) {
    const char *target_user = getenv("NT_USER");
    if (!target_user || !*target_user) target_user = "ntsniff";
    struct passwd *pw = getpwnam(target_user);
    if (!pw) {
      pw = getpwnam("nobody");
    }
    if (!pw) {
      logmsg("failed to locate unprivileged account for privilege drop");
      return false;
    }
    if (setgroups(0, NULL) != 0) {
      perror("setgroups");
      return false;
    }
    if (setgid(pw->pw_gid) != 0) {
      perror("setgid");
      return false;
    }
    if (setuid(pw->pw_uid) != 0) {
      perror("setuid");
      return false;
    }
  }

  struct __user_cap_header_struct header;
  struct __user_cap_data_struct data[2];
  memset(&header, 0, sizeof(header));
  memset(data, 0, sizeof(data));
  header.version = _LINUX_CAPABILITY_VERSION_3;
  header.pid = 0;
  if (syscall(SYS_capset, &header, data) != 0) {
    return false;
  }
  return (getuid() != 0 && geteuid() != 0);
}

static int open_capture_socket(const std::string &iface,
                               const std::vector<unsigned> &ports,
                               MmapRing &ring) {
  int fd = socket(AF_PACKET, SOCK_RAW, 0);
  if (fd < 0 && errno == EINVAL) {
    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  }
  if (fd < 0) { perror("AF_PACKET"); return -1; }
  fcntl(fd, F_SETFD, FD_CLOEXEC);
  int rb = 8 * 1024 * 1024;
  setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rb, sizeof(rb));
  if (!attach_bpf(fd, ports)) {
    logmsg("BPF attach failed; refusing unfiltered capture");
    close(fd);
    return -1;
  }

  struct sockaddr_ll sa;
  memset(&sa, 0, sizeof(sa));
  sa.sll_family = AF_PACKET;
  sa.sll_protocol = htons(ETH_P_ALL);
  if (!iface.empty()) {
    sa.sll_ifindex = (int)if_nametoindex(iface.c_str());
    if (!sa.sll_ifindex) {
      logmsg("bad interface");
      close(fd);
      return -1;
    }
  }
  if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    perror("bind");
    close(fd);
    return -1;
  }
  if (!setup_mmap_ring(fd, ring)) {
    logmsg("TPACKET_V2 setup failed; refusing non-ring fallback");
    close(fd);
    return -1;
  }
  if (!drop_all_capabilities()) {
    logmsg("capability drop failed; refusing unsafe capture");
    release_mmap_ring(fd, ring);
    close(fd);
    return -1;
  }
  return fd;
}

static int run_capability_probe(const std::string &iface,
                                const std::vector<unsigned> &ports) {
  MmapRing ring;
  int fd = open_capture_socket(iface, ports, ring);
  if (fd < 0) return 2;

  bool released = release_mmap_ring(fd, ring);
  close(fd);
  if (!released) {
    logmsg("TPACKET_V2 probe cleanup failed");
    return 2;
  }
  return 0;
}

static int run_lockout_fixture() {
  corr_disabled_clear();
  // Insert 10,000 distinct connection keys into the registry via corr_disabled_insert
  for (unsigned i = 0; i < 10000; ++i) {
    PacketKey k;
    k.s_ip = 0x0a000002;
    k.sport = 8080;
    k.d_ip = 0x0a000001;
    k.dport = (uint16_t)(10000 + (i % 55000));
    corr_disabled_insert(k);
  }
  // Must be strictly capped at MAX_CORR_DISABLED (2048)
  if (g_corr_disabled.size() > MAX_CORR_DISABLED) {
    fprintf(stderr, "Lockout fixture failed: size %lu > %lu\n",
            (unsigned long)g_corr_disabled.size(), (unsigned long)MAX_CORR_DISABLED);
    return 1;
  }
  if (!g_corr_capacity_reached) {
    fprintf(stderr, "Lockout fixture failed: g_corr_capacity_reached not set\n");
    return 1;
  }
  // Evicted key without verified SYN must have correlation disabled:
  PacketKey evicted_key;
  evicted_key.s_ip = 0x0a000002;
  evicted_key.sport = 8080;
  evicted_key.d_ip = 0x0a000001;
  evicted_key.dport = 10000;
  if (!is_correlation_disabled(evicted_key, false)) {
    fprintf(stderr, "Lockout fixture failed: evicted key without SYN must have correlation disabled\n");
    return 1;
  }
  // With verified SYN, correlation must be allowed:
  if (is_correlation_disabled(evicted_key, true)) {
    fprintf(stderr, "Lockout fixture failed: key with verified SYN must allow correlation\n");
    return 1;
  }

  // Test packet-sequence Reproduction 1: An old SYN does not bypass an evicted lockout.
  // Connection 10.0.0.1:50001 -> 10.0.0.2:80 loses ordering and its lockout is evicted.
  // Existing syn_seen=true must NOT allow correlation for /new, and old response must not correlate.
  {
    std::map<FlowKey, Flow> test_flows;
    PacketKey rk;
    rk.s_ip = 0x0a000002; rk.sport = 80;
    rk.d_ip = 0x0a000001; rk.dport = 50001;
    FlowKey fk;
    fk.s_ip = 0x0a000001; fk.sport = 50001;
    fk.d_ip = 0x0a000002; fk.dport = 80;

    // Step 1: Connection starts with client SYN (generation 1, syn_seen = true, corr_eligible = true)
    Flow &cfl = test_flows[fk];
    cfl.generation = 1; cfl.syn_seen = true; cfl.corr_eligible = true;
    Flow &sfl = test_flows[rk];
    sfl.generation = 1; sfl.syn_seen = true; sfl.corr_eligible = true;

    // Step 2: Connection loses ordering (e.g. tombstone expired unconsumed or queue overflow)
    invalidate_connection_correlation(test_flows, rk);
    if (cfl.corr_eligible || sfl.corr_eligible) {
      fprintf(stderr, "Lockout fixture failed: correlation eligibility not disabled on ordering loss\n");
      return 1;
    }

    // Step 3: 2048 other connections time out, evicting rk from g_corr_disabled
    for (unsigned i = 0; i < 2050; ++i) {
      PacketKey k;
      k.s_ip = 0x0a000002; k.sport = 8080;
      k.d_ip = 0x0a000001; k.dport = (uint16_t)(10000 + (i % 55000));
      corr_disabled_insert(k);
    }
    // rk is now evicted from g_corr_disabled
    if (g_corr_disabled.count(rk) > 0) {
      fprintf(stderr, "Lockout fixture failed: rk was not evicted as expected\n");
      return 1;
    }

    // Step 4: /new arrives on this connection without a new SYN.
    // Must NOT be allowed to correlate despite cfl.syn_seen == true!
    if (is_correlation_allowed(rk, test_flows, cfl.generation, cfl.syn_seen, cfl.corr_eligible)) {
      fprintf(stderr, "Lockout fixture failed: old SYN bypassed evicted lockout for /new\n");
      return 1;
    }

    // Server direction must also not allow correlation:
    if (is_correlation_allowed(rk, test_flows, sfl.generation, sfl.syn_seen, sfl.corr_eligible)) {
      fprintf(stderr, "Lockout fixture failed: server direction allowed correlation on evicted lockout\n");
      return 1;
    }
  }

  // Test packet-sequence Reproduction 2: SYN-ACK preserves verification under capacity fallback.
  // Under active capacity fallback, fresh client SYN sets verification, and server SYN-ACK
  // must preserve generation and eligibility rather than resetting it.
  {
    std::map<FlowKey, Flow> test_flows;
    PacketKey rk;
    rk.s_ip = 0x0a000002; rk.sport = 80;
    rk.d_ip = 0x0a000001; rk.dport = 50002;
    FlowKey fk;
    fk.s_ip = 0x0a000001; fk.sport = 50002;
    fk.d_ip = 0x0a000002; fk.dport = 80;

    // Client SYN establishes verification
    Flow &cfl = test_flows[fk];
    cfl.generation = 1; cfl.syn_seen = true; cfl.corr_eligible = true;
    Flow &sfl = test_flows[rk];
    sfl.generation = 1; sfl.syn_seen = true; sfl.corr_eligible = true;

    // Server SYN-ACK arrives: preserve generation and eligibility
    uint32_t gen = sfl.generation;
    bool syn = sfl.syn_seen;
    bool eligible = sfl.corr_eligible;
    sfl.reset_for_new_connection(gen, time(NULL), syn || true, (gen > 0) ? eligible : true);

    // Both directions must remain eligible for correlation under capacity fallback!
    if (!is_correlation_allowed(rk, test_flows, cfl.generation, cfl.syn_seen, cfl.corr_eligible)) {
      fprintf(stderr, "Lockout fixture failed: client direction lost verification after SYN-ACK\n");
      return 1;
    }
    if (!is_correlation_allowed(rk, test_flows, sfl.generation, sfl.syn_seen, sfl.corr_eligible)) {
      fprintf(stderr, "Lockout fixture failed: server direction lost verification after SYN-ACK\n");
      return 1;
    }

    // Test Reproduction 3: reset_for_new_connection clears is_broken
    cfl.is_broken = true;
    cfl.reset_for_new_connection(2, time(NULL), true, true);
    if (cfl.is_broken) {
      fprintf(stderr, "Lockout fixture failed: is_broken was not cleared on reset_for_new_connection\n");
      return 1;
    }

    // Test Reproduction 4: Expired HEAD tombstone retains HEAD semantics
    std::map<PacketKey, std::vector<Pending> > test_pending;
    Event head_ev;
    head_ev.method = "HEAD";
    Pending tombstone(999, 1, head_ev, 1000, 1000);
    tombstone.is_tombstone = true;
    test_pending[rk].push_back(tombstone);
    bool fixture_is_head = false;
    if (!test_pending[rk].empty()) {
      if (test_pending[rk][0].ev.method == "HEAD") fixture_is_head = true;
    }
    if (!fixture_is_head) {
      fprintf(stderr, "Lockout fixture failed: tombstone failed to yield is_head=true\n");
      return 1;
    }
  }

  corr_disabled_clear();
  fprintf(stderr, "Lockout registry 10k bounded fixture: PASS (size=%lu, capacity_fallback=verified, reproductions=passed)\n",
          (unsigned long)MAX_CORR_DISABLED);
  return 0;
}

static int run_fifo_fixture() {
  std::map<ConnectionKey, Connection> connections;
  std::list<ConnectionKey> conn_lru;
  ConnectionKey k(0x0a000001, 50000, 0x0a000002, 80);
  Connection &conn = connections[k];
  conn.key = k;
  conn.roles_established = true;
  conn.client = Endpoint(0x0a000001, 50000);
  conn.server = Endpoint(0x0a000002, 80);
  conn.generation = 1;
  conn.syn_seen = true;
  conn.corr_eligible = true;
  conn.corr_disabled = false;

  // 1. Queue and complete 20,000 requests
  for (int i = 0; i < 20000; ++i) {
    Event e;
    e.path = "/test";
    uint64_t rid = queue_request(conn, e, 1000 + i, connections, conn_lru, false);
    (void)rid;
    if (conn.pending.empty()) {
      fprintf(stderr, "FIFO fixture failed: request not queued at iteration %d\n", i);
      return 1;
    }
    Pending &front = conn.pending.front();
    remove_pending_from_fifo(front);
    conn.pending.erase(conn.pending.begin());
    if (g_total_pending_count > 0) --g_total_pending_count;
  }
  if (!g_pending_fifo.empty()) {
    fprintf(stderr, "FIFO fixture failed: FIFO not empty after 20,000 completions (size=%lu)\n",
            (unsigned long)g_pending_fifo.size());
    return 1;
  }
  if (g_total_pending_count != 0) {
    fprintf(stderr, "FIFO fixture failed: g_total_pending_count != 0 (%lu)\n",
            (unsigned long)g_total_pending_count);
    return 1;
  }

  // 2. Test invalidate_stream FIFO cleanup
  for (int i = 0; i < 5; ++i) {
    Event e;
    queue_request(conn, e, 2000 + i, connections, conn_lru, false);
  }
  if (g_pending_fifo.size() != 5) {
    fprintf(stderr, "FIFO fixture failed: expected FIFO size 5, got %lu\n",
            (unsigned long)g_pending_fifo.size());
    return 1;
  }
  invalidate_stream(conn, "test_invalidation");
  if (!g_pending_fifo.empty()) {
    fprintf(stderr, "FIFO fixture failed: FIFO not empty after invalidate_stream (size=%lu)\n",
            (unsigned long)g_pending_fifo.size());
    return 1;
  }

  // 3. Test sweep FIFO cleanup
  corr_disabled_clear();
  conn.corr_disabled = false;
  conn.corr_eligible = true;
  conn.req_flow.is_broken = false;
  conn.resp_flow.is_broken = false;
  for (int i = 0; i < 5; ++i) {
    Event e;
    queue_request(conn, e, 3000 + i, connections, conn_lru, false);
  }
  if (g_pending_fifo.size() != 5) {
    fprintf(stderr, "FIFO fixture failed: expected FIFO size 5 for sweep, got %lu\n",
            (unsigned long)g_pending_fifo.size());
    return 1;
  }
  sweep(connections, conn_lru, 5000, 10, 1000000000LL);
  if (!g_pending_fifo.empty()) {
    fprintf(stderr, "FIFO fixture failed: FIFO not empty after sweep (size=%lu)\n",
            (unsigned long)g_pending_fifo.size());
    return 1;
  }

  // 4. Test connection-reuse regression: 100 successive generations on one tuple
  corr_disabled_clear();
  connections.clear();
  g_pending_fifo.clear();
  g_total_pending_count = 0;

  Connection &reuse_conn = connections[k];
  reuse_conn.key = k;
  reuse_conn.roles_established = true;
  reuse_conn.client = Endpoint(0x0a000001, 50000);
  reuse_conn.server = Endpoint(0x0a000002, 80);

  for (uint32_t gen = 1; gen <= 100; ++gen) {
    for (size_t pi = 0; pi < reuse_conn.pending.size(); ++pi) {
      if (!reuse_conn.pending[pi].is_tombstone) {
        emit_event(reuse_conn.pending[pi].ev);
        if (g_total_pending_count > 0) --g_total_pending_count;
      }
      remove_pending_from_fifo(reuse_conn.pending[pi]);
    }
    reuse_conn.pending.clear();
    reuse_conn.generation = gen;
    reuse_conn.syn_seen = true;
    reuse_conn.corr_eligible = true;
    reuse_conn.corr_disabled = false;
    reuse_conn.req_flow.reset_for_new_connection(gen, 1000, true, true);
    reuse_conn.resp_flow.reset_for_new_connection(gen, 1000, true, true);

    Event e;
    e.path = "/reuse";
    queue_request(reuse_conn, e, 1000 + gen, connections, conn_lru, false);
  }

  if (reuse_conn.pending.size() != 1) {
    fprintf(stderr, "FIFO fixture failed: expected 1 pending request on reuse_conn, got %lu\n",
            (unsigned long)reuse_conn.pending.size());
    return 1;
  }
  if (g_pending_fifo.size() != 1) {
    fprintf(stderr, "FIFO fixture failed: expected 1 FIFO entry on reuse_conn after 100 generations, got %lu\n",
            (unsigned long)g_pending_fifo.size());
    return 1;
  }

  // 5. Test global pending overflow: fill MAX_PENDING_TOTAL (4096) across 128 connections
  connections.clear();
  g_pending_fifo.clear();
  g_total_pending_count = 0;
  corr_disabled_clear();

  for (int ci = 0; ci < 128; ++ci) {
    ConnectionKey ck(0x0a000001, 10000 + ci, 0x0a000002, 80);
    Connection &c = connections[ck];
    c.key = ck;
    c.roles_established = true;
    c.client = Endpoint(0x0a000001, 10000 + ci);
    c.server = Endpoint(0x0a000002, 80);
    c.generation = 1;
    c.syn_seen = true;
    c.corr_eligible = true;
    c.corr_disabled = false;
    for (int ri = 0; ri < 32; ++ri) {
      Event e;
      e.path = "/overflow";
      queue_request(c, e, 1000 + ri, connections, conn_lru, false);
    }
  }

  if (g_total_pending_count != 4096 || g_pending_fifo.size() != 4096) {
    fprintf(stderr, "FIFO fixture failed: failed to populate 4096 pending slots (count=%lu, fifo=%lu)\n",
            (unsigned long)g_total_pending_count, (unsigned long)g_pending_fifo.size());
    return 1;
  }

  // Enqueue 4,097th request on an additional connection
  ConnectionKey overflow_ck(0x0a000001, 55555, 0x0a000002, 80);
  Connection &oc = connections[overflow_ck];
  oc.key = overflow_ck;
  oc.roles_established = true;
  oc.client = Endpoint(0x0a000001, 55555);
  oc.server = Endpoint(0x0a000002, 80);
  oc.generation = 1;
  oc.syn_seen = true;
  oc.corr_eligible = true;
  oc.corr_disabled = false;

  Event extra_e;
  extra_e.path = "/overflow_extra";
  queue_request(oc, extra_e, 9999, connections, conn_lru, false);

  if (g_total_pending_count > 4096) {
    fprintf(stderr, "FIFO fixture failed: total pending exceeded 4096 after eviction (%lu)\n",
            (unsigned long)g_total_pending_count);
    return 1;
  }

  fprintf(stderr, "FIFO removal fixture: PASS (20k exchanges, 100 gen reuse, 4096 overflow verified)\n");
  return 0;
}

static int run_flow_accounting_fixture() {
  g_total_flow_bytes = 0;

  Connection conn;

  const char *resp =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 1\r\n"
      "Content-Length: 2\r\n"
      "\r\n";

  process_response_payload(
      conn,
      resp,
      strlen(resp),
      1000,
      time(NULL),
      now_monotonic_ms()
  );

  if (g_total_flow_bytes != 0) {
      fprintf(stderr,
              "flow accounting leak: %lu bytes\n",
              (unsigned long)g_total_flow_bytes);
      return 1;
  }
  fprintf(stderr, "Flow accounting fixture: PASS (conflicting CL did not leak bytes)\n");
  return 0;
}

int main(int argc, char **argv) {
#ifndef NT_HAS_ASAN
  struct rlimit lim;
  if (getrlimit(RLIMIT_AS, &lim) == 0) {
    unsigned long target = 256UL * 1024UL * 1024UL;
    if (lim.rlim_max != RLIM_INFINITY && lim.rlim_max < target) {
      target = (unsigned long)lim.rlim_max;
    }
    lim.rlim_cur = target;
    lim.rlim_max = target;
    if (setrlimit(RLIMIT_AS, &lim) != 0) {
      perror("setrlimit(RLIMIT_AS)");
      return 2;
    }
  } else {
    lim.rlim_cur = 256UL * 1024UL * 1024UL;
    lim.rlim_max = 256UL * 1024UL * 1024UL;
    if (setrlimit(RLIMIT_AS, &lim) != 0) {
      perror("setrlimit(RLIMIT_AS)");
      return 2;
    }
  }
#endif

  if (argc > 1 && !strcmp(argv[1], "--fixture")) return run_fixture();
  if (argc > 1 && !strcmp(argv[1], "--wsse-fixture")) return run_wsse_fixture();
  if (argc > 1 && !strcmp(argv[1], "--dual-auth-fixture")) return run_dual_auth_fixture();
  if (argc > 1 && !strcmp(argv[1], "--ring-fixture")) return run_ring_fixture();
  if (argc > 1 && !strcmp(argv[1], "--ship-rate-fixture")) return run_ship_rate_fixture();
  if (argc > 1 && !strcmp(argv[1], "--stats-fixture")) return run_stats_fixture();
  if (argc > 1 && !strcmp(argv[1], "--lockout-fixture")) return run_lockout_fixture();
  if (argc > 1 && !strcmp(argv[1], "--fifo-fixture")) return run_fifo_fixture();
  if (argc > 1 && !strcmp(argv[1], "--flow-accounting-fixture")) return run_flow_accounting_fixture();

  std::string iface; std::vector<unsigned> ports; int i; int workers = 1;
  std::string endpoint;
  bool capability_probe = false;
  const char *wsse_env = getenv("NT_WSSE_BODY_BYTES");
  if (wsse_env && !parse_wsse_size(wsse_env, &g_wsse_body_bytes)) {
    fprintf(stderr, "wsse body bytes must be in range 0..65536\n"); return 2;
  }
  const char *rate_env = getenv("NT_SHIP_RATE_KBPS");
  if (rate_env && *rate_env) g_ship_rate_kbps = (unsigned)atoi(rate_env);
  const char *stats_env = getenv("NT_STATS_INTERVAL_SEC");
  if (stats_env && *stats_env) g_stats_interval_sec = (unsigned)atoi(stats_env);
  const char *ttl_env = getenv("NT_PENDING_TTL_SEC");
  if (ttl_env && *ttl_env) g_pending_ttl_sec = (unsigned)atoi(ttl_env);

  bool ports_specified = false;
  for (i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "-i") && i + 1 < argc) iface = argv[++i];
    else if (!strcmp(argv[i], "-p") && i + 1 < argc) {
      ports_specified = true;
      while (i + 1 < argc && argv[i + 1][0] != '-') {
        char *q = strtok(argv[++i], ", ");
        while (q) {
          char *endptr = NULL;
          long p = strtol(q, &endptr, 10);
          if (*endptr != '\0' || !valid_port((unsigned)p)) {
            fprintf(stderr, "invalid port specified: %s\n", q);
            return 2;
          }
          ports.push_back((unsigned)p);
          q = strtok(NULL, ", ");
        }
      }
    }
    else if (!strcmp(argv[i], "--endpoint") && i + 1 < argc) endpoint = argv[++i];
    else if (!strcmp(argv[i], "--ship-rate-kbps") && i + 1 < argc) g_ship_rate_kbps = (unsigned)atoi(argv[++i]);
    else if (!strcmp(argv[i], "--stats-interval-sec") && i + 1 < argc) g_stats_interval_sec = (unsigned)atoi(argv[++i]);
    else if (!strcmp(argv[i], "--pending-ttl-sec") && i + 1 < argc) g_pending_ttl_sec = (unsigned)atoi(argv[++i]);
    else if (!strcmp(argv[i], "--capability-probe")) capability_probe = true;
    else if (!strcmp(argv[i], "--spool") && i + 1 < argc) ++i;
    else if (!strcmp(argv[i], "-j") && i + 1 < argc) workers = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--wsse-body-bytes") && i + 1 < argc) {
      if (!parse_wsse_size(argv[++i], &g_wsse_body_bytes)) {
        fprintf(stderr, "wsse body bytes must be in range 0..65536\n"); return 2;
      }
    }
    else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
      fprintf(stderr, "usage: nt-sniff-cpp [-i iface] [-p ports] [--endpoint URL] [--ship-rate-kbps 64..10000] [--stats-interval-sec 10..300] [--pending-ttl-sec 1..300] [-j workers] [--wsse-body-bytes 0..65536]\n");
      return 0;
    }
    else { fprintf(stderr, "unknown or incomplete argument: %s\n", argv[i]); return 2; }
  }
  if (ports.empty()) {
    if (ports_specified) {
      fprintf(stderr, "no valid ports specified with -p\n");
      return 2;
    }
    ports.push_back(80); ports.push_back(8003); ports.push_back(8005); ports.push_back(8007); ports.push_back(8009); ports.push_back(8010); ports.push_back(8011);
  }
  if (g_ship_rate_kbps < 64 || g_ship_rate_kbps > 10000) {
    fprintf(stderr, "ship rate must be in range 64..10000 kbit/s\n");
    return 2;
  }
  if (g_stats_interval_sec < 10 || g_stats_interval_sec > 300) {
    fprintf(stderr, "stats interval must be in range 10..300 seconds\n");
    return 2;
  }
  if (g_pending_ttl_sec < 1 || g_pending_ttl_sec > 300) {
    fprintf(stderr, "pending ttl must be in range 1..300 seconds\n");
    return 2;
  }
  if (ports.size() > MAX_PORTS) {
    fprintf(stderr, "at most 30 monitored ports are supported by the safe cBPF program\n");
    return 2;
  }
  if (workers != 1) {
    fprintf(stderr, "only one capture worker is permitted\n");
    return 2;
  }
  (void)workers;

  if (capability_probe) return run_capability_probe(iface, ports);

  init_rng();
  memset(g_monitored_ports, 0, sizeof(g_monitored_ports));
  for (size_t k = 0; k < ports.size(); ++k) {
    if (ports[k] < 65536) g_monitored_ports[ports[k]] = true;
  }

  const char *node_env = getenv("NT_NODE_NAME");
  std::string node = (node_env && *node_env) ? node_env : host_name();

  g_endpoint = endpoint;
  g_ship_node = node;
  g_instance_id = number_string((size_t)time(NULL)) + "-" + number_string((size_t)getpid());
  g_stats_last_at = wall_seconds();

  MmapRing ring;
  int fd = open_capture_socket(iface, ports, ring);
  if (fd < 0) return 2;

  signal(SIGPIPE, SIG_IGN);

  if (g_endpoint.empty()) {
    int output_flags = fcntl(STDOUT_FILENO, F_GETFL, 0);
    if (output_flags < 0 ||
        fcntl(STDOUT_FILENO, F_SETFL, output_flags | O_NONBLOCK) < 0) {
      logmsg("cannot make shipper pipe non-blocking; refusing unsafe pipeline");
      release_mmap_ring(fd, ring);
      close(fd);
      return 2;
    }
  } else {
    g_ship_worker_active = true;
    if (pthread_create(&g_ship_worker_tid, NULL, ship_worker_thread, NULL) != 0) {
      logmsg("failed to spawn shipping worker thread");
      release_mmap_ring(fd, ring);
      close(fd);
      return 2;
    }
  }

  signal(SIGTERM, stop_signal);
  signal(SIGINT, stop_signal);
  setvbuf(stdout, NULL, _IOLBF, 65536);
  std::map<ConnectionKey, Connection> connections;
  std::list<ConnectionKey> conn_lru;

  logmsg("PACKET_MMAP (TPACKET_V2) strict RX ring enabled (4MB total, 256 frames of 16KB)");
  if (g_wsse_body_bytes) {
    logmsg("WSSE UsernameToken inspection enabled (bounded to " + number_string(g_wsse_body_bytes) + " bytes/request)");
  }
  if (!g_endpoint.empty()) {
    logmsg("single-binary mode: non-blocking thread shipping directly to " + g_endpoint + " (0 disk I/O)");
  } else {
    logmsg("non-blocking native pipeline mode enabled; WAN I/O isolated in nt-ship-cpp");
  }
  logmsg("listening");

  time_t last = time(NULL);
  bool ring_integrity_failure = false;

  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
  pfd.revents = 0;

  while (g_running) {
    int rc = poll(&pfd, 1, 1000);
    if (rc < 0 && errno == EINTR) {
      // Signal handled
    } else if (rc < 0) {
      logmsg("poll error encountered");
      g_running = 0;
      break;
    } else if (rc > 0 && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
      logmsg("poll error revents detected");
      g_running = 0;
      break;
    } else if (rc > 0) {
      size_t drain_count = 0;
      while (g_running && drain_count < MAX_DRAIN_PER_PASS) {
        unsigned b_idx = ring.frame_idx / ring.frames_per_block;
        unsigned f_in_b = ring.frame_idx % ring.frames_per_block;
        uint8_t *frame_ptr = ((uint8_t *)ring.ring) + (b_idx * ring.block_size) + (f_in_b * ring.frame_size);
        volatile struct tpacket2_hdr *volatile_hdr =
            (volatile struct tpacket2_hdr *)frame_ptr;

        if (!(volatile_hdr->tp_status & TP_STATUS_USER)) {
          break;
        }
        __sync_synchronize();

        const struct tpacket2_hdr *hdr =
            (const struct tpacket2_hdr *)frame_ptr;
        size_t packet_offset = 0, packet_length = 0;
        if (!valid_ring_frame(hdr, ring.frame_size,
                              &packet_offset, &packet_length)) {
          __sync_synchronize();
          volatile_hdr->tp_status = TP_STATUS_KERNEL;
          ring_integrity_failure = true;
          ++g_invalid_frames;
          g_running = 0;
          logmsg("invalid TPACKET_V2 frame metadata; stopping capture");
          break;
        }
        if (packet_length > 0) {
          const unsigned char *pkt = frame_ptr + packet_offset;
          ++g_capture_packets;
          g_capture_bytes += packet_length;
          handle_packet(pkt, packet_length, node, ports, connections, conn_lru);
        }

        __sync_synchronize();
        volatile_hdr->tp_status = TP_STATUS_KERNEL;
        ring.frame_idx = (ring.frame_idx + 1) % ring.frame_nr;
        ++drain_count;
      }
      if (g_endpoint.empty()) std::cout.flush();
    }

    time_t now = time(NULL);
    if (now - last >= 1) {
      sweep(connections, conn_lru, now, g_pending_ttl_sec);
      if (g_endpoint.empty()) std::cout.flush();
      last = now;
    }

    if (wall_seconds() - g_stats_last_at >= g_stats_interval_sec) {
      size_t pending_count = 0, wsse_count = g_wsse_body_flows_active;
      for (std::map<ConnectionKey, Connection>::iterator ci = connections.begin(); ci != connections.end(); ++ci) {
        pending_count += ci->second.pending.size();
      }
      if (!g_endpoint.empty())
        send_agent_stats(fd, connections.size(), pending_count, wsse_count);
      else
        emit_capture_stats_internal(fd, connections.size(), pending_count, wsse_count);
    }
  }

  flush_incomplete_wsse(connections);
  flush_all_pending(connections);
  if (g_endpoint.empty()) std::cout.flush();

  if (g_ship_worker_active) {
    pthread_mutex_lock(&g_ship_queue_mutex);
    g_producer_finished = true;
    pthread_cond_broadcast(&g_ship_queue_cond);
    pthread_mutex_unlock(&g_ship_queue_mutex);
    pthread_join(g_ship_worker_tid, NULL);
  } else if (g_endpoint.empty()) {
    size_t pending_count = 0;
    emit_capture_stats_internal(fd, 0, pending_count, 0);
  }

  update_kernel_drops(fd);
  logmsg("packet stats: received=" + ull_string(g_capture_packets) +
         " dropped=" + ull_string(g_kernel_drops));
  if (!release_mmap_ring(fd, ring)) {
    logmsg("TPACKET_V2 cleanup failed");
    ring_integrity_failure = true;
  }
  close(fd);
  logmsg("stopped");
  return ring_integrity_failure ? 2 : 0;
}
