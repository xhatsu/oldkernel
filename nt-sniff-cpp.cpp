/*
 * nt-sniff-cpp.cpp - C++03-compatible old-kernel HTTP capture agent.
 *
 * Replaces the Python hot loop while retaining the oldkernel JSONL contract:
 * AF_PACKET -> classic BPF -> bounded HTTP header flow table -> response
 * correlation -> JSONL stdout -> nt-ship.py.
 *
 * Build target: CentOS 6 / GCC 4.4, Linux 2.6.32. No third-party deps.
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
#include <linux/filter.h>
#include <linux/capability.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <list>
#include <sstream>
#include <string>

#include <vector>
#include <algorithm>

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
static const unsigned FLOW_TTL = 15;
static const unsigned DEFAULT_PENDING_TTL = 30;
static unsigned g_pending_ttl_sec = DEFAULT_PENDING_TTL;
static const unsigned ACCEPT = 2048;
static const int SO_ATTACH_FILTER_OLD = 26;
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

/* Strict Base64 decoder with uint32 accumulator, immediate stop at ':', and invalid char rejection */
static std::string b64decode_user(const char *in, size_t in_len) {
  while (in_len > 0 && isspace((unsigned char)*in)) { ++in; --in_len; }
  while (in_len > 0 && isspace((unsigned char)in[in_len - 1])) { --in_len; }
  std::string out;
  uint32_t val = 0;
  int bits = -8;
  for (size_t i = 0; i < in_len; ++i) {
    unsigned char c = (unsigned char)in[i];
    int d = -1;
    if (c >= 'A' && c <= 'Z') d = c - 'A';
    else if (c >= 'a' && c <= 'z') d = c - 'a' + 26;
    else if (c >= '0' && c <= '9') d = c - '0' + 52;
    else if (c == '+') d = 62;
    else if (c == '/') d = 63;
    else if (c == '=') break;
    else if (isspace(c)) continue;
    else return "";
    val = (val << 6) | (uint32_t)d;
    bits += 6;
    if (bits >= 0) {
      char ch = (char)((val >> bits) & 0xff);
      bits -= 8;
      if (ch == ':') break;
      out += ch;
      if (out.size() > 64) break;
    }
  }
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
  RequestMeta() : content_length(0), has_content_length(false), has_conflict_cl(false) {}
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

struct Flow {
  uint32_t next_seq;
  bool has_seq;
  bool is_broken;
  bool correlation_disabled;
  bool syn_seen;
  time_t touched;
  long long first_byte_mono_ms;
  uint32_t generation;
  std::string buf;
  std::vector<TcpSegment> ooo;

  enum HttpState {
    HTTP_STATE_HEADER,
    HTTP_STATE_BODY,
    HTTP_STATE_CHUNK,
    HTTP_STATE_CLOSE_BODY
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

  Flow() : next_seq(0), has_seq(false), is_broken(false), correlation_disabled(false),
           syn_seen(false), touched(time(NULL)), first_byte_mono_ms(0), generation(0),
           state(HTTP_STATE_HEADER), body_remaining(0), chunk_payload_remaining(0),
           chunk_reading_len(true), chunk_reading_crlf(false), chunk_reading_trailer(false),
           awaiting_wsse(false), wsse_goal(0) {}


  void clear_buffers() {
    flow_bytes_sub(buf.size());
    buf.clear();
    flow_bytes_sub(wsse_buf.size());
    wsse_buf.clear();
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

static uint64_t g_req_id_seq = 0;

struct Pending {
  uint64_t req_id;
  uint32_t generation;
  Event ev;
  long long started_wall_ms;
  long long started_mono_ms;
  bool is_tombstone;
  long long tombstone_mono_ms;
  Pending() : req_id(0), generation(0), started_wall_ms(0), started_mono_ms(0),
              is_tombstone(false), tombstone_mono_ms(0) {}
  Pending(uint64_t id, uint32_t gen, const Event &e, long long wall_t, long long mono_t)
    : req_id(id), generation(gen), ev(e), started_wall_ms(wall_t), started_mono_ms(mono_t),
      is_tombstone(false), tombstone_mono_ms(0) {}
};

struct PendingQueueRef {
  uint64_t req_id;
  uint32_t generation;
  PacketKey key;
  long long started_mono_ms;
};

static size_t g_total_pending_count = 0;
static std::list<PendingQueueRef> g_pending_fifo;

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
  if (!sp2) sp2 = (eol > data && *(eol - 1) == '\r') ? eol - 1 : eol;
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
      size_t hname_len = colon - p;
      const char *val_start = colon + 1;
      while (val_start < line_end && (*val_start == ' ' || *val_start == '\t')) ++val_start;
      const char *val_end = line_end;
      while (val_end > val_start && (val_end[-1] == '\r' || val_end[-1] == '\n' || val_end[-1] == ' ' || val_end[-1] == '\t')) --val_end;
      size_t val_len = val_end - val_start;

      if (hname_len == 13 && !strncasecmp(p, "authorization", 13)) {
        if (val_len > 6 && !strncasecmp(val_start, "Basic ", 6)) {
          std::string basic_user = b64decode_user(val_start + 6, val_len - 6);
          if (!basic_user.empty()) {
            e->basic_user = basic_user;
            e->user = basic_user;
            e->scheme = "basic";
          }
        } else if (val_len > 7 && !strncasecmp(val_start, "Bearer ", 7)) {
          e->scheme = "bearer";
        }
      } else if (hname_len == 11 && !strncasecmp(p, "traceparent", 11)) {
        e->traceparent.assign(val_start, val_len);
        e->trace_id = trace_id_from_parent(e->traceparent);
      } else if (hname_len == 4 && !strncasecmp(p, "host", 4)) {
        e->host_hdr.assign(val_start, val_len);
      } else if (hname_len == 10 && !strncasecmp(p, "user-agent", 10)) {
        e->user_agent.assign(val_start, val_len);
      } else if (hname_len == 15 && !strncasecmp(p, "x-forwarded-for", 15)) {
        e->xff.assign(val_start, val_len);
      } else if (meta && hname_len == 12 && !strncasecmp(p, "content-type", 12)) {
        meta->content_type.assign(val_start, val_len);
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
        meta->transfer_encoding.assign(val_start, val_len);
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

static bool xml_unescape(const std::string &in, std::string *out) {
  out->clear();
  out->reserve(in.size());
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
    else if ((c & 0xf8) == 0xf0) { need = 3; }
    else return false;

    if (need) {
      if (i + need >= s.size()) return false;
      if (need == 1 && c < 0xc2) return false;
      if (need == 2 && c == 0xe0 && (unsigned char)s[i + 1] < 0xa0) return false;
      if (need == 2 && c == 0xed && (unsigned char)s[i + 1] >= 0xa0) return false;
      if (need == 3 && c == 0xf0 && (unsigned char)s[i + 1] < 0x90) return false;
      if (need == 3 && c == 0xf4 && (unsigned char)s[i + 1] >= 0x90) return false;
      cp = c & ((1U << (7 - need - 1)) - 1);
      for (size_t j = 1; j <= need; ++j) cp = (cp << 6) | ((unsigned char)s[i + j] & 0x3f);
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
      if (username_depth && !username_bad && !xml_unescape(body.substr(pos), &chars)) username_bad = true;
      break;
    }
    if (username_depth && !username_bad && lt > pos &&
        !xml_unescape(body.substr(pos, lt - pos), &chars)) username_bad = true;
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
                           bool *has_clen, bool *is_chunked, bool *is_close) {
  *has_clen = false;
  *clen = 0;
  *is_chunked = false;
  *is_close = false;
  const char *end = data + len;
  const char *p = data;
  const char *eol = (const char *)memchr(p, '\n', end - p);
  if (!eol) return false;
  if (strncmp(p, "HTTP/", 5) != 0) return false;
  bool is_http_10 = (eol - p >= 8 && strncmp(p, "HTTP/1.0", 8) == 0);
  bool conn_close = false;
  bool conn_keep_alive = false;

  const char *sp1 = (const char *)memchr(p, ' ', eol - p);
  if (!sp1) return false;
  const char *sc_start = sp1 + 1;
  while (sc_start < eol && *sc_start == ' ') ++sc_start;
  *status = atoi(sc_start);
  if (*status < 100 || *status > 599) return false;
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
            return false;
          }
          *clen = n;
          *has_clen = true;
        } else {
          return false;
        }
      } else if (hlen == 17 && !strncasecmp(p, "transfer-encoding", 17)) {
        std::string te(v, vlen);
        if (lower(te).find("chunked") != std::string::npos) {
          *is_chunked = true;
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
  if (*has_clen && *is_chunked) return false;
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
static std::vector<std::string> g_ship_buf;
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
static size_t bounded_batch_count(const std::vector<std::string> &buf,
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
        g_ship_buf.erase(g_ship_buf.begin());
        ++g_events_dropped;
        ++g_drop_oversized;
      } else {
        batch.assign(g_ship_buf.begin(), g_ship_buf.begin() + n);
        g_ship_buf.erase(g_ship_buf.begin(), g_ship_buf.begin() + n);
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
      if (post_body(g_endpoint, "/api/ingest", body, 10, &next_slot)) {
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
  unsigned long long in_delta = g_events_in - g_prev_events_in;
  unsigned long long pushed_delta = g_events_pushed - g_prev_events_pushed;
  unsigned long long dropped_delta = g_events_dropped - g_prev_events_dropped;
  unsigned long long batches_pushed_delta = g_batches_pushed - g_prev_batches_pushed;
  unsigned long long batches_failed_delta = g_batches_failed - g_prev_batches_failed;
  unsigned long long bytes_delta = g_bytes_pushed - g_prev_bytes_pushed;
  unsigned long long queue_delta = g_drop_queue - g_prev_drop_queue;
  unsigned long long hub_delta = g_drop_hub - g_prev_drop_hub;
  unsigned long long oversized_delta = g_drop_oversized - g_prev_drop_oversized;
  size_t ship_buf_size = g_ship_buf.size();
  size_t queue_high = g_queue_high_water;
  unsigned last_status = g_last_push_status;
  time_t last_succ = g_last_success_at;
  unsigned consec_fails = g_consecutive_failures;
  unsigned long long stats_drop = g_stats_dropped;
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
      << "\"events_in_total\":" << ull_string(g_events_in) << ",\"events_in_delta\":" << ull_string(in_delta)
      << ",\"events_pushed_total\":" << ull_string(g_events_pushed) << ",\"events_pushed_delta\":" << ull_string(pushed_delta)
      << ",\"events_dropped_total\":" << ull_string(g_events_dropped) << ",\"events_dropped_delta\":" << ull_string(dropped_delta)
      << ",\"drop_causes\":{\"queue_full_total\":" << ull_string(g_drop_queue) << ",\"queue_full_delta\":" << ull_string(queue_delta)
      << ",\"hub_failure_total\":" << ull_string(g_drop_hub) << ",\"hub_failure_delta\":" << ull_string(hub_delta)
      << ",\"oversized_total\":" << ull_string(g_drop_oversized) << ",\"oversized_delta\":" << ull_string(oversized_delta) << "}"
      << ",\"batches_pushed_total\":" << ull_string(g_batches_pushed) << ",\"batches_pushed_delta\":" << ull_string(batches_pushed_delta)
      << ",\"batches_failed_total\":" << ull_string(g_batches_failed) << ",\"batches_failed_delta\":" << ull_string(batches_failed_delta)
      << ",\"bytes_pushed_total\":" << ull_string(g_bytes_pushed) << ",\"bytes_pushed_delta\":" << ull_string(bytes_delta)
      << ",\"push_events_per_second\":" << double_string(pushed_delta / elapsed)
      << ",\"push_kbps\":" << double_string(8.0 * bytes_delta / (1000.0 * elapsed))
      << ",\"drop_events_per_second\":" << double_string(dropped_delta / elapsed)
      << ",\"drop_percent\":" << double_string(100.0 * dropped_delta / (in_delta ? in_delta : 1))
      << ",\"queue_depth_events\":" << ship_buf_size << ",\"queue_capacity_events\":" << MAX_QUEUE
      << ",\"queue_high_water_events\":" << queue_high << ",\"last_push_http_status\":" << last_status
      << ",\"last_success_at\":" << (unsigned long)last_succ << ",\"consecutive_failures\":" << consec_fails
      << ",\"stats_samples_dropped_total\":" << ull_string(stats_drop) << "},\"resources\":{"
      << "\"cpu_user_seconds\":" << double_string(user_cpu) << ",\"cpu_system_seconds\":" << double_string(sys_cpu)
      << ",\"cpu_percent_one_core\":" << double_string(cpu_pct) << ",\"rss_bytes\":" << rss
      << ",\"virtual_bytes\":" << virt << ",\"open_fds\":" << count_open_fds() << ",\"threads\":" << threads
      << "},\"limits\":{\"cpu_core\":" << cpu_core << ",\"address_space_bytes\":268435456"
      << ",\"ship_rate_kbps\":" << g_ship_rate_kbps << ",\"http_body_max_bytes\":" << MAX_POST_BYTES
      << ",\"ship_threads_max\":1,\"wsse_body_bytes\":" << g_wsse_body_bytes << "}}";
  g_prev_capture_packets = g_capture_packets; g_prev_capture_bytes = g_capture_bytes;
  g_prev_events_emitted = g_events_emitted;
  pthread_mutex_lock(&g_ship_queue_mutex);
  g_prev_events_in = g_events_in;
  g_prev_events_pushed = g_events_pushed; g_prev_events_dropped = g_events_dropped;
  g_prev_batches_pushed = g_batches_pushed; g_prev_batches_failed = g_batches_failed;
  g_prev_bytes_pushed = g_bytes_pushed; g_prev_drop_queue = g_drop_queue;
  g_prev_drop_hub = g_drop_hub; g_prev_drop_oversized = g_drop_oversized;
  pthread_mutex_unlock(&g_ship_queue_mutex);
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

static void emit_event(const Event &e) {
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
  ++g_events_emitted;

  if (!g_endpoint.empty()) {
    ++g_events_in;
    pthread_mutex_lock(&g_ship_queue_mutex);
    if (g_ship_buf.size() >= MAX_QUEUE) {
      g_ship_buf.erase(g_ship_buf.begin());
      ++g_events_dropped;
      ++g_drop_queue;
    }
    g_ship_buf.push_back(ss.str());
    if (g_ship_buf.size() > g_queue_high_water) g_queue_high_water = g_ship_buf.size();
    pthread_cond_signal(&g_ship_queue_cond);
    pthread_mutex_unlock(&g_ship_queue_mutex);
  } else {
    write_nonblocking_line(ss.str());
  }
}

static void queue_request(const Event &e, uint32_t s_ip, unsigned sport,
                          uint32_t d_ip, unsigned dport,
                          std::map<PacketKey, std::vector<Pending> > &pending,
                          long long first_byte_mono_ms = 0,
                          uint32_t gen = 0,
                          bool syn_seen = false) {
  PacketKey rk;
  rk.s_ip = d_ip; rk.sport = (uint16_t)dport;
  rk.d_ip = s_ip; rk.dport = (uint16_t)sport;

  long long mono_now = now_monotonic_ms();
  long long started_mono = (first_byte_mono_ms > 0) ? first_byte_mono_ms : mono_now;

  bool verified = syn_seen || (gen > 0);
  if (is_correlation_disabled(rk, verified)) {
    emit_event(e);
    return;
  }

  while (g_total_pending_count >= MAX_PENDING_TOTAL && !g_pending_fifo.empty()) {
    PendingQueueRef ref = g_pending_fifo.front();
    g_pending_fifo.pop_front();
    std::map<PacketKey, std::vector<Pending> >::iterator it = pending.find(ref.key);
    if (it != pending.end()) {
      for (size_t i = 0; i < it->second.size(); ++i) {
        if (it->second[i].req_id == ref.req_id) {
          // Global eviction disrupts ordering for this key: flush all and lock out.
          while (!it->second.empty()) {
            if (!it->second.front().is_tombstone) {
              emit_event(it->second.front().ev);
              if (g_total_pending_count > 0) --g_total_pending_count;
            }
            it->second.erase(it->second.begin());
          }
          pending.erase(it);
          corr_disabled_insert(ref.key);
          break;
        }
      }
    }
  }

  if (is_correlation_disabled(rk, verified)) {
    emit_event(e);
    return;
  }

  std::vector<Pending> &queue = pending[rk];
  if (queue.size() >= MAX_PENDING_PER_FLOW) {
    // Per-flow overflow: flush all entries for this 4-tuple, permanently lock out.
    while (!queue.empty()) {
      if (!queue.front().is_tombstone) {
        emit_event(queue.front().ev);
        if (g_total_pending_count > 0) --g_total_pending_count;
      }
      queue.erase(queue.begin());
    }
    pending.erase(rk);
    corr_disabled_insert(rk);
    emit_event(e);
    return;
  }

  uint64_t req_id = ++g_req_id_seq;
  queue.push_back(Pending(req_id, gen, e, now_ms(), started_mono));
  ++g_total_pending_count;


  PendingQueueRef new_ref;
  new_ref.req_id = req_id;
  new_ref.generation = gen;
  new_ref.key = rk;
  new_ref.started_mono_ms = started_mono;
  g_pending_fifo.push_back(new_ref);

  if (g_pending_fifo.size() > MAX_PENDING_TOTAL * 2) {
    std::list<PendingQueueRef>::iterator fi = g_pending_fifo.begin();
    while (fi != g_pending_fifo.end()) {
      std::map<PacketKey, std::vector<Pending> >::iterator it = pending.find(fi->key);
      bool alive = false;
      if (it != pending.end()) {
        for (size_t j = 0; j < it->second.size(); ++j) {
          if (it->second[j].req_id == fi->req_id) {
            alive = true;
            break;
          }
        }
      }
      if (!alive) {
        fi = g_pending_fifo.erase(fi);
      } else {
        ++fi;
      }
    }
  }
}

static void flush_incomplete_wsse(std::map<FlowKey, Flow> &flows,
                                  std::map<PacketKey, std::vector<Pending> > &pending) {
  for (std::map<FlowKey, Flow>::iterator f = flows.begin(); f != flows.end(); ++f) {
    if (f->second.awaiting_wsse) {
      queue_request(f->second.wsse_event, f->first.s_ip, f->first.sport,
                    f->first.d_ip, f->first.dport, pending, f->second.first_byte_mono_ms,
                    f->second.generation, f->second.syn_seen);

      f->second.awaiting_wsse = false;
    }
    f->second.clear_buffers();
  }
  flows.clear();
  g_total_flow_bytes = 0;
}

static void flush_all_pending(std::map<PacketKey, std::vector<Pending> > &pending) {
  for (std::map<PacketKey, std::vector<Pending> >::iterator p = pending.begin(); p != pending.end(); ++p) {
    for (size_t i = 0; i < p->second.size(); ++i) {
      if (!p->second[i].is_tombstone) {
        emit_event(p->second[i].ev);
      }
    }
  }
  pending.clear();
  g_pending_fifo.clear();
  g_total_pending_count = 0;
  corr_disabled_clear();
}



static void sweep(std::map<FlowKey, Flow> &flows,
                  std::map<PacketKey, std::vector<Pending> > &pending,
                  time_t now, unsigned pending_ttl_sec,
                  long long now_mono = 0) {
  for (std::map<FlowKey, Flow>::iterator f = flows.begin(); f != flows.end();) {
    std::map<FlowKey, Flow>::iterator fn = f; ++fn;
    if ((unsigned)(now - f->second.touched) > FLOW_TTL) {
      if (f->second.awaiting_wsse) {
        emit_event(f->second.wsse_event);
        f->second.awaiting_wsse = false;
      }
      f->second.clear_buffers();
      flows.erase(f);
    }
    f = fn;
  }

  if (now_mono <= 0) now_mono = now_monotonic_ms();
  long long ttl_ms = (long long)pending_ttl_sec * 1000LL;
  for (std::map<PacketKey, std::vector<Pending> >::iterator p = pending.begin(); p != pending.end();) {
    std::map<PacketKey, std::vector<Pending> >::iterator pn = p; ++pn;
    size_t i = 0;
    while (i < p->second.size()) {
      Pending &entry = p->second[i];
      if (entry.is_tombstone) {
        if (now_mono - entry.tombstone_mono_ms > 10000LL) {
          // Tombstone expired un-consumed: flush all remaining entries in this
          // queue immediately (ordering is now ambiguous). Then permanently
          // disable response correlation for this 4-tuple until a new SYN.
          PacketKey disabled_key = p->first;
          p->second.erase(p->second.begin() + i);
          while (i < p->second.size()) {
            Pending &tail = p->second[i];
            if (!tail.is_tombstone) {
              emit_event(tail.ev);
              if (g_total_pending_count > 0) --g_total_pending_count;
            }
            p->second.erase(p->second.begin() + i);
          }
          corr_disabled_insert(disabled_key);
          // Leave i unchanged; inner while exits on next check

        } else {
          ++i;
        }
      } else if (now_mono - entry.started_mono_ms > ttl_ms) {
        emit_event(entry.ev);
        if (g_total_pending_count > 0) --g_total_pending_count;
        entry.is_tombstone = true;
        entry.tombstone_mono_ms = now_mono;
        ++i;
      } else {
        ++i;
      }
    }
    if (p->second.empty()) pending.erase(p);
    p = pn;
  }

  while (!g_pending_fifo.empty() &&
         (now_mono - g_pending_fifo.front().started_mono_ms > ttl_ms * 2LL)) {
    g_pending_fifo.pop_front();
  }
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
        int32_t o_overlap = -odiff;
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

static bool g_monitored_ports[65536];

static size_t active_wsse_flows(const std::map<FlowKey, Flow> &flows) {
  size_t count = 0;
  for (std::map<FlowKey, Flow>::const_iterator it = flows.begin(); it != flows.end(); ++it)
    if (it->second.awaiting_wsse) ++count;
  return count;
}

static void evict_oldest_flow_if_needed(std::map<FlowKey, Flow> &flows,
                                        std::map<PacketKey, std::vector<Pending> > &pending) {
  while (!flows.empty() && (flows.size() >= MAX_FLOWS || g_total_flow_bytes >= MAX_TOTAL_BUFFER_BYTES)) {
    std::map<FlowKey, Flow>::iterator oldest = flows.begin();
    for (std::map<FlowKey, Flow>::iterator it = flows.begin(); it != flows.end(); ++it) {
      if (it->second.touched < oldest->second.touched) oldest = it;
    }
    if (oldest->second.awaiting_wsse) {
      queue_request(oldest->second.wsse_event, oldest->first.s_ip, oldest->first.sport,
                    oldest->first.d_ip, oldest->first.dport, pending, oldest->second.first_byte_mono_ms,
                    oldest->second.generation, oldest->second.syn_seen);

      oldest->second.awaiting_wsse = false;
    }
    oldest->second.clear_buffers();
    flows.erase(oldest);
  }
}

static bool handle_packet(const unsigned char *buf, size_t n, const std::string &node, const std::vector<unsigned> &ports,
                          std::map<FlowKey, Flow> &flows, std::map<PacketKey, std::vector<Pending> > &pending,
                          time_t pcap_now = 0, long long pcap_mono_now = 0) {
  (void)ports;
  if (n < 34) return false;
  size_t off = 14;
  unsigned short et = ntohs(read_u16(buf + 12));
  if (et == ETH_P_8021Q) { if (n < 38) return false; et = ntohs(read_u16(buf + 16)); off = 18; }
  if (et != ETH_P_IP || n < off + 20) return false;

  unsigned char ihl = (unsigned char)(buf[off] & 15) * 4;
  if ((buf[off] >> 4) != 4 || ihl < 20 || buf[off + 9] != 6) return false;

  // Reject fragmented IP packets (non-first fragment has frag offset > 0)
  uint16_t frag = ntohs(read_u16(buf + off + 6));
  if (frag & 0x1fff) return false;

  // IPv4 total length validation and truncation check
  uint16_t ip_total_len = ntohs(read_u16(buf + off + 2));
  bool is_truncated = false;
  if (ip_total_len > 0) {
    if (ip_total_len < ihl + 20) return false;
    if (n - off < ip_total_len) {
      is_truncated = true;
    } else if (n - off > ip_total_len) {
      n = off + ip_total_len; // Exclude Ethernet padding
    }
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

  // Direction A: Server -> Client Response Reassembly
  if (src_mon && !dst_mon) {
    FlowKey rfk;
    rfk.s_ip = s_ip; rfk.sport = (uint16_t)sport;
    rfk.d_ip = d_ip; rfk.dport = (uint16_t)dport;

    if (tcp_flags & 0x02) { // SYN from server
      evict_oldest_flow_if_needed(flows, pending);
      Flow &rfl = flows[rfk];
      rfl.clear_buffers();
      rfl = Flow();
      rfl.has_seq = true;
      rfl.next_seq = seq + 1;
      rfl.is_broken = false;
      rfl.touched = now;
      return true;
    }

    if (plen > 0) {
      evict_oldest_flow_if_needed(flows, pending);
      Flow &rfl = flows[rfk];
      rfl.touched = now;

      if (!rfl.has_seq) {
        if ((plen >= 5 && memcmp(payload, "HTTP/", 5) == 0) ||
            (plen < 5 && memcmp(payload, "HTTP/", plen) == 0)) {
          rfl.has_seq = true;
          rfl.next_seq = seq;
          rfl.is_broken = false;
        } else {
          if (rfl.ooo.size() < MAX_OOO_SEGMENTS && !is_truncated) {
            bool dup = false;
            for (size_t i = 0; i < rfl.ooo.size(); ++i) {
              if (rfl.ooo[i].seq == seq) { dup = true; break; }
            }
            if (!dup) {
              rfl.ooo_push(seq, payload, plen);
            }
          }
          return true;
        }
      }

      int32_t diff = seq_diff(seq, rfl.next_seq);
      if (diff == 0) {
        if (is_truncated) {
          rfl.is_broken = true;
        } else {
          if (!rfl.buf_append(payload, plen)) return true;
          rfl.next_seq += (uint32_t)plen;
          if (!drain_ooo_segments(rfl)) return true;
        }
      } else if (diff < 0) {
        int32_t overlap = -diff;
        if ((size_t)overlap < plen && !is_truncated) {
          size_t flen = plen - overlap;
          if (!rfl.buf_append(payload + overlap, flen)) return true;
          rfl.next_seq += (uint32_t)flen;
          if (!drain_ooo_segments(rfl)) return true;
        }
      } else { // diff > 0
        if (rfl.ooo.size() < MAX_OOO_SEGMENTS && !is_truncated) {
          bool dup = false;
          for (size_t i = 0; i < rfl.ooo.size(); ++i) {
            if (rfl.ooo[i].seq == seq) { dup = true; break; }
          }
          if (!dup) {
            rfl.ooo_push(seq, payload, plen);
          }
        } else {
          rfl.is_broken = true;
        }
      }

      // Parse complete responses from reassembled buffer using HTTP framing
      while (!rfl.buf.empty() && !rfl.is_broken) {
        if (rfl.state == Flow::HTTP_STATE_HEADER) {
          size_t end = rfl.buf.find("\r\n\r\n");
          if (end == std::string::npos) {
            if (rfl.buf.size() > MAX_HEADER_BYTES) {
              rfl.clear_buffers();
              rfl.is_broken = true;
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

          int st = 0; size_t cl = 0; bool has_cl = false, is_chunked = false, is_close = false;
          if (!parse_response(rfl.buf.data(), end + 2, &st, &cl, &has_cl, &is_chunked, &is_close)) {
            // Ambiguous framing (conflicting Content-Length, bad status, etc.).
            // Discard the header and mark the stream broken so body bytes are
            // not re-scanned as a new response – prevents fabricated statuses.
            rfl.clear_buffers();
            rfl.is_broken = true;
            break;
          }

          if (st >= 100 && st <= 199 && st != 101) {
            rfl.buf_erase(0, end + 4);
            continue;
          }

          PacketKey pk;
          pk.s_ip = s_ip; pk.sport = (uint16_t)sport;
          pk.d_ip = d_ip; pk.dport = (uint16_t)dport;
          bool verified = rfl.syn_seen || (rfl.generation > 0);
          std::map<PacketKey, std::vector<Pending> >::iterator p =
              is_correlation_disabled(pk, verified) ? pending.end() : pending.find(pk);
          bool is_head = false;

          if (p != pending.end() && !p->second.empty()) {
            if (rfl.generation != 0 && p->second[0].generation != 0 && p->second[0].generation != rfl.generation) {
              // Generation mismatch! Stale request from previous connection.
              emit_event(p->second[0].ev);
              if (!p->second[0].is_tombstone && g_total_pending_count > 0) --g_total_pending_count;
              p->second.erase(p->second.begin());
              if (p->second.empty()) pending.erase(p);
            } else if (p->second[0].is_tombstone) {
              // Late response for expired request: consume tombstone, do not attach to newer requests
              p->second.erase(p->second.begin());
              if (p->second.empty()) pending.erase(p);
            } else {
              Event e = p->second[0].ev;
              if (e.method == "HEAD") is_head = true;
              e.status = st;
              e.has_status = true;
              e.duration_ms = (long)(mono_now - p->second[0].started_mono_ms);
              if (e.duration_ms < 0) e.duration_ms = 0;
              e.has_duration = true;
              if (has_cl) {
                e.resp_bytes = (unsigned)cl;
                e.has_resp = true;
              }
              emit_event(e);
              p->second.erase(p->second.begin());
              if (g_total_pending_count > 0) --g_total_pending_count;
              if (p->second.empty()) pending.erase(p);
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
              rfl.clear_buffers();
              rfl.is_broken = true;
            }
            break;
          }
          if (rfl.chunk_reading_len) {
            size_t crlf = rfl.buf.find("\r\n");
            if (crlf == std::string::npos) {
              if (rfl.buf.size() > 64) {
                rfl.clear_buffers();
                rfl.is_broken = true;
              }
              break;
            }
            std::string line = trim(rfl.buf.substr(0, crlf));
            size_t semi = line.find(';');
            std::string hex_str = (semi != std::string::npos) ? trim(line.substr(0, semi)) : line;
            if (hex_str.empty() || hex_str.size() > 16) {
              rfl.clear_buffers();
              rfl.is_broken = true;
              break;
            }
            bool valid_hex = true;
            for (size_t hi = 0; hi < hex_str.size(); ++hi) {
              if (!isxdigit((unsigned char)hex_str[hi])) { valid_hex = false; break; }
            }
            if (!valid_hex) {
              rfl.clear_buffers();
              rfl.is_broken = true;
              break;
            }
            char *endptr = NULL;
            errno = 0;
            unsigned long long parsed_len = strtoull(hex_str.c_str(), &endptr, 16);
            if (errno != 0 || endptr != hex_str.c_str() + hex_str.size() || parsed_len > 16777216ULL) {
              rfl.clear_buffers();
              rfl.is_broken = true;
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
              rfl.clear_buffers();
              rfl.is_broken = true;
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
    }

    if (tcp_flags & 0x05) { // Server FIN or RST
      std::map<FlowKey, Flow>::iterator it = flows.find(rfk);
      if (it != flows.end()) {
        it->second.clear_buffers();
        flows.erase(it);
      }
    }
    return true;
  }

  // Direction B: Client -> Server Request Reassembly
  if (!dst_mon) {
    if (tcp_flags & 0x05) {
      FlowKey rfk; rfk.s_ip = d_ip; rfk.sport = (uint16_t)dport; rfk.d_ip = s_ip; rfk.dport = (uint16_t)sport;
      std::map<FlowKey, Flow>::iterator it = flows.find(rfk);
      if (it != flows.end()) {
        it->second.clear_buffers();
        flows.erase(it);
      }
    }
    return false;
  }

  FlowKey fk;
  fk.s_ip = s_ip; fk.sport = (uint16_t)sport; fk.d_ip = d_ip; fk.dport = (uint16_t)dport;

  if (tcp_flags & 0x02) { // SYN from client: new connection generation!
    evict_oldest_flow_if_needed(flows, pending);
    PacketKey rk; rk.s_ip = d_ip; rk.sport = (uint16_t)dport; rk.d_ip = s_ip; rk.dport = (uint16_t)sport;

    // Purge previous generation's pending requests for this 4-tuple
    std::map<PacketKey, std::vector<Pending> >::iterator p = pending.find(rk);
    if (p != pending.end()) {
      for (size_t i = 0; i < p->second.size(); ++i) {
        if (!p->second[i].is_tombstone) {
          emit_event(p->second[i].ev);
          if (g_total_pending_count > 0) --g_total_pending_count;
        }
      }
      pending.erase(p);
    }
    // Re-enable correlation for this 4-tuple: SYN proves a fresh TCP connection
    // with no ambiguous ordering state from the previous stream.
    corr_disabled_erase(rk);

    Flow &fl = flows[fk];
    if (fl.awaiting_wsse) {
      if (!fl.wsse_event.method.empty()) {
        emit_event(fl.wsse_event);
      }
      fl.awaiting_wsse = false;
    }
    uint32_t next_gen = fl.generation + 1;
    fl.clear_buffers();
    fl = Flow();
    fl.generation = next_gen;
    fl.syn_seen = true;
    fl.has_seq = true;
    fl.next_seq = seq + 1;
    fl.touched = now;
    fl.first_byte_mono_ms = 0;

    // Reset server response flow for this 4-tuple and carry forward new generation
    std::map<FlowKey, Flow>::iterator rfit = flows.find(rk);
    if (rfit != flows.end()) {
      rfit->second.clear_buffers();
    }
    Flow &resp_fl = flows[rk];
    resp_fl = Flow();
    resp_fl.generation = next_gen;
    resp_fl.syn_seen = true;
    return true;

  }

  evict_oldest_flow_if_needed(flows, pending);
  Flow &fl = flows[fk];
  fl.touched = now;

  if (plen > 0) {
    if (!fl.has_seq) {
      if (is_method_or_prefix(payload, plen)) {
        fl.has_seq = true;
        fl.next_seq = seq;
        fl.is_broken = false;
      } else {
        if (fl.ooo.size() < MAX_OOO_SEGMENTS && !is_truncated) {
          bool dup = false;
          for (size_t i = 0; i < fl.ooo.size(); ++i) {
            if (fl.ooo[i].seq == seq) { dup = true; break; }
          }
          if (!dup) {
            fl.ooo_push(seq, payload, plen);
          }
        }
        return true;
      }
    }

    int32_t diff = seq_diff(seq, fl.next_seq);
    if (diff == 0) {
      if (is_truncated) {
        fl.is_broken = true;
      } else {
        if (!fl.buf_append(payload, plen)) return true;
        fl.next_seq += (uint32_t)plen;
        if (!drain_ooo_segments(fl)) return true;
      }
    } else if (diff < 0) {
      int32_t overlap = -diff;
      if ((size_t)overlap < plen && !is_truncated) {
        size_t flen = plen - overlap;
        if (!fl.buf_append(payload + overlap, flen)) return true;
        fl.next_seq += (uint32_t)flen;
        if (!drain_ooo_segments(fl)) return true;
      }
    } else { // diff > 0 (out of order gap)
      if (fl.ooo.size() < MAX_OOO_SEGMENTS && !is_truncated) {
        bool dup = false;
        for (size_t i = 0; i < fl.ooo.size(); ++i) {
          if (fl.ooo[i].seq == seq) { dup = true; break; }
        }
        if (!dup) {
          fl.ooo_push(seq, payload, plen);
        }
      } else {
        fl.is_broken = true;
      }
    }

    // HTTP Framing State Machine for requests
    while (!fl.buf.empty() && !fl.is_broken) {
      if (fl.state == Flow::HTTP_STATE_HEADER) {
        if (!fl.first_byte_mono_ms) fl.first_byte_mono_ms = mono_now;

        size_t end = fl.buf.find("\r\n\r\n");
        if (end == std::string::npos) {
          if (fl.buf.size() > MAX_HEADER_BYTES) {
            fl.clear_buffers();
            fl.is_broken = true;
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
        e.ts = now; e.host = node; e.service = "port:" + num(dport);
        e.caller = ip_to_str(s_ip); e.caller_port = sport;
        e.dst_ip = ip_to_str(d_ip); e.dst_port = dport;
        e.req_bytes = (unsigned)(end + 4);

        if (!parse_request(fl.buf.data(), end + 2, &e, &meta)) {
          fl.buf_erase(0, end + 4);
          continue;
        }

        // Reject conflicting Content-Length + chunked encoding (RFC 7230 request smuggling prevention)
        bool has_chunked = (lower(meta.transfer_encoding).find("chunked") != std::string::npos);
        if (meta.has_conflict_cl || (meta.has_content_length && has_chunked)) {
          fl.buf_erase(0, end + 4);
          fl.clear_buffers();
          fl.is_broken = true;
          break;
        }

        fl.buf_erase(0, end + 4);

        bool wsse_eligible = (g_wsse_body_bytes > 0 &&
                              is_soap_content_type(meta.content_type) &&
                              meta.has_content_length &&
                              meta.content_length > 0 &&
                              !has_chunked &&
                              active_wsse_flows(flows) < MAX_WSSE_BODY_FLOWS);

        if (wsse_eligible) {
          fl.awaiting_wsse = true;
          fl.wsse_event = e;
          flow_bytes_sub(fl.wsse_buf.size());
          fl.wsse_buf.clear();
          fl.wsse_goal = meta.content_length < g_wsse_body_bytes ? meta.content_length : g_wsse_body_bytes;
        } else {
          queue_request(e, s_ip, sport, d_ip, dport, pending, fl.first_byte_mono_ms, fl.generation, fl.syn_seen);
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
          std::string username = extract_wsse_username(fl.wsse_buf);
          if (!username.empty() || fl.wsse_buf.size() >= fl.wsse_goal) {
            Event ev = fl.wsse_event;
            if (!username.empty()) {
              ev.wsse_user = username; ev.user = username; ev.scheme = "wsse";
            }
            queue_request(ev, s_ip, sport, d_ip, dport, pending, fl.first_byte_mono_ms, fl.generation, fl.syn_seen);
            fl.awaiting_wsse = false;
          }
        }

        fl.buf_erase(0, to_consume);
        fl.body_remaining -= to_consume;
        if (fl.body_remaining == 0) {
          if (fl.awaiting_wsse) {
            queue_request(fl.wsse_event, s_ip, sport, d_ip, dport, pending, fl.first_byte_mono_ms, fl.generation, fl.syn_seen);
            fl.awaiting_wsse = false;
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
            fl.clear_buffers();
            fl.is_broken = true;
          }
          break;
        }
        if (fl.chunk_reading_len) {
          size_t crlf = fl.buf.find("\r\n");
          if (crlf == std::string::npos) {
            if (fl.buf.size() > 64) {
              fl.clear_buffers();
              fl.is_broken = true;
            }
            break;
          }
          std::string line = trim(fl.buf.substr(0, crlf));
          size_t semi = line.find(';');
          std::string hex_str = (semi != std::string::npos) ? trim(line.substr(0, semi)) : line;
          if (hex_str.empty() || hex_str.size() > 16) {
            fl.clear_buffers();
            fl.is_broken = true;
            break;
          }
          bool valid_hex = true;
          for (size_t hi = 0; hi < hex_str.size(); ++hi) {
            if (!isxdigit((unsigned char)hex_str[hi])) { valid_hex = false; break; }
          }
          if (!valid_hex) {
            fl.clear_buffers();
            fl.is_broken = true;
            break;
          }
          char *endptr = NULL;
          errno = 0;
          unsigned long long parsed_len = strtoull(hex_str.c_str(), &endptr, 16);
          if (errno != 0 || endptr != hex_str.c_str() + hex_str.size() || parsed_len > 16777216ULL) {
            fl.clear_buffers();
            fl.is_broken = true;
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
            fl.clear_buffers();
            fl.is_broken = true;
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
  }

  // FIN / RST Lifecycle: process after payload
  if (tcp_flags & 0x05) {
    if (fl.awaiting_wsse) {
      queue_request(fl.wsse_event, s_ip, sport, d_ip, dport, pending, fl.first_byte_mono_ms, fl.generation, fl.syn_seen);
      fl.awaiting_wsse = false;
    }

    fl.clear_buffers();
    flows.erase(fk);
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
  return setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER_OLD, &prog, sizeof(prog)) == 0;
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
               frame_size(2048), frame_nr(2048), frames_per_block(32), frame_idx(0) {}
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
  uint8_t frame[2048];
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
  std::map<FlowKey, Flow> flows;
  std::map<PacketKey, std::vector<Pending> > pending;
  if (!handle_packet(&packet[0], packet.size(), "cpp-dual-fixture",
                     ports, flows, pending)) return 9;
  if (!flows.empty() || pending.size() != 1) return 10;
  flush_all_pending(pending);
  return 0;
}

static int run_ship_rate_fixture() {
  std::vector<std::string> events;
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
  struct __user_cap_header_struct header;
  struct __user_cap_data_struct data[2];
  memset(&header, 0, sizeof(header));
  memset(data, 0, sizeof(data));
  header.version = _LINUX_CAPABILITY_VERSION_3;
  header.pid = 0;
  return syscall(SYS_capset, &header, data) == 0;
}

static int open_capture_socket(const std::string &iface,
                               const std::vector<unsigned> &ports,
                               MmapRing &ring) {
  int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
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
  corr_disabled_clear();
  fprintf(stderr, "Lockout registry 10k bounded fixture: PASS (size=%lu, capacity_fallback=verified)\n",
          (unsigned long)MAX_CORR_DISABLED);
  return 0;
}

int main(int argc, char **argv) {
  if (argc > 1 && !strcmp(argv[1], "--fixture")) return run_fixture();
  if (argc > 1 && !strcmp(argv[1], "--wsse-fixture")) return run_wsse_fixture();
  if (argc > 1 && !strcmp(argv[1], "--dual-auth-fixture")) return run_dual_auth_fixture();
  if (argc > 1 && !strcmp(argv[1], "--ring-fixture")) return run_ring_fixture();
  if (argc > 1 && !strcmp(argv[1], "--ship-rate-fixture")) return run_ship_rate_fixture();
  if (argc > 1 && !strcmp(argv[1], "--stats-fixture")) return run_stats_fixture();
  if (argc > 1 && !strcmp(argv[1], "--lockout-fixture")) return run_lockout_fixture();

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

  for (i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "-i") && i + 1 < argc) iface = argv[++i];
    else if (!strcmp(argv[i], "-p") && i + 1 < argc) {
      while (i + 1 < argc && argv[i + 1][0] != '-') {
        char *q = strtok(argv[++i], ", ");
        while (q) { long p = atol(q); if (valid_port((unsigned)p)) ports.push_back((unsigned)p); q = strtok(NULL, ", "); }
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
  if (ports.empty()) { ports.push_back(80); ports.push_back(8003); ports.push_back(8005); ports.push_back(8007); ports.push_back(8009); ports.push_back(8010); ports.push_back(8011); }
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
  std::map<FlowKey, Flow> flows;
  std::map<PacketKey, std::vector<Pending> > pending;

  logmsg("PACKET_MMAP (TPACKET_V2) strict RX ring enabled (4MB, 2048 frames)");
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
    } else if (rc > 0 && (pfd.revents & (POLLERR | POLLNVAL))) {
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
          handle_packet(pkt, packet_length, node, ports, flows, pending);
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
      sweep(flows, pending, now, g_pending_ttl_sec);
      if (g_endpoint.empty()) std::cout.flush();
      last = now;
    }

    if (wall_seconds() - g_stats_last_at >= g_stats_interval_sec) {
      size_t pending_count = 0, wsse_count = 0;
      for (std::map<PacketKey, std::vector<Pending> >::iterator pi = pending.begin(); pi != pending.end(); ++pi)
        pending_count += pi->second.size();
      for (std::map<FlowKey, Flow>::iterator fi = flows.begin(); fi != flows.end(); ++fi)
        if (fi->second.awaiting_wsse) ++wsse_count;
      if (!g_endpoint.empty())
        send_agent_stats(fd, flows.size(), pending_count, wsse_count);
      else
        emit_capture_stats_internal(fd, flows.size(), pending_count, wsse_count);
    }
  }

  flush_incomplete_wsse(flows, pending);
  flush_all_pending(pending);
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
