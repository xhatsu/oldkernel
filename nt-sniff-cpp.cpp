/*
 * nt-sniff-cpp.cpp - C++03-compatible old-kernel HTTP capture agent.
 *
 * Replaces the Python hot loop while retaining the oldkernel JSONL contract:
 * AF_PACKET -> classic BPF -> bounded HTTP header flow table -> response
 * correlation -> JSONL stdout -> nt-ship.py.
 *
 * Build target: CentOS 6 / GCC 4.4, Linux 2.6.32. No third-party deps.
 * This is intentionally HTTP header-only. TLS remains ecapture's concern.
 */
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <iostream>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

static volatile sig_atomic_t g_running = 1;
static void stop_signal(int) { g_running = 0; }

static const size_t MAX_FLOWS = 8192;
static const size_t MAX_PENDING = 8192;
static const size_t MAX_HEADER = 262144;
static const size_t MAX_BATCH = 400;
static const size_t MAX_QUEUE = 4000;
static const int FLUSH_SEC = 5;
static const int RETRY_SEC = 60;
static const unsigned FLOW_TTL = 15;
static const unsigned PENDING_TTL = 3;
static const unsigned ACCEPT = 2048;
static const int SO_ATTACH_FILTER_OLD = 26;
static const unsigned short ETH_P_IP_HOST = 0x0800;
static const unsigned short ETH_P_8021Q_HOST = 0x8100;

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
    if (c == '\\' || c == '"') { x += '\\'; x += (char)c; }
    else if (c == '\n') x += "\\n";
    else if (c == '\r') x += "\\r";
    else if (c == '\t') x += "\\t";
    else if (c < 32) x += '?';
    else x += (char)c;
  }
  x += '"'; return x;
}
static long long now_ms() {
  struct timeval tv; gettimeofday(&tv, NULL);
  return (long long)tv.tv_sec * 1000LL + tv.tv_usec / 1000;
}
static std::string num(long v) { std::ostringstream o; o << v; return o.str(); }
static bool valid_port(unsigned p) { return p > 0 && p <= 65535; }
static bool has_method(const std::string &m) {
  return m == "GET" || m == "POST" || m == "PUT" || m == "DELETE" ||
         m == "PATCH" || m == "HEAD" || m == "OPTIONS";
}
static std::string host_name() {
  char b[256]; if (gethostname(b, sizeof(b) - 1) != 0) return "unknown-node";
  b[sizeof(b) - 1] = 0; char *p = strchr(b, '.'); if (p) *p = 0; return b;
}
static std::string b64decode_user(const char *in, size_t in_len) {
  while (in_len > 0 && isspace((unsigned char)*in)) { ++in; --in_len; }
  while (in_len > 0 && isspace((unsigned char)in[in_len - 1])) { --in_len; }
  std::string out; int val = 0, bits = -8; size_t i;
  for (i = 0; i < in_len; ++i) {
    unsigned char c = (unsigned char)in[i]; int d = -1;
    if (c >= 'A' && c <= 'Z') d = c - 'A';
    else if (c >= 'a' && c <= 'z') d = c - 'a' + 26;
    else if (c >= '0' && c <= '9') d = c - '0' + 52;
    else if (c == '+') d = 62;
    else if (c == '/') d = 63;
    else if (c == '=') break;
    if (d < 0) continue;
    val = (val << 6) + d;
    bits += 6;
    if (bits >= 0) {
      out += (char)((val >> bits) & 0xff);
      bits -= 8;
      if (out.size() > 512) return "";
    }
  }
  size_t p = out.find(':');
  if (p == std::string::npos) return "";
  return out.substr(0, p > 64 ? 64 : p);
}
static std::string ip_to_str(uint32_t ip_be) {
  char b[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &ip_be, b, sizeof(b));
  return b;
}

static std::string trace_id_from_parent(const std::string &tp) {
  std::string x = trim(tp);
  if (x.size() == 55 && x[2] == '-' && x[35] == '-' && x[52] == '-') return lower(x.substr(3, 32));
  return "";
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
  std::string host_hdr, user_agent, xff, caller, dst_ip, traceparent, trace_id;
  unsigned caller_port, dst_port, req_bytes, resp_bytes; int status; long duration_ms;
  bool has_status, has_duration, has_resp;
  Event() : ts(0), caller_port(0), dst_port(0), req_bytes(0), resp_bytes(0), status(0), duration_ms(0), has_status(false), has_duration(false), has_resp(false) {}
};
struct Flow { std::string buf; time_t touched; Flow() : touched(time(NULL)) {} };
struct Pending {
  Event ev;
  long long started_ms;
  Pending() : started_ms(0) {}
  Pending(const Event &e, long long t) : ev(e), started_ms(t) {}
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
};
typedef FlowKey PacketKey;

static void logmsg(const std::string &s) { fprintf(stderr, "nt-sniff-cpp: %s\n", s.c_str()); fflush(stderr); }

static bool parse_request(const char *data, size_t len, Event *e) {
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
          e->user = b64decode_user(val_start + 6, val_len - 6);
          e->scheme = "basic";
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
      }
    }
    p = line_end + 1;
  }

  if (e->user.empty()) e->user = "-anonymous-";
  if (e->scheme.empty()) e->scheme = "none";
  if (e->trace_id.empty()) e->traceparent = make_traceparent(&e->trace_id);
  return true;
}

static bool parse_response(const char *data, size_t len, int *status, unsigned *clen) {
  const char *end = data + len;
  const char *p = data;
  const char *eol = (const char *)memchr(p, '\n', end - p);
  if (!eol) return false;
  if (strncmp(p, "HTTP/", 5) != 0) return false;
  const char *sp1 = (const char *)memchr(p, ' ', eol - p);
  if (!sp1) return false;
  const char *sc_start = sp1 + 1;
  while (sc_start < eol && *sc_start == ' ') ++sc_start;
  *status = atoi(sc_start);
  if (*status < 100 || *status > 599) return false;
  *clen = 0;
  p = eol + 1;
  while (p < end) {
    if (*p == '\r' || *p == '\n') break;
    const char *line_end = (const char *)memchr(p, '\n', end - p);
    if (!line_end) line_end = end;
    const char *colon = (const char *)memchr(p, ':', line_end - p);
    if (colon) {
      size_t hlen = colon - p;
      if (hlen == 14 && !strncasecmp(p, "content-length", 14)) {
        const char *v = colon + 1;
        while (v < line_end && (*v == ' ' || *v == '\t')) ++v;
        long n = atol(v);
        if (n >= 0 && n <= 0x7fffffff) *clen = (unsigned)n;
      }
    }
    p = line_end + 1;
  }
  return true;
}

static std::string g_endpoint;
static std::string g_ship_node;
static std::vector<std::string> g_ship_buf;

static std::string shellq(const std::string &s) {
  std::string o = "'";
  for (size_t i = 0; i < s.size(); ++i) { if (s[i] == '\'') o += "'\\''"; else o += s[i]; }
  return o + "'";
}
static std::string number_string(size_t n) { std::ostringstream o; o << n; return o.str(); }
static std::string json_array(const std::vector<std::string> &a) {
  std::string o = "["; for (size_t i = 0; i < a.size(); ++i) { if (i) o += ","; o += a[i]; } return o + "]";
}
static bool post(const std::string &endpoint, const std::string &node, const std::vector<std::string> &batch) {
  std::string body = "{\"node\":" + jsonq(node) + ",\"events\":" + json_array(batch) + "}";
  std::string cmd = "curl -sSf --max-time 10 -o /dev/null -H 'Content-Type: application/json' --data-binary @- " + shellq(endpoint + "/api/ingest");
  FILE *fp = popen(cmd.c_str(), "w"); if (!fp) return false;
  fwrite(body.data(), 1, body.size(), fp);
  int rc = pclose(fp);
  return WIFEXITED(rc) && WEXITSTATUS(rc) == 0;
}
static void send_batches(const std::string &endpoint, const std::string &node,
                         std::vector<std::string> *buf, bool flush_all) {
  while (!buf->empty() && (flush_all || buf->size() >= MAX_BATCH)) {
    size_t n = buf->size() >= MAX_BATCH ? MAX_BATCH : buf->size();
    std::vector<std::string> batch(buf->begin(), buf->begin() + n);
    if (post(endpoint, node, batch)) {
      buf->erase(buf->begin(), buf->begin() + n);
      logmsg("flushed " + number_string(n) + " events");
    } else {
      /* Pure in-memory drop when Hub unreachable (zero disk I/O) */
      buf->erase(buf->begin(), buf->begin() + n);
      logmsg("WARN: Hub unreachable, dropped " + number_string(n) + " events (in-memory drop, 0 disk I/O)");
      break;
    }
  }
}

static void emit_event(const Event &e) {
  std::ostringstream ss;
  ss << "{\"ts\":" << e.ts << ",\"host\":" << jsonq(e.host) << ",\"src\":\"pcap\",\"service\":" << jsonq(e.service)
     << ",\"method\":" << jsonq(e.method) << ",\"path\":" << jsonq(e.path) << ",\"user\":" << jsonq(e.user)
     << ",\"scheme\":" << jsonq(e.scheme) << ",\"source_probe\":\"pcap-http-cpp\",\"host_hdr\":" << jsonq(e.host_hdr)
     << ",\"user_agent\":" << jsonq(e.user_agent) << ",\"x_forwarded_for\":" << jsonq(e.xff)
     << ",\"caller\":" << jsonq(e.caller) << ",\"caller_port\":" << e.caller_port << ",\"dst_ip\":" << jsonq(e.dst_ip)
     << ",\"dst_port\":" << e.dst_port << ",\"traceparent\":" << jsonq(e.traceparent) << ",\"trace_id\":" << jsonq(e.trace_id)
     << ",\"service_id\":null,\"module_id\":\"pcap-http-cpp\",\"req_bytes\":" << e.req_bytes;
  if (e.has_status) ss << ",\"status\":" << e.status; else ss << ",\"status\":null";
  if (e.has_duration) ss << ",\"duration_ms\":" << e.duration_ms; else ss << ",\"duration_ms\":null";
  if (e.has_resp) ss << ",\"resp_bytes\":" << e.resp_bytes; else ss << ",\"resp_bytes\":null";
  ss << "}";

  if (!g_endpoint.empty()) {
    if (g_ship_buf.size() >= MAX_QUEUE) {
      g_ship_buf.erase(g_ship_buf.begin());
    }
    g_ship_buf.push_back(ss.str());
  } else {
    std::cout << ss.str() << "\n";
  }
}

static void flush_oldest(std::map<PacketKey, std::vector<Pending> > &pending) {
  if (pending.empty()) return;
  std::map<PacketKey, std::vector<Pending> >::iterator it = pending.begin();
  if (!it->second.empty()) {
    emit_event(it->second[0].ev);
    it->second.erase(it->second.begin());
  }
  if (it->second.empty()) {
    pending.erase(it);
  }
}
static void sweep(std::map<FlowKey, Flow> &flows, std::map<PacketKey, std::vector<Pending> > &pending, time_t now) {
  std::map<FlowKey, Flow>::iterator f, fn;
  for (f = flows.begin(); f != flows.end();) {
    fn = f; ++fn;
    if ((unsigned)(now - f->second.touched) > FLOW_TTL) flows.erase(f);
    f = fn;
  }
  long long current_ms = (long long)now * 1000LL;
  std::map<PacketKey, std::vector<Pending> >::iterator p, pn;
  for (p = pending.begin(); p != pending.end();) {
    pn = p; ++pn;
    size_t i = 0;
    while (i < p->second.size()) {
      if (current_ms - p->second[i].started_ms > (long long)PENDING_TTL * 1000LL) {
        emit_event(p->second[i].ev);
        p->second.erase(p->second.begin() + i);
      } else {
        ++i;
      }
    }
    if (p->second.empty()) pending.erase(p);
    p = pn;
  }
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

static bool g_monitored_ports[65536];

static bool handle_packet(const unsigned char *buf, size_t n, const std::string &node, const std::vector<unsigned> &ports,
                          std::map<FlowKey, Flow> &flows, std::map<PacketKey, std::vector<Pending> > &pending) {
  (void)ports;
  if (n < 34) return false;
  size_t off = 14;
  unsigned short et = ntohs(*(const unsigned short *)(buf + 12));
  if (et == ETH_P_8021Q) { if (n < 38) return false; et = ntohs(*(const unsigned short *)(buf + 16)); off = 18; }
  if (et != ETH_P_IP || n < off + 20) return false;
  unsigned char ihl = (unsigned char)(buf[off] & 15) * 4;
  if ((buf[off] >> 4) != 4 || buf[off + 9] != 6 || n < off + ihl + 20) return false;

  uint32_t s_ip = *(const uint32_t *)(buf + off + 12);
  uint32_t d_ip = *(const uint32_t *)(buf + off + 16);
  size_t to = off + ihl;
  unsigned sport = ntohs(*(const unsigned short *)(buf + to));
  unsigned dport = ntohs(*(const unsigned short *)(buf + to + 2));
  unsigned doff = (buf[to + 12] >> 4) * 4;
  if (n < to + doff) return false;
  const char *payload = (const char *)(buf + to + doff);
  size_t plen = n - to - doff;
  if (!plen) return false;

  time_t now = time(NULL);
  bool dst_mon = (dport < 65536) ? g_monitored_ports[dport] : false;
  bool src_mon = (sport < 65536) ? g_monitored_ports[sport] : false;

  if (src_mon && !dst_mon && plen >= 5) {
    if (memcmp(payload, "HTTP/", 5) == 0) {
      PacketKey k;
      k.s_ip = s_ip; k.sport = (uint16_t)sport; k.d_ip = d_ip; k.dport = (uint16_t)dport;
      std::map<PacketKey, std::vector<Pending> >::iterator p = pending.find(k);
      if (p != pending.end() && !p->second.empty()) {
        int st; unsigned cl;
        if (parse_response(payload, plen, &st, &cl)) {
          Event e = p->second[0].ev;
          e.status = st; e.has_status = true;
          e.duration_ms = (long)(now_ms() - p->second[0].started_ms);
          if (e.duration_ms < 0) e.duration_ms = 0;
          e.has_duration = true;
          if (cl) { e.resp_bytes = cl; e.has_resp = true; }
          emit_event(e);
          p->second.erase(p->second.begin());
          if (p->second.empty()) pending.erase(p);
        }
      }
    }
    return true;
  }
  unsigned char tcp_flags = buf[to + 13];
  if (!dst_mon) {
    if (tcp_flags & 0x05) { /* FIN or RST */
      FlowKey rfk; rfk.s_ip = d_ip; rfk.sport = (uint16_t)dport; rfk.d_ip = s_ip; rfk.dport = (uint16_t)sport;
      flows.erase(rfk);
    }
    return false;
  }

  FlowKey fk;
  fk.s_ip = s_ip; fk.sport = (uint16_t)sport; fk.d_ip = d_ip; fk.dport = (uint16_t)dport;
  if (tcp_flags & 0x05) { /* FIN or RST */
    flows.erase(fk);
    return true;
  }

  if (flows.find(fk) == flows.end() && flows.size() >= MAX_FLOWS) {
    flows.erase(flows.begin());
  }
  Flow &fl = flows[fk]; fl.touched = now; fl.buf.append(payload, plen);
  if (fl.buf.size() > MAX_HEADER) { flows.erase(fk); return false; }
  while (true) {
    size_t start = find_http_start(fl.buf);
    if (start == std::string::npos) { fl.buf.clear(); break; }
    if (start > 0) fl.buf.erase(0, start);
    size_t end = fl.buf.find("\r\n\r\n");
    if (end == std::string::npos) break;
    Event e; e.ts = now; e.host = node; e.service = "port:" + num(dport); e.caller = ip_to_str(s_ip); e.caller_port = sport; e.dst_ip = ip_to_str(d_ip); e.dst_port = dport; e.req_bytes = (unsigned)(end + 4);
    if (!parse_request(fl.buf.data(), end, &e)) { fl.buf.erase(0, end + 4); continue; }
    fl.buf.erase(0, end + 4);
    PacketKey rk; rk.s_ip = d_ip; rk.sport = (uint16_t)dport; rk.d_ip = s_ip; rk.dport = (uint16_t)sport;
    if (pending.size() >= MAX_PENDING) flush_oldest(pending);
    pending[rk].push_back(Pending(e, now_ms()));
  }
  if (fl.buf.empty()) {
    flows.erase(fk);
  }
  return true;
}

static bool attach_bpf(int fd, const std::vector<unsigned> &ports) {
  if (ports.empty()) return false;
  std::vector<struct sock_filter> f; size_t i;
  /* Dual-path cBPF: Path A (standard IPv4) and Path B (802.1Q VLAN tagged IPv4). */
  unsigned N = (unsigned)ports.size();
  unsigned reject = 11 + N * 8;
  unsigned accept = reject + 1;
  struct sock_filter x;
#define ADD(C,J,T,K) do { x.code=(C); x.jt=(J); x.jf=(T); x.k=(K); f.push_back(x); } while(0)
  /* [0] Load EtherType at offset 12 */
  ADD(BPF_LD|BPF_H|BPF_ABS, 0, 0, 12);
  /* [1] If standard IPv4 (0x0800), jump over Path B (6 + 4*N instructions) to Path A */
  ADD(BPF_JMP|BPF_JEQ|BPF_K, (unsigned)(6 + 4 * N), 0, ETH_P_IP_HOST);

  /* --- Path B: 802.1Q VLAN (index 2) --- */
  /* [2] If not 802.1Q (0x8100), reject */
  ADD(BPF_JMP|BPF_JEQ|BPF_K, 0, (unsigned)(reject - (unsigned)f.size() - 1), ETH_P_8021Q_HOST);
  /* [3] Load encapsulated EtherType at offset 16 */
  ADD(BPF_LD|BPF_H|BPF_ABS, 0, 0, 16);
  /* [4] If encapsulated != IPv4, reject */
  ADD(BPF_JMP|BPF_JEQ|BPF_K, 0, (unsigned)(reject - (unsigned)f.size() - 1), ETH_P_IP_HOST);
  /* [5] Load IP protocol at offset 27 (23 + 4) */
  ADD(BPF_LD|BPF_B|BPF_ABS, 0, 0, 27);
  /* [6] If not TCP, reject */
  ADD(BPF_JMP|BPF_JEQ|BPF_K, 0, (unsigned)(reject - (unsigned)f.size() - 1), IPPROTO_TCP);
  /* [7] Load IHL at offset 18 (14 + 4) */
  ADD(BPF_LDX|BPF_B|BPF_MSH, 0, 0, 18);
  /* Destination port checks for VLAN */
  for (i = 0; i < ports.size(); ++i) {
    ADD(BPF_LD|BPF_H|BPF_IND, 0, 0, 20);
    unsigned jt = accept - (unsigned)f.size() - 1;
    ADD(BPF_JMP|BPF_JEQ|BPF_K, jt, 0, ports[i]);
  }
  /* Source port checks for VLAN */
  for (i = 0; i < ports.size(); ++i) {
    ADD(BPF_LD|BPF_H|BPF_IND, 0, 0, 18);
    unsigned jt = accept - (unsigned)f.size() - 1;
    unsigned jf = (i < ports.size() - 1) ? 0 : (reject - (unsigned)f.size() - 1);
    ADD(BPF_JMP|BPF_JEQ|BPF_K, jt, jf, ports[i]);
  }

  /* --- Path A: Standard IPv4 --- */
  /* Load IP protocol at offset 23 */
  ADD(BPF_LD|BPF_B|BPF_ABS, 0, 0, 23);
  /* If not TCP, reject */
  ADD(BPF_JMP|BPF_JEQ|BPF_K, 0, (unsigned)(reject - (unsigned)f.size() - 1), IPPROTO_TCP);
  /* Load IHL at offset 14 */
  ADD(BPF_LDX|BPF_B|BPF_MSH, 0, 0, 14);
  /* Destination port checks for standard IPv4 */
  for (i = 0; i < ports.size(); ++i) {
    ADD(BPF_LD|BPF_H|BPF_IND, 0, 0, 16);
    unsigned jt = accept - (unsigned)f.size() - 1;
    ADD(BPF_JMP|BPF_JEQ|BPF_K, jt, 0, ports[i]);
  }
  /* Source port checks for standard IPv4 */
  for (i = 0; i < ports.size(); ++i) {
    ADD(BPF_LD|BPF_H|BPF_IND, 0, 0, 14);
    unsigned jt = accept - (unsigned)f.size() - 1;
    unsigned jf = (i < ports.size() - 1) ? 0 : (reject - (unsigned)f.size() - 1);
    ADD(BPF_JMP|BPF_JEQ|BPF_K, jt, jf, ports[i]);
  }

  /* [reject] Drop packet */
  ADD(BPF_RET|BPF_K, 0, 0, 0);
  /* [accept] Accept packet (2048 bytes) */
  ADD(BPF_RET|BPF_K, 0, 0, ACCEPT);
#undef ADD
  if (f.size() > 4096) return false;
  struct sock_fprog prog; prog.len = (unsigned short)f.size(); prog.filter = &f[0];
#ifndef SO_ATTACH_FILTER
#define SO_ATTACH_FILTER 26
#endif
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
               frame_size(2048), frame_nr(2048), frames_per_block(32), frame_idx(0) {}
};

static bool setup_mmap_ring(int fd, MmapRing &mr) {
  int ver = TPACKET_V2;
  if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver)) < 0) {
    return false;
  }
  struct tpacket_req req;
  memset(&req, 0, sizeof(req));
  req.tp_block_size = 65536;
  req.tp_block_nr = 64;       /* 4MB shared memory ring buffer */
  req.tp_frame_size = 2048;   /* 2KB per frame */
  req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size; /* 2048 frames */

  if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
    return false;
  }
  mr.ring_size = (size_t)req.tp_block_size * req.tp_block_nr;
  mr.block_size = req.tp_block_size;
  mr.block_nr = req.tp_block_nr;
  mr.frame_size = req.tp_frame_size;
  mr.frame_nr = req.tp_frame_nr;
  mr.frames_per_block = req.tp_block_size / req.tp_frame_size;
  mr.frame_idx = 0;

  mr.ring = mmap(NULL, mr.ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (mr.ring == MAP_FAILED) {
    mr.ring_size = 0;
    return false;
  }
  return true;
}

static int run_fixture() {
  std::string req = "GET /api/items?x=1 HTTP/1.1\r\nHost: api.local\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\nTraceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n\r\n";
  Event e; e.ts = 1700000000; e.host = "cpp-node"; e.service = "port:8080"; e.caller = "10.0.0.9"; e.caller_port = 51000; e.dst_ip = "10.0.0.2"; e.dst_port = 8080; e.req_bytes = (unsigned)req.size(); parse_request(req.data(), req.size() - 4, &e); e.status = 200; e.has_status = true; e.duration_ms = 3; e.has_duration = true; e.resp_bytes = 42; e.has_resp = true; emit_event(e); return 0;
}

int main(int argc, char **argv) {
  if (argc > 1 && !strcmp(argv[1], "--fixture")) return run_fixture();
  std::string iface; std::vector<unsigned> ports; int i; int workers = 1;
  std::string endpoint;
  for (i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "-i") && i + 1 < argc) iface = argv[++i];
    else if (!strcmp(argv[i], "-p") && i + 1 < argc) {
      while (i + 1 < argc && argv[i + 1][0] != '-') {
        char *q = strtok(argv[++i], ", ");
        while (q) { long p = atol(q); if (valid_port((unsigned)p)) ports.push_back((unsigned)p); q = strtok(NULL, ", "); }
      }
    }
    else if (!strcmp(argv[i], "--endpoint") && i + 1 < argc) endpoint = argv[++i];
    else if (!strcmp(argv[i], "--spool") && i + 1 < argc) ++i; /* ignored: 0 disk write */
    else if (!strcmp(argv[i], "-j") && i + 1 < argc) workers = atoi(argv[++i]);
    else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
      fprintf(stderr, "usage: nt-sniff-cpp [-i iface] [-p ports] [--endpoint URL] [-j workers]\n");
      return 0;
    }
  }
  if (ports.empty()) { ports.push_back(80); ports.push_back(8003); ports.push_back(8005); ports.push_back(8007); ports.push_back(8009); ports.push_back(8010); ports.push_back(8011); }
  (void)workers;

  init_rng();
  memset(g_monitored_ports, 0, sizeof(g_monitored_ports));
  for (size_t k = 0; k < ports.size(); ++k) {
    if (ports[k] < 65536) g_monitored_ports[ports[k]] = true;
  }

  const char *node_env = getenv("NT_NODE_NAME");
  std::string node = (node_env && *node_env) ? node_env : host_name();

  g_endpoint = endpoint;
  g_ship_node = node;

  int fd = socket(AF_PACKET, SOCK_RAW, htons(3));
  if (fd < 0) { perror("AF_PACKET"); return 2; }
  int rb = 8 * 1024 * 1024;
  setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rb, sizeof(rb));
  if (!attach_bpf(fd, ports)) logmsg("WARN: BPF attach failed; continuing unfiltered");

  MmapRing ring;
  bool use_mmap = setup_mmap_ring(fd, ring);

  struct sockaddr_ll sa;
  memset(&sa, 0, sizeof(sa));
  sa.sll_family = AF_PACKET;
  sa.sll_protocol = htons(3);
  if (!iface.empty()) {
    sa.sll_ifindex = (int)if_nametoindex(iface.c_str());
    if (!sa.sll_ifindex) { logmsg("bad interface"); close(fd); return 2; }
  }
  if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("bind"); close(fd); return 2; }

  signal(SIGTERM, stop_signal);
  signal(SIGINT, stop_signal);
  setvbuf(stdout, NULL, _IOLBF, 65536);
  std::map<FlowKey, Flow> flows;
  std::map<PacketKey, std::vector<Pending> > pending;

  if (use_mmap) {
    logmsg("PACKET_MMAP (TPACKET_V2) zero-copy ring enabled (4MB, 2048 frames)");
  } else {
    logmsg("WARN: PACKET_MMAP setup failed, falling back to standard socket recv");
  }
  if (!g_endpoint.empty()) {
    logmsg("single-binary in-memory mode: shipping directly to " + g_endpoint + " (0 disk I/O)");
  }
  logmsg("listening");

  time_t last = time(NULL), last_flush = last;
  unsigned char *fallback_buf = NULL;
  if (!use_mmap) {
    fallback_buf = (unsigned char *)malloc(65536);
    if (!fallback_buf) {
      close(fd);
      logmsg("buffer allocation failed");
      return 2;
    }
  }

  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLIN | POLLERR;
  pfd.revents = 0;

  while (g_running) {
    int rc = poll(&pfd, 1, 1000);
    if (rc < 0 && errno == EINTR) {
      /* Signal handled, loop condition will check g_running */
    } else if (rc >= 0) {
      if (use_mmap) {
        /* Drain all ready frames in the ring without extra syscalls */
        while (g_running) {
          unsigned b_idx = ring.frame_idx / ring.frames_per_block;
          unsigned f_in_b = ring.frame_idx % ring.frames_per_block;
          uint8_t *frame_ptr = ((uint8_t *)ring.ring) + (b_idx * ring.block_size) + (f_in_b * ring.frame_size);
          struct tpacket2_hdr *hdr = (struct tpacket2_hdr *)frame_ptr;

          if (!(hdr->tp_status & TP_STATUS_USER)) {
            break; /* No more kernel-populated frames in ring right now */
          }

          if (hdr->tp_snaplen > 0) {
            const unsigned char *pkt = ((const unsigned char *)hdr) + hdr->tp_mac;
            handle_packet(pkt, (size_t)hdr->tp_snaplen, node, ports, flows, pending);
          }

          hdr->tp_status = TP_STATUS_KERNEL; /* Return frame ownership to kernel */
          ring.frame_idx = (ring.frame_idx + 1) % ring.frame_nr;
        }
        if (g_endpoint.empty()) std::cout.flush();
      } else {
        if (pfd.revents & POLLIN) {
          ssize_t n = recv(fd, fallback_buf, 65536, 0);
          if (n > 0) {
            handle_packet(fallback_buf, (size_t)n, node, ports, flows, pending);
            if (g_endpoint.empty()) std::cout.flush();
          }
        }
      }
    }

    time_t now = time(NULL);
    if (now - last >= 1) {
      sweep(flows, pending, now);
      if (g_endpoint.empty()) std::cout.flush();
      last = now;
    }

    if (!g_endpoint.empty()) {
      if (now - last_flush >= FLUSH_SEC || g_ship_buf.size() >= MAX_BATCH) {
        if (!g_ship_buf.empty()) send_batches(g_endpoint, g_ship_node, &g_ship_buf, true);
        last_flush = now;
      }
    }
  }

  if (!g_endpoint.empty() && !g_ship_buf.empty()) {
    send_batches(g_endpoint, g_ship_node, &g_ship_buf, true);
  }

  if (use_mmap && ring.ring != MAP_FAILED) {
    munmap(ring.ring, ring.ring_size);
  }
  if (fallback_buf) free(fallback_buf);
  close(fd);
  logmsg("stopped");
  return 0;
}
