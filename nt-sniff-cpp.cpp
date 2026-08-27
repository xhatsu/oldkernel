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
#include <sys/ioctl.h>
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

#include <map>
#include <sstream>
#include <string>
#include <vector>

static volatile sig_atomic_t g_running = 1;
static void stop_signal(int) { g_running = 0; }

static const size_t MAX_FLOWS = 8192;
static const size_t MAX_PENDING = 8192;
static const size_t MAX_HEADER = 262144;
static const unsigned FLOW_TTL = 300;
static const unsigned PENDING_TTL = 5;
static const unsigned ACCEPT = 0x40000;
static const int SO_ATTACH_FILTER_OLD = 26;
static const unsigned short ETH_P_IP_HOST = 0x0800;

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
static std::string b64decode_user(const std::string &v) {
  std::string in = trim(v), out; int val = 0, bits = -8; size_t i;
  for (i = 0; i < in.size(); ++i) {
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
static std::string header_value(const std::string &head, const std::string &want) {
  std::istringstream in(head); std::string line, w = lower(want);
  while (std::getline(in, line)) {
    if (!line.empty() && line[line.size() - 1] == '\r') line.erase(line.size() - 1);
    size_t p = line.find(':'); if (p == std::string::npos) continue;
    if (lower(trim(line.substr(0, p))) == w) return trim(line.substr(p + 1));
  }
  return "";
}
static std::string trace_id_from_parent(const std::string &tp) {
  std::string x = trim(tp);
  if (x.size() == 55 && x[2] == '-' && x[35] == '-' && x[52] == '-') return lower(x.substr(3, 32));
  return "";
}
static std::string make_traceparent(std::string *tid) {
  unsigned char b[24]; size_t i; FILE *f = fopen("/dev/urandom", "rb");
  if (f) { size_t got = fread(b, 1, sizeof(b), f); (void)got; fclose(f); }
  else { unsigned long t = (unsigned long)time(NULL) ^ (unsigned long)getpid(); for (i = 0; i < sizeof(b); ++i) b[i] = (unsigned char)(t = t * 1103515245UL + 12345UL); }
  static const char *hex = "0123456789abcdef"; std::string a, c;
  for (i = 0; i < 16; ++i) { a += hex[b[i] >> 4]; a += hex[b[i] & 15]; }
  for (i = 16; i < 24; ++i) { c += hex[b[i] >> 4]; c += hex[b[i] & 15]; }
  *tid = a; return "00-" + a + "-" + c + "-01";
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
struct PacketKey { std::string src; unsigned sport; std::string dst; unsigned dport; bool operator<(const PacketKey &x) const { return src != x.src ? src < x.src : sport != x.sport ? sport < x.sport : dst != x.dst ? dst < x.dst : dport < x.dport; } };

static std::string key_string(const std::string &a, unsigned ap, const std::string &b, unsigned bp) { return a + ":" + num(ap) + "->" + b + ":" + num(bp); }
static void logmsg(const std::string &s) { fprintf(stderr, "nt-sniff-cpp: %s\n", s.c_str()); fflush(stderr); }

static bool parse_request(const std::string &head, Event *e) {
  std::string first; std::istringstream in(head); if (!std::getline(in, first)) return false;
  std::istringstream p(trim(first)); if (!(p >> e->method >> e->path)) return false;
  if (!has_method(e->method)) return false;
  size_t q = e->path.find('?'); if (q != std::string::npos) e->path.erase(q);
  if (e->path.size() > 120) e->path.erase(120);
  std::string auth = header_value(head, "authorization");
  if (lower(auth).find("basic ") == 0) { e->user = b64decode_user(auth.substr(6)); e->scheme = "basic"; }
  else if (lower(auth).find("bearer ") == 0) e->scheme = "bearer";
  std::string x = header_value(head, "traceparent"); e->trace_id = trace_id_from_parent(x); e->traceparent = e->trace_id.empty() ? make_traceparent(&e->trace_id) : x;
  e->host_hdr = header_value(head, "host");
  e->user_agent = header_value(head, "user-agent");
  e->xff = header_value(head, "x-forwarded-for");
  if (e->user.empty()) {
    e->user = "-anonymous-";
  }
  if (e->scheme.empty()) {
    e->scheme = "none";
  }
  return true;
}
static bool parse_response(const std::string &payload, int *status, unsigned *clen) {
  size_t end = payload.find("\r\n\r\n");
  std::string h = payload.substr(0, end == std::string::npos ? payload.size() : end);
  if (h.size() > MAX_HEADER) return false;
  std::istringstream in(h);
  std::string first;
  if (!std::getline(in, first)) return false;
  std::istringstream p(first);
  std::string proto;
  if (!(p >> proto >> *status)) return false;
  if (proto.find("HTTP/") != 0 || *status < 100 || *status > 599) return false;
  *clen = 0; std::string line;
  while (std::getline(in, line)) { size_t x = line.find(':'); if (x != std::string::npos && lower(trim(line.substr(0, x))) == "content-length") { long n = atol(trim(line.substr(x + 1)).c_str()); if (n >= 0 && n <= 0x7fffffff) *clen = (unsigned)n; } }
  return true;
}
static void emit_event(const Event &e) {
  std::cout << "{\"ts\":" << e.ts << ",\"host\":" << jsonq(e.host) << ",\"src\":\"pcap\",\"service\":" << jsonq(e.service)
            << ",\"method\":" << jsonq(e.method) << ",\"path\":" << jsonq(e.path) << ",\"user\":" << jsonq(e.user)
            << ",\"scheme\":" << jsonq(e.scheme) << ",\"source_probe\":\"pcap-http-cpp\",\"host_hdr\":" << jsonq(e.host_hdr)
            << ",\"user_agent\":" << jsonq(e.user_agent) << ",\"x_forwarded_for\":" << jsonq(e.xff)
            << ",\"caller\":" << jsonq(e.caller) << ",\"caller_port\":" << e.caller_port << ",\"dst_ip\":" << jsonq(e.dst_ip)
            << ",\"dst_port\":" << e.dst_port << ",\"traceparent\":" << jsonq(e.traceparent) << ",\"trace_id\":" << jsonq(e.trace_id)
            << ",\"service_id\":null,\"module_id\":\"pcap-http-cpp\",\"req_bytes\":" << e.req_bytes;
  if (e.has_status) std::cout << ",\"status\":" << e.status; else std::cout << ",\"status\":null";
  if (e.has_duration) std::cout << ",\"duration_ms\":" << e.duration_ms; else std::cout << ",\"duration_ms\":null";
  if (e.has_resp) std::cout << ",\"resp_bytes\":" << e.resp_bytes; else std::cout << ",\"resp_bytes\":null";
  std::cout << "}\n"; std::cout.flush();
}

static void flush_oldest(std::map<PacketKey, std::vector<Pending> > &pending) {
  std::map<PacketKey, std::vector<Pending> >::iterator best = pending.end(); long long bt = 0; bool found = false;
  std::map<PacketKey, std::vector<Pending> >::iterator i;
  for (i = pending.begin(); i != pending.end(); ++i) if (!i->second.empty() && (!found || i->second[0].started_ms < bt)) { best = i; bt = i->second[0].started_ms; found = true; }
  if (found) { emit_event(best->second[0].ev); best->second.erase(best->second.begin()); if (best->second.empty()) pending.erase(best); }
}
static void sweep(std::map<std::string, Flow> &flows, std::map<PacketKey, std::vector<Pending> > &pending, time_t now) {
  std::map<std::string, Flow>::iterator f, fn;
  for (f = flows.begin(); f != flows.end();) {
    fn = f; ++fn;
    if ((unsigned)(now - f->second.touched) > FLOW_TTL) flows.erase(f);
    f = fn;
  }
  long long current_ms = (long long)now * 1000LL;
  std::map<PacketKey, std::vector<Pending> >::iterator p, pn;
  for (p = pending.begin(); p != pending.end();) {
    pn = p; ++pn;
    if (!p->second.empty() && current_ms - p->second[0].started_ms > (long long)PENDING_TTL * 1000LL) {
      emit_event(p->second[0].ev); pending.erase(p);
    }
    p = pn;
  }
}
static bool handle_packet(const unsigned char *buf, size_t n, const std::string &node, const std::vector<unsigned> &ports,
                          std::map<std::string, Flow> &flows, std::map<PacketKey, std::vector<Pending> > &pending) {
  if (n < 34) return false;
  size_t off = 14;
  unsigned short et = ntohs(*(const unsigned short *)(buf + 12));
  if (et == ETH_P_8021Q) { if (n < 38) return false; et = ntohs(*(const unsigned short *)(buf + 16)); off = 18; }
  if (et != ETH_P_IP || n < off + 20) return false;
  unsigned char ihl = (unsigned char)(buf[off] & 15) * 4;
  if ((buf[off] >> 4) != 4 || buf[off + 9] != 6 || n < off + ihl + 20) return false;
  char a[INET_ADDRSTRLEN], b[INET_ADDRSTRLEN]; inet_ntop(AF_INET, buf + off + 12, a, sizeof(a)); inet_ntop(AF_INET, buf + off + 16, b, sizeof(b));
  size_t to = off + ihl; unsigned sport = ntohs(*(const unsigned short *)(buf + to)); unsigned dport = ntohs(*(const unsigned short *)(buf + to + 2)); unsigned doff = (buf[to + 12] >> 4) * 4; if (n < to + doff) return false; const char *payload = (const char *)(buf + to + doff); size_t plen = n - to - doff; if (!plen) return false;
  time_t now = time(NULL);
  bool dst_mon = false, src_mon = false;
  size_t j;
  for (j = 0; j < ports.size(); ++j) {
    if (dport == ports[j]) dst_mon = true;
    if (sport == ports[j]) src_mon = true;
  }
  if (src_mon && !dst_mon && plen >= 5 && memcmp(payload, "HTTP/", 5) == 0) {
    PacketKey k;
    k.src = a; k.sport = sport; k.dst = b; k.dport = dport;
    std::map<PacketKey, std::vector<Pending> >::iterator p = pending.find(k);
    if (p != pending.end() && !p->second.empty()) {
      int st; unsigned cl;
      if (parse_response(std::string(payload, plen), &st, &cl)) {
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
    return true;
  }
  if (!dst_mon) return false;
  std::string fk = key_string(a, sport, b, dport); Flow &fl = flows[fk]; fl.touched = now; fl.buf.append(payload, plen);
  if (fl.buf.size() > MAX_HEADER) { flows.erase(fk); return false; }
  size_t end = fl.buf.find("\r\n\r\n"); if (end == std::string::npos) return false;
  Event e; e.ts = now; e.host = node; e.service = "port:" + num(dport); e.caller = a; e.caller_port = sport; e.dst_ip = b; e.dst_port = dport; e.req_bytes = (unsigned)(end + 4);
  if (!parse_request(fl.buf.substr(0, end), &e)) { flows.erase(fk); return false; } flows.erase(fk);
  PacketKey rk; rk.src = b; rk.sport = dport; rk.dst = a; rk.dport = sport; if (pending.size() >= MAX_PENDING) flush_oldest(pending); pending[rk].push_back(Pending(e, now_ms())); return true;
}

static bool attach_bpf(int fd, const std::vector<unsigned> &ports) {
  /* BPF is optional at startup: the parser still performs the same checks
     after bind. This keeps the binary usable on kernels rejecting the
     generated filter, while logging the degraded mode. */
  std::vector<struct sock_filter> f; size_t i; unsigned reject = 0, accept;
  /* Ethernet IPv4, TCP, then destination OR source monitored port. */
  reject = 4 + (unsigned)ports.size() * 4 + 1; accept = reject + 1;
  struct sock_filter x;
#define ADD(C,J,T,K) do { x.code=(C); x.jt=(J); x.jf=(T); x.k=(K); f.push_back(x); } while(0)
  ADD(BPF_LD|BPF_H|BPF_ABS,0,0,12); ADD(BPF_JMP|BPF_JEQ|BPF_K,0,reject-2,ETH_P_IP_HOST);
  ADD(BPF_LD|BPF_B|BPF_ABS,0,0,23); ADD(BPF_JMP|BPF_JEQ|BPF_K,0,reject-4,IPPROTO_TCP);
  ADD(BPF_LD|BPF_B|BPF_MSH,0,0,14);
  for (i = 0; i < ports.size(); ++i) {
    ADD(BPF_LD|BPF_H|BPF_IND, 0, 0, 16);
    unsigned jt = accept - (unsigned)f.size() - 1;
    unsigned jf = 0;
    ADD(BPF_JMP|BPF_JEQ|BPF_K, jt, jf, ports[i]);
  }
  for (i = 0; i < ports.size(); ++i) {
    ADD(BPF_LD|BPF_H|BPF_IND, 0, 0, 14);
    unsigned jt = accept - (unsigned)f.size() - 1;
    unsigned jf = (i < ports.size() - 1) ? 0 : (reject - (unsigned)f.size() - 1);
    ADD(BPF_JMP|BPF_JEQ|BPF_K, jt, jf, ports[i]);
  }
  ADD(BPF_RET|BPF_K,0,0,0); ADD(BPF_RET|BPF_K,0,0,ACCEPT);
#undef ADD
  if (f.size() > 4096) return false;
  struct sock_fprog prog; prog.len = (unsigned short)f.size(); prog.filter = &f[0]; return setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER_OLD, &prog, sizeof(prog)) == 0;
}

static int run_fixture() {
  std::string req = "GET /api/items?x=1 HTTP/1.1\r\nHost: api.local\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\nTraceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n\r\n";
  Event e; e.ts = 1700000000; e.host = "cpp-node"; e.service = "port:8080"; e.caller = "10.0.0.9"; e.caller_port = 51000; e.dst_ip = "10.0.0.2"; e.dst_port = 8080; e.req_bytes = (unsigned)req.size(); parse_request(req.substr(0, req.size() - 4), &e); e.status = 200; e.has_status = true; e.duration_ms = 3; e.has_duration = true; e.resp_bytes = 42; e.has_resp = true; emit_event(e); return 0;
}
int main(int argc, char **argv) {
  if (argc > 1 && !strcmp(argv[1], "--fixture")) return run_fixture();
  std::string iface; std::vector<unsigned> ports; int i; int workers = 1;
  for (i = 1; i < argc; ++i) { if (!strcmp(argv[i], "-i") && i + 1 < argc) iface = argv[++i]; else if (!strcmp(argv[i], "-p") && i + 1 < argc) { char *q = strtok(argv[++i], ","); while (q) { long p = atol(q); if (valid_port((unsigned)p)) ports.push_back((unsigned)p); q = strtok(NULL, ","); } } else if (!strcmp(argv[i], "-j") && i + 1 < argc) workers = atoi(argv[++i]); else if (!strcmp(argv[i], "-h")) { fprintf(stderr, "usage: nt-sniff-cpp [-i iface] [-p ports] [-j workers]\n"); return 0; } }
  if (ports.empty()) { ports.push_back(80); ports.push_back(8003); ports.push_back(8005); ports.push_back(8007); ports.push_back(8009); ports.push_back(8010); ports.push_back(8011); }
  (void)workers; std::string node = host_name(); int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)); if (fd < 0) { perror("AF_PACKET"); return 2; }
  int rb = 8 * 1024 * 1024;
  setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rb, sizeof(rb));
  if (!attach_bpf(fd, ports)) logmsg("WARN: BPF attach failed; continuing unfiltered");
  struct sockaddr_ll sa; memset(&sa, 0, sizeof(sa)); sa.sll_family = AF_PACKET; if (!iface.empty()) { sa.sll_ifindex = (int)if_nametoindex(iface.c_str()); if (!sa.sll_ifindex) { logmsg("bad interface"); close(fd); return 2; } } if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("bind"); close(fd); return 2; }
  signal(SIGTERM, stop_signal);
  signal(SIGINT, stop_signal);
  std::map<std::string, Flow> flows;
  std::map<PacketKey, std::vector<Pending> > pending;
  logmsg("listening");
  time_t last = time(NULL);
  unsigned char *buf = (unsigned char *)malloc(65536);
  if (!buf) {
    close(fd);
    logmsg("buffer allocation failed");
    return 2;
  }
  while (g_running) {
    fd_set r;
    FD_ZERO(&r);
    FD_SET(fd, &r);
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    int rc = select(fd + 1, &r, NULL, NULL, &tv);
    if (rc > 0 && FD_ISSET(fd, &r)) {
      ssize_t n = recv(fd, buf, 65536, 0);
      if (n > 0) handle_packet(buf, (size_t)n, node, ports, flows, pending);
    }
    time_t now = time(NULL);
    if (now - last >= 1) {
      sweep(flows, pending, now);
      last = now;
    }
  }
  free(buf); close(fd); logmsg("stopped"); return 0;
}
