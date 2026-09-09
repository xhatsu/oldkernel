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
#include <linux/filter.h>
#include <linux/capability.h>
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
static const size_t MAX_PENDING_PER_FLOW = 32;
static const size_t MAX_PORTS = 30;
static const size_t MAX_HEADER = 262144;
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
  RequestMeta() : content_length(0), has_content_length(false) {}
};
struct Flow {
  std::string buf;
  time_t touched;
  Event event;
  size_t body_goal;
  bool awaiting_body;
  Flow() : touched(time(NULL)), body_goal(0), awaiting_body(false) {}
};
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
        meta->has_content_length = parse_decimal_size(val_start, val_len, &meta->content_length);
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

static bool is_soap_content_type(const std::string &value) {
  std::string media = lower(value);
  size_t semi = media.find(';');
  if (semi != std::string::npos) media.erase(semi);
  media = trim(media);
  return media == "text/xml" || media == "application/xml" ||
         media == "application/soap+xml" ||
         (media.size() > 4 && media.compare(media.size() - 4, 4, "+xml") == 0);
}

static void split_qname(const std::string &name, std::string *prefix, std::string *local) {
  size_t colon = name.find(':');
  if (colon == std::string::npos) { prefix->clear(); *local = name; }
  else { *prefix = name.substr(0, colon); *local = name.substr(colon + 1); }
}

static bool append_utf8(unsigned long cp, std::string *out) {
  if (cp == 0 || cp > 0x10ffffUL || (cp >= 0xd800UL && cp <= 0xdfffUL)) return false;
  if (cp < 0x80) out->push_back((char)cp);
  else if (cp < 0x800) {
    out->push_back((char)(0xc0 | (cp >> 6)));
    out->push_back((char)(0x80 | (cp & 0x3f)));
  } else if (cp < 0x10000) {
    out->push_back((char)(0xe0 | (cp >> 12)));
    out->push_back((char)(0x80 | ((cp >> 6) & 0x3f)));
    out->push_back((char)(0x80 | (cp & 0x3f)));
  } else {
    out->push_back((char)(0xf0 | (cp >> 18)));
    out->push_back((char)(0x80 | ((cp >> 12) & 0x3f)));
    out->push_back((char)(0x80 | ((cp >> 6) & 0x3f)));
    out->push_back((char)(0x80 | (cp & 0x3f)));
  }
  return true;
}

static bool xml_unescape(const std::string &text, std::string *out) {
  for (size_t i = 0; i < text.size();) {
    if (text[i] != '&') { out->push_back(text[i++]); continue; }
    size_t semi = text.find(';', i + 1);
    if (semi == std::string::npos || semi - i > 12) return false;
    std::string ent = text.substr(i + 1, semi - i - 1);
    if (ent == "amp") out->push_back('&');
    else if (ent == "lt") out->push_back('<');
    else if (ent == "gt") out->push_back('>');
    else if (ent == "quot") out->push_back('"');
    else if (ent == "apos") out->push_back('\'');
    else if (!ent.empty() && ent[0] == '#') {
      char *endp = NULL;
      unsigned long cp = strtoul(ent.c_str() + ((ent.size() > 1 && (ent[1] == 'x' || ent[1] == 'X')) ? 2 : 1),
                                 &endp, (ent.size() > 1 && (ent[1] == 'x' || ent[1] == 'X')) ? 16 : 10);
      if (!endp || *endp || !append_utf8(cp, out)) return false;
    } else return false;
    i = semi + 1;
  }
  return true;
}

static bool valid_utf8_username(const std::string &s) {
  if (s.empty() || s.size() > MAX_WSSE_USERNAME * 4) return false;
  size_t characters = 0;
  for (size_t i = 0; i < s.size();) {
    unsigned char c = (unsigned char)s[i];
    unsigned long cp = c;
    if (c < 0x80) { ++i; }
    else {
    size_t need = (c >= 0xc2 && c <= 0xdf) ? 1 :
                  (c >= 0xe0 && c <= 0xef) ? 2 :
                  (c >= 0xf0 && c <= 0xf4) ? 3 : 99;
    if (need == 99 || i + need >= s.size()) return false;
    for (size_t j = 1; j <= need; ++j)
      if (((unsigned char)s[i + j] & 0xc0) != 0x80) return false;
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
      break; /* a bounded prefix is commonly incomplete */
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
static unsigned g_ship_rate_kbps = DEFAULT_SHIP_RATE_KBPS;
static unsigned g_stats_interval_sec = 30;
static size_t g_wsse_body_bytes = 0;
static double g_next_ship_slot = 0.0;
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
static void pace_upload(size_t bytes) {
  const double bytes_per_sec = (double)g_ship_rate_kbps * 1000.0 / 8.0;
  double now = wall_seconds();
  if (g_next_ship_slot < now || g_next_ship_slot - now > 60.0) g_next_ship_slot = now;
  double slot = g_next_ship_slot;
  g_next_ship_slot += (double)bytes / bytes_per_sec;
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
static bool post_body(const std::string &endpoint, const std::string &path,
                      const std::string &body, unsigned timeout_sec) {
  pace_upload(body.size());
  std::string cmd = "curl -sSf --max-time " + number_string(timeout_sec) + " --limit-rate " +
    number_string((size_t)g_ship_rate_kbps * 1000U / 8U) +
    " -o /dev/null -H 'Content-Type: application/json' --data-binary @- " + shellq(endpoint + path);
  FILE *fp = popen(cmd.c_str(), "w"); if (!fp) return false;
  fwrite(body.data(), 1, body.size(), fp);
  int rc = pclose(fp);
  return WIFEXITED(rc) && WEXITSTATUS(rc) == 0;
}
static bool post(const std::string &endpoint, const std::string &node, const std::vector<std::string> &batch) {
  std::string body = "{\"node\":" + jsonq(node) + ",\"events\":" + json_array(batch) + "}";
  if (body.size() > MAX_POST_BYTES) return false;
  bool ok = post_body(endpoint, "/api/ingest", body, 10);
  if (ok) {
    g_events_pushed += batch.size();
    ++g_batches_pushed;
    g_bytes_pushed += body.size();
    g_consecutive_failures = 0;
    g_last_push_status = 200;
    g_last_success_at = time(NULL);
  }
  return ok;
}
static void send_batches(const std::string &endpoint, const std::string &node,
                         std::vector<std::string> *buf, bool flush_all) {
  while (!buf->empty() && (flush_all || buf->size() >= MAX_BATCH)) {
    size_t n = bounded_batch_count(*buf, node);
    if (!n) {
      buf->erase(buf->begin());
      ++g_events_dropped;
      ++g_drop_oversized;
      logmsg("WARN: dropped oversized event; encoded body exceeds 65536 bytes");
      continue;
    }
    std::vector<std::string> batch(buf->begin(), buf->begin() + n);
    if (post(endpoint, node, batch)) {
      buf->erase(buf->begin(), buf->begin() + n);
      logmsg("flushed " + number_string(n) + " events");
    } else {
      /* Pure in-memory drop when Hub unreachable (zero disk I/O) */
      buf->erase(buf->begin(), buf->begin() + n);
      g_events_dropped += n;
      g_drop_hub += n;
      ++g_batches_failed;
      ++g_consecutive_failures;
      g_last_push_status = 0;
      logmsg("WARN: Hub unreachable, dropped " + number_string(n) + " events (in-memory drop, 0 disk I/O)");
      break;
    }
  }
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
  unsigned long long in_delta = g_events_in - g_prev_events_in;
  unsigned long long pushed_delta = g_events_pushed - g_prev_events_pushed;
  unsigned long long dropped_delta = g_events_dropped - g_prev_events_dropped;
  unsigned long long batches_pushed_delta = g_batches_pushed - g_prev_batches_pushed;
  unsigned long long batches_failed_delta = g_batches_failed - g_prev_batches_failed;
  unsigned long long bytes_delta = g_bytes_pushed - g_prev_bytes_pushed;
  unsigned long long queue_delta = g_drop_queue - g_prev_drop_queue;
  unsigned long long hub_delta = g_drop_hub - g_prev_drop_hub;
  unsigned long long oversized_delta = g_drop_oversized - g_prev_drop_oversized;
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
      << ",\"queue_depth_events\":" << g_ship_buf.size() << ",\"queue_capacity_events\":" << MAX_QUEUE
      << ",\"queue_high_water_events\":" << g_queue_high_water << ",\"last_push_http_status\":" << g_last_push_status
      << ",\"last_success_at\":" << (unsigned long)g_last_success_at << ",\"consecutive_failures\":" << g_consecutive_failures
      << ",\"stats_samples_dropped_total\":" << ull_string(g_stats_dropped) << "},\"resources\":{"
      << "\"cpu_user_seconds\":" << double_string(user_cpu) << ",\"cpu_system_seconds\":" << double_string(sys_cpu)
      << ",\"cpu_percent_one_core\":" << double_string(cpu_pct) << ",\"rss_bytes\":" << rss
      << ",\"virtual_bytes\":" << virt << ",\"open_fds\":" << count_open_fds() << ",\"threads\":" << threads
      << "},\"limits\":{\"cpu_core\":" << cpu_core << ",\"address_space_bytes\":268435456"
      << ",\"ship_rate_kbps\":" << g_ship_rate_kbps << ",\"http_body_max_bytes\":" << MAX_POST_BYTES
      << ",\"ship_threads_max\":1,\"wsse_body_bytes\":" << g_wsse_body_bytes << "}}";
  g_prev_capture_packets = g_capture_packets; g_prev_capture_bytes = g_capture_bytes;
  g_prev_events_emitted = g_events_emitted; g_prev_events_in = g_events_in;
  g_prev_events_pushed = g_events_pushed; g_prev_events_dropped = g_events_dropped;
  g_prev_batches_pushed = g_batches_pushed; g_prev_batches_failed = g_batches_failed;
  g_prev_bytes_pushed = g_bytes_pushed; g_prev_drop_queue = g_drop_queue;
  g_prev_drop_hub = g_drop_hub; g_prev_drop_oversized = g_drop_oversized;
  g_prev_output_pipe_drops = g_output_pipe_drops;
  g_stats_last_cpu = cpu_total; g_stats_last_at = now;
  return out.str();
}

static void send_agent_stats(int fd, size_t flows_active,
                             size_t pending_requests,
                             size_t wsse_body_flows) {
  std::string body = agent_stats_body(fd, flows_active, pending_requests,
                                      wsse_body_flows);
  if (body.size() > MAX_STATS_BYTES ||
      !post_body(g_endpoint, "/api/agent/stats", body, 2)) {
    ++g_stats_dropped;
  }
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
    if (g_ship_buf.size() >= MAX_QUEUE) {
      g_ship_buf.erase(g_ship_buf.begin());
      ++g_events_dropped;
      ++g_drop_queue;
    }
    g_ship_buf.push_back(ss.str());
    if (g_ship_buf.size() > g_queue_high_water) g_queue_high_water = g_ship_buf.size();
  } else {
    write_nonblocking_line(ss.str());
  }
}

static void queue_request(const Event &e, uint32_t s_ip, unsigned sport,
                          uint32_t d_ip, unsigned dport,
                          std::map<PacketKey, std::vector<Pending> > &pending);

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
static void flush_all_pending(std::map<PacketKey, std::vector<Pending> > &pending) {
  std::map<PacketKey, std::vector<Pending> >::iterator p;
  for (p = pending.begin(); p != pending.end(); ++p) {
    for (size_t i = 0; i < p->second.size(); ++i) {
      emit_event(p->second[i].ev);
    }
  }
  pending.clear();
}
static void flush_incomplete_wsse(std::map<FlowKey, Flow> &flows,
                                  std::map<PacketKey, std::vector<Pending> > &pending) {
  std::map<FlowKey, Flow>::iterator f;
  for (f = flows.begin(); f != flows.end(); ++f) {
    if (f->second.awaiting_body && !f->second.event.basic_user.empty()) {
      queue_request(f->second.event, f->first.s_ip, f->first.sport,
                    f->first.d_ip, f->first.dport, pending);
    }
  }
  flows.clear();
}
static void sweep(std::map<FlowKey, Flow> &flows, std::map<PacketKey, std::vector<Pending> > &pending, time_t now) {
  std::map<FlowKey, Flow>::iterator f, fn;
  for (f = flows.begin(); f != flows.end();) {
    fn = f; ++fn;
    if ((unsigned)(now - f->second.touched) > FLOW_TTL) {
      if (f->second.awaiting_body && !f->second.event.basic_user.empty()) {
        queue_request(f->second.event, f->first.s_ip, f->first.sport,
                      f->first.d_ip, f->first.dport, pending);
      }
      flows.erase(f);
    }
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

static void queue_request(const Event &e, uint32_t s_ip, unsigned sport,
                          uint32_t d_ip, unsigned dport,
                          std::map<PacketKey, std::vector<Pending> > &pending) {
  PacketKey rk;
  rk.s_ip = d_ip; rk.sport = (uint16_t)dport;
  rk.d_ip = s_ip; rk.dport = (uint16_t)sport;
  if (pending.find(rk) == pending.end() && pending.size() >= MAX_PENDING) {
    flush_oldest(pending);
  }
  std::vector<Pending> &queue = pending[rk];
  if (queue.size() >= MAX_PENDING_PER_FLOW) {
    emit_event(queue[0].ev);
    queue.erase(queue.begin());
  }
  queue.push_back(Pending(e, now_ms()));
}

static size_t active_wsse_flows(const std::map<FlowKey, Flow> &flows) {
  size_t count = 0;
  std::map<FlowKey, Flow>::const_iterator it;
  for (it = flows.begin(); it != flows.end(); ++it)
    if (it->second.awaiting_body) ++count;
  return count;
}

static bool handle_packet(const unsigned char *buf, size_t n, const std::string &node, const std::vector<unsigned> &ports,
                          std::map<FlowKey, Flow> &flows, std::map<PacketKey, std::vector<Pending> > &pending) {
  (void)ports;
  if (n < 34) return false;
  size_t off = 14;
  unsigned short et = ntohs(read_u16(buf + 12));
  if (et == ETH_P_8021Q) { if (n < 38) return false; et = ntohs(read_u16(buf + 16)); off = 18; }
  if (et != ETH_P_IP || n < off + 20) return false;
  unsigned char ihl = (unsigned char)(buf[off] & 15) * 4;
  if ((buf[off] >> 4) != 4 || buf[off + 9] != 6 || n < off + ihl + 20) return false;

  uint32_t s_ip = read_u32(buf + off + 12);
  uint32_t d_ip = read_u32(buf + off + 16);
  size_t to = off + ihl;
  unsigned sport = ntohs(read_u16(buf + to));
  unsigned dport = ntohs(read_u16(buf + to + 2));
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
    std::map<FlowKey, Flow>::iterator existing = flows.find(fk);
    if (existing != flows.end() && existing->second.awaiting_body &&
        !existing->second.event.basic_user.empty()) {
      queue_request(existing->second.event, s_ip, sport, d_ip, dport, pending);
    }
    flows.erase(fk);
    return true;
  }

  if (flows.find(fk) == flows.end() && flows.size() >= MAX_FLOWS) {
    flows.erase(flows.begin());
  }
  Flow &fl = flows[fk]; fl.touched = now;
  if (fl.awaiting_body) {
    std::string next_segment(payload, plen);
    if (!fl.event.basic_user.empty() && find_http_start(next_segment) == 0) {
      Event previous = fl.event;
      fl = Flow();
      fl.touched = now;
      queue_request(previous, s_ip, sport, d_ip, dport, pending);
    } else {
      size_t remaining = fl.body_goal > fl.buf.size() ? fl.body_goal - fl.buf.size() : 0;
      if (remaining) fl.buf.append(payload, plen < remaining ? plen : remaining);
      std::string username = extract_wsse_username(fl.buf);
      if (!username.empty() || fl.buf.size() >= fl.body_goal) {
        Event event = fl.event;
        if (!username.empty()) {
          event.wsse_user = username; event.user = username; event.scheme = "wsse";
        }
        flows.erase(fk);
        queue_request(event, s_ip, sport, d_ip, dport, pending);
      }
      return true;
    }
  }
  fl.buf.append(payload, plen);
  if (fl.buf.size() > MAX_HEADER) { flows.erase(fk); return false; }
  while (true) {
    size_t start = find_http_start(fl.buf);
    if (start == std::string::npos) { fl.buf.clear(); break; }
    if (start > 0) fl.buf.erase(0, start);
    size_t end = fl.buf.find("\r\n\r\n");
    if (end == std::string::npos) break;
    Event e; RequestMeta meta; e.ts = now; e.host = node; e.service = "port:" + num(dport); e.caller = ip_to_str(s_ip); e.caller_port = sport; e.dst_ip = ip_to_str(d_ip); e.dst_port = dport; e.req_bytes = (unsigned)(end + 4);
    if (!parse_request(fl.buf.data(), end, &e, &meta)) { fl.buf.erase(0, end + 4); continue; }
    fl.buf.erase(0, end + 4);
    if (g_wsse_body_bytes &&
        is_soap_content_type(meta.content_type) && meta.has_content_length &&
        meta.content_length > 0 &&
        lower(meta.transfer_encoding).find("chunked") == std::string::npos &&
        active_wsse_flows(flows) < MAX_WSSE_BODY_FLOWS) {
      fl.event = e;
      fl.awaiting_body = true;
      fl.body_goal = meta.content_length < g_wsse_body_bytes ? meta.content_length : g_wsse_body_bytes;
      if (fl.body_goal > MAX_WSSE_BODY_BYTES) fl.body_goal = MAX_WSSE_BODY_BYTES;
      if (fl.buf.size() > fl.body_goal) fl.buf.resize(fl.body_goal);
      std::string username = extract_wsse_username(fl.buf);
      if (!username.empty() || fl.buf.size() >= fl.body_goal) {
        Event event = fl.event;
        if (!username.empty()) {
          event.wsse_user = username; event.user = username; event.scheme = "wsse";
        }
        flows.erase(fk);
        queue_request(event, s_ip, sport, d_ip, dport, pending);
      }
      return true;
    }
    queue_request(e, s_ip, sport, d_ip, dport, pending);
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
#define ADD(C,J,T,K) do { \
  unsigned _jt = (unsigned)(J), _jf = (unsigned)(T); \
  if (_jt > UCHAR_MAX || _jf > UCHAR_MAX) return false; \
  x.code=(C); x.jt=(unsigned char)_jt; x.jf=(unsigned char)_jf; x.k=(K); \
  f.push_back(x); \
} while(0)
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
  if (!valid_ring_geometry(mr)) return 20;
  unsigned char frame[2048];
  memset(frame, 0, sizeof(frame));
  struct tpacket2_hdr *hdr = (struct tpacket2_hdr *)frame;
  size_t off = 0, len = 0;
  hdr->tp_mac = TPACKET2_HDRLEN;
  hdr->tp_net = TPACKET2_HDRLEN + 14;
  hdr->tp_snaplen = 128;
  hdr->tp_len = 128;
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
  packet[26] = 192; packet[27] = 0; packet[28] = 2; packet[29] = 2;
  packet[30] = 192; packet[31] = 0; packet[32] = 2; packet[33] = 1;
  unsigned short sport = htons(51000), dport = htons(8080);
  memcpy(&packet[34], &sport, sizeof(sport));
  memcpy(&packet[36], &dport, sizeof(dport));
  packet[46] = 5U << 4; packet[47] = 0x18;
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

int main(int argc, char **argv) {
  if (argc > 1 && !strcmp(argv[1], "--fixture")) return run_fixture();
  if (argc > 1 && !strcmp(argv[1], "--wsse-fixture")) return run_wsse_fixture();
  if (argc > 1 && !strcmp(argv[1], "--dual-auth-fixture")) return run_dual_auth_fixture();
  if (argc > 1 && !strcmp(argv[1], "--ring-fixture")) return run_ring_fixture();
  if (argc > 1 && !strcmp(argv[1], "--ship-rate-fixture")) return run_ship_rate_fixture();
  if (argc > 1 && !strcmp(argv[1], "--stats-fixture")) return run_stats_fixture();
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
    else if (!strcmp(argv[i], "--capability-probe")) capability_probe = true;
    else if (!strcmp(argv[i], "--spool") && i + 1 < argc) ++i; /* ignored: 0 disk write */
    else if (!strcmp(argv[i], "-j") && i + 1 < argc) workers = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--wsse-body-bytes") && i + 1 < argc) {
      if (!parse_wsse_size(argv[++i], &g_wsse_body_bytes)) {
        fprintf(stderr, "wsse body bytes must be in range 0..65536\n"); return 2;
      }
    }
    else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
      fprintf(stderr, "usage: nt-sniff-cpp [-i iface] [-p ports] [--endpoint URL] [--ship-rate-kbps 64..10000] [--stats-interval-sec 10..300] [-j workers] [--wsse-body-bytes 0..65536]\n");
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

  if (g_endpoint.empty()) {
    int output_flags = fcntl(STDOUT_FILENO, F_GETFL, 0);
    if (output_flags < 0 ||
        fcntl(STDOUT_FILENO, F_SETFL, output_flags | O_NONBLOCK) < 0) {
      logmsg("cannot make shipper pipe non-blocking; refusing unsafe pipeline");
      release_mmap_ring(fd, ring);
      close(fd);
      return 2;
    }
    signal(SIGPIPE, SIG_IGN);
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
    logmsg("single-binary in-memory mode: shipping directly to " + g_endpoint + " (0 disk I/O)");
  } else {
    logmsg("non-blocking native pipeline mode enabled; WAN I/O isolated in nt-ship-cpp");
  }
  logmsg("listening");

  time_t last = time(NULL), last_flush = last;
  bool ring_integrity_failure = false;

  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLIN | POLLERR;
  pfd.revents = 0;

  while (g_running) {
    int rc = poll(&pfd, 1, 1000);
    if (rc < 0 && errno == EINTR) {
      /* Signal handled, loop condition will check g_running */
    } else if (rc >= 0) {
      /* Drain all ready frames in the ring without extra syscalls. */
      while (g_running) {
          unsigned b_idx = ring.frame_idx / ring.frames_per_block;
          unsigned f_in_b = ring.frame_idx % ring.frames_per_block;
          uint8_t *frame_ptr = ((uint8_t *)ring.ring) + (b_idx * ring.block_size) + (f_in_b * ring.frame_size);
          volatile struct tpacket2_hdr *volatile_hdr =
              (volatile struct tpacket2_hdr *)frame_ptr;

          if (!(volatile_hdr->tp_status & TP_STATUS_USER)) {
            break; /* No more kernel-populated frames in ring right now */
          }
          __sync_synchronize(); /* acquire kernel-owned frame contents */

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

          __sync_synchronize(); /* release all reads before returning ownership */
          volatile_hdr->tp_status = TP_STATUS_KERNEL;
          ring.frame_idx = (ring.frame_idx + 1) % ring.frame_nr;
      }
      if (g_endpoint.empty()) std::cout.flush();
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
    if (wall_seconds() - g_stats_last_at >= g_stats_interval_sec) {
      size_t pending_count = 0, wsse_count = 0;
      for (std::map<PacketKey, std::vector<Pending> >::iterator pi = pending.begin(); pi != pending.end(); ++pi)
        pending_count += pi->second.size();
      for (std::map<FlowKey, Flow>::iterator fi = flows.begin(); fi != flows.end(); ++fi)
        if (fi->second.awaiting_body) ++wsse_count;
      if (!g_endpoint.empty())
        send_agent_stats(fd, flows.size(), pending_count, wsse_count);
      else
        emit_capture_stats_internal(fd, flows.size(), pending_count, wsse_count);
    }
  }

  /* A response is optional enrichment. Preserve requests still awaiting a
   * response when SIGTERM/restart ends capture. */
  flush_incomplete_wsse(flows, pending);
  flush_all_pending(pending);
  if (g_endpoint.empty()) std::cout.flush();

  if (!g_endpoint.empty() && !g_ship_buf.empty()) {
    send_batches(g_endpoint, g_ship_node, &g_ship_buf, true);
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
