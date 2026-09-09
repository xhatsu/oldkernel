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
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
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
static const size_t MAX_HEADER = 262144;
static const size_t MAX_WSSE_BODY_BYTES = 65536;
static const size_t MAX_WSSE_BODY_FLOWS = 256;
static const size_t MAX_WSSE_USERNAME = 200;
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
static void flush_all_pending(std::map<PacketKey, std::vector<Pending> > &pending) {
  std::map<PacketKey, std::vector<Pending> >::iterator p;
  for (p = pending.begin(); p != pending.end(); ++p) {
    for (size_t i = 0; i < p->second.size(); ++i) {
      emit_event(p->second[i].ev);
    }
  }
  pending.clear();
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
static size_t g_wsse_body_bytes = 0;

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
  Flow &fl = flows[fk]; fl.touched = now;
  if (fl.awaiting_body) {
    size_t remaining = fl.body_goal > fl.buf.size() ? fl.body_goal - fl.buf.size() : 0;
    if (remaining) fl.buf.append(payload, plen < remaining ? plen : remaining);
    std::string username = extract_wsse_username(fl.buf);
    if (!username.empty() || fl.buf.size() >= fl.body_goal) {
      Event event = fl.event;
      if (!username.empty()) { event.user = username; event.scheme = "wsse"; }
      flows.erase(fk);
      queue_request(event, s_ip, sport, d_ip, dport, pending);
    }
    return true;
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
    if (e.user == "-anonymous-" && g_wsse_body_bytes &&
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
        if (!username.empty()) { event.user = username; event.scheme = "wsse"; }
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

static bool parse_wsse_size(const char *value, size_t *result) {
  if (!value || !*value) return false;
  size_t n = 0;
  if (!parse_decimal_size(value, strlen(value), &n) || n > MAX_WSSE_BODY_BYTES) return false;
  *result = n;
  return true;
}

static int run_capability_probe() {
  int fd = socket(AF_PACKET, SOCK_RAW, htons(3));
  if (fd < 0) { perror("AF_PACKET capability probe"); return 2; }
  close(fd);
  return 0;
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

int main(int argc, char **argv) {
  if (argc > 1 && !strcmp(argv[1], "--fixture")) return run_fixture();
  if (argc > 1 && !strcmp(argv[1], "--wsse-fixture")) return run_wsse_fixture();
  if (argc > 1 && !strcmp(argv[1], "--capability-probe")) return run_capability_probe();
  std::string iface; std::vector<unsigned> ports; int i; int workers = 1;
  std::string endpoint;
  const char *wsse_env = getenv("NT_WSSE_BODY_BYTES");
  if (wsse_env && !parse_wsse_size(wsse_env, &g_wsse_body_bytes)) {
    fprintf(stderr, "wsse body bytes must be in range 0..65536\n"); return 2;
  }
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
    else if (!strcmp(argv[i], "--wsse-body-bytes") && i + 1 < argc) {
      if (!parse_wsse_size(argv[++i], &g_wsse_body_bytes)) {
        fprintf(stderr, "wsse body bytes must be in range 0..65536\n"); return 2;
      }
    }
    else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
      fprintf(stderr, "usage: nt-sniff-cpp [-i iface] [-p ports] [--endpoint URL] [-j workers] [--wsse-body-bytes 0..65536]\n");
      return 0;
    }
    else { fprintf(stderr, "unknown or incomplete argument: %s\n", argv[i]); return 2; }
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
  if (!attach_bpf(fd, ports)) {
    logmsg("BPF attach failed; refusing unfiltered capture");
    close(fd);
    return 2;
  }

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
  if (!drop_all_capabilities()) {
    logmsg("capability drop failed; refusing unsafe capture");
    if (use_mmap && ring.ring != MAP_FAILED) munmap(ring.ring, ring.ring_size);
    close(fd);
    return 2;
  }

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
  if (g_wsse_body_bytes) {
    logmsg("WSSE UsernameToken inspection enabled (bounded to " + number_string(g_wsse_body_bytes) + " bytes/request)");
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

  /* A response is optional enrichment. Preserve requests still awaiting a
   * response when SIGTERM/restart ends capture. */
  flush_all_pending(pending);
  if (g_endpoint.empty()) std::cout.flush();

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
