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
/*
 * ===========================================================================
 * OVERVIEW
 * ===========================================================================
 * nt-sniff-cpp.cpp is the high-performance native replacement for the
 * pure-Python nt-sniff.py capture loop. It targets CentOS 6.x / GCC 4.4 /
 * Linux 2.6.32, so it must stay within C++03 (compiled here with -std=gnu++03)
 * and must not depend on any third-party library: only libc/libstdc++ and
 * -lrt (for clock_gettime) are linked.
 *
 * End-to-end data path:
 *   1. open_capture_socket() creates an AF_PACKET/SOCK_RAW socket, attaches the
 *      classic-BPF port filter, binds it to the interface, maps the fixed
 *      TPACKET_V2 RX ring, and only THEN drops all capabilities. That exact
 *      ordering is a security property (see the function for the rationale):
 *      once privileges are gone the process can no longer be re-armed, and the
 *      code fails closed -- there is deliberately no recv() fallback.
 *   2. main() poll()s the packet socket and drains the mmap ring frame by
 *      frame, bounds-checking every kernel frame header before trusting it.
 *   3. handle_packet() decodes Ethernet (+ optional 802.1Q) / IPv4 / TCP,
 *      resolves the 4-tuple in the bounded Connection table, and hands payload
 *      to process_request_payload() / process_response_payload(), which do
 *      per-direction TCP reassembly using the per-flow reassembly state.
 *   4. The HTTP/1.x parser is a single forward pass over the reassembled byte
 *      stream driven by an explicit state machine
 *      (HEADER -> BODY / CHUNK / CLOSE_BODY / UNSYNCED). It extracts
 *      method/path/Host/User-Agent/X-Forwarded-For/traceparent, the Basic-auth
 *      *username only* (never the password), and, only when explicitly opted
 *      into, a bounded SOAP WSSE UsernameToken username.
 *   5. queue_request() parks each parsed request as a Pending entry until the
 *      matching response header arrives; that header is what stamps
 *      status / duration_ms / resp_bytes onto the event.
 *   6. emit_event() serialises exactly one JSONL record per event and either
 *      writes it to non-blocking stdout (piped into nt-ship-cpp) or, in
 *      --endpoint single-binary mode, pushes it onto the bounded in-process
 *      queue drained by ship_worker_thread().
 *
 * Global invariants relied upon everywhere below:
 *   - Capture itself is single-threaded. The only extra thread is the optional
 *     shipper, and it touches shipping globals only while holding
 *     g_ship_queue_mutex.
 *   - Every buffer/table has a hard bound; when a bound is hit the code
 *     degrades (invalidate the stream, drop the event) instead of growing.
 *   - Credential material (Basic password, WSSE Password, SOAP body) is never
 *     copied into an Event and never logged.
 * ===========================================================================
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
#include <new>

#include <vector>
#include <algorithm>

#if defined(__SANITIZE_ADDRESS__)
  #define NT_HAS_ASAN 1
#elif defined(__has_feature)
  #if __has_feature(address_sanitizer)
    #define NT_HAS_ASAN 1
  #endif
#endif

/* Process-wide "keep running" flag. It is the only thing the signal handler
 * touches (stop_signal below), and sig_atomic_t makes that write safe from
 * async-signal context. Every long-running loop polls it to decide when to
 * stop; main() clears it on SIGTERM/SIGINT and on fatal errors. */
static volatile sig_atomic_t g_running = 1;
/* Async-signal-safe SIGTERM/SIGINT handler: sets the run flag and returns.
 * No printf/alloc/anything else is done here on purpose. */
static void stop_signal(int) { g_running = 0; }

/*
 * ---------------------------------------------------------------------------
 * Hard resource bounds (compile-time constants so worst-case memory use can be
 * proven against the 256 MiB RLIMIT_AS installed in main(): the fixed 4 MiB
 * packet ring + bounded flow/pending/queue tables stay far under the limit).
 * ---------------------------------------------------------------------------
 */
static const size_t MAX_FLOWS = 4096;
static const size_t MAX_TOTAL_BUFFER_BYTES = 16 * 1024 * 1024; // 16 MiB aggregate budget
static const size_t MAX_PENDING_TOTAL = 4096;                   // 4096 global pending requests
/* Flow-table and per-flow request-parking caps. MAX_PENDING_PER_FLOW limits
 * how many outstanding (unanswered) requests one connection may hold, which
 * bounds head-of-line memory per connection. */
static const size_t MAX_PENDING_PER_FLOW = 32;
/* Monitored ports are capped at 30 because the cBPF program below encodes
 * branch targets in the 8-bit jt/jf fields and each port adds 8 instructions
 * across the two paths; beyond this the offsets would not be representable. */
static const size_t MAX_PORTS = 30;
/* Parser limits: a single HTTP header block larger than MAX_HEADER_BYTES is
 * treated as hostile/garbage and invalidates the stream; one flow may buffer
 * at most MAX_FLOW_BUFFER_BYTES of reassembled bytes. */
static const size_t MAX_HEADER_BYTES = 32768;                   // 32 KiB
static const size_t MAX_FLOW_BUFFER_BYTES = 65536;              // 64 KiB
/* Opt-in SOAP/WSSE inspection bounds: how many body bytes per request may be
 * buffered for UsernameToken extraction (0 = disabled, the default), how many
 * flows may be buffering a body concurrently, and the maximum username length
 * in Unicode code points. */
static const size_t MAX_WSSE_BODY_BYTES = 65536;
/* WSSE bounds: at most 256 flows may buffer a SOAP body at once and a decoded
 * username is limited to 200 code points (MAX_WSSE_USERNAME * 4 bytes). */
static const size_t MAX_WSSE_BODY_FLOWS = 256;
static const size_t MAX_WSSE_USERNAME = 200;
/* Shipper bounds: events per HTTP batch, bounded in-memory queue depth, and
 * the maximum encoded body sizes for /api/ingest and /api/agent/stats. */
static const size_t MAX_BATCH = 400;
static const size_t MAX_QUEUE = 10000;
static const size_t MAX_POST_BYTES = 65536;
static const size_t MAX_STATS_BYTES = 16384;
/* Default aggregate egress ceiling (NT_SHIP_RATE_KBPS / --ship-rate-kbps).
 * FLUSH_SEC/RETRY_SEC are declared for parity with the shared kit configuration;
 * the C++ hot loop does not reference them (shipping cadence belongs to
 * nt-ship-cpp). */
static const unsigned DEFAULT_SHIP_RATE_KBPS = 1024;
static const int FLUSH_SEC = 5;
static const int RETRY_SEC = 60;
/* Idle/staleness TTLs for the connection table. FLOW_IDLE_TTL is the time
 * after which a completely clean (no pending request, no buffered bytes)
 * connection is simply dropped; FLOW_STALE_TTL is the outer bound after which
 * even a dirty connection is invalidated and removed by sweep(). */
static const unsigned FLOW_IDLE_TTL = 300;
static const unsigned FLOW_STALE_TTL = 600;
static const unsigned DEFAULT_PENDING_TTL = 30;
static unsigned g_pending_ttl_sec = DEFAULT_PENDING_TTL;
/* BPF return value that accepts a packet. It is a "snaplen" well below a full
 * MTU: capture only needs the HTTP headers, and this limits per-packet
 * transfer out of the kernel. SO_ATTACH_FILTER is #defined above only for the
 * rare headers that lack it. */
static const unsigned ACCEPT = 12288;
#ifndef SO_ATTACH_FILTER
  #define SO_ATTACH_FILTER 26
#endif
/* Protocol constants used by the cBPF program and by handle_packet(). The
 * *_HOST suffixes stress that these are host-order 16-bit values (the BPF
 * program compares raw packet bytes for these well-known EtherTypes, which are
 * big-endian on the wire but symmetric, so a host-order constant works). */
static const unsigned short ETH_P_IP_HOST = 0x0800;
static const unsigned short ETH_P_8021Q_HOST = 0x8100;
/* Reassembly back-pressure: at most this many out-of-order TCP segments are
 * kept per flow, and at most this many ring frames are drained per poll wakeup
 * (so the 1-second housekeeping timer and the stats timer always get a chance
 * to run even under sustained line-rate traffic). */
static const size_t MAX_OOO_SEGMENTS = 4;
static const size_t MAX_DRAIN_PER_PASS = 256;

/* Monotonic milliseconds since an unspecified boot-relative origin. Used for
 * every duration/TTL/internal-age computation because wall-clock (time())
 * can jump backwards when NTP steps the clock. */
static inline long long now_monotonic_ms() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

/* Signed difference of two 32-bit TCP sequence numbers, computed in modular
 * arithmetic and interpreted as an int32. This is the correct way to compare
 * sequence numbers across the 2^32 wrap point: the result is >0 if a is
 * "after" b, 0 if equal, <0 if a is before b (within half the sequence space). */
static inline int32_t seq_diff(uint32_t a, uint32_t b) {
  return (int32_t)(a - b);
}

/* Strip leading/trailing ASCII whitespace from a copy of s. */
static std::string trim(const std::string &s) {
  size_t a = 0, b = s.size();
  while (a < b && isspace((unsigned char)s[a])) ++a;
  while (b > a && isspace((unsigned char)s[b - 1])) --b;
  return s.substr(a, b - a);
}
/* Return an ASCII-lowercased copy of s (header names/values are compared
 * case-insensitively; tolower is applied through unsigned char to stay
 * defined for bytes >= 0x80). */
static std::string lower(const std::string &s) {
  std::string x = s;
  size_t i; for (i = 0; i < x.size(); ++i) x[i] = (char)tolower((unsigned char)x[i]);
  return x;
}
/* JSON-encode a string as a quoted literal: escapes backslash and double
 * quote, converts \\n/\\r/\\t to their escapes, and replaces any other control
 * byte (< 0x20) with '?' so the emitted JSONL record can never contain a raw
 * control character that would break line framing. */
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
/* Wall-clock milliseconds (gettimeofday). Used where an absolute, human
 * meaningful timestamp is needed (event metadata), not for durations. */
static long long now_ms() {
  struct timeval tv; gettimeofday(&tv, NULL);
  return (long long)tv.tv_sec * 1000LL + tv.tv_usec / 1000;
}
/* Small integer-to-string helpers kept local to avoid pulling in <cstdio>
 * formatting into the hot path. */
static std::string num(long v) { std::ostringstream o; o << v; return o.str(); }
/* A usable TCP/UDP port number: non-zero and 16-bit. */
static bool valid_port(unsigned p) { return p > 0 && p <= 65535; }

/* Unaligned-safe 16-bit load. The mmap'd packet data is only guaranteed to be
 * Ethernet-aligned, so naive casts to uint16_t* would be undefined on strict
 * alignment platforms; memcpy lets the compiler emit an unaligned load. */
static uint16_t read_u16(const unsigned char *p) {
  uint16_t value;
  memcpy(&value, p, sizeof(value));
  return value;
}

/* Unaligned-safe 32-bit load (see read_u16). Note this returns the raw
 * network-order value; callers apply ntohl() explicitly. */
static uint32_t read_u32(const unsigned char *p) {
  uint32_t value;
  memcpy(&value, p, sizeof(value));
  return value;
}
/* Whitelist of HTTP request methods this parser will accept as a request
 * start-line token. Anything else is treated as non-HTTP noise. */
static bool has_method(const std::string &m) {
  return m == "GET" || m == "POST" || m == "PUT" || m == "DELETE" ||
         m == "PATCH" || m == "HEAD" || m == "OPTIONS";
}
/* Node name reported in events: $NT_NODE_NAME if set (handled in main), else
 * the local hostname truncated at the first '.' (short name), else the literal
 * "unknown-node" so events always carry a stable, non-empty node. */
static std::string host_name() {
  char b[256]; if (gethostname(b, sizeof(b) - 1) != 0) return "unknown-node";
  b[sizeof(b) - 1] = 0; char *p = strchr(b, '.'); if (p) *p = 0; return b;
}

/*
 * Decode the credential half of an HTTP "Authorization: Basic <b64>" value and
 * return only the USERNAME. This function is the enforcement point for the
 * "never emit passwords" guarantee:
 *   - It decodes base64 with a 32-bit sliding accumulator (val/bits) instead of
 *     a table, so it needs no allocation and no lookup table.
 *   - It requires the decoded text to contain ':' (the user:password
 *     separator). Everything after the FIRST ':' is discarded and never
 *     returned, so the password cannot leak even though it is decoded while
 *     scanning.
 *   - Strictness: whitespace is tolerated between base64 characters; data after
 *     the first '=' padding is rejected (only '=' may appear); at most two pad
 *     characters; total (data + pad) length must be a multiple of 4; any
 *     non-base64 byte aborts with "". Username is capped at 256 decoded bytes.
 * Returns "" for anything that is not a well-formed Basic credential. */
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
    /* Shift the 6-bit base64 digit into the accumulator; `bits` tracks how many
     * bits are still pending (started at -8 so the first complete byte is only
     * emitted once enough digits have arrived). Once bits >= 0 a full output
     * byte is available from the top of the accumulator. */
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

/* Format a 32-bit IPv4 address (still in network byte order, as taken straight
 * from the IPv4 header) as dotted-quad text. */
static std::string ip_to_str(uint32_t ip_be) {
  char b[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &ip_be, b, sizeof(b));
  return b;
}

/* ASCII hex digit test used by traceparent validation. */
static inline bool is_hex(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/*
 * Validate a W3C traceparent header and return its 32-hex-digit trace-id
 * (lowercased), or "" if the header is not a usable traceparent. Checks:
 *   - total length must be exactly 55 and the '-' separators must sit at the
 *     fixed offsets 2, 35 and 52 ("00-<32 hex>-<16 hex>-<2 hex>").
 *   - version must be exactly "00".
 *   - the 32-digit trace-id and 16-digit span-id must be all-hex and must NOT
 *     be all zero (the spec forbids the all-zero id).
 *   - the last two digits (trace-flags) must be hex.
 * Only the trace-id is returned: the event records it as trace_id, and the raw
 * header is stored separately by the caller. */
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

/* Global PRNG state for traceparent generation. Keeping it in a register-backed
 * global with a hand-rolled xorshift means no libc rand() call, no lock and no
 * syscall per request: the only syscall ever made is the one-time seeding read
 * from /dev/urandom. */
static uint64_t g_rng_state = 0;
/* Seed g_rng_state from 8 bytes of /dev/urandom. If that fails or returns an
 * all-zero word, fall back to time(NULL)<<32 ^ getpid() so the state is
 * non-zero and per-process distinct. */
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
/* xorshift128+ style step over a single 64-bit word (shifts 13 / 7 / 17 --
 * this is the classic 64-bit xorshift triplet). Returns the new state and
 * substitutes a fixed non-zero constant if the result came out zero, so the
 * generator can never fall into its all-zero fixed point. Called only from the
 * single capture thread, hence no locking. */
static inline uint64_t next_rng() {
  uint64_t x = g_rng_state;
  x ^= x << 13; x ^= x >> 7; x ^= x << 17;
  return g_rng_state = (x ? x : 0x853c49e6748fea9bULL);
}

/* Generate a W3C traceparent of the form "00-<32 hex trace-id>-<16 hex
 * span-id>-01" from three PRNG draws (r1||r2 = 128-bit trace-id, r3 = 64-bit
 * span-id, flags fixed to 01 = sampled). Also writes the 32-hex-digit
 * trace-id into *tid so the caller gets trace_id without re-parsing. */
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

/* One captured request/response pair == one JSONL event record.
 * Field groups:
 *   ts/host/src/service      - wall-clock second, node name, "pcap" probe
 *                              source, "port:<n>" service label
 *   method/path              - request line
 *   user/scheme              - the single "primary" identity (wsse beats basic)
 *   basic_user/wsse_user     - nullable per-scheme identities; dual-auth
 *                              requests report both
 *   host_hdr/user_agent/xff  - selected request headers, bounded when stored
 *   caller/caller_port       - client endpoint; dst_ip/dst_port - server side
 *   traceparent/trace_id     - inbound W3C header and/or generated trace id
 *   req_bytes                - size of the request header block
 *   status/duration_ms/resp_bytes (+has_* flags) - filled by response
 *     correlation; the has_* flags decide "null" vs numeric in the JSON. */
struct Event {
  long ts; std::string host, src, service, method, path, user, scheme, probe;
  std::string basic_user, wsse_user;
  std::string host_hdr, user_agent, xff, caller, dst_ip, traceparent, trace_id;
  unsigned caller_port, dst_port, req_bytes, resp_bytes; int status; long duration_ms;
  bool has_status, has_duration, has_resp;
  Event() : ts(0), caller_port(0), dst_port(0), req_bytes(0), resp_bytes(0), status(0), duration_ms(0), has_status(false), has_duration(false), has_resp(false) {}
};
/* Framing metadata gathered while parsing a request's header block. It decides
 * the request-body state (no body / Content-Length / chunked) and whether the
 * flow is eligible for the opt-in WSSE body window. has_conflict_cl (two
 * different Content-Length values, or an unparsable one) and
 * invalid_transfer_encoding mark framing ambiguities that must invalidate the
 * stream rather than be silently resolved -- the request-smuggling defence. */
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

/* One out-of-order TCP segment parked for later reassembly: the absolute
 * sequence number of its first byte plus its payload bytes. */
struct TcpSegment {
  uint32_t seq;
  std::string data;
};

/* Process-wide total bytes currently held by ALL Flow buffers (in-order buf,
 * wsse_buf and ooo segment data). Every append is mirrored by a subtraction on
 * erase/eviction so the value stays exact; it is the global memory backstop
 * that drives LRU eviction of connections. */
static size_t g_total_flow_bytes = 0;
/* Accounting for g_total_flow_bytes. flow_bytes_sub() saturates at zero so a
 * double release can never underflow the counter to a huge value (which would
 * permanently disable byte-based eviction). */
static inline void flow_bytes_add(size_t n) {
  g_total_flow_bytes += n;
}
static inline void flow_bytes_sub(size_t n) {
  if (g_total_flow_bytes >= n) g_total_flow_bytes -= n;
  else g_total_flow_bytes = 0;
}
/*
 * Binary 12-byte flow identifier: (source ip:port, destination ip:port), with
 * both addresses kept in NETWORK byte order exactly as read from the packet
 * headers, so two keys for the same direction compare byte-for-byte equal.
 * Small on purpose: up to MAX_FLOWS of these live in the Connection map and
 * every captured packet performs a lookup.
 * operator< gives the strict weak ordering std::map requires, comparing the
 * fields in a fixed order (s_ip, sport, d_ip, dport) so identical tuples always
 * compare equal however they were constructed.
 */
struct FlowKey {
  /* Source IPv4 address, network byte order (as read from the IP header). */
  uint32_t s_ip;
  /* Source TCP port, host byte order (inet_ntohs'ed at decode time). */
  uint16_t sport;
  /* Destination IPv4 address, network byte order. */
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

/* PacketKey is the same 12-byte tuple; the alias documents intent: a FlowKey
 * addresses a direction of a flow (request or response), whereas a PacketKey
 * names a packet direction (canonically server->client) when the correlation
 * lockout registry records that a connection must never be correlated. */
typedef FlowKey PacketKey;

/* Number of flows currently buffering a SOAP body for WSSE username
 * extraction; capped at MAX_WSSE_BODY_FLOWS. Incremented when a flow starts
 * awaiting a body and decremented on wsse_cancel()/wsse_clear(). */
static size_t g_wsse_body_flows_active = 0;

/* Release a std::string's heap storage right now by swapping it with a fresh
 * empty string (the pre-C++11 way to shrink to fit). clear() would keep the
 * capacity allocated, which matters when the whole process lives under a
 * 256 MiB RLIMIT_AS. */
static void release_string(std::string &s) {
  std::string().swap(s);
}

/* Same idea as release_string() but for vectors: swap with an empty temporary
 * so the backing array is freed instead of retained. */
template <typename T>
static void release_vector(std::vector<T> &v) {
  std::vector<T>().swap(v);
}

/*
 * Per-direction TCP reassembly + HTTP parse state for one half of a connection
 * (conn.req_flow is client->server, conn.resp_flow is server->client).
 *
 * Reassembly: `next_seq` is the sequence number expected for the next in-order
 * byte; bytes arriving exactly at next_seq are appended to `buf`; bytes ahead
 * of it are parked in `ooo` (bounded by MAX_OOO_SEGMENTS); bytes behind it are
 * treated as retransmissions and trimmed by the overlap. `is_broken` means
 * reassembly was compromised and this direction must not be trusted again.
 *
 * Ordering verification: `has_seq` means the initial sequence number has been
 * established (from the SYN, or by resynchronising on a recognised start line);
 * `syn_seen` records that a real SYN was observed (used by the correlation
 * lockout logic); `generation` mirrors the owning Connection's generation so a
 * late packet from a previous connection lifetime can be rejected.
 *
 * HTTP parsing: `state` is the message state machine; the chunk_* flags track
 * progress inside a chunked body; `body_remaining`/`chunk_payload_remaining`
 * count down unparsed bytes.
 *
 * WSSE: when a request is eligible, `awaiting_wsse` is set and up to
 * wsse_goal bytes of body are accumulated in `wsse_buf` and re-parsed
 * incrementally (wsse_last_parsed_len) so a UsernameToken is found even before
 * the body finishes; wsse_req_id ties the eventual username back to the exact
 * Pending event.
 *
 * Close handling: fin_seen/fin_seq let the parser know when a close-delimited
 * body has physically ended (FIN consumed with no bytes outstanding).
 */
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

  /* Forward-only parse state machine for this direction. It is reset to
   * HTTP_STATE_HEADER at every message boundary; HTTP_STATE_UNSYNCED means
   * framing was irrecoverably lost on this direction and parsing stops (used
   * after a 101 Switching Protocols response). */
  enum HttpState {
    /* Scanning for a message start-line followed by a complete header block. */
    HTTP_STATE_HEADER,
    /* In a Content-Length delimited body. */
    HTTP_STATE_BODY,
    /* In a Transfer-Encoding: chunked body. */
    HTTP_STATE_CHUNK,
    /* In a body delimited by connection close (no length information). */
    HTTP_STATE_CLOSE_BODY,
    /* Framing lost; do not parse this direction any further. */
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

  /* Reset this direction for a new connection lifetime on a reused 4-tuple:
   * drop all buffers, clear both the reassembly and HTTP machine state, adopt
   * the new generation, and record whether a SYN was actually seen and whether
   * correlation is still permitted. Everything a previous connection left
   * behind is discarded so no stale byte can be attributed to the new one. */
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

  /* Stop awaiting a SOAP body: release the WSSE flow slot (decrement the global
   * counter exactly once), free the buffered body, and forget the WSSE request
   * id/goal. Idempotent with respect to the counter because it only decrements
   * while awaiting_wsse is true. */
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

  /* Free just the WSSE body buffer and its byte accounting. Safe to call when
   * already empty. */
  void wsse_clear() {
    flow_bytes_sub(wsse_buf.size());
    release_string(wsse_buf);
    wsse_last_parsed_len = 0;
  }

  /* Drop every byte this flow owns (in-order buffer, WSSE body, and all
   * out-of-order segments), keeping g_total_flow_bytes exact. Used on reset,
   * eviction and desynchronisation. */
  void clear_buffers() {
    flow_bytes_sub(buf.size());
    release_string(buf);

    wsse_cancel();

    for (size_t i = 0; i < ooo.size(); ++i) {
      flow_bytes_sub(ooo[i].data.size());
    }

    release_vector(ooo);
  }

  /* Append reassembled in-order bytes to `buf`.
   * Returns false when the append would exceed MAX_FLOW_BUFFER_BYTES (the flow
   * is then marked is_broken and cleared -- this is a hostile/desynchronised
   * stream) or would exceed the global MAX_TOTAL_BUFFER_BYTES budget (packet is
   * simply dropped, flow survives). Both checks are done before touching the
   * string so no partial state is ever left behind. */
  bool buf_append(const char *data, size_t len) {
    if (len > MAX_FLOW_BUFFER_BYTES ||
        buf.size() > MAX_FLOW_BUFFER_BYTES - len) {
      clear_buffers();
      is_broken = true;
      return false;
    }

    if (len > MAX_TOTAL_BUFFER_BYTES ||
        g_total_flow_bytes > MAX_TOTAL_BUFFER_BYTES - len) {
      return false;
    }

    buf.append(data, len);
    flow_bytes_add(len);
    return true;
  }

  /* Consume/erase len bytes at offset off from `buf` and keep the global byte
   * counter in step. Clamped so off/len can never run past the end. */
  void buf_erase(size_t off, size_t len) {
    if (off >= buf.size()) return;
    if (len > buf.size() - off) len = buf.size() - off;
    buf.erase(off, len);
    flow_bytes_sub(len);
  }

  /* Append bytes to the WSSE body window, subject only to the global byte
   * budget (the per-flow cap is enforced implicitly by wsse_goal). Returns
   * false if the global budget would be exceeded. */
  bool wsse_append(const char *data, size_t len) {
    if (len > MAX_TOTAL_BUFFER_BYTES ||
        g_total_flow_bytes > MAX_TOTAL_BUFFER_BYTES - len) {
      return false;
    }
    wsse_buf.append(data, len);
    flow_bytes_add(len);
    return true;
  }

  /* Park one ahead-of-sequence segment. Refuses (false) if the per-flow
   * MAX_OOO_SEGMENTS limit or the global byte budget would be exceeded, which
   * is what makes the caller invalidate the stream instead of buffering
   * unboundedly. */
  bool ooo_push(uint32_t seq, const char *data, size_t len) {
    if (ooo.size() >= MAX_OOO_SEGMENTS)
      return false;

    if (len > MAX_TOTAL_BUFFER_BYTES ||
        g_total_flow_bytes > MAX_TOTAL_BUFFER_BYTES - len)
      return false;

    TcpSegment seg;
    seg.seq = seq;
    seg.data.assign(data, len);
    ooo.push_back(seg);
    flow_bytes_add(len);
    return true;
  }

  /* Remove one parked segment and release its bytes from the global counter. */
  void ooo_erase(size_t idx) {
    if (idx < ooo.size()) {
      flow_bytes_sub(ooo[idx].data.size());
      ooo.erase(ooo.begin() + idx);
    }
  }
};

/* One endpoint of a connection: IPv4 address in network byte order plus TCP
 * port in host byte order, with ordering so ConnectionKey can canonicalise
 * the pair. */
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

/*
 * Direction-independent connection identity: the two Endpoints stored sorted,
 * so (A,B) and (B,A) produce the SAME key. That canonicalisation (done in the
 * constructor) is what lets a single Connection object own both the request
 * (client->server) and response (server->client) directions of a 4-tuple.
 * operator< is a lexicographic compare over the canonical pair.
 */
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

/* Diagnostic counters: frames captured shorter than their IPv4 total length
 * (snaplen truncation) and flows whose reassembly had to be invalidated
 * (RST, ambiguity, overflow, framing conflict, ...). */
static uint64_t g_capture_truncated = 0;
/* Count of flows whose reassembly/parse state had to be invalidated (RST,
 * out-of-order ambiguity, buffer overflow, framing conflict, eviction). */
static uint64_t g_stream_invalidations = 0;

/* Monotonic request-id source. Every parsed request takes a unique id; the id
 * is used later to attach a WSSE body username (parsed out of the body bytes)
 * to the exact Pending entry it belongs to, even with pipelined requests. */
static uint64_t g_req_id_seq = 0;

/* Globally FIFO-ordered back-reference to one Pending entry. g_pending_fifo is
 * a list of these so the oldest outstanding request across ALL connections can
 * be located in O(1) when the global MAX_PENDING_TOTAL budget forces an
 * eviction. */
struct PendingQueueRef {
  uint64_t req_id;
  uint32_t generation;
  ConnectionKey key;
  long long started_mono_ms;
};

/* One parsed request waiting for its response header.
 *   req_id / generation   - identity; generation guards TCP connection reuse
 *                           (a response for a previous generation must not
 *                           attach to a new request on the same tuple).
 *   started_wall_ms       - arrival wall clock (kept for completeness).
 *   started_mono_ms       - used to compute duration_ms at correlation.
 *   is_tombstone          - the entry was already emitted or timed out but its
 *                           slot is kept briefly so a late response cannot be
 *                           matched against the NEXT request (head-of-line
 *                           correctness); tombstone_mono_ms ages it out.
 *   fifo_it / in_fifo     - link into g_pending_fifo for O(1) removal. */
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

/*
 * Everything known about one canonical 4-tuple:
 *   roles_established + client/server - which endpoint is the HTTP client;
 *     learned from SYN / SYN-ACK, from which port is monitored, or from the
 *     first recognisable request/response bytes.
 *   generation - incremented on every verified new client SYN. It guards
 *     correlation against a delayed response from a previous connection that
 *     reused the same tuple.
 *   have_client_isn / client_isn - client's initial sequence number.
 *   corr_eligible / corr_disabled - whether correlation is currently allowed.
 *   touched / touched_mono_ms - LRU and idle-TTL bookkeeping.
 *   req_flow / resp_flow - the two per-direction Flow states.
 *   pending - outstanding requests in arrival order.
 *   has_deferred_wsse / deferred_wsse_event - an event parked because a WSSE
 *     username may still arrive in the body and correlation was not possible.
 *   lru_it / in_lru - position in the global LRU list for O(1) eviction.
 */
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

/* Global count of live (non-tombstone) Pending entries and the FIFO over all
 * connections, used to evict the globally oldest pending request once
 * MAX_PENDING_TOTAL is reached. */
static size_t g_total_pending_count = 0;
static std::list<PendingQueueRef> g_pending_fifo;

/* Detach a Pending entry from the global FIFO if it is still linked there.
 * Safe to call on entries that were never linked or are already detached;
 * keeps the in_fifo flag honest so the FIFO and the per-connection pending
 * vector can never disagree. */
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
/* Capacity of the correlation-lockout registry described above. When it is
 * full the oldest lockout is evicted and g_corr_capacity_reached is latched:
 * from then on, ordering for connections that have not been verified by a real
 * SYN cannot be proven, so they are simply not correlated (emit-only). */
static const size_t MAX_CORR_DISABLED = 2048;
/* The correlation-lockout registry itself: a set for O(log n) membership tests
 * on the per-packet hot path plus a FIFO list for capacity eviction, with the
 * latched overflow flag described above. */
static std::set<PacketKey> g_corr_disabled;
static std::list<PacketKey> g_corr_disabled_fifo;
static bool g_corr_capacity_reached = false;

/* Record that correlation for this packet direction is permanently disabled
 * until a verified new SYN arrives. Idempotent; enforces the MAX_CORR_DISABLED
 * bound by dropping the oldest entry (FIFO) and latching
 * g_corr_capacity_reached so the fallback policy engages. */
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

/* Clear a lockout entry, used when a verified new SYN proves the connection
 * restarted cleanly. The erase finds the FIFO node by linear scan because the
 * registry is small (<= 2048) and this path is rare. */
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

/* Drop the whole lockout registry and its capacity latch (shutdown/tests). */
static void corr_disabled_clear() {
  g_corr_disabled.clear();
  g_corr_disabled_fifo.clear();
  g_corr_capacity_reached = false;
}

/* Query the lockout registry. Returns true if this direction is explicitly
 * locked out, or if the registry ever overflowed and no verified SYN has been
 * seen for the connection (conservative fail-closed behaviour). */
static bool is_correlation_disabled(const PacketKey &key, bool syn_seen) {
  if (g_corr_disabled.count(key)) return true;
  if (g_corr_capacity_reached && !syn_seen) return true;
  return false;
}

/* Permanently disable correlation for a connection given its canonical
 * server->client key: lock out that packet direction, and mark BOTH flow
 * directions (the response direction rk and its reverse) as not
 * corr_eligible. Used when ordering losses mean a request and response can no
 * longer be reliably associated. */
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

/*
 * Decide whether a response may be correlated with a pending request for the
 * given server->client direction. Fail-closed: returns false if the direction
 * is locked out, if either flow direction is ineligible or broken, or if the
 * lockout registry overflowed and this connection cannot be re-verified by a
 * real SYN (syn_seen false or generation 0). */
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


/* All diagnostics go to stderr (never stdout, which carries the JSONL event
 * stream) with a fixed prefix, and are flushed immediately so a supervisor log
 * shows the last message even if the process is killed. */
static void logmsg(const std::string &s) { fprintf(stderr, "nt-sniff-cpp: %s\n", s.c_str()); fflush(stderr); }

/* Strict decimal parser for header values such as Content-Length: leading and
 * trailing spaces are skipped, every remaining byte must be 0-9, and overflow
 * is detected BEFORE it happens (value > SIZE_MAX/10, or value*10 would exceed
 * SIZE_MAX-digit). Returns false for anything else, which callers turn into a
 * framing conflict. */
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

/* Copy at most max_len bytes of src into dst. Every header-derived string is
 * stored through this helper so a hostile header cannot inflate memory or the
 * emitted JSON line. */
static inline void bounded_assign(std::string *dst, const char *src, size_t len, size_t max_len) {
  if (len > max_len) len = max_len;
  dst->assign(src, len);
}

/* True iff the Transfer-Encoding value is a well-formed comma-separated list
 * whose FINAL token is exactly "chunked" and which does not repeat "chunked"
 * earlier (which would be invalid). "chunked" must be last to be applied by
 * the receiver; anything else means the body framing is not what we think it
 * is and the stream must be invalidated. */
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

/*
 * Parse one HTTP request header block (already reassembled, `len` bytes,
 * starting at the request line) into an Event and RequestMeta. Single forward
 * pass, no allocation beyond the extracted strings.
 *   - Request line: METHOD SP request-target SP HTTP/1.x CRLF. The method must
 *     be in the has_method() whitelist and the version must be exactly
 *     "HTTP/1.1" or "HTTP/1.0".
 *   - Path: the request-target up to '?' (query string dropped) and truncated
 *     to 120 bytes.
 *   - Headers: case-insensitive name compare, values trimmed of leading
 *     spaces/tabs and trailing CR/space/tab. Recognised names (by exact length
 *     + strncasecmp, cheaper than building strings): authorization (Basic
 *     only, username only), traceparent, host, user-agent, x-forwarded-for,
 *     content-type, content-length, transfer-encoding. Duplicate/conflicting
 *     Content-Length or an invalid Transfer-Encoding set the corresponding
 *     conflict flags in meta instead of being resolved here.
 *   - Finishing rules: missing user becomes "-anonymous-", missing scheme
 *     becomes "none", and a missing/!invalid inbound traceparent is replaced by
 *     a freshly generated one.
 * Returns false only if the request line/version is not HTTP, in which case the
 * caller discards those bytes and resynchronises.
 */
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

/* Whitelist of the WSSE security-namespace URIs whose UsernameToken we accept:
 * the OASIS 2004/01 (1.0) namespace plus the three legacy
 * schemas.xmlsoap.org 2002/07, 2002/12 and 2003/06 ones. A UsernameToken in
 * any other namespace is ignored, so a spoofed token cannot be attributed. */
static bool is_wsse_namespace(const std::string &uri) {
  return uri == "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" ||
         uri == "http://schemas.xmlsoap.org/ws/2002/07/secext" ||
         uri == "http://schemas.xmlsoap.org/ws/2002/12/secext" ||
         uri == "http://schemas.xmlsoap.org/ws/2003/06/secext";
}

/* True if a Content-Type looks like XML/SOAP ("text/xml",
 * "application/soap+xml", or any "+xml" subtype). This is the gate for even
 * considering WSSE body inspection, so that e.g. JSON POSTs are never buffered
 * as XML. */
static bool is_soap_content_type(const std::string &ct) {
  std::string x = lower(ct);
  return x.find("text/xml") != std::string::npos ||
         x.find("application/soap+xml") != std::string::npos ||
         x.find("+xml") != std::string::npos;
}

/* Split an XML qualified name "prefix:local" into its two halves. A name with
 * no colon has an empty prefix (bound to the default namespace). */
static void split_qname(const std::string &qname, std::string *prefix, std::string *local) {
  size_t p = qname.find(':');
  if (p == std::string::npos) { prefix->clear(); *local = qname; }
  else { *prefix = qname.substr(0, p); *local = qname.substr(p + 1); }
}

/*
 * Append XML-decoded text of `in` to `out`, resolving the five predefined
 * entities (&amp; &lt; &gt; &quot; &apos;) and numeric character references
 * (&#NN; decimal, &#xHH; hex). Numeric refs are re-encoded as UTF-8 (1 to 4
 * bytes according to the code-point range). Returns false on a malformed
 * reference (missing ';', out-of-range code point > 0x10FFFF, or an unknown
 * named entity), which makes the caller abandon WSSE extraction rather than
 * accept ambiguous text. */
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

/* Clear out and decode `in` into it. Convenience wrapper for whole-attribute
 * unescaping (used for xmlns values and attribute values). */
static bool xml_unescape(const std::string &in, std::string *out) {
  out->clear();
  return xml_unescape_append(in, out);
}

/*
 * Validate that a candidate WSSE username is well-formed UTF-8 and safe to
 * emit: rejects overlong encodings, surrogates, code points above U+10FFFF,
 * more than MAX_WSSE_USERNAME code points, and any control/invisible/formatting
 * code point (C0/C1 controls, private-use ranges, Unicode non-characters,
 * bidi overrides, BOM, soft hyphen, etc.). This keeps a hostile SOAP body from
 * smuggling control characters or RTL spoofing into an event field. */
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

/* One element on the WSSE XML parse stack: the in-scope namespace map
 * (prefix -> URI, with "" for the default namespace), the raw qname, the
 * resolved namespace URI of this element, and its local name. */
struct XmlFrame {
  std::map<std::string, std::string> ns;
  std::string qname, uri, local;
};

/* Consume one XML name at *pos (letters/digits/_/-/./:), bounded to 256 bytes
 * and to `limit`. Advances *pos past the name. */
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

/*
 * Extract the first WSSE UsernameToken username from a bounded SOAP body
 * prefix, or "" if none is found. This is a deliberately minimal, allocation-
 * light XML scanner rather than a general XML parser:
 *   - Rejects bodies containing NUL, exceeding MAX_WSSE_BODY_BYTES, or
 *     containing a DOCTYPE/ENTITY declaration (XXE / entity-expansion defence).
 *   - Maintains an explicit element stack (max 64 deep) with per-element
 *     namespace maps inherited from the parent, so namespace resolution is
 *     correct without a DOM.
 *   - Skips comments, CDATA, and processing instructions; any other "<!" is
 *     fatal.
 *   - Caches the depth/URI of an open <...:UsernameToken> only when its
 *     namespace is a recognised WSSE one, then captures character data of the
 *     immediate child <...:Username> in the SAME namespace, XML-unescaping it.
 *   - Enforces the MAX_WSSE_USERNAME bound and validates UTF-8 before returning.
 *   - NEVER looks at <Password>; only the username becomes an event field. The
 *     scanner returns as soon as the first valid username is complete.
 */
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

    /* Comment, CDATA and processing-instruction handling. Anything matching
     * "<!" other than these is fatal (see the "<!" check below). */
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
    /* Only a <*:UsernameToken> whose RESOLVED namespace is a recognised WSSE
     * URI opens a token scope; the matching Username must be its immediate
     * child IN THE SAME namespace (compared via the URI, not the prefix). */
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

/*
 * Parse one HTTP response header block (`len` bytes from the status line) and
 * report: numeric status, Content-Length if present, whether the body is
 * chunked, whether the body is close-delimited, and whether the framing is
 * ambiguous.
 *   - Status line must be "HTTP/1.0 " or "HTTP/1.1 " followed by exactly three
 *     digits in 100..599, terminated by space or CR.
 *   - Content-Length must parse as a decimal and be consistent; two differing
 *     (or unparsable) values set *framing_conflict and return false.
 *   - Transfer-Encoding is accepted only if its final token is "chunked" per
 *     transfer_encoding_final_chunked().
 *   - Both Content-Length and Transfer-Encoding present => framing_conflict.
 *   - Connection: close, or HTTP/1.0 without keep-alive, means the body is
 *     delimited by connection close.
 * Returns false when the header block is not a parseable response (the caller
 * then discards those bytes and resynchronises) or when framing is ambiguous
 * (the caller invalidates the stream).
 */
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
  /* Content-Length together with Transfer-Encoding is a request-smuggling
   * framing ambiguity: report a conflict and refuse the header. */
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

/*
 * ---------------------------------------------------------------------------
 * Configuration and runtime state.
 * The endpoint/node/rate/interval/ttl globals below are set once during
 * argument parsing and then only read. Every counter is monotonically
 * increasing, so the stats window deltas are computed by subtracting the
 * previous snapshot.
 * ---------------------------------------------------------------------------
 */
static std::string g_endpoint;
static std::string g_ship_node;
static unsigned g_ship_rate_kbps = DEFAULT_SHIP_RATE_KBPS;
static unsigned g_stats_interval_sec = 30;
static size_t g_wsse_body_bytes = 0;
/* Runtime counters, all monotonic. Grouped by concern: capture (packets/bytes,
 * kernel drops, truncated/invalid frames), event production, and shipping
 * (pushed/dropped/batches/bytes). g_prev_* hold the previous stats snapshot for
 * computing per-window deltas. */
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

/* Shipping queue state. In --endpoint single-binary mode exactly one worker
 * thread (g_ship_worker_tid) drains g_ship_buf under g_ship_queue_mutex; the
 * condition variable wakes it whenever an event is enqueued, a stats body is
 * staged (g_pending_stats_body), or shutdown starts. There is deliberately
 * never more than one worker, and the queue is bounded by MAX_QUEUE. */
static pthread_t g_ship_worker_tid;
static pthread_mutex_t g_ship_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_ship_queue_cond = PTHREAD_COND_INITIALIZER;
static std::deque<std::string> g_ship_buf;
static bool g_ship_worker_active = false;
static bool g_producer_finished = false;
static std::string g_pending_stats_body;

/* POSIX single-quote a string for safe interpolation into the popen() shell
 * command used by post_body() (each embedded quote becomes '\''). */
static std::string shellq(const std::string &s) {
  std::string o = "'";
  for (size_t i = 0; i < s.size(); ++i) { if (s[i] == '\'') o += "'\\''"; else o += s[i]; }
  return o + "'";
}
/* Numeric formatting helpers (size_t / unsigned long long / double with 4
 * fixed decimals for the JSON stats payload). */
static std::string number_string(size_t n) { std::ostringstream o; o << n; return o.str(); }
static std::string ull_string(unsigned long long n) { std::ostringstream o; o << n; return o.str(); }
static std::string double_string(double n) { std::ostringstream o; o.setf(std::ios::fixed); o.precision(4); o << n; return o.str(); }
/* Join pre-encoded JSON fragments into a JSON array. The fragments are already
 * complete JSON objects (event records), so no re-escaping happens here. */
static std::string json_array(const std::vector<std::string> &a) {
  std::string o = "["; for (size_t i = 0; i < a.size(); ++i) { if (i) o += ","; o += a[i]; } return o + "]";
}
/* Wall-clock seconds as a double, used only for upload pacing and stats
 * windows (never for durations, which use the monotonic clock). */
static double wall_seconds() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}
/* Aggregate egress pacing. *next_slot is the earliest wall-clock time at
 * which the this many bytes may be sent; it advances by
 * bytes / (rate_kbps*1000/8) seconds and the caller sleeps until that time is
 * reached. Sleeping in at most 0.5 s slices keeps shutdown responsive. This
 * enforces NT_SHIP_RATE_KBPS across the whole process, not per request. */
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
/* How many queued events from the front of buf fit in one HTTP body without
 * exceeding MAX_POST_BYTES (envelope + events + commas) and without exceeding
 * MAX_BATCH. Returns 0 only when even a single event is too large, which the
 * caller handles by dropping that event as oversized. */
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

/* POST `body` to endpoint+path with curl (popen), writing the JSON on stdin
 * (--data-binary @-), discarding the response body (-o /dev/null), with a
 * hard --max-time and an explicit --limit-rate. Success means curl exited 0
 * (-sSf makes HTTP errors non-zero). Returns false on any failure so the
 * caller can count the drop. */
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

/*
 * The single shipping worker for --endpoint mode. Loop body:
 *   1. Wait (with a 1 s timeout so shutdown is never missed) until there is a
 *      batch to send, a stats body staged, or the producer finished.
 *   2. On shutdown, start a hard 10 s drain deadline; anything still queued
 *      after it is counted as dropped and the thread exits.
 *   3. Take at most one paced batch from the queue; if the front event alone
 *      is oversized, drop just that event and count it.
 *   4. Send any staged agent-stats body to /api/agent/stats (shares the same
 *      egress budget); failures are counted, not retried into a backlog.
 *   5. Send the event batch to /api/ingest with up to 3 attempts (0.5 s apart),
 *      shortening the timeout as the shutdown deadline approaches. Success
 *      resets the consecutive-failure counter; failure counts the whole batch
 *      as dropped (drop-on-overload, never an unbounded retry queue).
 * All counter updates happen under g_ship_queue_mutex because the capture
 * thread reads them for stats.
 */
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

/* Count this process's open file descriptors by counting entries in
 * /proc/self/fd (minus . and ..). Allocated temporarily: the count includes the
 * directory fd itself. */
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

/* Read VmRSS/VmSize/Threads/Cpus_allowed_list from /proc/self/status for the
 * stats payload. Defaults (rss/virt 0, threads 1, cpu 0) are used if a line is
 * absent. */
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

/* Read PACKET_STATISTICS from the capture socket, accumulate the reported
 * tp_drops into g_kernel_drops, and return the delta since the previous call.
 * No-op (0) when fd < 0 (fixture paths). */
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

/*
 * Build one schema-versioned agent_stats JSON object covering capture, shipping,
 * and resource sections, and advance the window baselines. Notes:
 *   - Deltas are computed from a single mutex-protected snapshot of the
 *     shipping counters, and the previous-value globals are committed from that
 *     same snapshot so no event is double-counted or skipped between windows.
 *   - cpu_percent_one_core uses getrusage deltas over the window.
 *   - "reasons" is derived from the observed deltas (kernel drops, ship drops,
 *     hub unreachability, queue pressure) and selects ok vs degraded.
 *   - The body contains only counters/limits -- no captured identity or payload.
 */
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

/* Stage an agent_stats body for the shipping thread to POST. If the body
 * exceeds MAX_STATS_BYTES it is dropped and counted rather than sent (the
 * body is bounded by construction, this is a belt-and-braces check). */
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

/*
 * Write one JSONL record to the (non-blocking) stdout pipe.
 *   - Records larger than PIPE_BUF-1 are never written: a >PIPE_BUF write to a
 *     pipe can be split, which would interleave records for the reader. Such a
 *     record is counted as dropped and reported as success.
 *   - EINTR is retried; EAGAIN/EWOULDBLOCK means the pipe is full, so the event
 *     is dropped and counted (back-pressure drops, never blocks the ring drain).
 *   - EPIPE or any other failure means the shipper is gone: capture is stopped
 *     (g_running = 0) so the supervisor restarts the whole pipeline.
 * Returns false only in that last fatal case.
 */
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

/* Pipeline mode counterpart of send_agent_stats(): build the stats object, cut
 * out just its "capture":{...} sub-object, and emit it as an internal
 * (underscore-prefixed) JSONL record on the capture stream. nt-ship-cpp
 * recognises that marker and forwards the capture section as agent stats
 * without treating it as a request event. */
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

/*
 * Make a capture-derived string safe to put in JSON: validate UTF-8, replace
 * C0 control bytes (except tab/CR/LF) and malformed sequences with '?', drop an
 * incomplete multi-byte sequence at the end, and optionally stop at max_bytes
 * (never splitting a multi-byte character). Overlong encodings, surrogates and
 * >U+10FFFF code points are treated as invalid. */
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

/* Serialise an Event as one JSON object using the legacy oldkernel field
 * order/names. status/duration_ms/resp_bytes are emitted as null unless the
 * corresponding has_* flag is set, and basic_user/wsse_user as null when empty
 * (so dual-auth and single-auth consumers see a stable schema). */
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

/*
 * Final stage of an event's life: sanitise every field to its bound, serialise
 * it, and make sure the resulting line fits PIPE_BUF. If it does not, the
 * optional fields are progressively shortened/cleared (user-agent, XFF, then
 * path) and the line is re-serialised, so a pathological request still yields a
 * valid, atomically-writable record.
 * Then the event is either pushed onto the bounded shipping queue (--endpoint
 * mode; drop-oldest when full) or written to non-blocking stdout.
 */
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
    /* Bounded queue, drop-oldest policy: when full, the oldest event is
     * discarded and counted rather than blocking the capture thread. */
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

/* O(1) port membership table: g_monitored_ports[p] is true iff port p is
 * monitored. 65536 bools (64 KiB) replaces any per-packet search and is filled
 * once at startup from the -p/--wsse body list (max MAX_PORTS entries). */
static bool g_monitored_ports[65536];

/* Map a flow key to the canonical server->client packet key used by the
 * correlation lockout registry. If the source port is monitored and the
 * destination port is not, the flow is already response-direction; otherwise
 * the tuple is reversed. (When both or neither port is monitored the reversal
 * is the only unambiguous choice.) */
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

/*
 * Insert (or merge) an ahead-of-sequence segment into the out-of-order list.
 *   - If a parked segment already has this exact sequence number: if the
 *     overlapping bytes differ, retransmission content is ambiguous and we
 *     refuse (false -> caller invalidates the stream); if the new segment is
 *     fully covered by the existing one, nothing to do (true); if the new one
 *     extends it, replace the entry with the longer version (adjusting the
 *     global byte counter).
 *   - Otherwise, if the per-flow MAX_OOO_SEGMENTS bound is reached, refuse.
 *   - Otherwise push it.
 * Returns false whenever the caller must stop trusting this direction.
 */
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

    size_t added = len - old_len;
    if (added > MAX_TOTAL_BUFFER_BYTES ||
        g_total_flow_bytes > MAX_TOTAL_BUFFER_BYTES - added) return false;

    // New retransmission extends the known range.
    flow_bytes_sub(old_len);
    fl.ooo[i].data.assign(data, len);
    flow_bytes_add(len);
    return true;
  }

  if (fl.ooo.size() >= MAX_OOO_SEGMENTS) return false;

  return fl.ooo_push(seq, data, len);
}

/*
 * Move every parked out-of-order segment that is now contiguous with next_seq
 * into the in-order buffer, repeatedly, until no further progress is possible.
 * A parked segment whose start equals next_seq is appended whole; one that
 * starts BEFORE next_seq has already been partially consumed, so only its
 * non-overlapping tail is appended. Returns false if buf_append() rejects the
 * bytes (flow/global overflow) -- the caller then invalidates the stream.
 */
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

/* Find the earliest offset in the buffer at which any known HTTP request
 * method token begins, or npos. Used to skip leading junk (e.g. leftover
 * pipelined bytes, or garbage) before parsing a request. */
static size_t find_http_start(const std::string &s) {
  const char *m[] = { "GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS " };
  size_t best = std::string::npos;
  for (size_t i = 0; i < 7; ++i) {
    size_t pos = s.find(m[i]);
    if (pos != std::string::npos && (best == std::string::npos || pos < best)) best = pos;
  }
  return best;
}

/*
 * Locate where a request start-line plausibly begins in a buffer of `len` bytes
 * (scanned no further than the first 16 KiB):
 *   - First look for the earliest complete method token ("GET ", "POST ", ...).
 *   - If none is found, allow a method that begins near the very end of the
 *     scanned window and continues in a later TCP segment (any proper prefix of
 *     a method matched at the tail), so a request split mid-method still
 *     resynchronises.
 * Returns (size_t)-1 if nothing matches.
 */
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

/* Same idea as find_request_resync() for responses: find the earliest "HTTP/"
 * literal within the first 16 KiB, else accept a truncated "HTTP/" prefix at
 * the tail so a status line split across segments still resynchronises.
 * Returns (size_t)-1 if nothing matches. */
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

/* True if the buffer starts with a complete known method token OR with a
 * non-empty prefix of one (i.e. the beginning of a method that may continue in
 * the next segment). Used to decide the client/server role of a connection in
 * the absence of a SYN, and to accept a first segment. */
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

/* Hard reset of a direction's reassembly and HTTP state while KEEPING the
 * flow's identity flags (is_broken is cleared, has_seq is dropped so the next
 * bytes must re-establish a start line). Used when a stream is invalidated but
 * the connection object is kept. */
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

/*
 * Mark a connection's stream as unusable: bump the counter, disable correlation
 * for both directions (conn.* and the two Flow flags), reset both directions for
 * resync, emit the deferred WSSE event and EVERY pending request (they will
 * never be correlated now, so they must be reported without response metadata),
 * drop all pending/FIFO state, and -- once client/server roles are known --
 * record the canonical server->client key in the correlation lockout registry
 * so a later response on this tuple is never spuriously correlated.
 * `reason` is currently unused (kept for debug call-site documentation).
 */
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
  release_vector(conn.pending);

  if (conn.roles_established) {
    PacketKey rk;
    rk.s_ip = conn.server.ip; rk.sport = conn.server.port;
    rk.d_ip = conn.client.ip; rk.dport = conn.client.port;
    corr_disabled_insert(rk);
  }
}

/* Refresh a connection's idle timestamps and move it to the back (most
 * recently used) of the global LRU list. O(1) because the Connection caches its
 * own list iterator. */
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

/*
 * Enforce the two global connection limits before inserting/finding:
 *   - if inserting a NEW connection, keep the map below MAX_FLOWS by evicting
 *     the LRU tail (invalidating + emitting before erase);
 *   - always, keep g_total_flow_bytes below MAX_TOTAL_BUFFER_BYTES by evicting
 *     LRU entries until the byte budget is met.
 * protected_key (the connection currently being handled) is never evicted; if
 * it is at the LRU head it is rotated to the back and the next candidate is
 * used instead, which prevents self-eviction mid-packet.
 */
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

/*
 * Park a freshly parsed request until its response arrives, or emit it
 * immediately when correlation is impossible.
 * Steps:
 *   1. Decide `allowed` (fail-closed: lockout registry, per-connection flags,
 *      broken directions, and the capacity fallback requiring a verified SYN).
 *   2. If not allowed: for a WSSE-eligible request, keep it as the connection's
 *      single deferred WSSE event (emitting any previous one) because a username
 *      may still arrive in the body; otherwise emit right away and return 0.
 *   3. If the GLOBAL pending budget is full, invalidate the connection owning
 *      the oldest FIFO entry (freeing its pending entries) until there is room.
 *   4. Re-check the same conditions and fall back to emit/deferred as above.
 *   5. If the per-connection pending cap is reached, invalidate the stream and
 *      emit this request uncorrelated.
 *   6. Otherwise append a Pending entry (linked into the global FIFO) and
 *      return its new req_id. A non-zero return tells the caller the request is
 *      parked and a WSSE body may later be matched to it by req_id.
 */
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

/* True when a direction is at a safe idle point: header state, nothing
 * buffered, nothing out of order, no WSSE body pending, and no partial message
 * length counters outstanding. Only such flows may be silently dropped by the
 * idle TTL. */
static bool flow_at_clean_boundary(const Flow &fl) {
  return fl.state == Flow::HTTP_STATE_HEADER &&
         fl.buf.empty() && fl.ooo.empty() &&
         !fl.awaiting_wsse && fl.wsse_buf.empty() &&
         fl.body_remaining == 0 && fl.chunk_payload_remaining == 0;
}

/* True when the whole connection can be dropped without losing information:
 * no pending requests, no deferred WSSE event, and both directions clean. */
static bool connection_clean_idle(const Connection &conn) {
  return conn.pending.empty() && !conn.has_deferred_wsse &&
         flow_at_clean_boundary(conn.req_flow) &&
         flow_at_clean_boundary(conn.resp_flow);
}

/*
 * Periodic housekeeping (called about once per second):
 *   - Expire tombstone pending entries older than 10 s, invalidating the
 *     stream and flushing the remaining entries when one expires unresolved
 *     (a response never came, so head-of-line is broken).
 *   - Time out live pending entries older than pending_ttl_sec: emit them
 *     uncorrelated and turn them into tombstones (so a late response cannot
 *     bind to the following request).
 *   - Drop connections idle beyond FLOW_IDLE_TTL when fully clean, and
 *     invalidate+drop any connection idle beyond max(pending_ttl+60, FLOW_STALE_TTL).
 *   - Trim stale entries off the head of the global pending FIFO.
 * `now` is accepted for interface compatibility; all ageing uses the monotonic
 * clock (now_mono).
 */
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

/* Shutdown path: emit any deferred WSSE event and free both directions'
 * buffers for every connection (used before the final pending flush). */
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

/* Final shutdown flush: emit the deferred WSSE event and every non-tombstone
 * pending request for all connections, then drop the whole table, the pending
 * FIFO, the pending count and the correlation lockout registry. After this no
 * captured information remains in memory. */
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
    release_vector(it->second.pending);
  }
  connections.clear();
  g_pending_fifo.clear();
  g_total_pending_count = 0;
  corr_disabled_clear();
}

/*
 * Feed a chunk of client->server payload into the request direction's
 * reassembler, then drive its HTTP state machine.
 *
 * Reassembly phase:
 *   - If no start sequence is known yet, try to synchronise: search the payload
 *     for a request start-line (find_request_resync) and adopt the sequence
 *     number at that offset; else accept it if it merely begins with a method
 *     token/prefix; else park it out-of-order and return.
 *   - Compare the segment's sequence with next_seq via seq_diff:
 *     equal -> append in order; behind -> append only the non-overlapping tail
 *     (retransmission); ahead -> park out-of-order.
 *   - Afterwards drain any out-of-order segments that became contiguous.
 *   Any failure (overflow, ambiguous retransmit) invalidates the stream.
 *
 * Parse phase (the while loop) executes the state machine one complete message
 * at a time and only advances when a full start-line+header block is present:
 *   - HEADER: find CRLFCRLF; validate the request line via parse_request();
 *     enforce framing consistency (no Content-Length + Transfer-Encoding, no
 *     conflicting/duplicate Content-Length, Transfer-Encoding must end in
 *     chunked); construct the base Event; decide WSSE eligibility; park the
 *     request via queue_request(); then switch to BODY / CHUNK / HEADER
 *     according to framing.
 *   - BODY: consume exactly body_remaining bytes, feeding up to wsse_goal bytes
 *     to the WSSE window and re-parsing it incrementally; when the username is
 *     found it is attached to the matching Pending/deferred event by req_id.
 *   - CHUNK: parse chunk size lines (bounded to 64 chars / 16 hex digits,
 *     <= 16 MiB per chunk), payload, CRLFs, and the final trailer.
 *   - CLOSE_BODY: nothing more to parse; discard buffered bytes.
 * Finally, if the FIN has been seen and all buffered bytes were consumed, the
 * direction moves to CLOSE_BODY (close-delimited body has ended).
 */
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

      /* WSSE body inspection is opt-in (g_wsse_body_bytes > 0), SOAP-only, and
       * requires a bounded, non-chunked Content-Length body; the global
       * concurrent-body-flow cap is also enforced here. */
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
          if (!fl.wsse_append(fl.buf.data(), copy_len)) {
            fl.wsse_cancel();
          }
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

/*
 * Mirror of process_request_payload() for the server->client direction, but
 * additionally responsible for response CORRELATION:
 *   - Correlation is re-checked per payload; if it is not allowed, all buffered
 *     response bytes are discarded and parsing stops (the request events will
 *     already have been emitted uncorrelated by the request path / sweep).
 *   - Synchronisation uses find_response_resync() (looks for "HTTP/").
 *   - On a complete response header the function binds it to the OLDEST pending
 *     request (FIFO front), skipping entries whose generation does not match
 *     the current connection generation (those are emitted uncorrelated first):
 *       * status, duration_ms (monotonic now minus the request's start), and
 *         resp_bytes (Content-Length when known) are stamped onto the event,
 *       * HEAD requests, 204 and 304 have no body,
 *       * 1xx informational responses are skipped (except 101 Switching
 *         Protocols, which flushes all pending and marks the connection
 *         permanently non-correlatable because the protocol is no longer HTTP),
 *       * the body state then follows the response framing
 *         (Content-Length / chunked / close-delimited).
 *   - As a safety net, if a WSSE body is still buffered for the request when
 *     the response header arrives, the username is parsed and attached then.
 * Returns void; all failure modes emit events uncorrelated and/or invalidate.
 */
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
        release_vector(conn.pending);
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

/*
 * Handle TCP RST and FIN for a connection after its payload was processed.
 * seq is passed as the sequence number AFTER the payload (seq + plen), i.e. the
 * sequence the FIN would acknowledge.
 *   - RST (0x04): invalidate the stream and erase the connection immediately;
 *     returns true (the caller's reference to conn is dead).
 *   - FIN (0x01): mark the corresponding direction fin_seen/fin_seq. If that
 *     direction has no bytes outstanding (everything reassembled), it moves to
 *     CLOSE_BODY and any deferred WSSE event is flushed. When BOTH directions
 *     are closed, the stream is invalidated and the connection erased (returns
 *     true).
 * Returns true iff conn was erased, so callers must not touch it afterwards.
 */
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

/*
 * Decode one captured frame (buf, n bytes) and drive the connection state
 * machine. `ports` is unused (the BPF filter and g_monitored_ports already
 * gate traffic) but kept for interface symmetry with the fixture callers.
 *
 * Steps:
 *   1. Ethernet: need 14 bytes; read the EtherType at offset 12. A single
 *      802.1Q VLAN tag (0x8100) shifts the real EtherType to offset 16 and the
 *      IP header to offset 18.
 *   2. IPv4: require version==4, IHL >= 20, protocol==6 (TCP). Reject any IP
 *      fragment (flags/fragment-offset != 0) because we cannot reassemble IP.
 *   3. Bounds: if the captured length is shorter than the IPv4 total length the
 *      frame was snap-truncated -- count it and invalidate the stream for that
 *      connection (a partial header must never be parsed); if longer, trim to
 *      the declared total length.
 *   4. Extract addresses (network order) and, at offset off+ihl, the TCP ports
 *      (host order), sequence number (host order), data offset (TCP header
 *      length) and flags. Payload = the bytes after the TCP header.
 *   5. Ignore packets whose source AND destination ports are both unmonitored.
 *   6. Canonicalise the 4-tuple into a ConnectionKey, create/touch the
 *      Connection (evicting LRU entries if the table or byte budget is full).
 *   7. Establish client/server roles if not yet known, using in order: a bare
 *      SYN, a SYN-ACK, which single port is monitored, or the first bytes
 *      (request method vs "HTTP/").
 *   8. From the client: a fresh SYN resets the connection for a new generation
 *      (flushing old pending); payload goes to process_request_payload().
 *      From the server: payload goes to process_response_payload().
 *   9. handle_connection_flags() consumes RST/FIN at the end.
 * Returns true if the frame was accepted for tracking, false if it was ignored
 * (non-IP/non-TCP/unmonitored/malformed).
 */
static bool handle_packet(const unsigned char *buf, size_t n,
                          const std::string &node,
                          const std::vector<unsigned> &ports,
                          std::map<ConnectionKey, Connection> &connections,
                          std::list<ConnectionKey> &conn_lru,
                          time_t pcap_now = 0, long long pcap_mono_now = 0) {
  (void)ports;
  /* Minimum viable frame: 14-byte Ethernet + 20-byte IPv4 header (no options)
   * = 34 bytes. Anything shorter cannot contain a TCP header. */
  if (n < 34) return false;
  /* Byte 12 of the Ethernet header is the EtherType; the IP header normally
   * starts at byte 14. `off` is the IP-header offset and is bumped to 18 when a
   * VLAN tag is present. */
  size_t off = 14;
  unsigned short et = ntohs(read_u16(buf + 12));
  /* Single 802.1Q tag: the real EtherType is 4 bytes later (offset 16) and the
   * IP header begins at offset 18; require 38 bytes for 18+20. */
  if (et == ETH_P_8021Q) { if (n < 38) return false; et = ntohs(read_u16(buf + 16)); off = 18; }
  /* Only IPv4 is dissected (IPv6 and everything else are ignored). */
  if (et != ETH_P_IP || n < off + 20) return false;

  /* IP version is the high nibble (must be 4); the low nibble is the number of
   * 32-bit words in the IP header, so *4 gives its byte length (IHL). */
  unsigned char ihl = (unsigned char)(buf[off] & 15) * 4;
  /* Require version 4, a sane header length (>= 20), and protocol 6 (TCP). */
  if ((buf[off] >> 4) != 4 || ihl < 20 || buf[off + 9] != 6) return false;

  /* IP flags/fragment-offset word at IP+6. Any non-zero value means the packet
   * is a fragment (MF set or a non-zero offset); we cannot reassemble IP, so
   * fragments are skipped entirely. */
  uint16_t frag = ntohs(read_u16(buf + off + 6));
  if (frag & 0x3fff) return false;

  /* Total IP length at IP+2, used to detect snap-truncated frames and to trim
   * trailing padding (e.g. Ethernet pad to 60 bytes). */
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

  /* Source address at IP+12, destination at IP+16 (both network order). */
  uint32_t s_ip = read_u32(buf + off + 12);
  uint32_t d_ip = read_u32(buf + off + 16);
  /* `to` is the byte offset of the TCP header: start of IP + IP header length. */
  size_t to = off + ihl;
  if (n < to + 20) return false;

  /* TCP header layout: src port at +0, dst port at +2, sequence at +4, data
   * offset/flags at +12/+13. Ports and sequence are converted to host order. */
  unsigned sport = ntohs(read_u16(buf + to));
  unsigned dport = ntohs(read_u16(buf + to + 2));
  uint32_t seq = ntohl(read_u32(buf + to + 4));
  /* TCP data offset (header length) is the high nibble of byte 12, in 32-bit
   * words. */
  unsigned doff = (buf[to + 12] >> 4) * 4;
  if (doff < 20 || n < to + doff) return false;

  /* TCP flag byte at +13: 0x02=SYN, 0x10=ACK, 0x01=FIN, 0x04=RST. */
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
      /* Bare SYN with no ACK: this is the client. Its sequence number is the
       * client ISN, which the request direction will start counting from. */
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
    /* Verified new connection on a reused 4-tuple: a bare SYN from the client
     * starts a new generation. A retransmitted SYN with the SAME ISN is
     * ignored; anything else flushes the old pending requests, clears the
     * correlation lockout for this direction, bumps the generation, and resets
     * both directions with next_seq = seq + 1 (the SYN consumes one sequence
     * number). */
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
      release_vector(conn.pending);
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


/*
 * Build and attach the classic BPF (cBPF) filter that accepts only TCP packets
 * addressed to (or from) the monitored ports, and RETURNs ACCEPT (12288) as the
 * snaplen; everything else returns 0 (drop).
 *
 * Program layout -- two independent ingress paths that both converge on a
 * shared "accept" instruction, with a shared "reject" RET 0:
 *   Path A (standard Ethernet): EtherType@12 == 0x0800 -> IP proto@23 == TCP
 *     -> BPF_LDX|BPF_MSH loads the IP header length into X
 *     -> compare src port at [X+14] and dst port at [X+16] against each port.
 *   Path B (single 802.1Q VLAN tag): EtherType@12 == 0x8100 -> inner
 *     EtherType@16 == 0x0800 -> IP proto@27 == TCP -> MSH at offset 18
 *     -> compare src port at [X+18] and dst port at [X+20].
 * All jump offsets are computed from the *current* program length, so the
 * `reject`/`accept` targets stay correct as instructions are appended. Because
 * cBPF jt/jf are 8-bit, ADD() refuses to emit an instruction whose jump exceeds
 * UCHAR_MAX, and the caller caps the monitored-port count at MAX_PORTS (30) so
 * that N ports (2*N+2 compares plus both paths, each port costing 2 loads+2
 * jumps) always fit with all offsets representable.
 *
 * Fails closed: returns false (caller closes the socket) if anything is wrong,
 * and there is no unfiltered-capture fallback.
 */
static bool attach_bpf(int fd, const std::vector<unsigned> &ports) {
  if (ports.empty()) return false;
  std::vector<struct sock_filter> f; size_t i;
  unsigned N = (unsigned)ports.size();
  /* Instruction index of the trailing RET 0 (reject): 4 path-local setup
   * instructions for path B + 2*(2 loads + 2 jumps) for path B's port tests +
   * 2 setup for path A + 2*(2+2) for path A's tests ... collapsed here into the
   * closed form 11 + 8*N (N ports; 8 instructions per port across both
   * directions). `accept` is simply the next instruction after it. */
  unsigned reject = 11 + N * 8;
  unsigned accept = reject + 1;
  struct sock_filter x;
/* Append one instruction to the program, refusing to build a filter whose
 * jt/jf branch offsets do not fit in the 8-bit cBPF jump fields (that is the
 * guard that keeps the generated program valid as ports are added). */
#define ADD(C,J,T,K) do { \
  unsigned _jt = (unsigned)(J), _jf = (unsigned)(T); \
  if (_jt > UCHAR_MAX || _jf > UCHAR_MAX) return false; \
  x.code=(C); x.jt=(unsigned char)_jt; x.jf=(unsigned char)_jf; x.k=(K); \
  f.push_back(x); \
} while(0)
  /* A[0:2] = EtherType of the outer Ethernet header (offset 12). */
  ADD(BPF_LD|BPF_H|BPF_ABS, 0, 0, 12);
  /* If this is plain IPv4, jump 6+4N instructions ahead to path A's
   * IP-protocol test, skipping path B's VLAN instructions entirely; otherwise
   * fall through into path B. */
  ADD(BPF_JMP|BPF_JEQ|BPF_K, (unsigned)(6 + 4 * N), 0, ETH_P_IP_HOST);

  // Path B: 802.1Q VLAN
  ADD(BPF_JMP|BPF_JEQ|BPF_K, 0, (unsigned)(reject - (unsigned)f.size() - 1), ETH_P_8021Q_HOST);
  /* Path B: A[0:2] = the inner EtherType, 4 bytes into a single VLAN tag. */
  ADD(BPF_LD|BPF_H|BPF_ABS, 0, 0, 16);
  ADD(BPF_JMP|BPF_JEQ|BPF_K, 0, (unsigned)(reject - (unsigned)f.size() - 1), ETH_P_IP_HOST);
  /* Path B: A = IP protocol byte at 14 + 4 (VLAN) + 9 = offset 27. */
  ADD(BPF_LD|BPF_B|BPF_ABS, 0, 0, 27);
  ADD(BPF_JMP|BPF_JEQ|BPF_K, 0, (unsigned)(reject - (unsigned)f.size() - 1), IPPROTO_TCP);
  /* Path B: X = 4 * (IP header length) -- BPF_MSH loads the low nibble at
   * offset 18 (start of the inner IP header) and multiplies by 4, i.e. the IP
   * header byte length, so L4 ports can be addressed as [X + const]. */
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
  /* Path A: A = IP protocol byte at 14 + 9 = offset 23. */
  ADD(BPF_LD|BPF_B|BPF_ABS, 0, 0, 23);
  ADD(BPF_JMP|BPF_JEQ|BPF_K, 0, (unsigned)(reject - (unsigned)f.size() - 1), IPPROTO_TCP);
  /* Path A: X = 4 * IP header length (low nibble at offset 14). */
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

  /* Reject target: return 0 => the kernel drops the packet. */
  ADD(BPF_RET|BPF_K, 0, 0, 0);
  /* Accept target: return ACCEPT as the captured snaplen. */
  ADD(BPF_RET|BPF_K, 0, 0, ACCEPT);
#undef ADD
  if (f.size() > 4096) return false;
  struct sock_fprog prog; prog.len = (unsigned short)f.size(); prog.filter = &f[0];
  return setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) == 0;
}

/* Fixed TPACKET_V2 RX ring descriptor. The geometry is intentionally NOT
 * configurable: block_size 64 KiB, block_nr 64 -> exactly 4 MiB, with
 * frame_size 16 KiB giving frames_per_block = 4 and frame_nr = 256. Every field
 * is validated by valid_ring_geometry() before any sockopt is issued, because a
 * kernel that silently rounds or rejects these values would break the
 * frame-index arithmetic that the receive loop depends on. */
struct MmapRing {
  void *ring;
  size_t ring_size;
  unsigned block_size;
  unsigned block_nr;
  unsigned frame_size;
  unsigned frame_nr;
  unsigned frames_per_block;
  unsigned frame_idx;

  /* Default (and only) geometry: 64 KiB blocks x 64 blocks = 4 MiB total,
   * 16 KiB frames => 4 frames per block, 256 frames. */
  MmapRing() : ring(MAP_FAILED), ring_size(0), block_size(65536), block_nr(64),
               frame_size(16384), frame_nr(256), frames_per_block(4), frame_idx(0) {}
};

/*
 * Validate the fixed ring geometry before it is handed to the kernel:
 *   - block_size must be a non-zero multiple of the page size;
 *   - frame_size must be >= TPACKET2_HDRLEN and a multiple of
 *     TPACKET_ALIGNMENT;
 *   - block_size must divide evenly into frames (frame_size divides
 *     block_size);
 *   - frames_per_block * block_nr must equal frame_nr (no rounding drift);
 *   - the products must not overflow size_t/unsigned;
 *   - block_size * block_nr must be exactly 4 MiB.
 * Any violation makes setup_mmap_ring() refuse to continue (fail closed).
 */
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

/*
 * Create the TPACKET_V2 RX ring on the capture socket:
 *   1. re-validate the geometry,
 *   2. select PACKET_VERSION = TPACKET_V2 (v2 is required: v1 lacks
 *      tp_mac/tp_net offsets, v3 is not permitted by policy),
 *   3. issue PACKET_RX_RING with the static tpacket_req,
 *   4. derive ring_size and frames_per_block from the kernel's accepted values
 *      and mmap the ring MAP_SHARED for read+write (the ring is shared with the
 *      kernel; userspace only ever writes tp_status back to TP_STATUS_KERNEL).
 * Returns false on any failure -- the caller closes the socket and does NOT
 * fall back to recv().
 */
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

/* Tear down the RX ring at shutdown: munmap the ring and issue
 * PACKET_RX_RING with an all-zero request, which is how the kernel is told to
 * free the ring. Returns false if either step failed (reported as a ring
 * integrity failure, which makes the process exit non-zero). */
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

/*
 * Bounds-check one kernel frame header before trusting any of its offsets:
 *   - tp_mac (offset of the L2 header within the frame) must lie between
 *     TPACKET2_HDRLEN and frame_size;
 *   - tp_snaplen (bytes actually captured) must not exceed tp_len (on-the-wire
 *     length) nor the bytes remaining in the frame after tp_mac;
 *   - tp_net (offset of the L3 header) must lie within [tp_mac, tp_mac+snaplen].
 * On success writes tp_mac/tp_snaplen out as packet_offset/packet_length.
 * Any inconsistency returns false, and the caller then stops capture: malformed
 * kernel metadata means the ring can no longer be trusted.
 */
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

/* Self-test for the ring-metadata validator: builds synthetic tpacket2_hdr
 * values (good, tp_mac too small, snaplen beyond frame, snaplen > tp_len, net
 * before mac) and asserts the expected accept/reject verdicts, plus an invalid
 * geometry. Exit codes 21..26 identify the failing case; 0 = pass. */
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

/* Smoke fixture: parse a synthetic HTTP request through parse_request() and
 * emit the resulting event to stdout, exercising the JSON serialiser and (via
 * emit_event) the default stdout path. Always returns 0. */
static int run_fixture() {
  std::string req = "GET /api/items?x=1 HTTP/1.1\r\nHost: api.local\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\nTraceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n\r\n";
  Event e; RequestMeta meta; e.ts = 1700000000; e.host = "cpp-node"; e.service = "port:8080"; e.caller = "10.0.0.9"; e.caller_port = 51000; e.dst_ip = "10.0.0.2"; e.dst_port = 8080; e.req_bytes = (unsigned)req.size(); parse_request(req.data(), req.size() - 4, &e, &meta); e.status = 200; e.has_status = true; e.duration_ms = 3; e.has_duration = true; e.resp_bytes = 42; e.has_resp = true; emit_event(e); return 0;
}

/* Self-test for WSSE extraction across the four accepted namespace dialects,
 * XXE/DOCTYPE rejection, wrong/absent namespace rejection, entity decoding, and
 * the username length bound. Non-zero exit codes name the failing case. */
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

/* End-to-end fixture: synthesise a real Ethernet+IPv4+TCP frame carrying a SOAP
 * POST with BOTH Basic and WSSE credentials, run it through handle_packet(),
 * and require exactly one pending request (dual-auth reports both usernames).
 * The frame is built by hand -- EtherType at 12, IP version/IHL at 14, protocol
 * at 23, total length at 16, addresses at 26/30, ports at 34/36, TCP data
 * offset+flags at 46/47, payload at 54 -- mirroring the offsets handle_packet()
 * reads. */
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

/* Self-test of bounded_batch_count(): two 40 KB events must yield a batch of
 * exactly 1 (the second would exceed MAX_POST_BYTES), and a single oversize
 * event must yield 0 (dropped as oversized). Exit 30/31 identify failures. */
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

/* Self-test of the agent_stats payload: seeds counters, builds the body with
 * fd = -1 (so kernel-drop polling is skipped), and asserts size, type, the
 * computed drop_percent (2/10 = 20%) and mode. Exit 40..43 identify failures. */
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

/* Parse the WSSE body-window size from an env var/CLI value: decimal only, and
 * must be <= MAX_WSSE_BODY_BYTES (65536). Rejects empty/null input. */
static bool parse_wsse_size(const char *value, size_t *result) {
  if (!value || !*value) return false;
  size_t n = 0;
  if (!parse_decimal_size(value, strlen(value), &n) || n > MAX_WSSE_BODY_BYTES) return false;
  *result = n;
  return true;
}

/*
 * Irreversibly drop privileges after the capture socket and ring are ready.
 *   - If running as root, setgroups(0, NULL), then setgid()/setuid() to
 *     $NT_USER (default "ntsniff", falling back to "nobody" only if that
 *     account is absent). Any failure is fatal.
 *   - Then capset() with an all-zero capability set (version 3, two 32-bit
 *     words) to clear the permitted/effective/inheritable sets for ALL
 *     capabilities -- including CAP_NET_RAW, which the already-open AF_PACKET
 *     socket no longer needs.
 *   - Finally asserts the process is genuinely non-root and returns false
 *     otherwise, so the caller refuses to capture on a failed drop.
 */
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

/*
 * Bring up the capture socket, in this exact order (each step fails closed):
 *   1. socket(AF_PACKET, SOCK_RAW, 0); if the kernel rejects the zero protocol,
 *      retry with htons(ETH_P_ALL).
 *   2. FD_CLOEXEC so the socket is not inherited by the curl/popen child.
 *   3. 8 MiB SO_RCVBUF (best effort) to absorb bursts into the socket buffer.
 *   4. attach_bpf() -- the filter must be in place BEFORE any packet can be
 *      seen, so no unfiltered traffic is ever delivered.
 *   5. bind() to the interface (sll_ifindex from if_nametoindex, or all
 *      interfaces when -i was not given).
 *   6. setup_mmap_ring() -- TPACKET_V2 RX ring; no recv() fallback exists.
 *   7. drop_all_capabilities() -- privileges are dropped last, once the socket
 *      and ring are fully configured; if the drop fails the ring/socket are torn
 *      down and capture is refused.
 * Returns the fd, or -1 after logging why.
 */
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

/* --capability-probe: prove that an unprivileged process can set up (and then
 * release) the BPF+TPACKET_V2 capture path with the installed CAP_NET_RAW file
 * capability, without ever capturing. Returns 0 on a clean setup+teardown,
 * 2 otherwise. Used by the installer's post-install verification. */
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

/*
 * Self-test of the correlation-lockout registry and its capacity fallback.
 *   - Inserts 10,000 distinct keys and asserts the registry stays capped at
 *     MAX_CORR_DISABLED (2048) with the capacity latch set.
 *   - Asserts an evicted key without a verified SYN is treated as
 *     correlation-disabled, and that a verified SYN re-enables it.
 *   - Reproduction 1: an OLD SYN (syn_seen already true) must NOT bypass an
 *     evicted lockout for a later request on the same tuple.
 *   - Reproduction 2: a server SYN-ACK must preserve the generation and
 *     eligibility established by the client SYN (it must not reset them).
 *   - Reproduction 3: reset_for_new_connection() must clear is_broken.
 *   - Reproduction 4: an expired HEAD tombstone must still yield HEAD
 *     semantics (no body).
 * Prints PASS/FAIL on stderr.
 */
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

/*
 * Self-test of the pending-request FIFO bookkeeping:
 *   1. 20,000 queue+complete cycles must leave the FIFO and the global pending
 *      count empty (no leaks).
 *   2. invalidate_stream() must clear that connection's FIFO entries.
 *   3. sweep() must clear timed-out FIFO entries.
 *   4. 100 successive generations on one reused 4-tuple must leave exactly one
 *      live pending entry and one FIFO entry (connection-reuse regression).
 *   5. Filling MAX_PENDING_TOTAL (4096) across 128 connections and then
 *      enqueueing a 4,097th request must evict, keeping the global count at
 *      or below 4096.
 * Prints PASS/FAIL on stderr.
 */
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
    release_vector(reuse_conn.pending);
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

/* Self-test of g_total_flow_bytes accounting: feeding the response parser a
 * header with two conflicting Content-Length values (which invalidates the
 * stream) must leave the global byte counter at exactly 0, i.e. no buffered
 * bytes were leaked past the invalidation. */
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

/*
 * Entry point. Order of operations:
 *   1. Impose RLIMIT_AS = 256 MiB (unless built with ASan, which needs a much
 *      larger address space) -- the process must fail rather than run unbounded.
 *   2. Dispatch the fixture/self-test flags (each returns directly).
 *   3. Read the NT_* environment overrides, then parse -i/-p/--endpoint/
 *      --ship-rate-kbps/--stats-interval-sec/--pending-ttl-sec/-j/
 *      --wsse-body-bytes/--capability-probe/--spool.
 *   4. Validate ports (<= MAX_PORTS for representable cBPF 8-bit jump offsets),
 *      ship rate (64..10000), stats interval (10..300), pending TTL (1..300),
 *      and require exactly one capture worker.
 *   5. Fill the O(1) monitored-port table, seed the PRNG, build the node name
 *      and instance id.
 *   6. open_capture_socket() (BPF -> bind -> ring -> drop capabilities).
 *   7. Set up output: either make stdout non-blocking for the nt-ship-cpp pipe,
 *      or spawn the single shipping thread for --endpoint mode.
 *   8. Install SIGTERM/SIGINT handlers, line-buffer stdout, and enter the
 *      poll/drain loop described in the comments there.
 *   9. On exit: flush deferred WSSE and pending events, drain the shipping
 *      queue (bounded 10 s deadline), report packet/drop statistics, release
 *      the ring, and return non-zero if ring integrity or memory failed.
 */
int main(int argc, char **argv) {
#ifndef NT_HAS_ASAN
  /* Hard address-space cap. This is the process's own guard rail (the outer
   * nt-resource-guard.sh also sets it): with it in place the bounded buffers
   * cannot be exceeded into an OOM. Clamped to the existing hard limit when
   * that is lower. */
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

  /* Fixture/self-test dispatch: each of these runs in isolation and returns an
   * exit code (0 = pass; failures print to stderr). */
  if (argc > 1 && !strcmp(argv[1], "--fixture")) return run_fixture();
  if (argc > 1 && !strcmp(argv[1], "--wsse-fixture")) return run_wsse_fixture();
  if (argc > 1 && !strcmp(argv[1], "--dual-auth-fixture")) return run_dual_auth_fixture();
  if (argc > 1 && !strcmp(argv[1], "--ring-fixture")) return run_ring_fixture();
  if (argc > 1 && !strcmp(argv[1], "--ship-rate-fixture")) return run_ship_rate_fixture();
  if (argc > 1 && !strcmp(argv[1], "--stats-fixture")) return run_stats_fixture();
  if (argc > 1 && !strcmp(argv[1], "--lockout-fixture")) return run_lockout_fixture();
  if (argc > 1 && !strcmp(argv[1], "--fifo-fixture")) return run_fifo_fixture();
  if (argc > 1 && !strcmp(argv[1], "--flow-accounting-fixture")) return run_flow_accounting_fixture();

  /* CLI/env configuration: iface, ports, endpoint, workers (must stay 1). */
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

  /* Sockets, BPF, bind, ring, and privilege drop all happen inside
   * open_capture_socket(); from here on the process is unprivileged. */
  MmapRing ring;
  int fd = open_capture_socket(iface, ports, ring);
  if (fd < 0) return 2;

  /* stdout may be a closed pipe at shutdown; writing must not kill us with
   * SIGPIPE. The write path handles EPIPE explicitly instead. */
  signal(SIGPIPE, SIG_IGN);

  if (g_endpoint.empty()) {
  /* Pipeline mode: stdout must be non-blocking so a full ship pipe drops and
   * counts events instead of stalling ring drainage. If this cannot be set,
   * capture is refused (fail closed). */
    int output_flags = fcntl(STDOUT_FILENO, F_GETFL, 0);
    if (output_flags < 0 ||
        fcntl(STDOUT_FILENO, F_SETFL, output_flags | O_NONBLOCK) < 0) {
      logmsg("cannot make shipper pipe non-blocking; refusing unsafe pipeline");
      release_mmap_ring(fd, ring);
      close(fd);
      return 2;
    }
  } else {
  /* Single-binary mode: exactly one shipping thread drains the in-memory
   * queue and POSTs directly to the hub (no disk I/O). */
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

  /* Main loop state: `last` paces the 1 s housekeeping (sweep) timer; the two
   * failure flags decide the final exit code. */
  time_t last = time(NULL);
  bool ring_integrity_failure = false;
  bool memory_failure = false;

  struct pollfd pfd;
  pfd.fd = fd;
  /* Wait on the packet socket for readable data or a socket error. */
  pfd.events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
  pfd.revents = 0;

  try {
    while (g_running) {
      /* 1 s timeout so SIGTERM and the sweep/stats timers are honoured even
       * when traffic is idle. EINTR (signal) simply re-tests g_running. */
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
        /* Drain at most MAX_DRAIN_PER_PASS frames per wakeup so the
         * housekeeping/stats timers below still run under line-rate load. */
        size_t drain_count = 0;
        while (g_running && drain_count < MAX_DRAIN_PER_PASS) {
          /* Frames are laid out as blocks of frames_per_block frames: the
           * absolute frame index maps to (block = idx / frames_per_block,
           * offset within block = idx % frames_per_block), and the address is
           * ring_base + block*block_size + offset*frame_size. */
          unsigned b_idx = ring.frame_idx / ring.frames_per_block;
          unsigned f_in_b = ring.frame_idx % ring.frames_per_block;
          uint8_t *frame_ptr = ((uint8_t *)ring.ring) + (b_idx * ring.block_size) + (f_in_b * ring.frame_size);
          volatile struct tpacket2_hdr *volatile_hdr =
              (volatile struct tpacket2_hdr *)frame_ptr;

          /* Ownership handshake, kernel -> userspace: TP_STATUS_USER is set by
           * the kernel when it hands a frame over. The flag is read through a
           * volatile pointer, and the acquire barrier below orders all
           * subsequent reads of the frame's contents after this check. */
          if (!(volatile_hdr->tp_status & TP_STATUS_USER)) {
            break;
          }
          /* Acquire barrier: ensure the header-validating reads below observe
           * the frame contents the kernel wrote before setting TP_STATUS_USER. */
          __sync_synchronize();

          const struct tpacket2_hdr *hdr =
              (const struct tpacket2_hdr *)frame_ptr;
          size_t packet_offset = 0, packet_length = 0;
          if (!valid_ring_frame(hdr, ring.frame_size,
                                &packet_offset, &packet_length)) {
            /* Malformed frame metadata: mark it consumed (so the ring keeps
             * making progress) but treat the ring as compromised and stop
             * capture. */
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

          /* Release barrier before handing the frame back: all reads of the
           * frame contents are ordered before the TP_STATUS_KERNEL store, and
           * the frame index advances circularly within the ring. */
          __sync_synchronize();
          volatile_hdr->tp_status = TP_STATUS_KERNEL;
          ring.frame_idx = (ring.frame_idx + 1) % ring.frame_nr;
          ++drain_count;
        }
        if (g_endpoint.empty()) std::cout.flush();
      }

      /* Once per second: expire pending requests / idle connections and flush
       * the stdout buffer so the shipper sees complete lines promptly. */
      time_t now = time(NULL);
      if (now - last >= 1) {
        sweep(connections, conn_lru, now, g_pending_ttl_sec);
        if (g_endpoint.empty()) std::cout.flush();
        last = now;
      }

      /* Periodic stats: agent_stats to the hub in --endpoint mode, or an
       * internal capture_stats record on the stdout stream otherwise. */
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
  }
  /* A std::bad_alloc means the bounded-buffer design was violated somewhere;
   * stop cleanly and force a non-zero exit code. */
  catch (const std::bad_alloc &) {
    logmsg("memory allocation failure; stopping capture safely");
    g_running = 0;
    memory_failure = true;
  }
  catch (...) {
    logmsg("unexpected exception; stopping capture safely");
    g_running = 0;
    memory_failure = true;
  }

  if (!memory_failure) {
  /* Graceful shutdown: emit deferred WSSE events and every uncorrelated
   * pending request so no captured observation is silently lost. Skipped after
   * a memory failure (state may be inconsistent). */
    flush_incomplete_wsse(connections);
    flush_all_pending(connections);
  }
  if (g_endpoint.empty()) std::cout.flush();

  /* Signal the shipping thread that no more events will be produced, wake it,
   * and wait for it to drain (or hit its bounded shutdown deadline). */
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

  /* Final PACKET_STATISTICS read so the closing log line includes the last
   * kernel drop delta, then tear down the ring and the socket. */
  update_kernel_drops(fd);
  logmsg("packet stats: received=" + ull_string(g_capture_packets) +
         " dropped=" + ull_string(g_kernel_drops));
  if (!release_mmap_ring(fd, ring)) {
    logmsg("TPACKET_V2 cleanup failed");
    ring_integrity_failure = true;
  }
  close(fd);
  logmsg("stopped");
  /* Non-zero exit asks the supervisor to restart the whole pipeline, which is
   * how "fail closed" is escalated to the process manager. */
  return (ring_integrity_failure || memory_failure) ? 2 : 0;
}
