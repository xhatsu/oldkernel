/*
 * nt-ship-cpp.cpp -- zero-dependency, C++03-only JSONL event shipper for the
 * "oldkernel" capture kit (CentOS 6.x, Linux 2.6.32, g++ 4.4 era toolchains).
 *
 * ROLE IN THE PIPELINE
 *   nt-sniff-cpp writes one JSON event per line to stdout; the supervisor wires
 *   that stdout into this process's stdin:
 *       nt-sniff-cpp | nt-ship-cpp --endpoint http://HUB:PORT
 *   Each stdin line is already-complete event JSON. This program never parses
 *   packet payloads or event fields; it only queues, batches, paces, and POSTs
 *   them to the Hub, so it stays cheap on very old hardware.
 *
 * DESIGN CONSTRAINTS (see AGENTS.md rules 8..11)
 *   - Bounded memory only: a fixed 10,000-event / 20 MiB in-memory queue and at
 *     most MAX_INFLIGHT concurrent HTTP requests. There is NO disk spool and NO
 *     retry accumulation: overload is dropped and counted, never buffered.
 *   - Aggregate egress pacing: NT_SHIP_RATE_KBPS (64..10000 kbit/s, default 1024)
 *     limits application-payload bytes crossing the wire, shared by the event
 *     stream and indirectly bounding the stats stream.
 *   - Each encoded HTTP request body is capped at 64 KiB (MAX_POST_BYTES).
 *   - Exactly one uploader thread, created with an explicit 512 KiB stack, and
 *     pinned by the outer nt-resource-guard.sh; the main thread only reads stdin.
 *   - Fail closed: if the 512 KiB stack or the address-space rlimit cannot be
 *     enforced, the process refuses to start (exit 70) instead of running
 *     unbounded.
 *
 * THREADING MODEL
 *   main thread     : owns stdin, appends events to the shared queue under
 *                     g_lock, and updates the process-wide signal/lifecycle flags.
 *   uploader thread : owns EVERY socket/Connection, drains the queue into Batches,
 *                     drives the nonblocking HTTP state machine, and periodically
 *                     POSTs coalesced agent stats.
 *   All shared state is guarded by g_lock. g_cond wakes the uploader when new
 *   input arrives and it would otherwise be sleeping in poll()/cond_timedwait().
 */
#include <string>
#include <vector>
#include <deque>
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <ctime>
#include <algorithm>
#include <pthread.h>
#include <dirent.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

/*
 * AddressSanitizer detection. When ASAN is active the RLIMIT_AS clamp below is
 * compiled out, because ASAN reserves a huge virtual shadow region that would
 * otherwise immediately fail against the 256 MiB address-space ceiling.
 */
#if defined(__SANITIZE_ADDRESS__)
  #define NT_HAS_ASAN 1
#elif defined(__has_feature)
  #if __has_feature(address_sanitizer)
    #define NT_HAS_ASAN 1
  #endif
#endif

/*
 * Zero-third-party-library HTTP shipper.
 *
 * Build:
 *   g++ -std=gnu++98 -O2 -Wall -Wextra -Werror -pthread \
 *       nt-ship-cpp.cpp -lrt -o nt-ship-cpp
 *
 * Runtime protocol restrictions:
 *   - endpoint MUST be plain http:// (HTTPS deliberately unsupported)
 *   - HTTP/1.1 persistent connections
 *   - response bodies with Content-Length and chunked transfer are drained
 *   - responses without framing are accepted by status and the connection is closed
 */

/*
 * Fixed compile-time tuning limits. All are size_t/unsigned so they compare
 * against std::string::size()/deque::size() without narrowing conversions.
 */
static const size_t MAX_BATCH_EVENTS = 400;   /* events per POST; batch is cut here even if the queue is deeper */
static const size_t MAX_QUEUE = 10000;   /* hard cap on queued event count (bounded memory) */
static const size_t MAX_QUEUE_EVENTS = MAX_QUEUE;   /* alias used by the admission check and stats reporting */
static const size_t MAX_QUEUE_BYTES = 20U * 1024U * 1024U;   /* hard cap on total queued bytes */
static const size_t MAX_POST_BYTES = 65536;   /* 64 KiB ceiling on any encoded HTTP body (events AND stats) */
static const size_t MAX_STATS_BYTES = 16384;   /* largest capture-stats line accepted from stdin / emitted */
static const size_t MAX_INPUT_LINE = 65535;   /* largest single JSONL event accepted from stdin */
static const size_t MAX_RESPONSE_BYTES = 1024U * 1024U;   /* largest response body we will drain before giving up */
static const size_t MAX_HEADER_BYTES = 32U * 1024U;   /* largest response header block accepted */
static const unsigned FLUSH_MS = 1000;   /* flush a partial batch once its oldest event is ~1 s old */
static const unsigned DEFAULT_INFLIGHT = 2;   /* default parallel connections (small bounded pipeline) */
static const unsigned MAX_INFLIGHT_LIMIT = 4;   /* upper bound for --max-inflight / NT_MAX_INFLIGHT */
static const unsigned MAX_RETRY_AGE_SEC = 60;   /* a batch older than this is dropped, never retried forever */
static const unsigned MAX_RETRY_DELAY_MS = 30000;   /* exponential-backoff ceiling */
static const unsigned SHUTDOWN_GRACE_SEC = 10;   /* seconds allowed to drain queued work after EOF/shutdown */
static const unsigned CONNECT_TIMEOUT_MS = 3000;   /* TCP connect deadline while connect() is still in progress */

/*
 * Process-wide signal flags. "volatile sig_atomic_t" is the only portable type a
 * signal handler may write; stop_signal() sets these and nothing else.
 */
static volatile sig_atomic_t g_running = 1;   /* 1 while the process should keep running */
static volatile sig_atomic_t g_stopped_by_signal = 0;   /* 1 when SIGTERM/SIGINT asked us to stop (selects exit code) */
static unsigned g_ship_rate_kbps = 1024;   /* aggregate application-payload ceiling, kbit/s (validated 64..10000) */
static unsigned g_stats_interval_sec = 30;   /* target seconds between /api/agent/stats posts */
static unsigned g_max_inflight = DEFAULT_INFLIGHT;   /* number of Connection slots in the uploader pool */

/*
 * Queue + cross-thread handshake. g_lock protects every global below (and the
 * counters); g_cond is signalled by the main thread when a new event arrives, so
 * the uploader can abandon its timed wait and drain at once instead of spinning.
 */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cond = PTHREAD_COND_INITIALIZER;   /* "input arrived" wakeup for the uploader */
static std::deque<std::string> g_queue;   /* bounded FIFO of raw JSONL event strings, not yet batched */
static size_t g_queue_bytes = 0;   /* running sum of queue element sizes (avoids O(n) rescans on admission) */
static double g_queue_first_at = 0.0;   /* wall time the FRONT event entered the queue (0 when empty; drives flush age) */
static bool g_input_done = false;   /* set when stdin closed; uploader drains remaining work then exits */
static std::string g_capture_json = "{}";   /* latest capture_stats object, forwarded verbatim into agent stats */
static unsigned long long g_capture_generation = 0;   /* bumped whenever g_capture_json changes */
static unsigned long long g_stats_generation_sent = 0;   /* capture generation already published to the Hub */

/*
 * Lifetime counters (never reset): monotonic totals used both for the
 * /api/agent/stats deltas and for drop accounting. All are written under g_lock.
 */
/* Lifetime counters. */
static unsigned long long g_input_total = 0;   /* events read from stdin */
static unsigned long long g_posted_total = 0;   /* events accepted by the Hub (HTTP 2xx) */
static unsigned long long g_dropped_total = 0;   /* events discarded for any reason */
static unsigned long long g_oversized_total = 0;   /* events dropped for exceeding a size bound */
static unsigned long long g_batches_total = 0;   /* batches created (doubles as the batch-id sequence) */
static unsigned long long g_batches_failed_total = 0;   /* batches dropped after retries/grace expired */
static unsigned long long g_bytes_posted_total = 0;   /* application-payload bytes successfully POSTed */
static unsigned long long g_queue_drops_total = 0;   /* events dropped because the local queue was full */
static unsigned long long g_hub_drops_total = 0;   /* events lost to Hub errors/timeouts after retries */
static unsigned long long g_stats_drops_total = 0;   /* agent-stats samples that failed to POST */
static unsigned long long g_requests_started_total = 0;   /* HTTP attempts begun, including retries */
static unsigned long long g_requests_success_total = 0;   /* attempts that received 2xx */
static unsigned long long g_requests_failed_total = 0;   /* attempts that failed (transport or non-2xx) */
static unsigned long long g_requests_retried_total = 0;   /* attempts that were retries (attempts > 1) */
static unsigned long long g_reconnects_total = 0;   /* new TCP connections opened */
static unsigned long long g_queue_high_water = 0;   /* peak queued event count ever seen */
static unsigned long long g_queue_bytes_high_water = 0;   /* peak queued bytes ever seen */

/*
 * Previous sample of the counters above, used to compute non-overlapping
 * *_delta fields for each stats window. Updated only by shipping_stats_body()
 * while holding g_lock.
 */
/* Previous counters for interval stats. */
static unsigned long long g_prev_input = 0;   /* baseline: g_input_total at last stats sample */
static unsigned long long g_prev_posted = 0;   /* baseline: g_posted_total */
static unsigned long long g_prev_dropped = 0;   /* baseline: g_dropped_total */
static unsigned long long g_prev_bytes_posted = 0;   /* baseline: g_bytes_posted_total */
static unsigned long long g_prev_queue_drops = 0;   /* baseline: g_queue_drops_total */
static unsigned long long g_prev_hub_drops = 0;   /* baseline: g_hub_drops_total */
static unsigned long long g_prev_oversized = 0;   /* baseline: g_oversized_total */
static unsigned long long g_prev_batches_total = 0;   /* baseline: g_batches_total */
static unsigned long long g_prev_batches_failed = 0;   /* baseline: g_batches_failed_total */

static unsigned long long g_sequence = 0;   /* monotonic agent-stats sequence number */
static unsigned g_consecutive_failures = 0;   /* reset to 0 on any 2xx; surfaced in stats as a health signal */
static int g_last_http_status = 0;   /* HTTP status of the most recent attempt (0 = transport error) */
static time_t g_last_success_epoch = 0;   /* wall-clock time of the last 2xx */
static time_t g_started_epoch = 0;   /* process start time; seeds instance id and retry jitter */
static double g_last_stats_at = 0.0;   /* time base for the "window_seconds" of the last stats sample */
static double g_last_stats_cpu = 0.0;   /* total CPU seconds at the last stats sample (for cpu_percent_one_core) */
static std::string g_endpoint;   /* raw --endpoint argument */
static std::string g_node;   /* node name: NT_NODE_NAME or the system hostname */
static std::string g_instance_id;   /* "<start_epoch>-<pid>"; prefixes batch ids so a restart yields fresh ids */

/*
 * Parsed form of the --endpoint URL. Kept deliberately flat: host/port feed
 * getaddrinfo(), base_path is prepended to every API suffix, and host_header is
 * the exact "Host:" value (brackets for IPv6, default port 80 omitted).
 */
struct Endpoint {
  std::string host;   /* bare host or IPv6 literal without brackets */
  std::string host_header;   /* value for the Host: header (re-bracketed IPv6, ":port" unless 80) */
  std::string port;   /* decimal TCP port as text, for getaddrinfo */
  std::string base_path;   /* normalized URL prefix, e.g. "" or "/nt" (never ends in "/") */
};
static Endpoint g_ep;   /* the single parsed endpoint, read-only after startup */

/* Signal handler: async-signal-safe, so it only flips the two flags above. */
static void stop_signal(int sig) { (void)sig; g_stopped_by_signal = 1; g_running = 0; }
/* All diagnostics go to stderr so stdout stays free for machine-readable output. */
static void logmsg(const std::string &s) { std::cerr << "nt-ship-cpp: " << s << std::endl; }
/* Decimal-format an unsigned long long (avoids locale/stream-state surprises). */
static std::string ulls(unsigned long long n) { std::ostringstream o; o << n; return o.str(); }

/*
 * Wall clock in fractional seconds. Single time base for pacing, deadlines,
 * batch ages and stats windows. It is NOT monotonic (gettimeofday can step
 * backwards), which is why limiter_refill() re-bases on a backwards step.
 */
static double wall_seconds() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}

/*
 * Wrap s in JSON double quotes and escape it so the result is always a valid
 * JSON string:
 *   - backslash and double-quote are backslash-escaped,
 *   - newline/CR/tab become their two-character short escapes,
 *   - any other control byte (< 0x20) is replaced by '?' (a valid scalar)
 *     instead of emitting a raw control character that would break the Hub,
 *   - bytes >= 0x80 pass through unchanged (UTF-8 is assumed).
 * The unsigned char cast prevents sign-extension when plain char is signed.
 */
static std::string jsonq(const std::string &s) {
  std::string x = "\"";
  for (size_t i = 0; i < s.size(); ++i) {
    unsigned char c = (unsigned char)s[i];
    if (c == '\\' || c == '"') { x += '\\'; x += (char)c; }
    else if (c == '\n') x += "\\n";
    else if (c == '\r') x += "\\r";
    else if (c == '\t') x += "\\t";
    else if (c < 32) x += '?';
    else x += (char)c;
  }
  return x + "\"";
}

/* ASCII-only tolower; used to compare HTTP header names/values case-insensitively. */
static std::string lower_ascii(const std::string &s) {
  std::string out(s);
  for (size_t i = 0; i < out.size(); ++i) {
    if (out[i] >= 'A' && out[i] <= 'Z') out[i] = (char)(out[i] - 'A' + 'a');
  }
  return out;
}

/* Strip leading spaces/tabs and trailing spaces/tabs/CR/LF (HTTP OWS + line end). */
static std::string trim_ascii(const std::string &s) {
  size_t a = 0, b = s.size();
  while (a < b && (s[a] == ' ' || s[a] == '\t')) ++a;
  while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
  return s.substr(a, b - a);
}

/*
 * Parse "http://HOST[:PORT][/base]" and the bracketed IPv6 form
 * "http://[::1]:8080/base" into host / port / base_path / Host-header. HTTPS is
 * deliberately rejected: this build has no TLS. Returns false and fills *err
 * with an operator-readable reason on any malformed input. The parsed values
 * feed getaddrinfo() and the HTTP request line/Host header.
 */
static bool parse_endpoint(const std::string &url, Endpoint *ep, std::string *err) {
  if (!ep) return false;
  const std::string prefix = "http://";
  if (url.compare(0, prefix.size(), prefix) != 0) {
    if (err) *err = "endpoint must start with http://; HTTPS is not supported by the zero-library build";
    return false;
  }
  /* Split at the first '/' after the scheme: everything before is authority
   * (host[:port]), everything after (including the slash) is the base path. */
  size_t p = prefix.size();
  size_t slash = url.find('/', p);
  std::string authority = slash == std::string::npos ? url.substr(p) : url.substr(p, slash - p);
  std::string path = slash == std::string::npos ? "" : url.substr(slash);
  if (authority.empty()) { if (err) *err = "endpoint host is empty"; return false; }

  std::string host, port = "80";   /* port defaults to 80 when the URL omits it */
  /* Bracketed IPv6 literal: "[addr]" or "[addr]:port". */
  if (authority[0] == '[') {
    size_t rb = authority.find(']');
    if (rb == std::string::npos) { if (err) *err = "invalid bracketed IPv6 endpoint"; return false; }
    host = authority.substr(1, rb - 1);
    if (rb + 1 < authority.size()) {
      if (authority[rb + 1] != ':' || rb + 2 >= authority.size()) { if (err) *err = "invalid endpoint port"; return false; }
      port = authority.substr(rb + 2);
    }
  } else {
    /* Exactly one ':' means HOST:PORT. Zero or several colons (a bare IPv6
     * literal without brackets) means the whole authority is the host and the
     * port keeps its default. */
    size_t colon = authority.rfind(':');
    if (colon != std::string::npos && authority.find(':') == colon) {
      host = authority.substr(0, colon);
      port = authority.substr(colon + 1);
    } else {
      host = authority;
    }
  }
  if (host.empty() || port.empty()) { if (err) *err = "invalid endpoint host or port"; return false; }
  /* The port must be all digits; reject service names to keep getaddrinfo
   * deterministic and avoid a slow NSS lookup at startup. */
  for (size_t i = 0; i < port.size(); ++i) {
    if (port[i] < '0' || port[i] > '9') { if (err) *err = "endpoint port must be numeric"; return false; }
  }
  unsigned long pn = strtoul(port.c_str(), NULL, 10);   /* numeric range check (1..65535) */
  if (pn == 0 || pn > 65535UL) { if (err) *err = "endpoint port out of range"; return false; }

  /* Normalize the base path: strip trailing slashes and turn "/" into "" so
   * endpoint_path() can simply concatenate the API suffix. */
  while (path.size() > 1 && path[path.size() - 1] == '/') path.erase(path.size() - 1);
  if (path == "/") path.clear();
  ep->host = host;
  ep->port = port;
  ep->base_path = path;
  /* Build the Host: header value. IPv6 literals must be re-bracketed, and the
   * default port 80 is omitted (standard HTTP Host formatting). */
  bool ipv6_literal = authority.size() > 0 && authority[0] == '[';
  std::string hh = ipv6_literal ? ("[" + host + "]") : host;
  if (port != "80") hh += ":" + port;
  ep->host_header = hh;
  return true;
}

/* Join the endpoint base path with an API suffix, e.g. "" + "/api/ingest". */
static std::string endpoint_path(const char *suffix) {
  return g_ep.base_path + suffix;
}

/*
 * Minimal, dependency-free extraction of one unsigned integer field from a JSON
 * object string: find "<key>": then parse the following decimal digits. It is
 * intentionally NOT a real JSON parser -- it only reads a few well-known numeric
 * fields of the capture-stats object (deltas, wsse_body_bytes). Returns 0 when
 * the key is absent, so callers treat "missing" as "no such drop".
 */
static unsigned long long json_uint(const std::string &s, const char *key) {
  std::string needle = std::string("\"") + key + "\":";
  size_t p = s.find(needle);
  if (p == std::string::npos) return 0;
  p += needle.size();
  while (p < s.size() && (s[p] == ' ' || s[p] == '\t')) ++p;
  /* Skip optional space/tab between the key and its value, then read digits. */
  unsigned long long v = 0;
  while (p < s.size() && s[p] >= '0' && s[p] <= '9') {
    v = v * 10ULL + (unsigned)(s[p] - '0'); ++p;
  }
  return v;
}

/* Count OS threads by enumerating /proc/self/task (present on Linux 2.6.32). */
static unsigned thread_count() {
  DIR *d = opendir("/proc/self/task"); if (!d) return 0;
  unsigned n = 0; struct dirent *e;
  while ((e = readdir(d)) != NULL) if (e->d_name[0] >= '0' && e->d_name[0] <= '9') ++n;
  closedir(d); return n;
}

/*
 * Read RSS and virtual size from /proc/self/statm (fields 1 and 2, in pages)
 * and convert to bytes using the runtime page size. Telemetry only: on any
 * failure both outputs degrade to zero.
 */
static void process_memory(unsigned long long *rss, unsigned long long *virt) {
  FILE *f = fopen("/proc/self/statm", "r"); unsigned long pages = 0, resident = 0;
  if (f) { if (fscanf(f, "%lu %lu", &pages, &resident) != 2) pages = resident = 0; fclose(f); }
  unsigned long long page = (unsigned long long)sysconf(_SC_PAGESIZE);
  *rss = (unsigned long long)resident * page; *virt = (unsigned long long)pages * page;
}

/* Count open file descriptors by enumerating /proc/self/fd (telemetry only). */
static unsigned open_fd_count() {
  DIR *d = opendir("/proc/self/fd"); if (!d) return 0;
  unsigned n = 0; struct dirent *e;
  while ((e = readdir(d)) != NULL) if (e->d_name[0] >= '0' && e->d_name[0] <= '9') ++n;
  closedir(d); return n;
}

/*
 * Return the CPU affinity list from /proc/self/status "Cpus_allowed_list" (the
 * resource guard pins the tree to one core). Falls back to "0" when absent.
 */
static std::string allowed_cpu() {
  FILE *f = fopen("/proc/self/status", "r"); if (!f) return "0";
  char line[512]; std::string result = "0";
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "Cpus_allowed_list:", 18) == 0) {
      char *p = line + 18; while (*p == ' ' || *p == '\t') ++p;
      char *end = p + strlen(p); while (end > p && (end[-1] == '\n' || end[-1] == '\r')) --end;
      result.assign(p, end - p); break;
    }
  }
  fclose(f); return result;
}

/*
 * Try to interpret one stdin line as a capture-stats envelope emitted by
 * nt-sniff-cpp instead of a normal event. Such a line carries the marker
 * "_nt_internal":"capture_stats_v1" and a "capture":{...} object; that object is
 * copied out VERBATIM (byte for byte) so it can be embedded unchanged in the
 * outgoing agent-stats JSON. Brace matching is quote- and escape-aware, so a '}'
 * inside a string cannot terminate the object early. Non-stats or absurdly large
 * lines return false and are handled as events.
 * NOTE: capture-stats lines are consumed here and never enter the event queue.
 */
static bool parse_capture_stats(const std::string &line, std::string *capture) {
  if (line.size() > MAX_STATS_BYTES || line.find("\"_nt_internal\":\"capture_stats_v1\"") == std::string::npos) return false;
  /* Locate the "capture": key, then the '{' that opens its object. */
  size_t p = line.find("\"capture\":"); if (p == std::string::npos) return false;
  p += strlen("\"capture\":");
  size_t start = line.find('{', p); if (start == std::string::npos) return false;
  /* Single-pass scanner: depth counts nested braces OUTSIDE strings; the
   * quoted/escaped pair tracks string literals so JSON braces inside them are
   * ignored. The object ends when depth returns to 0. */
  int depth = 0; bool quoted = false, escaped = false;
  for (size_t i = start; i < line.size(); ++i) {
    char c = line[i];
    if (quoted) { if (escaped) escaped = false; else if (c == '\\') escaped = true; else if (c == '"') quoted = false; continue; }
    if (c == '"') quoted = true;
    else if (c == '{') ++depth;
    else if (c == '}' && --depth == 0) { *capture = line.substr(start, i - start + 1); return true; }
  }
  return false;
}

/*
 * One in-flight upload unit. body is the fully encoded JSON payload
 * ({"node":...,"events":[...]}); attempts drives backoff; next_attempt_at is the
 * wall time at which a retry becomes eligible. A Batch is owned by exactly one
 * Connection while in flight and is allocated/freed only by the uploader thread,
 * so Batch pointers never cross threads.
 */
struct Batch {
  std::string id;   /* "<instance_id>-<sequence>", sent as X-Batch-Id */
  std::string body;   /* complete request body, pre-encoded once per attempt-free batch */
  size_t event_count;   /* number of events inside body (credited on success) */
  unsigned attempts;   /* HTTP attempts made so far (drives backoff and retry counters) */
  double created_at;   /* wall time of creation; enforces MAX_RETRY_AGE_SEC */
  double next_attempt_at;   /* earliest wall time for the next retry */
  Batch() : id(""), body(""), event_count(0), attempts(0), created_at(0.0), next_attempt_at(0.0) {}
};

/* Nonblocking HTTP state machine states, one per Connection slot. */
enum ConnState {
  CS_IDLE = 0,   /* free: may take a new batch from the queue */
  CS_RETRY_WAIT,   /* batch retained, waiting until next_attempt_at (backoff) */
  CS_CONNECTING,   /* TCP connect in progress; poll for POLLOUT then check SO_ERROR */
  CS_SENDING,   /* writing request bytes, rate-limited by the token bucket */
  CS_READING   /* draining and parsing the response */
};

/*
 * One socket slot in the bounded uploader pool. A Connection owns at most one
 * in-flight (or retry-waiting) Batch. request holds the full encoded request
 * (headers + body); response accumulates raw response bytes; header_end is the
 * offset just past "\\r\\n\\r\\n"; content_length is -1 when the header is absent
 * (unframed) and -2 when present-but-invalid; deadline bounds the current
 * operation. Only the uploader thread ever touches these fields.
 */
struct Connection {
  int fd;   /* socket, or -1 when none is open */
  ConnState state;   /* current state-machine state */
  Batch *batch;   /* owned in-flight batch, or NULL */
  std::string request;   /* full encoded request (headers + body) */
  size_t send_off;   /* bytes of request already written */
  std::string response;   /* raw bytes received so far */
  size_t header_end;   /* offset just past the header terminator (0 = not yet found) */
  long content_length;   /* -1 = no header, -2 = invalid, >=0 = exact body length */
  int http_status;   /* parsed 3-digit status code */
  bool chunked;   /* response uses chunked transfer-encoding */
  bool close_after_response;   /* socket must not be kept alive for the next batch */
  double deadline;   /* wall-time deadline for the current connect/send/read operation */

  Connection() : fd(-1), state(CS_IDLE), batch(NULL), request(""), send_off(0),
                 response(""), header_end(0), content_length(-1), http_status(0),
                 chunked(false), close_after_response(false), deadline(0.0) {}
};

/* Idempotently close the socket and mark the slot fd-less; safe to call twice. */
static void close_fd(Connection *c) {
  if (!c) return;
  if (c->fd >= 0) close(c->fd);
  c->fd = -1;
}

/* Forget all parsed response state so the next attempt starts clean.
 * Does not touch c->batch or the socket itself. */
static void reset_response(Connection *c) {
  c->response.clear();
  c->header_end = 0;
  c->content_length = -1;
  c->http_status = 0;
  c->chunked = false;
  c->close_after_response = false;
}

/* Put fd in nonblocking mode so the uploader's poll() loop never blocks
 * inside connect()/send()/recv(). */
static bool set_nonblock(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) return false;
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

/*
 * Resolve ep.host:ep.port with getaddrinfo() and open the first usable
 * nonblocking TCP socket, trying every returned address (so a host with both A
 * and AAAA records still works). SO_KEEPALIVE lets the kernel reap dead
 * keep-alive peers; TCP_NODELAY pushes small JSON bodies out immediately.
 * On success *connected is true when connect() completed at once, false when it
 * returned EINPROGRESS (the caller must wait for POLLOUT, then check SO_ERROR).
 * Returns -1 if no address could be opened.
 */
static int open_nonblocking_socket(const Endpoint &ep, bool *connected) {
  if (connected) *connected = false;
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  struct addrinfo *res = NULL;
  int grc = getaddrinfo(ep.host.c_str(), ep.port.c_str(), &hints, &res);
  if (grc != 0 || !res) return -1;

  int fd = -1;
  /* Walk the resolved address list; the first socket that opens and either
   * connects immediately or goes EINPROGRESS wins. */
  for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) continue;
    if (!set_nonblock(fd)) { close(fd); fd = -1; continue; }

    /* one is the classic "enable" value for the two boolean socket options. */
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
    if (rc == 0) { if (connected) *connected = true; break; }
    if (rc < 0 && errno == EINPROGRESS) break;   /* connect still running: keep this fd */
    close(fd); fd = -1;
  }
  freeaddrinfo(res);
  return fd;
}

/*
 * Decide how many queued events fit in one POST without exceeding MAX_POST_BYTES,
 * starting from the front of the queue.
 *   base = exact encoded size of the wrapper {"node":"...","events":[]}
 *   Events are comma-joined, so the marginal cost of event n is
 *   size() + (n ? 1 : 0) -- the "+1" is the separating comma (packed into
 *   `extra` below). The loop stops at the first event that would overflow.
 * Returns min(queued, MAX_BATCH_EVENTS) clamped by the 64 KiB body budget, and
 * therefore always >= 1 when the queue is non-empty unless the very first event
 * alone already exceeds the body budget.
 */
static size_t bounded_batch_count(const std::deque<std::string> &buf, const std::string &node) {
  size_t base = std::string("{\"node\":").size() + jsonq(node).size() + std::string(",\"events\":[]}").size();
  size_t n = 0;
  size_t limit = buf.size() < MAX_BATCH_EVENTS ? buf.size() : MAX_BATCH_EVENTS;
  while (n < limit) {
    /* Marginal cost of adding event n: its bytes plus a comma if it is not first. */
    size_t extra = buf[n].size() + (n ? 1 : 0);
    if (extra > MAX_POST_BYTES - base) break;
    base += extra;
    ++n;
  }
  return n;
}

/*
 * Remove up to bounded_batch_count() events from the FRONT of the shared queue
 * (under g_lock, so the main thread can keep appending to the back) and build
 * one Batch. If not even the first event fits under the 64 KiB cap, exactly that
 * one event is discarded and counted as oversized rather than stalling the
 * pipeline forever. g_queue_first_at is reset to "now" whenever a non-empty
 * remainder is left, which restarts the FLUSH_MS age window for the new front.
 * The batch-id sequence (g_batches_total) is bumped here, under the lock.
 * Returns NULL when nothing could be batched.
 */
static Batch *build_event_batch() {
  std::vector<std::string> events;
  std::string id;

  pthread_mutex_lock(&g_lock);
  size_t n = bounded_batch_count(g_queue, g_node);
  /* Queue non-empty but nothing fits: drop just the head event as oversized.
   * This guarantees progress even if a single line is pathologically large. */
  if (!n && !g_queue.empty()) {
    g_queue_bytes -= g_queue.front().size();
    g_queue.pop_front();
    ++g_dropped_total; ++g_oversized_total;
    if (g_queue.empty()) g_queue_first_at = 0.0;
    pthread_mutex_unlock(&g_lock);
    return NULL;
  }
  if (!n) { pthread_mutex_unlock(&g_lock); return NULL; }

  id = g_instance_id + "-" + ulls(++g_batches_total);   /* unique, monotonic batch id */
  events.reserve(n);
  for (size_t i = 0; i < n; ++i) {
    events.push_back(g_queue.front());
    g_queue_bytes -= g_queue.front().size();
    g_queue.pop_front();
  }
  if (g_queue.empty()) g_queue_first_at = 0.0;
  else g_queue_first_at = wall_seconds();
  pthread_mutex_unlock(&g_lock);

  Batch *b = new Batch();   /* owned by us until handed to a Connection */
  b->id = id;
  b->event_count = events.size();
  b->created_at = wall_seconds();
  /* Encode the batch payload: {"node":"<node>","events":[<event>,<event>,...]}.
   * Events are raw pre-validated JSONL, joined with commas (no comma before the
   * first one). The wrapper adds the surrounding braces/array. */
  std::string body = "{\"node\":" + jsonq(g_node) + ",\"events\":[";
  for (size_t i = 0; i < events.size(); ++i) { if (i) body += ','; body += events[i]; }   /* comma-join */
  body += "]}";
  if (body.size() > MAX_POST_BYTES) { delete b; return NULL; }   /* defensive final 64 KiB check */
  b->body.swap(body);   /* move (C++03 swap) instead of copying the large string */
  return b;
}

/*
 * Flush policy for the queue front: emit when we have a full batch (400 events),
 * or the oldest queued event has waited >= FLUSH_MS (1 s), or input/process is
 * ending (drain everything). Evaluated under g_lock.
 */
static bool queue_ready_to_flush(bool shutdown_started) {
  bool yes = false;
  pthread_mutex_lock(&g_lock);
  if (!g_queue.empty()) {
    double age = g_queue_first_at > 0.0 ? wall_seconds() - g_queue_first_at : 0.0;
    yes = g_queue.size() >= MAX_BATCH_EVENTS || age * 1000.0 >= FLUSH_MS ||
          g_input_done || !g_running || shutdown_started;
  }
  pthread_mutex_unlock(&g_lock);
  return yes;
}

/*
 * Serialize one HTTP/1.1 POST /api/ingest request (headers + body). The request
 * LINE uses endpoint_path() so a base path on the endpoint URL is preserved.
 * Content-Length is the exact body size; keep-alive lets a single socket serve
 * many batches; X-Batch-Id carries the batch id for Hub diagnostics/dedup. The
 * returned string is the entire byte sequence to write to the socket.
 */
static std::string make_request(const Batch &b) {
  std::ostringstream o;
  o << "POST " << endpoint_path("/api/ingest") << " HTTP/1.1\r\n"
    << "Host: " << g_ep.host_header << "\r\n"
    << "User-Agent: nt-ship-cpp-posix/1\r\n"
    << "Content-Type: application/json\r\n"
    << "Content-Length: " << b.body.size() << "\r\n"
    << "X-Batch-Id: " << b.id << "\r\n"
    << "Connection: keep-alive\r\n"
    << "\r\n";
  std::string req = o.str();
  req += b.body;
  return req;
}

/*
 * Per-attempt timeout in milliseconds. Estimated transfer time =
 * request_bytes / (kbps*1000/8 bytes per second), multiplied by (max_inflight+1)
 * because up to that many sockets share the single global rate limiter, plus a
 * 10 s slack for connect/handshake/Hub processing. Clamped to 15..55 s so a
 * mis-set rate can never yield an absurdly long or a zero timeout.
 */
static unsigned attempt_timeout_ms(size_t request_bytes) {
  double bytes_per_sec = (double)g_ship_rate_kbps * 1000.0 / 8.0;
  if (bytes_per_sec < 1.0) bytes_per_sec = 1.0;
  /* Allow for sharing the global limiter among max in-flight sockets. */
  double seconds = (double)request_bytes / bytes_per_sec;
  seconds *= (double)(g_max_inflight + 1U);
  seconds += 10.0;
  if (seconds < 15.0) seconds = 15.0;
  if (seconds > 55.0) seconds = 55.0;
  return (unsigned)(seconds * 1000.0);
}

/*
 * Backoff: 500 ms << (attempts-1) with the shift capped at 6 (=> 32 s, then the
 * MAX_RETRY_DELAY_MS ceiling), plus a small deterministic jitter derived from
 * the process start time and attempt count so many nodes do not retry in
 * lockstep after a Hub outage.
 */
static unsigned retry_delay_ms(unsigned attempts) {
  unsigned shift = attempts > 1 ? attempts - 1 : 0;
  if (shift > 6) shift = 6;
  unsigned ms = 500U << shift;   /* 500 ms, 1 s, 2 s, 4 s, ... */
  if (ms > MAX_RETRY_DELAY_MS) ms = MAX_RETRY_DELAY_MS;
  ms += (unsigned)((g_started_epoch + attempts * 1103515245U) % 251U);
  return ms;
}

/* Statuses worth retrying: request timeout (408), throttling (429), any 5xx. */
static bool transient_status(int status) {
  return status == 408 || status == 429 || (status >= 500 && status <= 599);
}

/* Book-keeping for a fresh HTTP attempt; counts retries too. Under g_lock. */
static void record_attempt_started(Batch *b) {
  pthread_mutex_lock(&g_lock);
  ++g_requests_started_total;
  if (b && b->attempts > 1) ++g_requests_retried_total;
  pthread_mutex_unlock(&g_lock);
}

/* Record a failed attempt: bump counters, reset the success streak, note status. */
static void record_attempt_failure(int status) {
  pthread_mutex_lock(&g_lock);
  ++g_requests_failed_total;
  ++g_consecutive_failures;
  g_last_http_status = status;
  pthread_mutex_unlock(&g_lock);
}

/* Record a 2xx: credit the batch event count and the application-payload bytes. */
static void record_success(Batch *b, int status) {
  pthread_mutex_lock(&g_lock);
  g_posted_total += b->event_count;
  g_bytes_posted_total += b->body.size();
  ++g_requests_success_total;
  g_consecutive_failures = 0;
  g_last_http_status = status;
  g_last_success_epoch = time(NULL);
  pthread_mutex_unlock(&g_lock);
}

/* Record a batch abandoned after retries/grace: its events are lost (dropped). */
static void record_final_drop(Batch *b, int status) {
  if (!b) return;
  pthread_mutex_lock(&g_lock);
  g_hub_drops_total += b->event_count;
  g_dropped_total += b->event_count;
  ++g_batches_failed_total;
  g_last_http_status = status;
  pthread_mutex_unlock(&g_lock);
}

/*
 * Put a failed attempt back into CS_RETRY_WAIT, or give up:
 *  - always close the socket (a partial/failed exchange is not reusable) and
 *    clear the request/response buffers,
 *  - if the batch is older than MAX_RETRY_AGE_SEC (or we are shutting down),
 *    account its events as dropped and free it,
 *  - otherwise set next_attempt_at = now + retry_delay_ms(attempts).
 * status is the HTTP status when known, or 0 for transport errors.
 */
static void schedule_retry(Connection *c, int status) {
  if (!c || !c->batch) return;
  record_attempt_failure(status);
  close_fd(c);
  c->request.clear();
  c->send_off = 0;
  reset_response(c);
  double age = wall_seconds() - c->batch->created_at;
  if (age >= MAX_RETRY_AGE_SEC || !g_running) {
    record_final_drop(c->batch, status);
    delete c->batch;
    c->batch = NULL;
    c->state = CS_IDLE;
    return;
  }
  c->batch->next_attempt_at = wall_seconds() + (double)retry_delay_ms(c->batch->attempts) / 1000.0;
  c->state = CS_RETRY_WAIT;
}

/*
 * Begin (or resume) an attempt for c->batch: rebuild the request, bump the
 * attempt counter, then either reuse the existing keep-alive socket
 * (straight to CS_SENDING) or open a new one. An unfinished connect
 * (EINPROGRESS) enters CS_CONNECTING with the shorter CONNECT_TIMEOUT_MS. Any
 * failure defers to schedule_retry(), so the state machine never busy-loops.
 */
static void start_attempt(Connection *c) {
  if (!c || !c->batch) return;
  reset_response(c);
  c->send_off = 0;
  c->request = make_request(*c->batch);
  ++c->batch->attempts;
  record_attempt_started(c->batch);

  /* Reuse a healthy keep-alive socket from the previous successful batch. */
  if (c->fd >= 0) {   /* reuse the healthy keep-alive socket */
    c->deadline = wall_seconds() + (double)attempt_timeout_ms(c->request.size()) / 1000.0;
    c->state = CS_SENDING;
    return;
  }

  bool connected = false;
  c->fd = open_nonblocking_socket(g_ep, &connected);
  if (c->fd < 0) {
    schedule_retry(c, 0);
    return;
  }
  pthread_mutex_lock(&g_lock); ++g_reconnects_total; pthread_mutex_unlock(&g_lock);
  c->deadline = wall_seconds() + (double)(connected ? attempt_timeout_ms(c->request.size()) : CONNECT_TIMEOUT_MS) / 1000.0;
  c->state = connected ? CS_SENDING : CS_CONNECTING;
}

/* Bind a freshly built batch to an idle slot and immediately start attempt #1. */
static void assign_batch(Connection *c, Batch *b) {
  c->batch = b;
  start_attempt(c);
}

/* Parse "HTTP/1.1 200 ..." from the header block into an integer status code. */
static bool parse_status_line(const std::string &headers, int *status) {
  size_t eol = headers.find("\r\n");
  if (eol == std::string::npos) return false;
  std::string line = headers.substr(0, eol);
  if (line.compare(0, 5, "HTTP/") != 0) return false;
  size_t sp = line.find(' ');
  if (sp == std::string::npos) return false;
  while (sp < line.size() && line[sp] == ' ') ++sp;
  if (sp + 3 > line.size()) return false;
  if (line[sp] < '0' || line[sp] > '9' || line[sp+1] < '0' || line[sp+1] > '9' || line[sp+2] < '0' || line[sp+2] > '9') return false;
  *status = (line[sp]-'0')*100 + (line[sp+1]-'0')*10 + (line[sp+2]-'0');
  return true;
}

/*
 * Scan the header block (bytes up to header_end) for the three framing headers
 * that matter. Names and values are lowercased for comparison:
 *   content-length    -> exact body length, or -2 if unparsable / too large
 *   transfer-encoding -> sets chunked when it contains "chunked"
 *   connection        -> sets close_after_response when it contains "close"
 * content_length stays -1 when the header is absent (unframed response). The
 * scan stops at the first empty line (end of headers).
 */
static void parse_response_headers(Connection *c) {
  std::string h = c->response.substr(0, c->header_end);
  c->content_length = -1;
  c->chunked = false;
  c->close_after_response = false;

  size_t pos = h.find("\r\n") + 2;
  while (pos < h.size()) {
    size_t eol = h.find("\r\n", pos);
    if (eol == std::string::npos || eol == pos) break;
    std::string line = h.substr(pos, eol - pos);
    size_t colon = line.find(':');
    if (colon != std::string::npos) {
      std::string name = lower_ascii(trim_ascii(line.substr(0, colon)));
      std::string value = lower_ascii(trim_ascii(line.substr(colon + 1)));
      if (name == "content-length") {   /* validated by a full-string strtoull + size cap */
        char *endp = NULL;
        unsigned long long v = strtoull(value.c_str(), &endp, 10);
        if (endp && *endp == 0 && v <= MAX_RESPONSE_BYTES) c->content_length = (long)v;
        else c->content_length = -2;
      } else if (name == "transfer-encoding" && value.find("chunked") != std::string::npos) {
        c->chunked = true;
      } else if (name == "connection" && value.find("close") != std::string::npos) {
        c->close_after_response = true;
      }
    }
    pos = eol + 2;
  }
}

/* Result of trying to parse a chunked body: need more bytes, done, or malformed. */
enum ChunkResult { CHUNK_INCOMPLETE = 0, CHUNK_COMPLETE = 1, CHUNK_INVALID = 2 };

/*
 * Walk HTTP/1.1 chunked encoding from pos: "<hex-size>[;extena]\r\n<data>\r\n" ...
 * terminated by a zero-size chunk plus optional trailers. Returns CHUNK_INCOMPLETE
 * when more bytes are required, CHUNK_COMPLETE once the terminating chunk (and
 * trailers, if any) have been seen, or CHUNK_INVALID on malformed size lines or
 * overflow. Chunk sizes are bounded (the running size is checked before each
 * 4-bit shift) and the accumulated body is capped at MAX_RESPONSE_BYTES, so a
 * confusing or hostile Hub cannot make us allocate without bound.
 */
static ChunkResult chunked_complete(const std::string &buf, size_t pos) {
  size_t total_body = 0;
  while (true) {
    size_t eol = buf.find("\r\n", pos);
    if (eol == std::string::npos) return CHUNK_INCOMPLETE;
    std::string line = buf.substr(pos, eol - pos);
    size_t semi = line.find(';');
    if (semi != std::string::npos) line.erase(semi);
    line = trim_ascii(line);
    if (line.empty()) return CHUNK_INVALID;
    unsigned long size = 0;
    for (size_t i = 0; i < line.size(); ++i) {
      char ch = line[i]; unsigned v;
      if (ch >= '0' && ch <= '9') v = (unsigned)(ch - '0');
      else if (ch >= 'a' && ch <= 'f') v = (unsigned)(ch - 'a' + 10);
      else if (ch >= 'A' && ch <= 'F') v = (unsigned)(ch - 'A' + 10);
      else return CHUNK_INVALID;
      if (size > (MAX_RESPONSE_BYTES >> 4)) return CHUNK_INVALID;   /* shift-overflow guard */
      size = (size << 4) + v;
    }
    pos = eol + 2;
    /* Zero-size chunk = end of body: an immediate CRLF means no trailers. */
    if (size == 0) {
      if (buf.size() >= pos + 2 && buf.compare(pos, 2, "\r\n") == 0) return CHUNK_COMPLETE;
      size_t trailer_end = buf.find("\r\n\r\n", pos);
      return trailer_end == std::string::npos ? CHUNK_INCOMPLETE : CHUNK_COMPLETE;
    }
    total_body += size;
    if (total_body > MAX_RESPONSE_BYTES) return CHUNK_INVALID;
    if (buf.size() < pos + size + 2) return CHUNK_INCOMPLETE;   /* need data + trailing CRLF */
    if (buf.compare(pos + size, 2, "\r\n") != 0) return CHUNK_INVALID;
    pos += size + 2;
  }
}

/* Whether the response is still incomplete, complete, or unparsable. */
enum ResponseResult { RESP_MORE = 0, RESP_COMPLETE = 1, RESP_INVALID = 2 };

/*
 * Decide whether the response in c->response is finished.
 *  - First time here: locate "\r\n\r\n", enforce MAX_HEADER_BYTES, parse the
 *    status line and framing headers, and reject an invalid Content-Length.
 *  - 1xx / 204 / 304 carry no body: complete as soon as headers are parsed.
 *  - chunked: defer to chunked_complete().
 *  - Content-Length: complete once that many body bytes have arrived.
 *  - No framing at all: trust the status but mark the socket non-reusable,
 *    because there is no way to know where the body ends.
 */
static ResponseResult response_complete(Connection *c) {
  if (!c->header_end) {
    size_t p = c->response.find("\r\n\r\n");
    if (p == std::string::npos) {
      if (c->response.size() > MAX_HEADER_BYTES) return RESP_INVALID;
      return RESP_MORE;
    }
    c->header_end = p + 4;
    if (!parse_status_line(c->response.substr(0, c->header_end), &c->http_status)) return RESP_INVALID;
    parse_response_headers(c);
    if (c->content_length == -2) return RESP_INVALID;
  }

  if ((c->http_status >= 100 && c->http_status < 200) || c->http_status == 204 || c->http_status == 304) return RESP_COMPLETE;   /* bodyless statuses */
  if (c->chunked) {
    ChunkResult cr = chunked_complete(c->response, c->header_end);
    if (cr == CHUNK_INVALID) return RESP_INVALID;
    return cr == CHUNK_COMPLETE ? RESP_COMPLETE : RESP_MORE;
  }
  if (c->content_length >= 0) {
    size_t body_have = c->response.size() - c->header_end;
    return body_have >= (size_t)c->content_length ? RESP_COMPLETE : RESP_MORE;
  }

  /* No response framing: status is usable, but connection cannot be safely reused. */
  c->close_after_response = true;
  return RESP_COMPLETE;
}

/*
 * Terminal handling for a fully parsed response:
 *  - 2xx: count success, free the batch, keep the socket for the next batch
 *    unless the server asked to close.
 *  - transient (408/429/5xx): schedule_retry(), bounded by MAX_RETRY_AGE_SEC.
 *  - anything else (4xx etc.): a permanent rejection -- count and drop the batch
 *    immediately and close the socket, since retrying will not help.
 * The slot always ends in CS_IDLE.
 */
static void finish_response(Connection *c) {
  if (!c || !c->batch) return;
  int status = c->http_status;
  bool keep = !c->close_after_response;

  if (status >= 200 && status < 300) {
    record_success(c->batch, status);
    delete c->batch;
    c->batch = NULL;
    c->request.clear(); c->send_off = 0; reset_response(c);
    if (!keep) close_fd(c);
    c->state = CS_IDLE;
  } else if (transient_status(status)) {
    schedule_retry(c, status);
  } else {
    record_attempt_failure(status);
    record_final_drop(c->batch, status);
    delete c->batch;
    c->batch = NULL;
    c->request.clear(); c->send_off = 0; reset_response(c);
    close_fd(c);
    c->state = CS_IDLE;
  }
}

// pace_upload token bucket limiter implements --limit-rate upload pacing
/*
 * Token bucket implementing --ship-rate-kbps upload pacing. rate is in
 * application-payload bytes per second (kbit/s * 1000 / 8); capacity is one
 * second of credit (with a 4096-byte floor) so an idle limiter may burst a
 * little while a sustained sender converges to the configured average. A single
 * bucket is shared by ALL in-flight sockets, which is what makes the ceiling an
 * aggregate (not per-connection) limit.
 */
struct TokenBucket {
  double rate;   /* refill rate, bytes/second */
  double capacity;   /* burst ceiling, bytes (one second of credit, >= 4096) */
  double tokens;   /* currently available bytes */
  double last;   /* wall time of the last refill */
  TokenBucket() : rate(1.0), capacity(1.0), tokens(1.0), last(0.0) {}
};

/* Seed the bucket from the configured rate; a full bucket allows an immediate
 * initial burst rather than throttling the very first bytes. */
static void limiter_init(TokenBucket *tb) {
  tb->rate = (double)g_ship_rate_kbps * 1000.0 / 8.0;
  if (tb->rate < 1.0) tb->rate = 1.0;
  tb->capacity = tb->rate;
  if (tb->capacity < 4096.0) tb->capacity = 4096.0;
  tb->tokens = tb->capacity;
  tb->last = wall_seconds();
}

/* Add tokens for the elapsed time and cap at capacity. A backwards clock step
 * (now < last) just re-bases 'last' instead of creating negative credit. */
static void limiter_refill(TokenBucket *tb, double now) {
  if (now < tb->last) { tb->last = now; return; }
  tb->tokens += (now - tb->last) * tb->rate;
  if (tb->tokens > tb->capacity) tb->tokens = tb->capacity;
  tb->last = now;
}

/*
 * How many bytes may be written right now: floor(tokens), additionally capped at
 * the caller's remaining bytes and at 16384 so one send() never drains a whole
 * second of credit in a single syscall (keeps the shaper smooth).
 */
static size_t limiter_allow(TokenBucket *tb, size_t remaining) {
  limiter_refill(tb, wall_seconds());
  size_t available = tb->tokens >= 1.0 ? (size_t)tb->tokens : 0;
  if (!available) return 0;
  size_t cap = remaining < 16384U ? remaining : 16384U;
  return available < cap ? available : cap;
}

/* Charge n bytes against the bucket (clamped at zero). */
static void limiter_consume(TokenBucket *tb, size_t n) {
  tb->tokens -= (double)n;
  if (tb->tokens < 0.0) tb->tokens = 0.0;
}

/*
 * Milliseconds until at least one token (one byte) is available; 1..100 ms. Used
 * as a poll() timeout so the uploader wakes as soon as the limiter refills
 * instead of spinning.
 */
static int limiter_wait_ms(TokenBucket *tb) {
  limiter_refill(tb, wall_seconds());
  if (tb->tokens >= 1.0) return 0;
  double sec = (1.0 - tb->tokens) / tb->rate;
  int ms = (int)(sec * 1000.0) + 1;
  if (ms < 1) ms = 1;
  if (ms > 100) ms = 100;
  return ms;
}

/*
 * Finish an EINPROGRESS connect. SO_ERROR reports the real connect() result --
 * poll() success alone only means the attempt finished, not that it succeeded.
 * On success move to CS_SENDING and arm the send deadline.
 */
static bool complete_connect(Connection *c) {
  int err = 0; socklen_t len = sizeof(err);
  if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0) return false;
  c->state = CS_SENDING;
  c->deadline = wall_seconds() + (double)attempt_timeout_ms(c->request.size()) / 1000.0;
  return true;
}

/*
 * Push as many request bytes as the limiter currently allows. A partial write
 * just advances send_off; poll() will fire again. When every byte is written,
 * switch to CS_READING and wipe any stale response. EAGAIN/EINTR are retried;
 * any other error is a transport failure and goes through schedule_retry().
 */
static void handle_send(Connection *c, TokenBucket *tb) {
  if (!c || c->fd < 0 || c->state != CS_SENDING) return;
  if (c->send_off >= c->request.size()) { c->state = CS_READING; reset_response(c); return; }
  size_t allowed = limiter_allow(tb, c->request.size() - c->send_off);
  if (!allowed) return;
  ssize_t n = send(c->fd, c->request.data() + c->send_off, allowed, 0);
  if (n > 0) {
    c->send_off += (size_t)n;
    limiter_consume(tb, (size_t)n);
    if (c->send_off == c->request.size()) { c->state = CS_READING; reset_response(c); }
    return;
  }
  if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
  schedule_retry(c, 0);
}

/*
 * Drain available response bytes (up to 8 KiB per recv) and re-evaluate
 * completeness after each chunk. The accumulated response is capped at
 * MAX_RESPONSE_BYTES + MAX_HEADER_BYTES. A clean EOF completes an unframed
 * response; any other EOF is a failure. EAGAIN returns to poll(), EINTR retries,
 * and other errors go through schedule_retry().
 */
static void handle_read(Connection *c) {
  if (!c || c->fd < 0 || c->state != CS_READING) return;
  char buf[8192];
  while (true) {
    ssize_t n = recv(c->fd, buf, sizeof(buf), 0);
    if (n > 0) {
      if (c->response.size() + (size_t)n > MAX_RESPONSE_BYTES + MAX_HEADER_BYTES) { schedule_retry(c, 0); return; }   /* hard cap */
      c->response.append(buf, (size_t)n);
      ResponseResult rr = response_complete(c);
      if (rr == RESP_COMPLETE) { finish_response(c); return; }
      if (rr == RESP_INVALID) { schedule_retry(c, 0); return; }
      continue;
    }
    if (n == 0) {
      /* If headers were fully parsed and no framing existed, EOF completes it. */
      if (c->header_end && c->content_length < 0 && !c->chunked && c->http_status > 0) {
        c->close_after_response = true;
        finish_response(c);
      } else {
        schedule_retry(c, 0);
      }
      return;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) return;
    if (errno == EINTR) continue;
    schedule_retry(c, 0);
    return;
  }
}

/*
 * Synchronous connect helper used only by the stats path (1000 ms budget). It
 * uses the same nonblocking socket + poll(POLLOUT) + SO_ERROR pattern; the fd
 * stays O_NONBLOCK, and the helpers below account for that via poll().
 */
static bool connect_blocking(const Endpoint &ep, unsigned timeout_ms, int *out_fd) {
  if (out_fd) *out_fd = -1;
  bool connected = false;
  int fd = open_nonblocking_socket(ep, &connected);
  if (fd < 0) return false;
  if (!connected) {
    struct pollfd pfd; pfd.fd = fd; pfd.events = POLLOUT; pfd.revents = 0;
    int rc;
    do { rc = poll(&pfd, 1, (int)timeout_ms); } while (rc < 0 && errno == EINTR);
    if (rc <= 0) { close(fd); return false; }
    int err = 0; socklen_t len = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0) { close(fd); return false; }
  }
  if (out_fd) *out_fd = fd; else close(fd);
  return true;
}

/*
 * Send the whole string with a wall-clock deadline. "blockingish" because the fd
 * stays O_NONBLOCK but we poll(POLLOUT) before each send() and loop until the
 * deadline or completion. Used only for the small stats POST.
 */
static bool send_all_blockingish(int fd, const std::string &s, unsigned timeout_ms) {
  size_t off = 0;
  double deadline = wall_seconds() + (double)timeout_ms / 1000.0;
  while (off < s.size()) {
    int left = (int)((deadline - wall_seconds()) * 1000.0);
    if (left <= 0) return false;
    struct pollfd pfd; pfd.fd = fd; pfd.events = POLLOUT; pfd.revents = 0;
    int rc = poll(&pfd, 1, left);
    if (rc < 0 && errno == EINTR) continue;
    if (rc <= 0) return false;
    ssize_t n = send(fd, s.data() + off, s.size() - off, 0);
    if (n > 0) { off += (size_t)n; continue; }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) continue;
    return false;
  }
  return true;
}

/*
 * Read response header bytes until "\r\n\r\n" (or the deadline / header cap) and
 * return the parsed status code, or 0 on timeout/malformed input. The stats path
 * does not need the body, so it stops at the end of the headers.
 */
static int read_status_blockingish(int fd, unsigned timeout_ms) {
  std::string buf;
  double deadline = wall_seconds() + (double)timeout_ms / 1000.0;
  while (buf.find("\r\n\r\n") == std::string::npos) {
    if (buf.size() > MAX_HEADER_BYTES) return 0;
    int left = (int)((deadline - wall_seconds()) * 1000.0);
    if (left <= 0) return 0;
    struct pollfd pfd; pfd.fd = fd; pfd.events = POLLIN; pfd.revents = 0;
    int rc = poll(&pfd, 1, left);
    if (rc < 0 && errno == EINTR) continue;
    if (rc <= 0) return 0;
    char tmp[2048]; ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
    if (n <= 0) return 0;
    buf.append(tmp, (size_t)n);
  }
  int status = 0;
  return parse_status_line(buf, &status) ? status : 0;
}

/*
 * Fire-and-forget POST /api/agent/stats with "Connection: close". Bounded to
 * 1000 ms connect plus 1000 ms send/receive and a 16 KiB body; returns the HTTP
 * status or 0. Deliberately synchronous and off the event path, so a slow stats
 * call can only delay stats -- never event shipping.
 */
static int post_stats_once(const std::string &body) {
  if (body.size() > MAX_STATS_BYTES) return 0;
  int fd = -1;
  if (!connect_blocking(g_ep, 1000, &fd)) return 0;
  std::ostringstream o;
  o << "POST " << endpoint_path("/api/agent/stats") << " HTTP/1.1\r\n"
    << "Host: " << g_ep.host_header << "\r\n"
    << "User-Agent: nt-ship-cpp-posix/1\r\n"
    << "Content-Type: application/json\r\n"
    << "Content-Length: " << body.size() << "\r\n"
    << "Connection: close\r\n\r\n";
  std::string req = o.str(); req += body;
  int status = 0;
  if (send_all_blockingish(fd, req, 1000)) status = read_status_blockingish(fd, 1000);
  close(fd);
  return status;
}

/*
 * Build the coalesced /api/agent/stats JSON. Two ideas dominate:
 *  (1) COALESCING: all counters are sampled once under g_lock and every field is
 *      emitted both as a lifetime *_total and as a *_delta since the previous
 *      sample; the *_prev_* baselines are then advanced, so consecutive samples
 *      never overlap and a missed/ dropped sample does not lose counts.
 *  (2) BOUNDING: the payload embeds the passed-in capture object VERBATIM and is
 *      otherwise flat and fixed-shape -- no per-event or per-user data -- so it
 *      stays far under MAX_STATS_BYTES and never leaks identities or payloads.
 * 'reasons' is a compact cause list (kernel_drop / ship_drop / hub_unreachable /
 * queue_pressure) that flips status to "degraded" whenever any counter moved.
 * Process resources (CPU%, RSS, fds, threads) and the effective limits are also
 * echoed. Called ONLY from the uploader thread.
 */
static std::string shipping_stats_body(const std::string &capture, unsigned inflight, unsigned retry_waiting) {
  double now_wall = wall_seconds(), elapsed = now_wall - g_last_stats_at;
  if (elapsed < 0.001) elapsed = 0.001;
  unsigned long long now = (unsigned long long)now_wall;
  unsigned long long in, posted, dropped, qhw, qbyteshw, qdepth, qbytes, seq;
  unsigned long long bytes_posted, queue_drops, hub_drops, oversized, batches, batches_failed, stats_drops;
  unsigned long long req_started, req_ok, req_failed, req_retried, reconnects;
  unsigned failures, status; time_t success;

  pthread_mutex_lock(&g_lock);
  /* Consistent snapshot of every shared counter, taken in one critical section. */
  in = g_input_total; posted = g_posted_total; dropped = g_dropped_total;
  qhw = g_queue_high_water; qbyteshw = g_queue_bytes_high_water;
  qdepth = g_queue.size(); qbytes = g_queue_bytes;
  bytes_posted = g_bytes_posted_total; queue_drops = g_queue_drops_total;
  hub_drops = g_hub_drops_total; oversized = g_oversized_total;
  batches = g_batches_total; batches_failed = g_batches_failed_total; stats_drops = g_stats_drops_total;
  req_started = g_requests_started_total; req_ok = g_requests_success_total;
  req_failed = g_requests_failed_total; req_retried = g_requests_retried_total; reconnects = g_reconnects_total;
  failures = g_consecutive_failures; status = (unsigned)g_last_http_status;
  success = g_last_success_epoch; seq = ++g_sequence;

  /* Window deltas; unsigned wrap is harmless because the counters are monotonic. */
  unsigned long long in_delta = in - g_prev_input, post_delta = posted - g_prev_posted;
  unsigned long long drop_delta = dropped - g_prev_dropped;
  unsigned long long bytes_delta = bytes_posted - g_prev_bytes_posted;
  unsigned long long queue_delta = queue_drops - g_prev_queue_drops;
  unsigned long long hub_delta = hub_drops - g_prev_hub_drops;
  unsigned long long oversized_delta = oversized - g_prev_oversized;
  unsigned long long batches_delta = batches - g_prev_batches_total;
  unsigned long long batches_failed_delta = batches_failed - g_prev_batches_failed;
  g_prev_input = in; g_prev_posted = posted; g_prev_dropped = dropped;
  g_prev_bytes_posted = bytes_posted; g_prev_queue_drops = queue_drops;
  g_prev_hub_drops = hub_drops; g_prev_oversized = oversized;
  g_prev_batches_total = batches; g_prev_batches_failed = batches_failed;
  pthread_mutex_unlock(&g_lock);

  struct rusage usage; memset(&usage, 0, sizeof(usage)); getrusage(RUSAGE_SELF, &usage);
  double cpu = usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1000000.0 +
               usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1000000.0;
  double cpu_pct = 100.0 * (cpu - g_last_stats_cpu) / elapsed; if (cpu_pct < 0) cpu_pct = 0;
  unsigned long long rss = 0, virt = 0; process_memory(&rss, &virt);

  std::string reasons;
  /* Derive the degraded "reasons" list from both capture-side and ship-side deltas. */
  if (json_uint(capture, "kernel_drops_delta")) reasons += "\"kernel_drop\"";
  if (drop_delta) { if (!reasons.empty()) reasons += ','; reasons += "\"ship_drop\""; }
  if (hub_delta) { if (!reasons.empty()) reasons += ','; reasons += "\"hub_unreachable\""; }
  if (queue_delta || json_uint(capture, "output_pipe_drops_delta")) { if (!reasons.empty()) reasons += ','; reasons += "\"queue_pressure\""; }

  /* batches_pushed = created minus failed; clamped so a transient inconsistency
   * can never underflow an unsigned value. */
  unsigned long long batches_pushed = batches >= batches_failed ? batches - batches_failed : 0;
  unsigned long long batches_pushed_delta = batches_delta >= batches_failed_delta ? batches_delta - batches_failed_delta : 0;

  std::ostringstream o;
  o << "{\"schema_version\":1,\"node\":" << jsonq(g_node)
    << ",\"type\":\"agent_stats\",\"instance_id\":" << jsonq(g_instance_id)
    << ",\"sequence\":" << seq << ",\"observed_at\":" << now
    << ",\"window_seconds\":" << elapsed
    << ",\"mode\":\"cpp\",\"status\":" << (reasons.empty() ? "\"ok\"" : "\"degraded\"")
    << ",\"reasons\":[" << reasons << "],\"capture\":" << capture
    << ",\"shipping\":{\"events_in_total\":" << in
    << ",\"events_in_delta\":" << in_delta
    << ",\"events_pushed_total\":" << posted
    << ",\"events_pushed_delta\":" << post_delta
    << ",\"events_dropped_total\":" << dropped
    << ",\"events_dropped_delta\":" << drop_delta
    << ",\"drop_causes\":{\"queue_full_total\":" << queue_drops << ",\"queue_full_delta\":" << queue_delta
    << ",\"hub_failure_total\":" << hub_drops << ",\"hub_failure_delta\":" << hub_delta
    << ",\"oversized_total\":" << oversized << ",\"oversized_delta\":" << oversized_delta << "}"
    << ",\"batches_created_total\":" << batches << ",\"batches_created_delta\":" << batches_delta
    << ",\"batches_failed_total\":" << batches_failed << ",\"batches_failed_delta\":" << batches_failed_delta
    << ",\"batches_pushed_total\":" << batches_pushed << ",\"batches_pushed_delta\":" << batches_pushed_delta
    << ",\"requests_started_total\":" << req_started
    << ",\"requests_success_total\":" << req_ok
    << ",\"requests_failed_total\":" << req_failed
    << ",\"requests_retried_total\":" << req_retried
    << ",\"tcp_connects_total\":" << reconnects
    << ",\"bytes_pushed_total\":" << bytes_posted << ",\"bytes_pushed_delta\":" << bytes_delta
    << ",\"push_events_per_second\":" << ((double)post_delta / elapsed)
    << ",\"push_kbps\":" << (8.0 * bytes_delta / (1000.0 * elapsed))
    << ",\"drop_events_per_second\":" << ((double)drop_delta / elapsed)
    << ",\"drop_percent\":" << (100.0 * drop_delta / (in_delta ? in_delta : 1))
    << ",\"queue_depth_events\":" << qdepth << ",\"queue_high_water_events\":" << qhw
    << ",\"queue_capacity_events\":" << MAX_QUEUE_EVENTS
    << ",\"queue_depth_bytes\":" << qbytes << ",\"queue_high_water_bytes\":" << qbyteshw
    << ",\"queue_capacity_bytes\":" << MAX_QUEUE_BYTES
    << ",\"inflight_requests\":" << inflight << ",\"retry_waiting\":" << retry_waiting
    << ",\"consecutive_failures\":" << failures
    << ",\"last_push_http_status\":" << status
    << ",\"last_success_at\":" << (unsigned long long)success
    << ",\"stats_samples_dropped_total\":" << stats_drops
    << "},\"resources\":{\"cpu_user_seconds\":" << (usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1000000.0)
    << ",\"cpu_system_seconds\":" << (usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1000000.0)
    << ",\"cpu_percent_one_core\":" << cpu_pct << ",\"rss_bytes\":" << rss
    << ",\"virtual_bytes\":" << virt << ",\"open_fds\":" << open_fd_count() << ",\"threads\":" << thread_count()
    << "},\"limits\":{\"cpu_core\":" << (unsigned)atoi(allowed_cpu().c_str()) << ",\"address_space_bytes\":268435456"
    << ",\"ship_rate_kbps\":" << g_ship_rate_kbps << ",\"http_body_max_bytes\":" << MAX_POST_BYTES
    << ",\"ship_threads_max\":1,\"max_inflight\":" << g_max_inflight
    << ",\"compression\":\"none\""
    << ",\"wsse_body_bytes\":" << json_uint(capture, "wsse_body_bytes")
    << "}}";
  g_last_stats_at = now_wall; g_last_stats_cpu = cpu;   /* advance baselines after a successful build */
  return o.str();
}

/* Pool occupancy: slots holding a batch and not merely parked in backoff. */
static unsigned count_inflight(const std::vector<Connection> &conns) {
  unsigned n = 0;
  for (size_t i = 0; i < conns.size(); ++i) {
    if (conns[i].batch && conns[i].state != CS_RETRY_WAIT) ++n;
  }
  return n;
}

/* Slots currently parked in backoff (stats "retry_waiting" gauge). */
static unsigned count_retry_wait(const std::vector<Connection> &conns) {
  unsigned n = 0;
  for (size_t i = 0; i < conns.size(); ++i) if (conns[i].state == CS_RETRY_WAIT) ++n;
  return n;
}

/*
 * Send agent stats at most once per second, and only when the capture side has
 * produced a NEW capture_stats object since the last attempt (generation compare
 * under g_lock). On failure g_stats_drops_total is bumped and the generation is
 * left un-acknowledged, so the next attempt re-sends it. Stats use a fresh
 * short-lived connection (post_stats_once) so they can never corrupt a
 * keep-alive event socket.
 */
static void maybe_send_stats(const std::vector<Connection> &conns, double *last_attempt) {
  if (!last_attempt || wall_seconds() - *last_attempt < 1.0) return;
  std::string capture; unsigned long long gen = 0;
  pthread_mutex_lock(&g_lock);
  if (g_capture_generation != g_stats_generation_sent) { capture = g_capture_json; gen = g_capture_generation; }
  pthread_mutex_unlock(&g_lock);
  if (capture.empty()) return;

  *last_attempt = wall_seconds();
  std::string body = shipping_stats_body(capture, count_inflight(conns), count_retry_wait(conns));
  int status = post_stats_once(body);
  pthread_mutex_lock(&g_lock);
  g_stats_generation_sent = gen;
  if (status < 200 || status >= 300) ++g_stats_drops_total;
  pthread_mutex_unlock(&g_lock);
}

/*
 * Last-resort shutdown drain (after SHUTDOWN_GRACE_SEC): free every in-flight
 * batch as dropped, close every socket, and clear the queue while counting each
 * queued event as a queue drop. Guarantees a bounded, prompt exit with no disk
 * I/O and no lingering work.
 */
static void drop_everything(std::vector<Connection> *conns) {
  if (conns) {
    for (size_t i = 0; i < conns->size(); ++i) {
      Connection &c = (*conns)[i];
      close_fd(&c);
      if (c.batch) {
        record_final_drop(c.batch, c.http_status);
        delete c.batch; c.batch = NULL;
      }
      c.state = CS_IDLE;
    }
  }
  pthread_mutex_lock(&g_lock);
  if (!g_queue.empty()) {
    g_dropped_total += g_queue.size();
    g_queue_drops_total += g_queue.size();
    g_queue.clear(); g_queue_bytes = 0; g_queue_first_at = 0.0;
  }
  pthread_mutex_unlock(&g_lock);
}

/*
 * Uploader thread: the entire network side of the process.
 *  - Owns every Connection (and therefore every socket and Batch pointer); the
 *    main thread never touches a socket.
 *  - Each iteration: start due retries, fill idle slots from the queue, send
 *    stats if due, time out stalled operations, then poll() all live sockets with
 *    a timeout that is the minimum of 100 ms, the limiter refill time, the
 *    earliest retry time and the earliest operation deadline.
 *  - With no sockets to poll it sleeps on g_cond (bounded timedwait) so new stdin
 *    data can wake it instantly instead of it spinning.
 *  - fair-share rotation (fairness_start) rotates the polling order each pass so
 *    no single slot can starve the others.
 *  - Exits only when input is done AND the queue is empty AND no batch is in
 *    flight, or when the shutdown grace expires (then drop_everything).
 */
static void *uploader_main(void *arg) {
  (void)arg;
  std::vector<Connection> conns(g_max_inflight);   /* fixed-size, bounded socket pool */
  TokenBucket limiter; limiter_init(&limiter);
  double shutdown_deadline = 0.0;
  double last_stats_attempt = 0.0;
  size_t fairness_start = 0;

  while (true) {
    bool done;
    pthread_mutex_lock(&g_lock); done = g_input_done || !g_running; pthread_mutex_unlock(&g_lock);
    if (done && shutdown_deadline <= 0.0) shutdown_deadline = wall_seconds() + SHUTDOWN_GRACE_SEC;   /* arm the drain grace once */
    bool shutting_down = shutdown_deadline > 0.0;
    if (shutting_down && wall_seconds() >= shutdown_deadline) { drop_everything(&conns); break; }

    /* Start due retries. */
    for (size_t i = 0; i < conns.size(); ++i) {
      Connection &c = conns[i];
      if (c.state == CS_RETRY_WAIT && c.batch && wall_seconds() >= c.batch->next_attempt_at) start_attempt(&c);   /* due backoff */
    }

    /* Fill idle slots from the capture queue. */
    for (size_t i = 0; i < conns.size(); ++i) {
      Connection &c = conns[i];
      if (c.state == CS_IDLE && !c.batch && queue_ready_to_flush(shutting_down)) {
        Batch *b = build_event_batch();   /* may return NULL (nothing ready / drain-only) */
        if (b) assign_batch(&c, b);
      }
    }

    maybe_send_stats(conns, &last_stats_attempt);   /* self-throttled to <=1/s */

    /* Timeout active operations. */
    double now = wall_seconds();
    for (size_t i = 0; i < conns.size(); ++i) {
      Connection &c = conns[i];
      if ((c.state == CS_CONNECTING || c.state == CS_SENDING || c.state == CS_READING) && c.deadline > 0.0 && now >= c.deadline) {
        schedule_retry(&c, 0);
      }
    }

    pthread_mutex_lock(&g_lock); bool queue_empty = g_queue.empty(); done = g_input_done || !g_running; pthread_mutex_unlock(&g_lock);
    bool any_batch = false;
    for (size_t i = 0; i < conns.size(); ++i) if (conns[i].batch) { any_batch = true; break; }
    if (done && queue_empty && !any_batch) break;

    std::vector<struct pollfd> pfds;
    std::vector<size_t> pindex;
    pfds.reserve(conns.size()); pindex.reserve(conns.size());
    limiter_refill(&limiter, wall_seconds());

    for (size_t step = 0; step < conns.size(); ++step) {
      size_t i = (fairness_start + step) % conns.size();   /* rotated start = fair sharing */
      Connection &c = conns[i];
      short ev = 0;
      if (c.fd >= 0) {
        if (c.state == CS_CONNECTING) ev = POLLOUT;
        else if (c.state == CS_SENDING && limiter.tokens >= 1.0) ev = POLLOUT;   /* only ask to write when we have credit */
        else if (c.state == CS_READING) ev = POLLIN;
      }
      if (ev) {
        struct pollfd p; p.fd = c.fd; p.events = ev; p.revents = 0;
        pfds.push_back(p); pindex.push_back(i);
      }
    }
    fairness_start = conns.empty() ? 0 : (fairness_start + 1) % conns.size();   /* advance the rotation */

    int timeout_ms = 100;
    int lw = limiter_wait_ms(&limiter); if (lw > 0 && lw < timeout_ms) timeout_ms = lw;   /* wake when the bucket refills */
    double earliest = wall_seconds() + (double)timeout_ms / 1000.0;
    for (size_t i = 0; i < conns.size(); ++i) {
      Connection &c = conns[i];
      if (c.state == CS_RETRY_WAIT && c.batch && c.batch->next_attempt_at < earliest) earliest = c.batch->next_attempt_at;   /* next retry */
      if ((c.state == CS_CONNECTING || c.state == CS_SENDING || c.state == CS_READING) && c.deadline > 0.0 && c.deadline < earliest) earliest = c.deadline;
    }
    int until = (int)((earliest - wall_seconds()) * 1000.0);
    if (until < 0) until = 0;
    if (until < timeout_ms) timeout_ms = until;

    int rc;
    if (!pfds.empty()) {
      do { rc = poll(&pfds[0], pfds.size(), timeout_ms); } while (rc < 0 && errno == EINTR && g_running);
    } else {
      pthread_mutex_lock(&g_lock);
      if (!g_input_done && g_running) {
        struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += (long)timeout_ms * 1000000L;
        while (ts.tv_nsec >= 1000000000L) { ++ts.tv_sec; ts.tv_nsec -= 1000000000L; }
        pthread_cond_timedwait(&g_cond, &g_lock, &ts);   /* idle: wake early on new input */
      }
      pthread_mutex_unlock(&g_lock);
      rc = 0;
    }

    if (rc > 0) {
      for (size_t j = 0; j < pfds.size(); ++j) {
        if (!pfds[j].revents) continue;
        Connection &c = conns[pindex[j]];
        short re = pfds[j].revents;
        if (re & (POLLERR | POLLNVAL)) { schedule_retry(&c, 0); continue; }   /* socket is dead */
        if (c.state == CS_CONNECTING && (re & (POLLOUT | POLLHUP))) {
          if (!complete_connect(&c)) { schedule_retry(&c, 0); continue; }
        }
        if (c.state == CS_SENDING && (re & POLLHUP)) {   /* peer closed mid-send */
          schedule_retry(&c, 0);
          continue;
        }
        if (c.state == CS_SENDING && (re & POLLOUT)) handle_send(&c, &limiter);
        if (c.state == CS_READING && (re & (POLLIN | POLLHUP))) handle_read(&c);
      }
    }
  }

  for (size_t i = 0; i < conns.size(); ++i) close_fd(&conns[i]);
  return NULL;
}

/*
 * main: parse configuration (environment first, then argv), validate the hard
 * limits, install signal handling, then run as the stdin reader. The uploader
 * thread is created BEFORE the read loop so events are drained while we block on
 * stdin.
 * Exit codes: 0 = clean stop on signal, 2 = usage/config error, 70 = unsafe
 * startup (rlimits/thread creation), 74 = stdin closed while still running
 * (a hint to the supervisor to restart the whole pipeline).
 */
int main(int argc, char **argv) {
  bool stats_fixture = false;   /* --stats-fixture: print one synthetic stats body and exit */
  const char *rate_env = getenv("NT_SHIP_RATE_KBPS");
  const char *stats_env = getenv("NT_STATS_INTERVAL_SEC");
  const char *inflight_env = getenv("NT_MAX_INFLIGHT");
  if (rate_env && *rate_env) g_ship_rate_kbps = (unsigned)atoi(rate_env);   /* env defaults, overridden by argv below */
  if (stats_env && *stats_env) g_stats_interval_sec = (unsigned)atoi(stats_env);
  if (inflight_env && *inflight_env) g_max_inflight = (unsigned)atoi(inflight_env);

  /* CLI parsing: every option except --stats-fixture/-h takes a value. */
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--endpoint" && i + 1 < argc) g_endpoint = argv[++i];
    else if (a == "--ship-rate-kbps" && i + 1 < argc) g_ship_rate_kbps = (unsigned)atoi(argv[++i]);
    else if (a == "--stats-interval-sec" && i + 1 < argc) g_stats_interval_sec = (unsigned)atoi(argv[++i]);
    else if (a == "--max-inflight" && i + 1 < argc) g_max_inflight = (unsigned)atoi(argv[++i]);
    else if (a == "--spool" && i + 1 < argc) ++i; /* accepted for CLI compatibility; still intentionally unused */
    else if (a == "--stats-fixture") stats_fixture = true;
    else if (a == "-h" || a == "--help") {
      std::cout << "usage: nt-ship-cpp --endpoint http://HOST[:PORT][/base] [--ship-rate-kbps 64..10000] [--stats-interval-sec 10..3600] [--max-inflight 1..4]\n";
      return 0;
    } else { std::cerr << "unknown arg: " << a << "\n"; return 2; }
  }

  /* Enforce the validated operating envelope before doing anything else. */
  if (g_ship_rate_kbps < 64 || g_ship_rate_kbps > 10000) { std::cerr << "ship rate must be in range 64..10000 kbit/s\n"; return 2; }
  if (g_stats_interval_sec < 10 || g_stats_interval_sec > 3600) { std::cerr << "stats interval must be in range 10..3600 seconds\n"; return 2; }
  if (g_max_inflight < 1 || g_max_inflight > MAX_INFLIGHT_LIMIT) { std::cerr << "max inflight must be in range 1..4\n"; return 2; }

  /* Graceful stop on TERM/INT; SIGPIPE is ignored so a Hub closing a keep-alive
   * socket surfaces as an EPIPE send error instead of killing the process. */
  signal(SIGTERM, stop_signal); signal(SIGINT, stop_signal); signal(SIGPIPE, SIG_IGN);
  /* Node identity: NT_NODE_NAME if set, else the hostname (always NUL-terminated). */
  char host[256]; gethostname(host, sizeof(host)); host[sizeof(host) - 1] = 0;
  const char *node_env = getenv("NT_NODE_NAME"); g_node = (node_env && *node_env) ? node_env : host;
  g_started_epoch = time(NULL); g_instance_id = ulls((unsigned long long)g_started_epoch) + "-" + ulls((unsigned long long)getpid());
  g_last_stats_at = wall_seconds();

  /* Test hook: emit one deterministic stats sample to stdout and exit, so the
   * stats contract can be validated without a Hub or any real traffic. */
  if (stats_fixture) {
    g_last_stats_at -= 30.0; g_input_total = 10; g_posted_total = 8;
    g_dropped_total = g_queue_drops_total = 2; g_bytes_posted_total = 6400;
    std::cout << shipping_stats_body("{\"packets_total\":100,\"packets_delta\":100,\"kernel_drops_total\":0,\"kernel_drops_delta\":0,\"output_pipe_drops_delta\":0,\"wsse_body_bytes\":8192}", 0, 0) << "\n";
    return 0;
  }

  /* The endpoint is required unless we are in stats-fixture mode. */
  if (g_endpoint.empty()) { std::cerr << "--endpoint required\n"; return 2; }
  std::string endpoint_error;
  if (!parse_endpoint(g_endpoint, &g_ep, &endpoint_error)) { std::cerr << endpoint_error << "\n"; return 2; }

#ifndef NT_HAS_ASAN
/*
 * Fail-closed address-space clamp. This mirrors the outer nt-resource-guard.sh
 * 256 MiB ceiling (it cannot be raised above the inherited hard limit) and aborts
 * startup if the kernel refuses, so the process can never run unbounded.
 */
  struct rlimit lim;
  if (getrlimit(RLIMIT_AS, &lim) == 0) {
    rlim_t target = (rlim_t)256U * 1024U * 1024U;
    if (lim.rlim_max != RLIM_INFINITY && lim.rlim_max < target) target = lim.rlim_max;
    lim.rlim_cur = target;
    if (setrlimit(RLIMIT_AS, &lim) != 0) { perror("setrlimit(RLIMIT_AS)"); return 70; }
  } else {
    lim.rlim_cur = (rlim_t)256U * 1024U * 1024U;
    lim.rlim_max = (rlim_t)256U * 1024U * 1024U;
    if (setrlimit(RLIMIT_AS, &lim) != 0) { perror("setrlimit(RLIMIT_AS)"); return 70; }
  }
#endif

  /* The uploader runs on an explicit 512 KiB stack: small enough to fit the
   * memory budget, large enough for the fixed 8 KiB read buffer and libc calls.
   * Failure to set it is fatal (refuse to start) rather than silently unbounded. */
  pthread_attr_t attr;
  if (pthread_attr_init(&attr) != 0) { logmsg("cannot initialize uploader limits; refusing unsafe startup"); return 70; }
  if (pthread_attr_setstacksize(&attr, 512U * 1024U) != 0) {
    pthread_attr_destroy(&attr); logmsg("cannot enforce 512 KiB uploader stack; refusing unsafe startup"); return 70;
  }
  pthread_t uploader;
  if (pthread_create(&uploader, &attr, uploader_main, NULL) != 0) {
    pthread_attr_destroy(&attr); logmsg("failed to start bounded uploader thread"); return 70;
  }
  pthread_attr_destroy(&attr);

  /* --- stdin reader: the only place events enter the process. --- */
  std::string line;
  while (g_running) {
    fd_set r; FD_ZERO(&r); FD_SET(0, &r);
    struct timeval tv; tv.tv_sec = 1; tv.tv_usec = 0;
    /* 1-second select() on stdin keeps us responsive to g_running changes
     * (signals) even when no input is arriving; select is used rather than a
     * blocking getline so the timeout is possible. */
    int rc = select(1, &r, NULL, NULL, &tv);
    if (rc < 0) { if (errno == EINTR) continue; logmsg("stdin select failed"); break; }
    if (rc == 0) continue;   /* timeout: loop and re-check g_running */
    if (!std::getline(std::cin, line)) break;   /* EOF: fall through to drain+join */
    if (line.empty()) continue;   /* ignore blank separator lines */

    /* Capture-stats envelopes are consumed here, OUTSIDE the event stream. */
    std::string capture;
    if (parse_capture_stats(line, &capture)) {
      pthread_mutex_lock(&g_lock); g_capture_json = capture; ++g_capture_generation; pthread_cond_signal(&g_cond); pthread_mutex_unlock(&g_lock);
      continue;
    }

    pthread_mutex_lock(&g_lock);
    ++g_input_total;   /* every non-stats line counts as one input event */
    if (line.size() > MAX_INPUT_LINE) {
      ++g_dropped_total; ++g_oversized_total;
    } else {
      /* Drop-on-overload: evict from the FRONT (oldest first) until there is
       * room for the new event, so memory stays bounded and the newest data
       * survives. Each eviction is counted as a queue drop. */
      while (!g_queue.empty() && (g_queue.size() >= MAX_QUEUE_EVENTS || g_queue_bytes + line.size() > MAX_QUEUE_BYTES)) {
        g_queue_bytes -= g_queue.front().size();
        g_queue.pop_front();
        ++g_dropped_total; ++g_queue_drops_total;
      }
      if (line.size() > MAX_QUEUE_BYTES) {   /* a single event larger than the whole queue */
        ++g_dropped_total; ++g_oversized_total;
      } else {
        bool was_empty = g_queue.empty();   /* needed to timestamp the new front */
        g_queue.push_back(line); g_queue_bytes += line.size();
        if (was_empty) g_queue_first_at = wall_seconds();
        if (g_queue.size() > g_queue_high_water) g_queue_high_water = g_queue.size();
        if (g_queue_bytes > g_queue_bytes_high_water) g_queue_bytes_high_water = g_queue_bytes;
      }
    }
    pthread_cond_signal(&g_cond);   /* wake the uploader: new work is available */
    pthread_mutex_unlock(&g_lock);
  }

  /* stdin ended: tell the uploader to drain everything and then exit. */
  pthread_mutex_lock(&g_lock);
  g_input_done = true;
  pthread_cond_signal(&g_cond);
  pthread_mutex_unlock(&g_lock);
  pthread_join(uploader, NULL);

  /* Distinguish a requested stop from an unexpected pipe closure: the latter
   * returns 74 so the supervisor restarts the full sniff|ship pipeline. */
  if (g_stopped_by_signal) { logmsg("stopped"); return 0; }
  logmsg("capture input closed unexpectedly; requesting supervised pipeline restart");
  return 74;
}
