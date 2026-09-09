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
#include <pthread.h>
#include <dirent.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>

static const size_t MAX_BATCH = 400;
static const size_t MAX_QUEUE = 4000;
static const size_t MAX_POST_BYTES = 65536;
static const size_t MAX_STATS_BYTES = 16384;
static const size_t MAX_INPUT_LINE = 65535;
static const int FLUSH_SEC = 5;

static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_stopped_by_signal = 0;
static unsigned g_ship_rate_kbps = 1024;
static unsigned g_stats_interval_sec = 30;
static double g_next_ship_slot = 0.0;
static double g_next_event_attempt = 0.0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static std::deque<std::string> g_queue;
static bool g_input_done = false;
static std::string g_capture_json = "{}";
static unsigned long long g_capture_generation = 0;
static unsigned long long g_stats_generation_sent = 0;
static unsigned long long g_input_total = 0;
static unsigned long long g_posted_total = 0;
static unsigned long long g_dropped_total = 0;
static unsigned long long g_oversized_total = 0;
static unsigned long long g_batches_total = 0;
static unsigned long long g_batches_failed_total = 0;
static unsigned long long g_bytes_posted_total = 0;
static unsigned long long g_queue_drops_total = 0;
static unsigned long long g_hub_drops_total = 0;
static unsigned long long g_stats_drops_total = 0;
static unsigned long long g_prev_input = 0;
static unsigned long long g_prev_posted = 0;
static unsigned long long g_prev_dropped = 0;
static unsigned long long g_prev_bytes_posted = 0;
static unsigned long long g_prev_queue_drops = 0;
static unsigned long long g_prev_hub_drops = 0;
static unsigned long long g_prev_oversized = 0;
static unsigned long long g_prev_batches_total = 0;
static unsigned long long g_prev_batches_failed = 0;
static unsigned long long g_queue_high_water = 0;
static unsigned long long g_sequence = 0;
static unsigned g_consecutive_failures = 0;
static int g_last_http_status = 0;
static time_t g_last_success_epoch = 0;
static time_t g_started_epoch = 0;
static double g_last_stats_at = 0.0;
static double g_last_stats_cpu = 0.0;
static std::string g_endpoint;
static std::string g_node;
static std::string g_instance_id;

static void stop_signal(int) { g_stopped_by_signal = 1; g_running = 0; }
static void logmsg(const std::string &s) { std::cerr << "nt-ship-cpp: " << s << std::endl; }
static std::string ulls(unsigned long long n) { std::ostringstream o; o << n; return o.str(); }
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
static std::string shellq(const std::string &s) {
  std::string o = "'";
  for (size_t i = 0; i < s.size(); ++i) { if (s[i] == '\'') o += "'\\''"; else o += s[i]; }
  return o + "'";
}
static double wall_seconds() {
  struct timeval tv; gettimeofday(&tv, NULL);
  return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}
static void pace_upload(size_t bytes) {
  double rate = (double)g_ship_rate_kbps * 1000.0 / 8.0, now = wall_seconds();
  if (g_next_ship_slot < now || g_next_ship_slot - now > 60.0) g_next_ship_slot = now;
  double slot = g_next_ship_slot;
  g_next_ship_slot += (double)bytes / rate;
  while (g_running && slot > (now = wall_seconds())) {
    double left = slot - now;
    useconds_t delay = (useconds_t)(left > 0.1 ? 100000 : left * 1000000.0);
    if (delay) usleep(delay);
  }
}
static std::string json_array(const std::vector<std::string> &a) {
  std::string o = "[";
  for (size_t i = 0; i < a.size(); ++i) { if (i) o += ","; o += a[i]; }
  return o + "]";
}
static size_t bounded_batch_count(const std::deque<std::string> &buf, const std::string &node) {
  size_t size = std::string("{\"node\":").size() + jsonq(node).size() + std::string(",\"events\":[]}").size();
  size_t n = 0, limit = buf.size() < MAX_BATCH ? buf.size() : MAX_BATCH;
  while (n < limit) {
    size_t extra = buf[n].size() + (n ? 1 : 0);
    if (extra > MAX_POST_BYTES - size) break;
    size += extra; ++n;
  }
  return n;
}
static int post_json(const std::string &url, const std::string &body, unsigned timeout_sec) {
  if (body.size() > MAX_POST_BYTES) return 0;
  pace_upload(body.size());
  std::string cmd = "curl -sSf --max-time " + ulls(timeout_sec) +
    " --limit-rate " + ulls((unsigned long long)g_ship_rate_kbps * 1000ULL / 8ULL) +
    " -o /dev/null -H 'Content-Type: application/json' --data-binary @- " + shellq(url);
  FILE *fp = popen(cmd.c_str(), "w");
  if (!fp) return 0;
  size_t written = fwrite(body.data(), 1, body.size(), fp);
  int rc = pclose(fp);
  if (written != body.size() || !WIFEXITED(rc) || WEXITSTATUS(rc) != 0) return 0;
  /* curl -f maps HTTP 4xx/5xx to failure. Exact success status is not exposed
     by this write-only pipe, so the stable v1 success value is 200. */
  return 200;
}
static unsigned long long json_uint(const std::string &s, const char *key) {
  std::string needle = std::string("\"") + key + "\":";
  size_t p = s.find(needle);
  if (p == std::string::npos) return 0;
  p += needle.size();
  while (p < s.size() && (s[p] == ' ' || s[p] == '\t')) ++p;
  unsigned long long v = 0;
  while (p < s.size() && s[p] >= '0' && s[p] <= '9') { v = v * 10ULL + (unsigned)(s[p] - '0'); ++p; }
  return v;
}
static unsigned thread_count() {
  DIR *d = opendir("/proc/self/task"); if (!d) return 0;
  unsigned n = 0; struct dirent *e;
  while ((e = readdir(d)) != NULL) if (e->d_name[0] >= '0' && e->d_name[0] <= '9') ++n;
  closedir(d); return n;
}
static void process_memory(unsigned long long *rss, unsigned long long *virt) {
  FILE *f = fopen("/proc/self/statm", "r"); unsigned long pages = 0, resident = 0;
  if (f) { if (fscanf(f, "%lu %lu", &pages, &resident) != 2) pages = resident = 0; fclose(f); }
  unsigned long long page = (unsigned long long)sysconf(_SC_PAGESIZE);
  *rss = (unsigned long long)resident * page; *virt = (unsigned long long)pages * page;
}
static unsigned open_fd_count() {
  DIR *d = opendir("/proc/self/fd"); if (!d) return 0;
  unsigned n = 0; struct dirent *e;
  while ((e = readdir(d)) != NULL) if (e->d_name[0] >= '0' && e->d_name[0] <= '9') ++n;
  closedir(d); return n;
}
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
static std::string shipping_stats_body(const std::string &capture) {
  double now_wall = wall_seconds(), elapsed = now_wall - g_last_stats_at;
  if (elapsed < 0.001) elapsed = 0.001;
  unsigned long long now = (unsigned long long)now_wall, in, posted, dropped, qhw, qdepth, seq;
  unsigned long long bytes_posted, queue_drops, hub_drops, oversized, batches, batches_failed, stats_drops;
  unsigned failures, status; time_t success;
  pthread_mutex_lock(&g_lock);
  in = g_input_total; posted = g_posted_total;
  dropped = g_dropped_total; qhw = g_queue_high_water; qdepth = g_queue.size();
  bytes_posted = g_bytes_posted_total; queue_drops = g_queue_drops_total;
  hub_drops = g_hub_drops_total; oversized = g_oversized_total;
  batches = g_batches_total; batches_failed = g_batches_failed_total; stats_drops = g_stats_drops_total;
  failures = g_consecutive_failures; status = (unsigned)g_last_http_status;
  success = g_last_success_epoch; seq = ++g_sequence;
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
  double cpu = usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1000000.0 + usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1000000.0;
  double cpu_pct = 100.0 * (cpu - g_last_stats_cpu) / elapsed; if (cpu_pct < 0) cpu_pct = 0;
  unsigned long long rss = 0, virt = 0; process_memory(&rss, &virt);
  std::string reasons;
  if (json_uint(capture, "kernel_drops_delta")) reasons += "\"kernel_drop\"";
  if (drop_delta) { if (!reasons.empty()) reasons += ","; reasons += "\"ship_drop\""; }
  if (hub_delta) { if (!reasons.empty()) reasons += ","; reasons += "\"hub_unreachable\""; }
  if (queue_delta || json_uint(capture, "output_pipe_drops_delta")) { if (!reasons.empty()) reasons += ","; reasons += "\"queue_pressure\""; }
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
    << ",\"batches_pushed_total\":" << batches << ",\"batches_pushed_delta\":" << batches_delta
    << ",\"batches_failed_total\":" << batches_failed << ",\"batches_failed_delta\":" << batches_failed_delta
    << ",\"bytes_pushed_total\":" << bytes_posted << ",\"bytes_pushed_delta\":" << bytes_delta
    << ",\"push_events_per_second\":" << ((double)post_delta / elapsed)
    << ",\"push_kbps\":" << (8.0 * bytes_delta / (1000.0 * elapsed))
    << ",\"drop_events_per_second\":" << ((double)drop_delta / elapsed)
    << ",\"drop_percent\":" << (100.0 * drop_delta / (in_delta ? in_delta : 1))
    << ",\"queue_depth_events\":" << qdepth << ",\"queue_high_water_events\":" << qhw
    << ",\"queue_capacity_events\":" << MAX_QUEUE
    << ",\"consecutive_failures\":" << failures
    << ",\"last_push_http_status\":" << status
    << ",\"last_success_at\":" << (unsigned long long)success
    << ",\"stats_samples_dropped_total\":" << stats_drops
    << "},\"resources\":{\"cpu_user_seconds\":" << (usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1000000.0)
    << ",\"cpu_system_seconds\":" << (usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1000000.0)
    << ",\"cpu_percent_one_core\":" << cpu_pct << ",\"rss_bytes\":" << rss
    << ",\"virtual_bytes\":" << virt << ",\"open_fds\":" << open_fd_count() << ",\"threads\":" << thread_count()
    << "},\"limits\":{\"cpu_core\":" << jsonq(allowed_cpu()) << ",\"address_space_bytes\":268435456"
    << ",\"ship_rate_kbps\":" << g_ship_rate_kbps << ",\"http_body_max_bytes\":" << MAX_POST_BYTES << ",\"ship_threads_max\":1"
    << ",\"wsse_body_bytes\":" << json_uint(capture, "wsse_body_bytes")
    << "}}";
  g_last_stats_at = now_wall; g_last_stats_cpu = cpu;
  return o.str();
}
static bool parse_capture_stats(const std::string &line, std::string *capture) {
  if (line.size() > MAX_STATS_BYTES || line.find("\"_nt_internal\":\"capture_stats_v1\"") == std::string::npos) return false;
  size_t p = line.find("\"capture\":"); if (p == std::string::npos) return false;
  p += strlen("\"capture\":");
  size_t start = line.find('{', p); if (start == std::string::npos) return false;
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
static void *uploader_main(void *) {
  time_t last_flush = time(NULL);
  while (true) {
    std::vector<std::string> batch;
    std::string capture; unsigned long long capture_gen = 0;
    bool done, empty;
    pthread_mutex_lock(&g_lock);
    time_t now = time(NULL);
    bool retry_ready = wall_seconds() >= g_next_event_attempt;
    bool flush = retry_ready && (g_queue.size() >= MAX_BATCH || (now - last_flush >= FLUSH_SEC) || g_input_done || !g_running);
    if (flush && !g_queue.empty()) {
      size_t n = bounded_batch_count(g_queue, g_node);
      if (!n) { g_queue.pop_front(); ++g_dropped_total; ++g_oversized_total; }
      else { for (size_t i = 0; i < n; ++i) { batch.push_back(g_queue.front()); g_queue.pop_front(); } }
      last_flush = now;
    }
    if (g_capture_generation != g_stats_generation_sent) { capture = g_capture_json; capture_gen = g_capture_generation; }
    done = g_input_done || !g_running; empty = g_queue.empty();
    pthread_mutex_unlock(&g_lock);

    if (!batch.empty()) {
      std::string body = "{\"node\":" + jsonq(g_node) + ",\"events\":" + json_array(batch) + "}";
      int status = post_json(g_endpoint + "/api/ingest", body, 10);
      pthread_mutex_lock(&g_lock);
      if (status) { g_posted_total += batch.size(); g_bytes_posted_total += body.size(); ++g_batches_total; g_consecutive_failures = 0; g_next_event_attempt = 0.0; g_last_http_status = status; g_last_success_epoch = time(NULL); }
      else {
        g_hub_drops_total += batch.size(); g_dropped_total += batch.size(); ++g_batches_failed_total;
        unsigned shift = g_consecutive_failures < 6 ? g_consecutive_failures : 6;
        ++g_consecutive_failures; g_next_event_attempt = wall_seconds() + (double)(1U << shift); g_last_http_status = 0;
      }
      pthread_mutex_unlock(&g_lock);
    }
    if (!capture.empty()) {
      std::string body = shipping_stats_body(capture);
      int status = body.size() <= MAX_STATS_BYTES ? post_json(g_endpoint + "/api/agent/stats", body, 2) : 0;
      pthread_mutex_lock(&g_lock);
      g_stats_generation_sent = capture_gen;
      if (!status) ++g_stats_drops_total;
      pthread_mutex_unlock(&g_lock);
    }
    if (done && empty && batch.empty()) break;
    usleep(100000);
  }
  return NULL;
}
int main(int argc, char **argv) {
  bool stats_fixture = false;
  const char *rate_env = getenv("NT_SHIP_RATE_KBPS");
  const char *stats_env = getenv("NT_STATS_INTERVAL_SEC");
  if (rate_env && *rate_env) g_ship_rate_kbps = (unsigned)atoi(rate_env);
  if (stats_env && *stats_env) g_stats_interval_sec = (unsigned)atoi(stats_env);
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--endpoint" && i + 1 < argc) g_endpoint = argv[++i];
    else if (a == "--ship-rate-kbps" && i + 1 < argc) g_ship_rate_kbps = (unsigned)atoi(argv[++i]);
    else if (a == "--stats-interval-sec" && i + 1 < argc) g_stats_interval_sec = (unsigned)atoi(argv[++i]);
    else if (a == "--spool" && i + 1 < argc) ++i;
    else if (a == "--stats-fixture") stats_fixture = true;
    else if (a == "-h" || a == "--help") { std::cout << "usage: nt-ship-cpp --endpoint URL [--ship-rate-kbps 64..10000] [--stats-interval-sec 10..3600]\n"; return 0; }
    else { std::cerr << "unknown arg: " << a << "\n"; return 2; }
  }
  if (g_endpoint.empty() && !stats_fixture) { std::cerr << "--endpoint required\n"; return 2; }
  if (g_ship_rate_kbps < 64 || g_ship_rate_kbps > 10000) { std::cerr << "ship rate must be in range 64..10000 kbit/s\n"; return 2; }
  if (g_stats_interval_sec < 10 || g_stats_interval_sec > 3600) { std::cerr << "stats interval must be in range 10..3600 seconds\n"; return 2; }
  signal(SIGTERM, stop_signal); signal(SIGINT, stop_signal); signal(SIGPIPE, SIG_IGN);
  char host[256]; gethostname(host, sizeof(host)); host[sizeof(host) - 1] = 0;
  const char *node_env = getenv("NT_NODE_NAME"); g_node = (node_env && *node_env) ? node_env : host;
  g_started_epoch = time(NULL); g_instance_id = ulls((unsigned long long)g_started_epoch) + "-" + ulls((unsigned long long)getpid());
  g_last_stats_at = wall_seconds();
  if (stats_fixture) {
    g_last_stats_at -= 30.0; g_input_total = 10; g_posted_total = 8;
    g_dropped_total = g_queue_drops_total = 2; g_bytes_posted_total = 6400;
    std::cout << shipping_stats_body("{\"packets_total\":100,\"packets_delta\":100,\"kernel_drops_total\":0,\"kernel_drops_delta\":0,\"output_pipe_drops_delta\":0,\"wsse_body_bytes\":8192}") << "\n";
    return 0;
  }
  pthread_attr_t attr;
  if (pthread_attr_init(&attr) != 0) { logmsg("cannot initialize uploader limits; refusing unsafe startup"); return 70; }
  if (pthread_attr_setstacksize(&attr, 512U * 1024U) != 0) {
    pthread_attr_destroy(&attr); logmsg("cannot enforce 512 KiB uploader stack; refusing unsafe startup"); return 70;
  }
  pthread_t uploader;
  if (pthread_create(&uploader, &attr, uploader_main, NULL) != 0) { pthread_attr_destroy(&attr); logmsg("failed to start bounded uploader thread"); return 70; }
  pthread_attr_destroy(&attr);

  std::string line;
  while (g_running) {
    fd_set r; FD_ZERO(&r); FD_SET(0, &r);
    struct timeval tv; tv.tv_sec = 1; tv.tv_usec = 0;
    int rc = select(1, &r, NULL, NULL, &tv);
    if (rc < 0) { if (errno == EINTR) continue; logmsg("stdin select failed"); break; }
    if (rc == 0) continue;
    if (!std::getline(std::cin, line)) break;
    if (line.empty()) continue;
    std::string capture;
    if (parse_capture_stats(line, &capture)) {
      pthread_mutex_lock(&g_lock); g_capture_json = capture; ++g_capture_generation; pthread_mutex_unlock(&g_lock);
      continue;
    }
    pthread_mutex_lock(&g_lock);
    ++g_input_total;
    if (line.size() > MAX_INPUT_LINE) { ++g_dropped_total; ++g_oversized_total; }
    else { if (g_queue.size() >= MAX_QUEUE) { g_queue.pop_front(); ++g_dropped_total; ++g_queue_drops_total; } g_queue.push_back(line); if (g_queue.size() > g_queue_high_water) g_queue_high_water = g_queue.size(); }
    pthread_mutex_unlock(&g_lock);
  }
  pthread_mutex_lock(&g_lock);
  while (g_queue.size() > MAX_BATCH) {
    g_queue.pop_front(); ++g_dropped_total; ++g_queue_drops_total;
  }
  /* EOF may mean capture failed. Permit at most one final bounded upload, so
     supervised restart cannot be delayed by a full 4,000-event backlog. */
  g_next_event_attempt = 0.0;
  g_input_done = true;
  pthread_mutex_unlock(&g_lock);
  pthread_join(uploader, NULL);
  if (g_stopped_by_signal) { logmsg("stopped"); return 0; }
  logmsg("capture input closed unexpectedly; requesting supervised pipeline restart");
  return 74;
}
