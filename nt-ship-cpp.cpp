#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <ctime>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>

static const size_t MAX_BATCH = 400;
static const size_t MAX_QUEUE = 4000;
static const size_t MAX_POST_BYTES = 65536;
static unsigned ship_rate_kbps = 1024;
static double next_ship_slot = 0.0;
static const int FLUSH_SEC = 5;
static const int RETRY_SEC = 60;
static volatile sig_atomic_t running = 1;
static void stop_signal(int) { running = 0; }
static void logmsg(const std::string &s) { std::cerr << "nt-ship-cpp: " << s << std::endl; }
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
  for (size_t i=0;i<s.size();++i) { if (s[i]=='\'') o += "'\\''"; else o += s[i]; }
  return o + "'";
}
static std::string number_string(size_t n) { std::ostringstream o; o << n; return o.str(); }
static std::string json_array(const std::vector<std::string> &a) {
  std::string o="["; for(size_t i=0;i<a.size();++i){if(i)o+=",";o+=a[i];} return o+"]";
}
static double wall_seconds() { struct timeval tv; gettimeofday(&tv,NULL); return (double)tv.tv_sec+(double)tv.tv_usec/1000000.0; }
static void pace_upload(size_t bytes) {
  double rate=(double)ship_rate_kbps*1000.0/8.0, now=wall_seconds();
  if(next_ship_slot<now||next_ship_slot-now>60.0) next_ship_slot=now;
  double slot=next_ship_slot; next_ship_slot+=(double)bytes/rate;
  while(slot>(now=wall_seconds())) { double left=slot-now; useconds_t delay=(useconds_t)(left>0.5?500000:left*1000000.0); if(delay) usleep(delay); }
}
static size_t bounded_batch_count(const std::vector<std::string> &buf,const std::string &node) {
  size_t size=std::string("{\"node\":").size()+jsonq(node).size()+std::string(",\"events\":[]}").size(), n=0, limit=buf.size()<MAX_BATCH?buf.size():MAX_BATCH;
  while(n<limit) { size_t extra=buf[n].size()+(n?1:0); if(extra>MAX_POST_BYTES-size) break; size+=extra; ++n; }
  return n;
}
static bool post(const std::string &endpoint, const std::string &node,
                 const std::vector<std::string> &batch) {
  std::string body="{\"node\":"+jsonq(node)+",\"events\":"+json_array(batch)+"}";
  if(body.size()>MAX_POST_BYTES) return false;
  pace_upload(body.size());
  std::string cmd="curl -sSf --max-time 10 --limit-rate "+number_string((size_t)ship_rate_kbps*1000U/8U)+" -o /dev/null -H 'Content-Type: application/json' --data-binary @- "+shellq(endpoint+"/api/ingest");
  FILE *fp=popen(cmd.c_str(),"w"); if(!fp) return false;
  fwrite(body.data(), 1, body.size(), fp);
  int rc=pclose(fp);
  return WIFEXITED(rc) && WEXITSTATUS(rc) == 0;
}
static void send_batches(const std::string &endpoint,const std::string &node,
                         std::vector<std::string> *buf, bool flush_all) {
  while (!buf->empty() && (flush_all || buf->size() >= MAX_BATCH)) {
    size_t n=bounded_batch_count(*buf,node);
    if(!n){buf->erase(buf->begin());logmsg("WARN: dropped oversized event; encoded body exceeds 65536 bytes");continue;}
    std::vector<std::string> batch(buf->begin(),buf->begin()+n);
    if(post(endpoint,node,batch)) {
      buf->erase(buf->begin(),buf->begin()+n);
      logmsg("flushed "+number_string(n)+" events");
    } else {
      buf->erase(buf->begin(),buf->begin()+n);
      logmsg("WARN: Hub unreachable, dropped "+number_string(n)+" events (in-memory drop, 0 disk I/O)");
      break;
    }
  }
}
int main(int argc,char **argv) {
  std::string endpoint; int i;
  const char *rate_env=getenv("NT_SHIP_RATE_KBPS"); if(rate_env&&*rate_env) ship_rate_kbps=(unsigned)atoi(rate_env);
  for(i=1;i<argc;++i){std::string a=argv[i]; if(a=="--endpoint"&&i+1<argc)endpoint=argv[++i]; else if(a=="--ship-rate-kbps"&&i+1<argc)ship_rate_kbps=(unsigned)atoi(argv[++i]); else if(a=="--spool"&&i+1<argc)++i; else if(a=="-h"||a=="--help"){std::cout<<"usage: nt-ship-cpp --endpoint URL [--ship-rate-kbps 64..10000]\n";return 0;} else {std::cerr<<"unknown arg: "<<a<<"\n";return 2;}}
  if(endpoint.empty()){std::cerr<<"--endpoint required\n";return 2;}
  if(ship_rate_kbps<64||ship_rate_kbps>10000){std::cerr<<"ship rate must be in range 64..10000 kbit/s\n";return 2;}
  signal(SIGTERM,stop_signal); signal(SIGINT,stop_signal);
  char host[256]; gethostname(host,sizeof(host)); host[sizeof(host)-1]=0;
  const char *node_env = getenv("NT_NODE_NAME");
  std::string node = (node_env && *node_env) ? node_env : host;
  std::vector<std::string> buf; time_t last=time(NULL);
  std::string line;
  while(running) {
    fd_set r; FD_ZERO(&r); FD_SET(0, &r);
    struct timeval tv; tv.tv_sec = 1; tv.tv_usec = 0;
    int rc = select(1, &r, NULL, NULL, &tv);
    if (rc > 0 && FD_ISSET(0, &r)) {
      while (running && std::cin && buf.size() < MAX_QUEUE) {
        if (!std::getline(std::cin, line)) break;
        if (!line.empty()) {
          if (buf.size() >= MAX_QUEUE) buf.erase(buf.begin());
          buf.push_back(line);
        }
        if (buf.size() >= MAX_BATCH) {
          send_batches(endpoint, node, &buf, false);
        }
        if (std::cin.rdbuf()->in_avail() <= 0) break;
      }
    }
    time_t now = time(NULL);
    if (now - last >= FLUSH_SEC || buf.size() >= MAX_BATCH) {
      if (!buf.empty()) send_batches(endpoint, node, &buf, true);
      last = now;
    }
  }
  if (!buf.empty()) send_batches(endpoint,node,&buf,true);
  logmsg("stopped"); return 0;
}
