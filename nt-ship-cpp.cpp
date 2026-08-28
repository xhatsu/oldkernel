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
#include <unistd.h>
#include <signal.h>

static const size_t MAX_BATCH = 400;
static const size_t MAX_QUEUE = 4000;
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
static bool read_file(const std::string &p, std::string *out) {
  std::ifstream f(p.c_str()); if (!f) return false;
  std::ostringstream ss; ss << f.rdbuf(); *out = ss.str(); return true;
}
static bool write_append(const std::string &p, const std::string &data) {
  std::string dir=p.substr(0,p.find_last_of('/'));
  if (!dir.empty()) { std::string cmd="mkdir -p "+shellq(dir); if (system(cmd.c_str()) != 0) return false; }
  std::ofstream f(p.c_str(), std::ios::out|std::ios::app); if (!f) return false;
  f << data; return f.good();
}
static std::string number_string(size_t n) { std::ostringstream o; o << n; return o.str(); }
static std::string json_array(const std::vector<std::string> &a) {
  std::string o="["; for(size_t i=0;i<a.size();++i){if(i)o+=",";o+=a[i];} return o+"]";
}
static bool post(const std::string &endpoint, const std::string &node,
                 const std::vector<std::string> &batch) {
  std::string body="{\"node\":"+jsonq(node)+",\"events\":"+json_array(batch)+"}";
  char code_tmpl[] = "/tmp/nt_code_XXXXXX";
  int tmp_fd = mkstemp(code_tmpl);
  if (tmp_fd < 0) return false;
  close(tmp_fd);
  std::string code_file = code_tmpl;
  std::string cmd="curl -sS --max-time 15 -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' --data-binary @- "+shellq(endpoint+"/api/ingest")+" > "+shellq(code_file);
  FILE *fp=popen(cmd.c_str(),"w"); if(!fp){ unlink(code_file.c_str()); return false; }
  fwrite(body.data(), 1, body.size(), fp);
  int rc=pclose(fp);
  std::string code;
  read_file(code_file, &code);
  unlink(code_file.c_str());
  while (!code.empty() && (code[code.size()-1]=='\r' || code[code.size()-1]=='\n' || code[code.size()-1]==' ')) code.erase(code.size()-1);
  return rc==0 && code=="200";
}
static void spool(const std::string &path, const std::vector<std::string> &batch) {
  std::string data; for(size_t i=0;i<batch.size();++i)data+=batch[i]+"\n";
  if(!write_append(path,data)) { logmsg("FATAL: cannot write spool"); exit(3); }
}
static void load_spool(const std::string &path, std::vector<std::string> *buf) {
  std::string data; if(!read_file(path,&data))return;
  std::istringstream in(data); std::string line; while(std::getline(in,line)) if(!line.empty()) buf->push_back(line);
  unlink(path.c_str());
}
static void send_batches(const std::string &endpoint,const std::string &node,const std::string &spool_path,
                         std::vector<std::string> *buf, bool flush_all) {
  while (!buf->empty() && (flush_all || buf->size() >= MAX_BATCH)) {
    size_t n=buf->size()>=MAX_BATCH?MAX_BATCH:buf->size();
    std::vector<std::string> batch(buf->begin(),buf->begin()+n);
    if(post(endpoint,node,batch)) { buf->erase(buf->begin(),buf->begin()+n); logmsg("flushed "+number_string(n)+" events"); }
    else { spool(spool_path,batch); buf->erase(buf->begin(),buf->begin()+n); logmsg("spooled "+number_string(n)+" events"); break; }
  }
}
int main(int argc,char **argv) {
  std::string endpoint, spool_path="/var/lib/networktracing/sniff-spool.jsonl"; int i;
  for(i=1;i<argc;++i){std::string a=argv[i]; if(a=="--endpoint"&&i+1<argc)endpoint=argv[++i]; else if(a=="--spool"&&i+1<argc)spool_path=argv[++i]; else if(a=="-h"||a=="--help"){std::cout<<"usage: nt-ship-cpp --endpoint URL [--spool PATH]\n";return 0;} else {std::cerr<<"unknown arg: "<<a<<"\n";return 2;}}
  if(endpoint.empty()){std::cerr<<"--endpoint required\n";return 2;}
  signal(SIGTERM,stop_signal); signal(SIGINT,stop_signal);
  char host[256]; gethostname(host,sizeof(host)); host[sizeof(host)-1]=0;
  const char *node_env = getenv("NT_NODE_NAME");
  std::string node = (node_env && *node_env) ? node_env : host;
  std::vector<std::string> buf; load_spool(spool_path,&buf); time_t last=time(NULL), last_retry=last;
  std::string line;
  while(running) {
    fd_set r; FD_ZERO(&r); FD_SET(0, &r);
    struct timeval tv; tv.tv_sec = 1; tv.tv_usec = 0;
    int rc = select(1, &r, NULL, NULL, &tv);
    if (rc > 0 && FD_ISSET(0, &r)) {
      if (!std::getline(std::cin, line)) break;
      if (!line.empty()) {
        buf.push_back(line);
        if (buf.size() >= MAX_QUEUE) {
          send_batches(endpoint, node, spool_path, &buf, false);
        }
      }
    }
    time_t now = time(NULL);
    if (now - last >= FLUSH_SEC || buf.size() >= MAX_BATCH) {
      if (!buf.empty()) send_batches(endpoint, node, spool_path, &buf, true);
      last = now;
    }
    if (now - last_retry >= RETRY_SEC) {
      load_spool(spool_path, &buf);
      last_retry = now;
    }
  }
  send_batches(endpoint,node,spool_path,&buf,true); logmsg("stopped"); return 0;
}
