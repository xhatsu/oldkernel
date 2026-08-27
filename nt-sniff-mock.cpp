#include <arpa/inet.h>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

struct Event {
  std::string host, src, service, method, path, user, scheme, source_probe;
  std::string caller, caller_port, dst_ip, traceparent, trace_id;
  int dst_port = 0;
  int status = 0;
  long duration_ms = 0;
  long req_bytes = 0;
  long resp_bytes = 0;
  bool has_status = false, has_duration = false, has_resp = false;
};

static std::string json_escape(const std::string &s) {
  std::string out;
  for (char c : s) {
    if (c == '\\' || c == '"') out += '\\';
    if (c == '\n') { out += "\\n"; continue; }
    if (c == '\r') { out += "\\r"; continue; }
    out += c;
  }
  return out;
}

static std::string header(const std::string &raw, const std::string &name) {
  std::istringstream in(raw);
  std::string line, lower_name = name;
  for (char &c : lower_name) c = static_cast<char>(::tolower(c));
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    std::string low = line;
    for (char &c : low) c = static_cast<char>(::tolower(c));
    if (low.compare(0, lower_name.size(), lower_name) == 0 &&
        low.size() > lower_name.size() && low[lower_name.size()] == ':')
      return line.substr(lower_name.size() + 1);
  }
  return "";
}

static std::string trim(std::string s) {
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(0, 1);
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
  return s;
}

static Event correlate(const std::string &request, const std::string &response,
                       const std::string &host, const std::string &client_ip,
                       int client_port, const std::string &server_ip, int server_port) {
  Event e;
  e.host = host; e.src = "pcap"; e.service = "port:" + std::to_string(server_port);
  e.source_probe = "pcap-http"; e.caller = client_ip;
  e.caller_port = std::to_string(client_port); e.dst_ip = server_ip; e.dst_port = server_port;
  std::istringstream req(request); std::string first;
  std::getline(req, first); first = trim(first);
  std::istringstream parts(first); parts >> e.method >> e.path;
  e.path = e.path.substr(0, e.path.find('?'));
  e.user = "-anonymous-";
  e.scheme = "none";
  std::string auth = trim(header(request, "authorization"));
  if (auth.rfind("Basic ", 0) == 0) { e.scheme = "basic"; e.user = "[REDACTED]"; }
  std::string tp = trim(header(request, "traceparent"));
  if (tp.size() >= 55) { e.traceparent = tp; e.trace_id = tp.substr(3, 32); }
  e.req_bytes = static_cast<long>(request.size());
  auto t0 = std::chrono::steady_clock::now();
  (void)t0; // fixture has deterministic response timestamp below
  std::istringstream resp(response); std::string rline;
  std::getline(resp, rline); rline = trim(rline);
  std::istringstream rs(rline); std::string proto; int status;
  if (rs >> proto >> status) { e.status = status; e.has_status = true; }
  std::string cl = trim(header(response, "content-length"));
  if (!cl.empty()) { e.resp_bytes = std::stol(cl); e.has_resp = true; }
  e.duration_ms = 3; e.has_duration = true;
  return e;
}

static void emit(const Event &e) {
  std::cout << "{\"ts\":1700000000,\"host\":\"" << json_escape(e.host)
            << "\",\"src\":\"" << e.src << "\",\"service\":\"" << e.service
            << "\",\"method\":\"" << e.method << "\",\"path\":\"" << json_escape(e.path)
            << "\",\"user\":\"" << e.user << "\",\"scheme\":\"" << e.scheme
            << "\",\"source_probe\":\"" << e.source_probe << "\",\"caller\":\""
            << e.caller << "\",\"caller_port\":" << e.caller_port << ",\"dst_ip\":\""
            << e.dst_ip << "\",\"dst_port\":" << e.dst_port << ",\"req_bytes\":" << e.req_bytes;
  if (e.has_status) std::cout << ",\"status\":" << e.status;
  else std::cout << ",\"status\":null";
  if (e.has_duration) std::cout << ",\"duration_ms\":" << e.duration_ms;
  else std::cout << ",\"duration_ms\":null";
  if (e.has_resp) std::cout << ",\"resp_bytes\":" << e.resp_bytes;
  else std::cout << ",\"resp_bytes\":null";
  std::cout << ",\"traceparent\":" << (e.traceparent.empty() ? "null" : "\"" + e.traceparent + "\"")
            << ",\"trace_id\":" << (e.trace_id.empty() ? "null" : "\"" + e.trace_id + "\"")
            << ",\"service_id\":null,\"module_id\":\"cpp-mock\"}\n";
}

int main() {
  const std::string req = "GET /api/items?x=1 HTTP/1.1\r\nHost: api.local\r\nAuthorization: Basic secret\r\nTraceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n\r\n";
  const std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n";
  emit(correlate(req, resp, "cpp-node", "10.0.0.9", 51000, "10.0.0.2", 8080));
  return 0;
}
