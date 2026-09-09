# Oldkernel Agent Statistics Protocol v1

## Purpose

The legacy agent reports its own capture, shipping, resource, and safety
health to the same Hub that receives trace events. Statistics are operational
telemetry, not captured application requests, so they use a separate endpoint
and must not be inserted into the normal event table or evaluated by policy.

No Hub port is assumed. Given an installer value such as:

```text
--server https://trace.internal.example:9443
```

the agent derives these paths from that exact base URL:

```text
POST https://trace.internal.example:9443/api/ingest
POST https://trace.internal.example:9443/api/agent/stats
```

## Request

```http
POST /api/agent/stats HTTP/1.1
Content-Type: application/json
```

If ingest authentication is enabled, the stats request uses the same
authentication mechanism. Tokens and credentials never appear in the body or
agent logs.

Example body:

```json
{
  "schema_version": 1,
  "type": "agent_stats",
  "node": "legacy-app-07",
  "instance_id": "1725872400-1842",
  "sequence": 42,
  "observed_at": 1725873660,
  "window_seconds": 30,
  "mode": "cpp",
  "status": "degraded",
  "reasons": ["kernel_drop", "ship_drop"],
  "capture": {
    "packets_total": 8401200,
    "packets_delta": 24800,
    "packet_bytes_total": 7281402200,
    "packet_bytes_delta": 21800400,
    "kernel_drops_total": 182,
    "kernel_drops_delta": 7,
    "kernel_drop_percent": 0.0282,
    "invalid_frames_total": 0,
    "events_emitted_total": 128440,
    "events_emitted_delta": 412,
    "flows_active": 83,
    "pending_requests": 11,
    "wsse_body_flows_active": 2
  },
  "shipping": {
    "events_in_total": 128440,
    "events_in_delta": 412,
    "events_pushed_total": 128400,
    "events_pushed_delta": 400,
    "events_dropped_total": 40,
    "events_dropped_delta": 12,
    "drop_causes": {
      "queue_full_total": 24,
      "queue_full_delta": 8,
      "hub_failure_total": 15,
      "hub_failure_delta": 4,
      "oversized_total": 1,
      "oversized_delta": 0
    },
    "batches_pushed_total": 329,
    "batches_pushed_delta": 1,
    "batches_failed_total": 3,
    "batches_failed_delta": 1,
    "bytes_pushed_total": 38201120,
    "bytes_pushed_delta": 119300,
    "push_events_per_second": 13.3333,
    "push_kbps": 31.8133,
    "drop_events_per_second": 0.4,
    "drop_percent": 2.9126,
    "queue_depth_events": 12,
    "queue_capacity_events": 4000,
    "queue_high_water_events": 388,
    "last_push_http_status": 503,
    "last_success_at": 1725873630,
    "consecutive_failures": 1,
    "stats_samples_dropped_total": 0
  },
  "resources": {
    "cpu_user_seconds": 318.41,
    "cpu_system_seconds": 74.22,
    "cpu_percent_one_core": 3.7,
    "rss_bytes": 18423808,
    "virtual_bytes": 77160448,
    "open_fds": 7,
    "threads": 1
  },
  "limits": {
    "cpu_core": 2,
    "address_space_bytes": 268435456,
    "ship_rate_kbps": 1024,
    "http_body_max_bytes": 65536,
    "ship_threads_max": 8,
    "wsse_body_bytes": 8192
  }
}
```

## Field semantics

`node`, `instance_id`, and `sequence` form the sample identity. The server
should treat `(node, instance_id, sequence)` as an idempotency key. A new
`instance_id` means the process restarted and cumulative counters reset.

`observed_at` is Unix time in seconds. `window_seconds` is the actual elapsed
sample window, normally 30 seconds. Every `*_total` is monotonic for one
instance. Every `*_delta` and rate covers only the reported window.

The rates are calculated as follows:

```text
kernel_drop_percent = 100 * kernel_drops_delta / max(1, packets_delta)
drop_percent        = 100 * events_dropped_delta / max(1, events_in_delta)
push_events_per_second = events_pushed_delta / window_seconds
drop_events_per_second = events_dropped_delta / window_seconds
push_kbps = 8 * bytes_pushed_delta / (1000 * window_seconds)
cpu_percent_one_core = 100 * process_cpu_seconds_delta / window_seconds
```

`cpu_percent_one_core` uses one logical core as 100 percent. It should remain
within that scale because the entire installed process tree is pinned to one
CPU.

`packets_total` counts packets delivered to the AF_PACKET socket.
`kernel_drops_total` accumulates Linux `PACKET_STATISTICS.tp_drops`. Reading
`PACKET_STATISTICS` resets the kernel's interval counters, so the agent must
accumulate them before reporting totals.

`events_dropped_total` is the sum of the fixed `drop_causes`: `queue_full`,
`hub_failure`, and `oversized`. It excludes the stats sample itself.
`stats_samples_dropped_total` records coalesced or failed health samples and
must not be added to the captured-event drop rate.

`status` is `ok` or `degraded`. `reasons` contains only bounded enum values:
`kernel_drop`, `ship_drop`, `hub_unreachable`, `queue_pressure`,
`resource_pressure`, or `invalid_ring_frame`. It must never contain exception
messages, URLs, usernames, addresses, request paths, or other unbounded data.

## Delivery and host-safety behavior

- Default interval: 30 seconds. Accepted configuration range: 10..300 seconds.
- Maximum encoded stats body: 16 KiB.
- One latest sample is retained in memory. A newer sample replaces an unsent
  sample; there is no disk spool and no growing retry queue.
- Statistics share `NT_SHIP_RATE_KBPS` with trace uploads. They do not receive
  a second bandwidth allowance.
- A stats failure is recorded in the next sample but never blocks capture or
  ordinary event delivery.
- Request timeout is bounded. There is no dedicated capture worker, CPU core,
  or unbounded metrics thread.
- Both capture implementations pass a bounded internal counter record through
  their existing pipe. The matching Python or native shipper consumes that
  record and never forwards it to `/api/ingest`; native capture also reports
  `output_pipe_drops_total` and `output_pipe_drops_delta`.
- Samples contain no packet payload, SOAP body, credential, username, trace
  identifier, source/destination address, URL, or request path.

## Server response

The Hub should return HTTP 200 after validating and accepting the sample:

```json
{
  "ok": true,
  "accepted": true,
  "schema_version": 1,
  "server_time": 1725873661
}
```

Duplicate samples should also return HTTP 200 with `accepted: false` rather
than creating a second row. Invalid documents should return HTTP 400. HTTP
429 or 5xx responses are treated as a dropped stats sample; the agent will
send a fresh cumulative snapshot at the next interval.

The server should retain the submitted rates for diagnosis but derive alerting
rates from successive cumulative totals whenever possible. That remains
correct when one or more interval samples are lost.

## Recommended server storage and metrics

Keep one latest row per node for dashboards and a time-series history with a
bounded retention period. Do not store stats in the request-event table.

Useful Prometheus mappings include:

```text
networktracing_agent_up{node,mode}
networktracing_agent_capture_packets_total{node,mode}
networktracing_agent_capture_kernel_drops_total{node,mode}
networktracing_agent_events_pushed_total{node,mode}
networktracing_agent_events_dropped_total{node,mode}
networktracing_agent_push_kbps{node,mode}
networktracing_agent_queue_depth_events{node,mode}
networktracing_agent_cpu_percent_one_core{node,mode}
networktracing_agent_rss_bytes{node,mode}
```

Only `node` and bounded enums such as `mode` or drop cause should be labels.
Never use paths, users, IP addresses, trace IDs, or exception text as metric
labels.
