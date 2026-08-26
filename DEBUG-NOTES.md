# DEBUG-NOTES.md — handoff for the next agent working on a real 2.6.32 VM

**Audience:** an agent (or human) with root SSH on an actual CentOS 6.8 /
kernel 2.6.32-642.el6 node, continuing validation of this kit.
**Read README.md first** for architecture + usage. This file is the
debugging playbook: what's proven, what's NOT, known traps, exact test
commands, and acceptance criteria.

## State of proof (as of 2026-08-26)

| Item | Status |
|---|---|
| Capture pipeline end-to-end on modern kernel | PROVEN — wire → AF_PACKET → reassembly → Basic extract → ship → hub (`source_probe=pcap-http`, `user=proofuser scheme=basic` visible in hub API) |
| Flow logic incl. split-delivery | PROVEN via unit harness (headers+body in separate segments → 1 event) |
| py2.6 *syntax* compatibility | Reviewed only — **never executed under python 2.6**; this VM run is where that gets proven |
| SELinux enforcing + setcap'd non-root capture | UNPROVEN — the #1 open risk |
| go1.x binary behavior on 2.6.32 | IRRELEVANT by design: this kit is pure python2.6; do not introduce Go here |
| Installer (--check/install/uninstall) | Syntax-checked + logic-reviewed only; never run against real el6 SysV/chkconfig |

## Known traps (all bit us once already — don't re-hit them)

1. **AF_PACKET protocol arg MUST be `socket.htons(0x0800)`.**
   A 0-protocol socket receives NOTHING (verified: 0 pkts). Never "fix"
   it to ntohs or plain 0. Ground truth lives in `/proc/net/packet`
   (Proto column shows `0800` when correct).
2. **Literal `\n` artifacts from file-writing tools.** If events arrive as
   one giant line or logs show visible backslash-n, grep for
   `"\\n"` inside string literals and fix to `"\n"`. Check with:
   `grep -n '\\\\n' nt-sniff.py nt-ship.py` (expect only comments/docstrings).
3. **py2.6 has no OrderedDict / f-strings / dict-comprehensions.**
   Keep stdlib-only, `%`-formatting, plain dicts (CPython insertion order
   is relied on for FIFO eviction — documented in enforce_limit()).
4. **urllib2 data must be str on py2** — the `hasattr(body,"encode")`
   guard in nt-ship.flush() exists for py3 test shims; harmless on py2.
   Do not remove it (the py3 harness in section "Testing without py2" uses it).
5. **json.loads failure mode = silent skip.** If the shipper feeds 0
   events but sniff.log shows requests captured, dump stdout of nt-sniff
   manually and validate each line parses.

## Debug workflow on the 2.6.32 VM

### Step 0 — get kit + smoke

```sh
HUB=<hub-ip>          # NetworkTracing hub running :30105 bootstrap + :31115 ingest
mkdir -p /tmp/ntkit && cd /tmp/ntkit
for f in el68-smoke.sh nt-sniff.py nt-ship.py install-oldkernel.sh README.md DEBUG-NOTES.md; do
  curl -sSf http://$HUB:30105/oldkernel/$f -o $f || wget -q http://$HUB:30105/oldkernel/$f -O $f
done
sudo sh el68-smoke.sh ; echo "smoke rc=$?"
```

If smoke fails at capped-interpreter/AF_PACKET: capture evidence before
changing anything —

```sh
getenforce; sestatus 2>/dev/null | head -5
audit2why < /var/log/audit/audit.log 2>/dev/null | tail -20
setcap cap_net_raw+ep /tmp/probe-bin && su -s /bin/sh nobody -c '/tmp/probe-bin -c1 -p -i eth0 -nn' ; echo rc=$?
```

Record outputs in your report. If SELinux is the blocker, the acceptable
outcomes are (a) targeted-policy exception, or (b) installer's automatic
root fallback (already implemented — verify it announces itself).

### Step 1 — prove py2.6 executes both scripts

```sh
python -V                                   # expect 2.6.6
python -m py_compile nt-sniff.py && echo SNIFF-OK
python -m py_compile nt-ship.py  && echo SHIP-OK
# any SyntaxError → fix to py2.6 grammar, note what broke in report
```

### Step 2 — live capture WITHOUT installing anything

```sh
# pick any plaintext HTTP port with traffic; if none, make some:
sudo python nt-sniff.py -i eth0 -p 80 > /tmp/cap.jsonl 2>/tmp/cap.err &
sleep 2
curl -u debuguser:pw http://127.0.0.1:80/ping 2>/dev/null || \
  curl -u debuguser:pw http://localhost:80/ping
sleep 4
sudo kill %1
wc -l /tmp/cap.jsonl                        # expect >= 1
cat /tmp/cap.jsonl                          # expect user=debuguser scheme=basic
```

Failure triage order:

```sh
cat /tmp/cap.err                             # sniffer stderr first
cat /proc/net/packet                         # Proto must be 0800 while sniffer runs
sudo tcpdump -i eth0 -c 3 'tcp port 80' -nn # does ANYTHING see the traffic?
python -c "import sys; print(sys.version)"   # confirm which interpreter ran
```

Known-good reference (modern box): identical commands produced exactly
one clean JSONL event per request within ~4s. If el6 differs ONLY by
timing (slow first flush), note it; FLUSH_SEC=5 in nt-ship.py is tunable.

### Step 3 — shipper against the real hub

```sh
cat /tmp/cap.jsonl | sudo python nt-ship.py --endpoint http://$HUB:31115 \
    --spool /var/lib/networktracing/spool.jsonl ; echo rc=$?
curl -s "http://$HUB:31115/api/events?limit=50" | grep pcap-http
```

Then the resilience path (spool+retry):

```sh
# point at a dead port, watch it spool instead of losing events:
echo '{"ts":1,"method":"GET","path":"/spool-test","user":"u1","scheme":"basic","src":"pcap"}' | \
  python nt-ship.py --endpoint http://127.0.0.1:1 --spool /tmp/sp.jsonl &
sleep 8; ls -la /tmp/sp.jsonl                 # events must be ON DISK
kill %1
# then recover through the good endpoint:
python nt-ship.py --endpoint http://$HUB:31115 --spool /tmp/sp.jsonl < /dev/null
curl -s "http://$HUB:31115/api/events?limit=10" | grep spool-test
```

### Step 4 — full install/uninstall lifecycle

```sh
sudo sh install-oldkernel.sh --check --endpoint http://$HUB:31115
sudo sh install-oldkernel.sh     --endpoint http://$HUB:31115
service networktracing-legacy status
# generate traffic on a monitored port, confirm in hub
sudo sh install-oldkernel.sh --uninstall        # must exit 0 with "verified clean"
ls /opt/networktracing-legacy 2>&1              # expect No such file
id ntsniff 2>&1                                 # account retained by design
```

Installer-specific things to watch on el6:

- `daemon`/functions sourcing was removed in favor of plain nohup+su;
  if start fails silently, run `/etc/init.d/networktracing-legacy start`
  with `sh -x` and record output.
- chkconfig registration requires the `# chkconfig:` header line intact.
- The capped-interpreter copy (`python-capnetraw`) must remain executable
  BY the ntsniff user; check perms if status shows flapping.

## Testing without py2 (dev-box sanity harness)

On a modern machine you can still exercise the shipper logic:

```python
import sys, types, urllib.request
u2 = types.ModuleType("urllib2")
u2.Request = urllib.request.Request; u2.urlopen = urllib.request.urlopen
sys.modules["urllib2"] = u2
sys.argv = ["nt-ship.py", "--endpoint", "http://HUB:31115", "--spool", "/tmp/sp"]
import importlib.util
spec = importlib.util.spec_from_file_location("ntship", "nt-ship.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
class FakeStdin:                      # feed lines here
    def readline(self):
        try: return input()
        except EOFError: return ""
sys.stdin = FakeStdin(); m.main()
```

The flow-logic unit test pattern (no socket needed) — feed raw request
bytes straight into `handle_payload`; see git history message
"flowlogic PASS" for the exact assertions used previously
(single-shot + split delivery + password-absence).

## Acceptance criteria for "done"

```
[ ] smoke exits 0 on the real el6 VM (or root-fallback path verified + noted)
[ ] py_compile passes under python 2.6 for BOTH scripts
[ ] live capture emits valid JSONL with correct user= attribution
[ ] events visible in hub API tagged source_probe=pcap-http
[ ] spool/retry proven (hub down → disk, hub up → delivered)
[ ] install → service active → uninstall verified-clean, all exit 0
[ ] any deviation from modern-kernel behavior documented below
```

## Deviations log (append findings here)

| Date | Finding | Action |
|---|---|---|
| 2026-08-26 | initial kit validated on modern kernel only | this file created |
| 2026-08-26 | **py2.6 runtime proven**: both scripts py_compile OK under 2.6.6, but nt-sniff crashed at first packet — `ip[0] & 0x0F` TypeError (str-index yields 1-char str on py2) | fixed in nt-sniff.py: added `b2i()` helper (ord() on py2) at the 4 byte-index sites; `fl.buf.extend(bytearray(payload))` for bytearray.extend(str) which also fails on py2.6 |
| 2026-08-26 | smoke FAIL was only missing tcpdump; el6 yum is dead (mirrorlist.centos.org EOL) | installed tcpdump from vault.centos.org 6.8 repo (https); smoke then 6/6 PASS incl. rootless capture under SELinux Enforcing |
| 2026-08-26 | installer: `sniff.log` redirect runs as ntsniff inside su -c but file didn't exist and PREFIX is root:root 755 → "Permission denied", service start failed | fixed in install-oldkernel.sh: touch/chown sniff.log right after mkdir of /var/lib/networktracing |
| 2026-08-26 | installer: setcap ran BEFORE chown on python-capnetraw → **chown silently stripped cap_net_raw** (getcap empty), sniffer got EPERM on AF_PACKET as ntsniff | fixed: chown first, then setcap. NEVER setcap-then-chown |
| 2026-08-26 | init script started sniffer and shipper as separate processes — sniffer stdout went to sniff.log, shipper stdin saw instant EOF → events never shipped ("0 events pending") | fixed: start block now launches one pipeline `sniffer | nt-ship` (su-wrapped sniffer stage when rootless); verified testuser event flows node→hub end-to-end |
| 2026-08-26 | full lifecycle re-run post-fixes: --check 0, install 0 (rootless as ntsniff), status running, e2e event `testuser /e2e-final` visible in hub API tagged pcap-http, spool+retry proven (dead endpoint → disk → recovered), uninstall exit 0 "verified clean" | acceptance criteria all met on real 2.6.32-642.el6 |
| 2026-08-26 | **CRITICAL shipper bug (found by load test)**: nt-ship.py never cleared its buffer after a SUCCESSFUL flush — every flush re-posted all previous events (dup factor grew to ~30x), POST payloads ballooned quadratically, flush timeouts triggered backoff, backoff slept up to 60s WITHOUT draining stdin, sniffer blocked on full pipe, AF_PACKET rcvbuf saturated at 125KB and the kernel dropped packets. Under 20k req/7min this yielded only 498/20000 unique events delivered | fixed: `del buf[:MAX_BATCH]` on success; backoff sleep capped at 0.5s so stdin always drains; spool now re-folded into batches ~once/min instead of only at startup; EOF drain-retry loop with RETRY_MAX |
| 2026-08-26 | **LOAD TEST RESULTS** (2 vCPU/2GB el6 VM): sustained 20k req / 421s (~48 rps): server 20000/20000, sniffer CPU ~2.6% of one core, socket queue Rmem=0 throughout, spool empty, zero loss. BURST 20k req in 26s (~770 rps): server unaffected, shipper delivered every event it received with 0 failures, but sniffer emitted only 14401/20000 — kernel AF_PACKET drops during the spike; python loop ceiling is roughly 1.5-2k pps total wire packets | sustained profile is SAFE for production; for burst tolerance add SO_ATTACH_FILTER BPF (TCP+port filter in kernel) and/or larger SO_RCVBUF in nt-sniff.py |
| 2026-08-26 | hub API limitation discovered: /api/events caps responses at newest 5000 rows, offset ignored, probe param not a real filter; kyanos flood evicts rows from the visible window — hub-side completeness counting of large runs is unreliable | verify completeness VM-side: httpd access-log count vs shipper flushed-sum vs spool-empty + rmem samples |
| 2026-08-26 | ops note: pkill/pgrep -f patterns self-match the invoking shell's cmdline if the pattern string appears in it — killed our own SSH sessions twice during testing | use `[n]t-sniff`-style brackets or kill by PID |
| 2026-08-26 | **first-run installer built**: hub mirrors can lag behind fixes (stale nt-sniff.py crashed the first-run install), so `build-firstrun.sh` now produces `install-firstrun-el68.sh` — a single self-contained file with the patched sniffer+shipper embedded as base64. Kit resolution order: local bundle → embedded payload → hub download. Verified on bare VM dir: install → service running rootless → `firstrunuser` event end-to-end in hub | rebuild after every kit change: `sh build-firstrun.sh`; one-liner: `curl -sSf http://HUB:30105/oldkernel/install-firstrun-el68.sh \| sh -s -- --endpoint http://HUB:31115` (once uploaded to hub) |
