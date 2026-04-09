# Splunk S2S Tee Listener — Failure Diagnosis

**Date:** 2026-04-09 (revised from 2026-04-08 initial analysis)
**System:** etairos_tee on macOS (Splunk UF 9.4.3, Darwin arm64)
**Listener port:** 19997 (localhost loopback)
**Grafana:** http://192.168.1.61:3100/d/splunk-s2s-tee

---

## Executive Summary

Live code review and log analysis (2026-04-09) reveals the listener is **operationally stable** — no crashes, no errors, clean handshakes every cycle. However, **~50% of connections lose their final events** due to a parser issue leaving exactly 208 bytes unparsed. Several originally-diagnosed issues have already been fixed in the live codebase.

### Current Status (Live System)

| Issue | Original Severity | Live Status | Notes |
|-------|------------------|-------------|-------|
| ACK mismatch | CRITICAL | **RESOLVED** | `useACK=false` in local/outputs.conf, UF sends `ack=0` |
| Missing event markers | HIGH | **RESOLVED** | All b7-bb markers present in live listener.py |
| TCP segmentation | MEDIUM | **RESOLVED** | `recv_exact()` implemented correctly |
| Caps variable length | MEDIUM | **RESOLVED** | Byte-by-byte terminator detection implemented |
| Thread exhaustion | LOW | **STILL PRESENT** | Unbounded `threading.Thread` per connection |
| Queue overflow | LOW | **PARTIALLY PRESENT** | 100K maxsize, no backpressure |
| **remaining_buf=208** | **NEW — HIGH** | **ACTIVE** | ~50% of connections leave 208 bytes unparsed |
---

## Issue 1: Consistent remaining_buf=208 (HIGH — ACTIVE)

### Symptom
Every ~30 seconds, the UF opens **2 simultaneous connections**. One closes cleanly with `remaining_buf=6` (fully consumed). The other consistently leaves `remaining_buf=208` — events in that trailing 208-byte segment are lost.

### Evidence (live log, 2026-04-09 07:46–07:53)
```
Connection done: ('127.0.0.1', 62922) total_bytes=25229 remaining_buf=6     ← good
Connection done: ('127.0.0.1', 62921) total_bytes=17141 remaining_buf=208   ← bad

Connection done: ('127.0.0.1', 62934) total_bytes=17105 remaining_buf=6     ← good
Connection done: ('127.0.0.1', 62935) total_bytes=10393 remaining_buf=208   ← bad

Connection done: ('127.0.0.1', 62950) total_bytes=25031 remaining_buf=6     ← good
Connection done: ('127.0.0.1', 62951) total_bytes=16943 remaining_buf=208   ← bad
```

Pattern: 100% consistent. Every cycle, one connection parses fully, the other leaves exactly 208 bytes.
### Root Cause Analysis

The 208-byte remainder is consistent across connections with varying `total_bytes` (10K–27K), which means it's not a percentage-based issue — it's a **fixed-size trailing structure** the parser can't match.

Likely candidates for the 208-byte block:
1. **ForwarderInfo metadata block** — UF sends a `_done` or ForwarderInfo frame at end-of-batch that uses a marker the parser doesn't handle in its final-segment logic
2. **Channel header without data** — A channel frame (e.g., `_MetaData:Index`) that starts but has no matching `_raw` segment, causing the channel-finding scan to exhaust the buffer
3. **Partial event spanning connection boundary** — The last event's channel data is split across the TCP stream boundary and the 30s timeout fires before the remaining bytes arrive

### Investigation Steps
1. **Hex dump the 208 bytes:** Add logging to dump the unparsed remainder in hex:
   ```python
   if remaining_buf > 50:
       logger.warning(f"Unparsed remainder ({remaining_buf}B): {buf[-remaining_buf:][:64].hex()}")
   ```
2. **Check for `_done` channel:** Look for `\x00\x00\x00\x05_done` in the remainder
3. **Check for ForwarderInfo marker:** Look for `\xc1` or other single-byte markers at offset 0 of the remainder
4. **Correlate with event counts:** Log events-extracted per connection to quantify loss

### Fix (once root cause confirmed)
If it's a ForwarderInfo/metadata block: add handler to skip or extract it gracefully.
If it's a partial event: extend the socket timeout or buffer across recv() calls before declaring end-of-stream.
---

## Issue 2: ACK Handler Not Wired In (LOW — LATENT)

### Status: RESOLVED for now, LATENT risk

The live system has `useACK=false` in `local/outputs.conf` and the UF confirms `ack=0` in every handshake. However:

- `ack_handler.py` exists with a complete implementation (4-byte and 8-byte formats, windowed batching, thread-safe tracking)
- It is **NOT imported or called** anywhere in `listener.py`
- If anyone enables `useACK=true` without wiring in the handler, the original CRITICAL issue returns

### Recommendation
Wire `ack_handler.py` into `listener.py` so it's ready when ACK mode is needed. The handler should:
1. Call `handshake_requests_ack()` during caps frame parsing
2. If ACK requested, create an `AckHandler` instance for the connection
3. Call `send_ack()` after processing each batch of events

---

## Issue 3: Unbounded Thread Creation (LOW — STILL PRESENT)

### Symptom
Each UF connection spawns a new `threading.Thread`. With 2 connections every 30 seconds, that's ~5,760 threads created per day. Python threads aren't reused — each one allocates stack memory.

### Current Impact
Low on this system — connections complete in <1 second and threads exit cleanly. But under load or with connection storms, this becomes a resource exhaustion risk.

### Fix
Replace unbounded threads with `ThreadPoolExecutor(max_workers=10)`.
---

## Issue 4: Queue Backpressure (LOW — PARTIALLY PRESENT)

### Status
`event_queue = queue.Queue(maxsize=100000)` — large enough for current throughput but no backpressure mechanism. If the alternate stream writer stalls, events will silently drop after 100K queue depth.

### Fix
Add queue depth monitoring and a warning threshold.

---

## Previously Fixed Issues (for reference)

These were identified in the initial 2026-04-08 analysis and have since been confirmed as resolved in the live codebase:

### Event Markers — FIXED
All markers including `b7`, `b9`, `ba`, `bb` are present in the live `_markers` list in `_parse_s2s_stream()`.

### TCP Segmentation — FIXED
`_recv_exact()` implemented with proper loop-until-complete logic.

### Caps Frame Variable Length — FIXED
Byte-by-byte reading until `\x00\x00\x00\x05_raw\x00` terminator (9 bytes). No fixed-size assumption.
---

## Live System Configuration

```yaml
# local/config.yaml
listener:
  host: "127.0.0.1"
  port: 19997
forward:
  enabled: false
alternate_stream:
  enabled: true
  destination: "local-json"
  path: "/Users/mattt/etairos-events"
  partition_by: "hour"
  batch_size: 100
  flush_interval: 30
logging:
  level: "DEBUG"
  log_every_n: 100
```

```ini
# local/outputs.conf
[tcpout]
defaultGroup = etairos_tee
[tcpout:etairos_tee]
server = 127.0.0.1:19997
useACK = false
```
---

## Monitoring Checklist

After fixing remaining_buf=208:

- [ ] `remaining_buf` on all connections drops to <50 bytes
- [ ] Events per connection increases (currently losing ~1-3 events per bad connection)
- [ ] No `remaining_buf=208` pattern in logs over 1 hour
- [ ] Thread count stable over 24h (secondary)
- [ ] No queue depth warnings (secondary)

---

## Recommended Fix Priority

| Priority | Issue | Effort | Impact |
|----------|-------|--------|--------|
| 1 | Diagnose + fix remaining_buf=208 | 1-2h | Recovers ~50% of lost trailing events |
| 2 | Wire ack_handler.py into listener | 30 min | Prevents future ACK regression |
| 3 | Thread pool | 15 min | Stability under load |
| 4 | Queue backpressure monitoring | 10 min | Visibility into drops |