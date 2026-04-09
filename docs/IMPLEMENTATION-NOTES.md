# Implementation Notes — S2S Listener

## Architecture

```
┌─────────────────┐      ┌───────────────────┐      ┌─────────────────┐
│  Splunk UF      │──S2S─▶│  etairos_tee     │──────▶│  Destinations   │
│  (Forwarder)    │      │  (Listener)       │      │  - JSONL files  │
│  Port 9997      │◀─────│  Port 19997       │      │  - S3/MinIO     │
└─────────────────┘      └───────────────────┘      │  - Kafka        │
                                                    │  - HTTP webhook │
                                                    └─────────────────┘
```

The listener:
1. Accepts S2S connections from UF on port 19997
2. Completes the S2S v3 handshake (hello + caps + IX response)
3. Parses the channel-multiplexed event stream
4. Writes events to configured destinations
## Key Files

| File | Purpose |
|------|---------|
| `listener.py` | Core S2S protocol handler |
| `start_listener.py` | Launcher script (sets up logging, paths) |
| `alternate_stream_writer.py` | Destination writer (JSONL, S3, etc.) |
| `ocsf_mapper.py` | OCSF v1.1 schema transformation |
| `ack_handler.py` | S2S ACK responder (implemented, not yet wired in) |
| `etairos_tee.sh` | Shell wrapper for Splunk scripted input |
| `config.yaml` | Listener and destination configuration |

## Configuration

### outputs.conf (UF)

Point the UF at the tee listener:

```ini
[tcpout]
defaultGroup = etairos_tee

[tcpout:etairos_tee]
server = 127.0.0.1:19997
useACK = false
compressed = false
```

**IMPORTANT:** `useACK` must be `false`. The `ack_handler.py` module exists with a complete
implementation but is not yet wired into `listener.py`. Enabling ACK mode will cause the UF
to wait for ACK responses that never come, triggering connection cycling and event duplication.
### config.yaml (Listener)

```yaml
listener:
  host: "127.0.0.1"
  port: 19997

alternate_stream:
  enabled: true
  destination: "local-json"
  path: "/path/to/output"
  partition_by: "hour"
  batch_size: 100
  flush_interval: 30
```

## Handshake Sequence

```
UF                          Listener
 │                              │
 │──── 400-byte hello ─────────▶│
 │                              │ Parse hostname, mgmt port
 │──── Variable caps frame ────▶│
 │                              │ Read byte-by-byte until terminator
 │◀─── 163-byte IX response ────│
 │                              │ Send canned response
 │──── Event data stream ──────▶│
 │                              │ Parse channels, extract events
 │                              │
```
## Critical Implementation Details

### 1. recv_exact() — TCP Segmentation Handling

TCP may deliver the handshake across multiple segments. The listener uses
`_recv_exact()` which loops until exactly N bytes are received:

```python
def _recv_exact(self, sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data
```

### 2. Caps Frame Terminator

The capabilities frame is variable-length. Read byte-by-byte until you see:

```python
CAPS_TERMINATOR = bytes.fromhex("000000055f72617700")
```

This is `\x00\x00\x00\x05_raw\x00` — a 9-byte sequence at the end of every caps frame.

**Do NOT assume 68 bytes.** Different UF versions may send different capability strings.
The live system consistently sees 68 bytes, but this will change with UF upgrades.

### 3. IX Response

The indexer response is a fixed 163-byte frame captured from Splunk 9.1:

```python
IX_RESPONSE = bytes.fromhex(
    "0000009f00000001000000125f5f7332735f636f6e74726f6c5f6d7367"
    "00000000746361705f726573706f6e73653d737563636573733b"
    "6361705f666c7573685f6b65793d747275653b"
    "6964785f63616e5f73656e645f68623d747275653b"
    "6964785f63616e5f726563765f746f6b656e3d747275653b"
    "76343d747275653b6368616e6e656c5f6c696d69743d3330303b"
    "706c3d360000000000000000055f72617700"
)
```
### 4. Channel Parsing

Events are NOT in 8-byte framed packets. The stream is channel-multiplexed:

```
1-byte channel_len | channel_name | event_data | 1-byte channel_len | ...
```

Scan for valid channel markers:
- Length byte 1-32
- Name starts with `_`
- Name contains only alphanumeric, `:`, `_`, `-`, `.`

Known channels: `_raw`, `_path`, `_MetaData:Index`, `_MetaData:Host`, `_MetaData:Sourcetype`

### 5. Event Markers (Complete List)

Events within `_MetaData:Index` segments are delimited by these markers:

**2-byte markers:**
- `\xa1\x01` — most common, standard event boundary
- `\xca\x01`, `\xca\x05` — alternate event boundary
- `\xc1\x01`, `\xc1\x05` — alternate event boundary
- `\xfe\x01` — alternate event boundary

**1-byte markers (discovered April 2026):**
- `\xc1` — ForwarderInfo events
- `\xb7` — splunkd.log events
- `\xb9` — metrics.log events
- `\xba` — mixed event segments
- `\xbb` — mixed event segments

The parser selects the most-frequent marker per segment for splitting, with
single-byte fallback (`\xca`, `\xc1`, `\xa1`).

### 6. Binary Cleanup

Event text often has trailing binary metadata. Trim at:
- First high byte (`\xff`, `\xfe`, `\xa1`, etc.) after a newline
- Printability ratio filter (>85% printable = valid event text)
- Minimum length filter (>5 chars, >10 chars after timestamp split)
## Running the Listener

### As a Splunk scripted input (recommended):

The app's `inputs.conf` starts `etairos_tee.sh` which calls:
```bash
$SPLUNK_HOME/bin/splunk cmd python3 $APP_DIR/bin/start_listener.py
```

### Why `splunk cmd python3`?

- Uses Splunk's bundled Python (correct version)
- Sets up correct `sys.path` for Splunk SDK imports
- Ensures compatible library versions

### Logs

- Main log: `$SPLUNK_HOME/var/log/splunk/etairos_tee.log`
- Debug stream dump: `/tmp/s2s_live_stream.bin` (first 32KB of each connection)

## Output Format

Events are written as JSONL with hive-style partitioned paths:

```
/output/year=2026/month=04/day=09/hour=06/ocsf_20260409_063000_12345.jsonl
```

Each line is a JSON object:

```json
{
  "_time": 1712567890.123,
  "_raw": "04-09-2026 06:30:00.123 +0000 INFO [component] Log message here",
  "host": "Mac.lucashouse.info",
  "source": "/Applications/SplunkForwarder/var/log/splunk/splunkd.log",
  "sourcetype": "splunkd",
  "index": "main"
}
```
## Troubleshooting

| Symptom | Check | Fix |
|---------|-------|-----|
| App not starting | `splunk list inputstatus` | Verify `etairos_tee.sh` is executable |
| UF not connecting | `lsof -i :19997` | Check outputs.conf points to 127.0.0.1:19997 |
| Handshake hangs | Caps frame hex in log | Verify terminator detection |
| No events extracted | `remaining_buf` in log | Check event markers, see below |
| Binary garbage in events | Printability ratio | Adjust >85% threshold |
| Connection cycling | UF splunkd.log | Ensure `useACK=false` in outputs.conf |
| remaining_buf=208 | Every other connection | See Active Issues below |

## Performance

Observed metrics (Mac M1, UF 9.4.3, loopback):

- Connections: ~4 per minute (2 simultaneous every 30s)
- Events per connection: 1-20 (depends on log volume)
- Parse rate: ~99% of bytes consumed on good connections
- Latency: <1 second from UF receive to file write
- Caps frame: consistently 68 bytes (ack=0; compression=0)

## Protocol Version Selection (v2 vs v3)

The tee controls which S2S version the UF uses by what it sends in the IX response.

**Default (v3):** Send the full 163-byte IX response with `v4=true;channel_limit=300;pl=6`.
The UF uses S2S v3 channel-multiplexed framing.

**v2 fallback:** Send a stripped-down IX response without v3/v4 capability flags.
The UF falls back to S2S v2 framing (simpler 8-byte length-prefixed frames).

The `negotiateNewProtocol=false` and `negotiateProtocolLevel=0` UF settings do NOT
reliably force v2. The receiver's response is what drives the negotiation.

Each UF output group negotiates independently — your production indexer group can
use v3 while the tee group uses v2, simultaneously, with no conflict.
## Active Issues (as of 2026-04-09)

### remaining_buf=208 on ~50% of connections

Every 30-second cycle, the UF opens 2 simultaneous connections. One parses cleanly
(`remaining_buf=6`), the other consistently leaves exactly 208 bytes unparsed.

**Impact:** Events in the trailing 208-byte segment are lost (~1-3 events per bad connection).

**Likely cause:** A fixed-size trailing structure (ForwarderInfo or `_done` frame) the
channel parser can't match because the "find next channel marker" scan exhausts the buffer.

**Next step:** Add hex dump logging of the 208-byte remainder to identify the structure:
```python
if len(raw_buf) > 50:
    self.logger.warning(f"Unparsed remainder ({len(raw_buf)}B): {raw_buf[:64].hex()}")
```

### ACK handler wired in (2026-04-09)

`ack_handler.py` is now imported and wired into `listener.py`. The handler:
- Reads `ack` config from config.yaml (auto/true/false mode)
- Checks the UF caps frame for `ack=1` when mode is `auto`
- Creates a per-connection `AckHandler` that sends fake 4-byte or 8-byte ACK responses
- Calls `record_event()` per extracted event and `flush()` on connection close
- `useACK=true` in outputs.conf now works correctly in both standalone and Splunk app modes

### Unbounded thread creation

Each connection spawns a new `threading.Thread`. At 4 connections/minute, this is
~5,760 threads/day. Should be replaced with `ThreadPoolExecutor(max_workers=10)`.

## Known Limitations

1. **No compression** — `compressed=false` required. S2S compression not implemented.

2. **Binary log formats filtered** — conf.log, btool.log, etc. are binary and excluded
   by the printability filter (>85% printable chars required).

3. **Source path truncation** — Minor cosmetic bug, path may be truncated by a few
   characters due to channel re-use in the UF.

4. **Single-host hostname** — `host` field is hardcoded to the hostname seen in the
   first handshake. In multi-UF proxy mode this would need per-connection tracking.