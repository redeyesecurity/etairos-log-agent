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
| `ocsf_mapper.py` | Optional OCSF schema transformation |
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

### config.yaml (Listener)

```yaml
listener:
  host: "127.0.0.1"
  port: 19997

alternate_stream:
  enabled: true
  destination: "local-json"
  path: "/path/to/output"
  partition_by: ["year", "month", "day", "hour"]
```

## Handshake Sequence

```
UF                          Listener
 │                              │
 │──── 400-byte hello ─────────▶│
 │                              │ Parse hostname, mgmt port
 │──── 68-byte caps frame ─────▶│
 │                              │ Read until terminator
 │◀─── 163-byte IX response ────│
 │                              │ Send canned response
 │──── Event data stream ──────▶│
 │                              │ Parse channels, extract events
 │                              │
```

## Critical Implementation Details

### 1. Caps Frame Terminator

The capabilities frame is variable-length. Read byte-by-byte until you see:

```python
CAPS_TERMINATOR = bytes.fromhex("000000055f72617700")
```

This is `\x00\x00\x00\x05_raw\x00` — a 9-byte sequence at the end of every caps frame.

**Do NOT assume 68 bytes.** Different UF versions may send different capability strings.

### 2. IX Response

The indexer response is a fixed 163-byte frame. Send this exact hex:

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

This was captured from a real Splunk 9.1 indexer.

### 3. Channel Parsing

Events are NOT in 8-byte framed packets. The stream is channel-multiplexed:

```
1-byte channel_len | channel_name | event_data | 1-byte channel_len | ...
```

Scan for valid channel markers:
- Length byte 1-32
- Name starts with `_`
- Name contains only alphanumeric, `:`, `_`, `-`, `.`

### 4. Event Markers

Look for these 2-byte markers to find event boundaries:
- `\xa1\x01`
- `\xca\x01`, `\xca\x05`
- `\xc1\x01`, `\xc1\x05`
- `\xfe\x01`

Single-byte `\xc1` marks ForwarderInfo events.

### 5. Binary Cleanup

Event text often has trailing binary metadata. Trim at:
- First high byte (`\xff`, `\xfe`, `\xa1`, etc.) after a newline
- Or check printability ratio (>85% printable = valid)

## Running the Listener

### As a background process (recommended):

```bash
sudo nohup /Applications/SplunkForwarder/bin/splunk cmd python3 \
    /Applications/SplunkForwarder/etc/apps/etairos_tee/bin/start_listener.py \
    > /tmp/etairos_tee.log 2>&1 &
```

### Why `splunk cmd python3`?

- Uses Splunk's bundled Python (correct version)
- Sets up correct `sys.path` for Splunk SDK imports
- Ensures compatible library versions

### Logs

- Main log: `/tmp/etairos_tee.log` (or configured path)
- Debug stream dump: `/tmp/s2s_live_stream.bin` (first 32KB of each connection)

## Output Format

Events are written as JSONL with partitioned paths:

```
/output/year=2026/month=04/day=08/hour=06/ocsf_20260408_063000_12345.jsonl
```

Each line is a JSON object:

```json
{
  "_time": 1712567890.123,
  "_raw": "2026-04-08 06:30:00 INFO [component] Log message here",
  "host": "Mac.lucashouse.info",
  "source": "/Applications/SplunkForwarder/var/log/splunk/splunkd.log",
  "sourcetype": "splunkd",
  "index": "main"
}
```

## Troubleshooting

### UF not connecting

1. Check `outputs.conf` points to correct host:port
2. Verify listener is running: `lsof -i :19997`
3. Check UF logs: `/Applications/SplunkForwarder/var/log/splunk/splunkd.log`

### Handshake hangs

- Caps terminator not being recognized
- Check for correct 9-byte terminator match
- Enable debug logging to see caps frame hex

### No events extracted

- Channel parsing misaligned
- Check event markers being searched
- Dump raw stream and analyze with hex editor

### Binary garbage in events

- Event text cleanup not trimming properly
- Add more separator patterns to trim logic
- Filter by printability ratio

## Performance

Observed metrics (Mac M1, UF 9.4.3):

- Connections: ~2 per minute
- Events per connection: 1-20 (depends on log volume)
- Parse rate: ~99.7% of bytes consumed
- Latency: <1 second from UF receive to file write

## Protocol Version Selection (v2 vs v3)

The tee controls which S2S version the UF uses by what it sends in the IX response.

**Default (v3):** Send the full 163-byte IX response with `v4=true;channel_limit=300;pl=6`.
The UF uses S2S v3 channel-multiplexed framing. Tee parser handles this at ~99.7%.

**v2 fallback:** Send a stripped-down IX response without v3/v4 capability flags.
The UF falls back to S2S v2 framing (simpler 8-byte length-prefixed frames).

**Important:** Only enable v2 on the tee if your production Splunk indexers **also
support v2**. Modern indexers (8.x, 9.x) support both, but verify before changing.

```python
# In listener.py, to request v2 framing from the UF:
# Replace IX_RESPONSE with this stripped version:
IX_RESPONSE_V2 = bytes.fromhex(
    "0000003800000001000000125f5f7332735f636f6e74726f6c5f6d736700"
    "000000146361705f726573706f6e73653d737563636573730000000000000000055f72617700"
)
```

The `negotiateNewProtocol=false` and `negotiateProtocolLevel=0` UF settings do NOT
reliably force v2. The receiver's response is what drives the negotiation.

Each UF output group negotiates independently — your production indexer group can
use v3 while the tee group uses v2, simultaneously, with no conflict.

## Known Limitations

1. **No forwarding to downstream indexer** — This is a tee/tap, not a proxy. Use UF
   multi-output (`defaultGroup = splunk_idx, lakehouse_tee`) instead of proxy forwarding.

2. **No ACK support** — `useACK=false` required on the tee output group. ACK mode
   uses different framing that the tee does not implement.

3. **No compression** — `compressed=false` required. Compression not implemented.

4. **Binary log formats filtered** — conf.log, btool.log, etc. are binary and excluded
   by the printability filter (>85% printable chars required).

5. **Source path truncation** — Minor cosmetic bug, path may be truncated by a few
   characters due to channel re-use in the UF.
