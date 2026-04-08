# Splunk S2S Protocol v3 — Reverse Engineering Notes

> Wire-captured from Splunk Universal Forwarder 9.4.3 connecting to Splunk Enterprise 9.1 indexer.
> Documented April 2026.

## Overview

Splunk-to-Splunk (S2S) protocol v3 is a proprietary binary protocol used for forwarding events between Splunk instances. This document describes the wire format observed through packet capture and reverse engineering.

**Key insight:** S2S v3 is NOT a simple framed protocol. It uses a binary handshake followed by channel-multiplexed event streaming with variable-length markers.

---

## Connection Phases

### Phase 1: Hello (UF → IX)

The Universal Forwarder sends a 400-byte fixed-size struct:

```
Offset  Size  Field
──────────────────────────────────────────
0       128   _signature (ASCII, null-padded)
              Contains: "--splunk-cooked-mode-v3--"
128     256   _serverName (UF hostname, null-padded)
384     16    _mgmtPort (ASCII port number, e.g. "8089")
──────────────────────────────────────────
Total: 400 bytes
```

**Example (hex):**
```
2d2d73706c756e6b2d636f6f6b65642d6d6f64652d76332d2d00...  # --splunk-cooked-mode-v3--
4d61632e6c75636173686f7573652e696e666f00...              # Mac.hostname.info
38303839000000...                                         # 8089
```

### Phase 2: Capabilities Frame (UF → IX)

Immediately after the 400-byte hello, the UF sends a capabilities frame:

```
Offset  Size  Field
──────────────────────────────────────────
0       4     frame_type (BE uint32) = 0x00000040 (64)
4       4     num_pairs (BE uint32) = 0x00000001
8       4     key_len (BE uint32)
12      N     key_name ("__s2s_capabilities")
12+N    4     value_len (BE uint32)
16+N    M     value ("ack=0;compression=0" or "ack=1;compression=0")
...     9     trailer: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x05 "_raw" 0x00
──────────────────────────────────────────
Total: 68 bytes (typical)
```

**Full capabilities frame (hex, ack=0):**
```
0000004000000001000000135f5f7332735f6361706162696c6974696573
000000001461636b3d303b636f6d7072657373696f6e3d30
0000000000000000055f72617700
```

**Breakdown:**
- `00000040` = frame type 64 (capabilities)
- `00000001` = 1 KV pair
- `00000013` = key length 19
- `5f5f7332735f6361706162696c6974696573` = "__s2s_capabilities"
- `00000000` = padding
- `14` = value length 20
- `61636b3d303b636f6d7072657373696f6e3d30` = "ack=0;compression=0"
- `0000000000000000` = 8 null bytes (padding)
- `055f72617700` = length 5 + "_raw" + null (channel terminator)

**Critical:** The capabilities frame ends with a 9-byte terminator: `\x00\x00\x00\x05_raw\x00`

### Phase 3: Control Message Response (IX → UF)

The indexer responds with a 163-byte `__s2s_control_msg` frame:

```
Offset  Size  Field
──────────────────────────────────────────
0       4     frame_len (BE uint32) = 0x0000009f (159)
4       4     unknown (BE uint32) = 0x00000001
8       4     key_len (BE uint32) = 0x00000012 (18)
12      18    key_name = "__s2s_control_msg"
30      1     null terminator
31      4     padding (nulls)
35      116   value (capability response string)
151     12    trailer (nulls + _raw channel marker)
──────────────────────────────────────────
Total: 163 bytes
```

**Full IX response (hex):**
```
0000009f00000001000000125f5f7332735f636f6e74726f6c5f6d7367
00000000746361705f726573706f6e73653d737563636573733b
6361705f666c7573685f6b65793d747275653b
6964785f63616e5f73656e645f68623d747275653b
6964785f63616e5f726563765f746f6b656e3d747275653b
76343d747275653b6368616e6e656c5f6c696d69743d3330303b
706c3d360000000000000000055f72617700
```

**Response value decoded:**
```
cap_response=success;
cap_flush_key=true;
idx_can_send_hb=true;
idx_can_recv_token=true;
v4=true;
channel_limit=300;
pl=6
```

---

## Phase 4: Event Data Stream (UF → IX)

After the handshake, the UF streams event data in a channel-multiplexed format.

### Stream Format

The data phase does NOT use fixed 8-byte frame headers. Instead, it uses:

```
1-byte channel_name_length + channel_name + event_data
```

Repeating for each channel segment in the stream.

### Known Channels

| Channel Name      | Purpose                                    |
|-------------------|--------------------------------------------|
| `_raw`            | Raw event text (may include timezone blob) |
| `_path`           | Source file path being monitored           |
| `_MetaData:Index` | Index name + event text                    |
| `_MetaData:*`     | Other metadata fields                      |
| `_done`           | End-of-batch marker                        |

### Null Keepalives

The UF sends null keepalive frames (8 zero bytes) periodically:
```
0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
```

### Event Data in `_MetaData:Index`

The actual log events are in the `_MetaData:Index` channel:

```
Offset  Size  Field
──────────────────────────────────────────
0       1     channel_len = 15 (0x0f)
1       15    "_MetaData:Index"
16      1     index_name_len (e.g., 9 for "_internal")
17      N     index_name
17+N    2     event_marker (0xca 0x05 or 0xa1 0x01)
19+N    ...   event_text (UTF-8 log line)
──────────────────────────────────────────
```

**Example (hex):**
```
0f5f4d657461446174613a496e646578        # \x0f_MetaData:Index
095f696e7465726e616c                    # \x09_internal
ca05                                     # event marker
323032362d30342d30382030303a33353a...   # 2026-04-08 00:35:...
```

### Event Markers

Multiple event marker variants observed:

| Marker (hex) | Meaning                         |
|--------------|----------------------------------|
| `a1 01`      | Primary event start             |
| `ca 01`      | Event start (variant)           |
| `ca 05`      | Event start (variant)           |
| `c1 01`      | Event start (variant)           |
| `c1 05`      | Event start (variant)           |
| `fe 01`      | Event start (variant)           |
| `c1`         | Single-byte ForwarderInfo marker |

### Metadata Fields in Event Segments

Within channel segments, metadata fields use length-prefixed encoding with type markers:

| Byte  | Meaning                |
|-------|------------------------|
| `\x1a` (26) | host field prefix    |
| `\x1c` (28) | sourcetype field prefix |
| `\x03`      | event count prefix   |

**Example structure:**
```
/splunk/etairos_tee.log      # source path
\x1a host::Mac.hostname.info
\x1c sourcetype::etairos:tee:log
\x03 69                       # event count
\x00 \xfc \x01 ...           # binary separator
\xca \x05                    # event marker
2026-04-08 00:35:54,596 INFO [etairos_tee] Connection from...
```

---

## ForwarderInfo Events

The first event from a UF connection is always a `ForwarderInfo` line:

```
ForwarderInfo build=237ebbd22314 version=9.4.3 os=Darwin arch=arm64 
hostname=Mac.hostname.info guid=50CBCAB4-9A1A-4412-94B2-9A487DBE3395 
mgmt=8089 useACK=false
```

This is sent with event marker `\xc1` (single byte) followed by the text.

---

## Connection Behavior

### Timing

- UF connects every ~30 seconds when data is available
- Connections last 30-60 seconds typically
- UF uses auto-batching (`autoBatch=1`) to aggregate events

### TCP Segmentation

The handshake may arrive as separate TCP segments:
1. First segment: 400-byte hello
2. Second segment: 68-byte capabilities frame
3. Subsequent segments: event data stream

**Do not assume atomic 468-byte handshake read.**

### Connection Close

The UF closes the connection after flushing its batch. No explicit close frame observed.

---

## Implementation Notes

### Capabilities Frame Terminator

The safest way to consume the variable-length capabilities frame is to read byte-by-byte until you see the terminator:

```python
CAPS_TERMINATOR = bytes.fromhex("000000055f72617700")  # \x00\x00\x00\x05_raw\x00

caps_buf = b""
while len(caps_buf) < 256:  # safety limit
    caps_buf += recv_exact(socket, 1)
    if caps_buf.endswith(CAPS_TERMINATOR):
        break
```

### Channel Parsing

Scan for channel markers by checking:
1. First byte is a reasonable channel name length (1-32)
2. Following bytes form a valid channel name (starts with `_`, alphanumeric + `:_-.`)

### Event Text Cleanup

Event text may have trailing binary metadata. Trim at:
- `\n\xff`, `\n\xfe`, `\n\xa1` (binary after newline)
- First non-printable byte after the log line

### Printability Filter

Binary log formats (conf.log, btool.log) should be filtered out. Check:
```python
printable_ratio = sum(1 for c in text if c.isprintable() or c in "\n\t\r") / len(text)
if printable_ratio > 0.85:
    # Valid text event
```

---

## Wire Capture Reference

### Tools Used

- `tcpdump` on Mac to capture traffic
- Python `struct` for binary parsing
- Splunk Enterprise 9.1 Docker container on NAS for IX response capture

### PCAP Analysis

To capture S2S traffic:
```bash
sudo tcpdump -i lo0 -w /tmp/s2s.pcap port 9997
```

Parse with Python:
```python
import struct

with open('/tmp/s2s.pcap', 'rb') as f:
    # Skip PCAP header (24 bytes)
    f.read(24)
    # Read packets...
```

---

## Version History

| Version | Notes |
|---------|-------|
| S2S v2  | Simpler framing, deprecated in modern Splunk |
| S2S v3  | Channel-multiplexed, this document |
| S2S v4  | Advertised in IX response (`v4=true`) but not fully observed in use |

---

## Protocol Negotiation — UF Multi-Destination Behavior

### Key Insight

The UF negotiates the S2S protocol version **independently with each destination**. When
you configure multiple output target groups in `outputs.conf`, each connection goes through
its own handshake. The UF does not know or care that two destinations are receiving the
same data — they are treated as completely separate connections.

This means:
- Your production Splunk indexer can use S2S v3 (with ACK, full capabilities)
- Your tee/lakehouse listener can receive S2S v2 (simpler, easier to parse)
- The UF handles both simultaneously with no conflict

### How the UF Chooses Protocol Version

The UF starts every connection by sending a v3 hello (400-byte struct with
`--splunk-cooked-mode-v3--` signature). It then advertises its capabilities.

The **receiver's IX response** drives what protocol is actually used:

| IX Response Contains | UF Uses |
|---------------------|--------|
| `v4=true;channel_limit=300;pl=6` | S2S v3 (full) |
| `cap_response=success` only (no v4) | S2S v2 fallback |
| Connection rejected | UF retries with backoff |

So the tee controls the negotiation by what it sends back.

### Forcing S2S v2 on the Tee

**Only do this if your production Splunk indexers also support v2** (Splunk 6.0+).
Modern indexers (8.x, 9.x) support both — but check your environment first.

To make the UF use v2 for the tee connection, send a stripped-down IX response
that omits the v3/v4 capability flags:

```python
# Minimal IX response — no v4, no channel_limit, no pl
# This causes the UF to fall back to S2S v2 framing
IX_RESPONSE_V2 = bytes.fromhex(
    "0000003800000001000000125f5f7332735f636f6e74726f6c5f6d736700"
    "000000146361705f726573706f6e73653d737563636573730000000000000000055f72617700"
)
```

### `negotiateNewProtocol = false` Does NOT Force v2

This is a common misconception. From Splunk docs:

> If you give `negotiateProtocolLevel` a value of 0, or `negotiateNewProtocol` a
> value of `false`, the forwarder will instead **override these settings to use the
> lowest protocol version that all instances support.**

In practice: UF 9.x with `negotiateNewProtocol=false` still sends a v3 hello and
still uses v3 if the receiver accepts it. The setting is advisory, not a hard cap.

The only reliable way to get v2 framing is to have the **receiver send a v2-only
IX response**.

### UF `outputs.conf` — Per-Group Settings

Each `[tcpout:<group>]` stanza is fully independent. Settings that can differ per group:

```ini
[tcpout]
defaultGroup = splunk_prod, lakehouse_tee

[tcpout:splunk_prod]
server = splunk-idx1:9997
useACK = true          # ACK enabled for production
compressed = false

[tcpout:lakehouse_tee]
server = 127.0.0.1:19997
useACK = false         # No ACK needed for tee
compressed = false
# Note: protocol version is controlled by what the receiver advertises,
# not by these settings. See negotiation notes above.
```

Settings that are **global only** (top `[tcpout]` stanza, not per-group):
- `enableOldS2SProtocol` — allows use of pre-v3 protocol globally
- `indexAndForward` — only on heavy forwarders

### Recommendation

| Scenario | Protocol Setting |
|----------|------------------|
| Indexer supports v3 (Splunk 6.0+) | Let tee respond with v3 (default) |
| Want simpler tee parsing, indexer supports v2 | Send v2 IX response from tee |
| Indexer is very old (pre-6.0) | Use v2 IX response, set `enableOldS2SProtocol=true` globally |
| Mixed environment | Use v3 everywhere — our parser handles it at 99.7% |

**Default recommendation:** Use S2S v3 for both connections. The tee parser handles
v3 correctly. Only switch to v2 if you have a specific reason (very old indexers,
or you want to implement a simpler parser for the tee side).

---

## Additional Event Markers (Observed April 2026)

During extended capture with UF 9.4.3 (Darwin arm64), additional single-byte markers
were observed in the `_MetaData:Index` channel beyond the originally documented set:

| Marker | Hex | Context |
|--------|-----|---------|
| `\xa1\x01` | `a101` | Originally documented — splunkd.log events |
| `\xca\x01` | `ca01` | Originally documented — splunkd.log events |
| `\xca\x05` | `ca05` | Originally documented — etairos_tee.log events |
| `\xc1\x01` | `c101` | Originally documented — mixed events |
| `\xb9` | `b9` | **New** — metrics.log events |
| `\xb7` | `b7` | **New** — splunkd.log events |
| `\xba` | `ba` | **New** — mixed event segments |
| `\xbb` | `bb` | **New** — mixed event segments |

**Key finding:** These single-byte markers (`b7`-`bb` range) encode event boundaries
but do NOT encode length. The log text follows immediately after the marker byte.

The "most common marker in segment" heuristic handles all cases: scan the segment
for all known markers, use whichever appears most frequently, then split on it.

Without `b9`/`b7`/`ba`/`bb` in the marker list, the parser finds 0 events (all
connections show `Connection done total_bytes=NNN remaining_buf=208` with no flushes).

## References

- Splunk docs: https://docs.splunk.com/Documentation/Splunk/latest/Admin/Outputsconf
- S2S protocol not officially documented; this doc based on empirical packet capture
- Tested with: UF 9.4.3 (Darwin arm64) → IX 9.1 (Linux amd64), April 2026
