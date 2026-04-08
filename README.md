# Splunk multi Log Agent

**A Splunk app that tees your Universal Forwarder output to any destination.**

Runs inside the UF as a scripted input. Intercepts the S2S data stream, converts events to OCSF format, and writes to one or more alternate destinations — while forwarding the original stream to your indexer unchanged.

```
┌──────────────────────────────────────────────────────────────────┐
│                  SPLUNK UNIVERSAL FORWARDER                      │
│                                                                  │
│  ┌────────────────┐     ┌──────────────────────────────────┐    │
│  │  Your existing │     │  etairos_tee (this app)          │    │
│  │  inputs.conf   │     │                                  │    │
│  └───────┬────────┘     │  Listens on localhost:19997      │    │
│          │              │  Uses UF's own Python binary     │    │
│          ▼              │  Logs to var/log/splunk/         │    │
│  ┌────────────────┐     │                                  │    │
│  │  outputs.conf  │────►│  1. Forward to real indexer      │    │
│  │  (points to    │     │  2. Convert to OCSF              │    │
│  │  localhost:    │     │  3. Write to alternate stream    │    │
│  │  19997)        │     │                                  │    │
│  └────────────────┘     └──────────────┬─────────────────-─┘    │
│                                        │                        │
└────────────────────────────────────────┼────────────────────────┘
                                         │
             ┌───────────────────────────┼───────────────────────┐
             │                           │                       │
             ▼                           ▼                       ▼
    ┌─────────────────┐       ┌─────────────────┐    ┌─────────────────┐
    │  Splunk Indexer │       │  S3 / Kafka /   │    │  Loki / ES /    │
    │  (unchanged)    │       │  local files    │    │  Webhook / ...  │
    └─────────────────┘       └─────────────────┘    └─────────────────┘
```

## Why a Splunk App?

Running inside the UF gives you something a standalone proxy cannot: **natural horizontal scale**.

Each UF handles its own tee instance locally. 1000 UFs means 1000 independent tee processes, each processing one host's worth of traffic over loopback. There is no central bottleneck, no HA to design, no load balancer to maintain. Scale is automatic because it matches your existing UF footprint.

The only shared resource is your destination (S3, Kafka, etc.) — and those are designed for concurrent writes.

## Installation

### Option 1: Deployment Server (recommended for production)

1. Copy the app to your deployment server:
   ```
   $SPLUNK_HOME/etc/deployment-apps/etairos_tee/
   ```

2. Create a serverclass targeting your UFs

3. Configure: create `local/config.yaml` with your indexer host and destination settings (see Configuration below)

4. Deploy — the app starts automatically on each UF

### Option 2: Manual install

```bash
# Linux / macOS
cp -r splunk-app/etairos_tee /opt/splunkforwarder/etc/apps/

# Windows
xcopy splunk-app\etairos_tee "C:\Program Files\SplunkUniversalForwarder\etc\apps\etairos_tee" /E /I
```

Then configure and restart:
```bash
cp /opt/splunkforwarder/etc/apps/etairos_tee/default/config.yaml \
   /opt/splunkforwarder/etc/apps/etairos_tee/local/config.yaml

# Edit local/config.yaml — minimum: set forward.host

/opt/splunkforwarder/bin/splunk restart
```

### Verify it's running

```bash
# Check the listener is up
netstat -tlnp | grep 19997

# Watch the log
tail -f /opt/splunkforwarder/var/log/splunk/etairos_tee.log

# Or in Splunk search
index=_internal sourcetype=etairos:tee:log
```

## Configuration

All settings in `local/config.yaml` (create from `default/config.yaml`).

### Deployment Mode: UF Multi-Output vs Proxy Forwarding

You have two options for getting data to both Splunk and the lakehouse:

#### Option A: UF Multi-Output (Recommended)

Configure the UF to send to both destinations natively:

```ini
# outputs.conf on the UF
[tcpout]
defaultGroup = splunk_indexers, lakehouse_tee

[tcpout:splunk_indexers]
server = splunk-idx1:9997, splunk-idx2:9997

[tcpout:lakehouse_tee]
server = 127.0.0.1:19997
useACK = false
compressed = false
```

```yaml
# config.yaml for the tee
forward:
  enabled: false   # <-- tee only, no proxy forwarding

alternate_stream:
  enabled: true
  destination: "s3"  # or local-json, kafka, etc.
```

**Advantages:**
- No single point of failure — if tee dies, Splunk still gets data
- No added latency — parallel writes, not serial
- Splunk gets 100% original bytes untouched
- Simpler tee code — parse only, no forwarding logic

#### Option B: Proxy Forwarding

Tee sits inline and forwards to Splunk:

```
UF → Tee → Splunk Indexer
          └→ Lakehouse
```

```yaml
# config.yaml
forward:
  enabled: true
  host: "splunk-indexer.corp"
  port: 9997

alternate_stream:
  enabled: true
```

**Use when:**
- You can't modify UF outputs.conf (managed by deployment server you don't control)
- You need to filter/transform data before it reaches Splunk
- Single egress point is required (firewall rules)

### Minimum required (tee-only mode)

```yaml
forward:
  enabled: false

alternate_stream:
  enabled: true
  destination: "local-json"
  path: "/var/log/etairos/events"
```

### Enable an alternate destination

Each destination is a list entry under `alternate_stream.destinations`. Set `enabled: true` on whichever you want. Multiple destinations can run simultaneously.

```yaml
alternate_stream:
  enabled: true
  destinations:

    - type: "s3"
      enabled: true
      bucket: "my-security-events"
      prefix: "ocsf"
      region: "us-east-1"
      # access_key / secret_key optional — blank uses IAM role

    - type: "kafka"
      enabled: true
      brokers:
        - "kafka1:9092"
      topic: "security-events"

    - type: "loki"
      enabled: true
      url: "http://loki:3100/loki/api/v1/push"
      labels:
        job: "splunk-uf"
```

Full reference for all 11 destinations (S3, Kafka, Loki, Elasticsearch, Webhook, Syslog, local-json, local-parquet, Azure Event Hubs, GCP Pub/Sub, Splunk HEC) is in `default/config.yaml`.

### Dependencies

The core agent runs on Splunk's bundled Python with no extra packages. Specific destinations require additional libraries, vendored into `lib/`:

```bash
# S3 / local Parquet
pip install pyarrow boto3 -t splunk-app/etairos_tee/lib/

# Kafka
pip install confluent-kafka -t splunk-app/etairos_tee/lib/

# Loki / Webhook / Splunk HEC / Elasticsearch
pip install requests -t splunk-app/etairos_tee/lib/

# Elasticsearch (native client)
pip install elasticsearch -t splunk-app/etairos_tee/lib/

# Azure Event Hubs
pip install azure-eventhub -t splunk-app/etairos_tee/lib/

# GCP Pub/Sub
pip install google-cloud-pubsub -t splunk-app/etairos_tee/lib/
```

Local JSON and Syslog have no extra dependencies.

## Logs

The app writes to `$SPLUNK_HOME/var/log/splunk/etairos_tee.log`, which `inputs.conf` monitors automatically. Events show up in `index=_internal` on your indexer.

```
2026-04-07 16:00:01,234 INFO [etairos_tee] Listening on 127.0.0.1:19997
2026-04-07 16:00:05,891 INFO [etairos_tee] Connection from 127.0.0.1
2026-04-07 16:00:06,100 INFO [etairos_tee] Events: 500 received, 500 forwarded, 500 to alternate stream
```

## OCSF Mapping

Events are mapped to [OCSF v1.1](https://schema.ocsf.io) based on sourcetype:

| Sourcetype | OCSF Class |
|------------|------------|
| `linux_secure`, `wineventlog:security` | Authentication (4002) |
| `cisco:asa`, `pan:traffic`, `netflow` | Network Activity (3005) |
| `stream:dns`, `cisco:umbrella:dns` | DNS Activity (3001) |
| `apache:access`, `nginx:access`, `iis` | HTTP Activity (3003) |
| `sysmon`, `wineventlog:system` | Process Activity (6001) |
| `auditd`, `linux:audit` | File System Activity (1001) |
| `snort`, `suricata`, `crowdstrike` | Security Finding (2001) |
| Everything else | Unknown (0) |

Unknown events are still forwarded and written — they just carry `class_uid=0` with the raw event preserved.

## Windows

Same app, no changes required. Splunk's Python is cross-platform. Logs go to:
```
C:\Program Files\SplunkUniversalForwarder\var\log\splunk\etairos_tee.log
```

---

## Standalone Mode (Advanced)

> **This is not the primary deployment model.** The Splunk app is recommended for almost all cases. Standalone mode exists for environments where you cannot or do not want to deploy a Splunk app — for example, a non-Splunk forwarder, a custom pipeline, or a development environment.
>
> **Note:** The standalone agent has a simplified S2S v3 implementation. The Splunk app (`splunk-app/etairos_tee/bin/listener.py`) has the full wire-accurate parser with ~99.7% parse rate. If you need maximum fidelity, use the Splunk app or port its parser to standalone.

### When standalone makes sense

- You are not using Splunk UFs
- You want to run the tee on a dedicated proxy host
- You are testing/developing the agent itself

### Running standalone

```bash
cd standalone/
python3 agent.py --config config.yaml
```

Or as a systemd service:
```bash
sudo cp -r standalone/ /opt/etairos-log-agent/
sudo cp standalone/etairos-log-agent.service /etc/systemd/system/
sudo systemctl enable --now etairos-log-agent
```

### Throughput limits and tuning

Unlike the UF app model (where each host runs its own instance), a standalone agent is a single process handling traffic from multiple UFs. This creates a central bottleneck you need to size for.

**Realistic throughput per standalone instance:**

| Configuration | EPS | Notes |
|---------------|-----|-------|
| Forward only (no alternate stream) | 50,000+ | Network bound |
| + local JSON | 30,000 | Disk I/O bound |
| + local Parquet | 15,000 | pyarrow serialization |
| + S3 Parquet | 10,000 | S3 API latency |
| + Kafka | 25,000 | Producer buffer |

**Tuning for high volume:**

```yaml
# Larger batches = fewer destination write calls
alternate_stream:
  destinations:
    - type: "s3"
      batch_size: 5000       # default: 1000
      flush_interval: 300    # default: 60

# Reduce logging overhead at high EPS
logging:
  level: "WARNING"           # default: INFO
  log_every_n: 5000          # default: 500

# Increase forward queue if indexer has latency spikes
forward:
  failover:
    queue_max: 500000        # default: 100000
```

**Horizontal scaling:**

Point multiple UF output groups at separate agent instances using DNS round-robin or Splunk's native load balancing in `outputs.conf`:

```ini
[tcpout:etairos_pool]
server = agent1:9997, agent2:9997, agent3:9997
autoLB = true
```

**Rule of thumb:** If you are managing more than 20-30 UFs or expect sustained traffic above 10,000 EPS through a single agent, use the Splunk app model instead. The per-host distribution eliminates the bottleneck entirely.

---

## Files

```
etairos-log-agent/
├── splunk-app/
│   └── etairos_tee/                 # Primary deployment — deploy this
│       ├── default/
│       │   ├── app.conf
│       │   ├── inputs.conf          # Starts listener + monitors logs
│       │   ├── outputs.conf         # Routes UF to local listener
│       │   ├── props.conf           # Log parsing
│       │   └── config.yaml          # All configuration (full destination reference)
│       ├── local/                   # Your overrides go here (gitignored)
│       ├── bin/
│       │   ├── start_listener.py    # Splunk scripted input entry point
│       │   ├── listener.py          # S2S tee logic
│       │   ├── ocsf_mapper.py       # OCSF conversion
│       │   ├── alternate_stream_writer.py  # Destination writers
│       │   └── ack_handler.py       # Fake S2S ACK responder
│       └── lib/                     # Vendored dependencies (pyarrow, boto3, etc.)
├── standalone/                      # Advanced: run without Splunk
│   ├── agent.py                     # Entry point
│   ├── config.yaml
│   ├── ocsf_mapper.py
│   ├── alternate_stream_writer.py
│   ├── ack_handler.py
│   └── etairos-log-agent.service    # systemd unit
└── docs/
    ├── architecture-diagram.md
    ├── S2S-PROTOCOL-V3.md           # Wire protocol reverse engineering
    └── IMPLEMENTATION-NOTES.md      # Listener implementation details
```

## Protocol Documentation

The S2S v3 protocol was reverse-engineered from packet captures. See:

- **[S2S-PROTOCOL-V3.md](docs/S2S-PROTOCOL-V3.md)** — Complete wire format documentation
- **[IMPLEMENTATION-NOTES.md](docs/IMPLEMENTATION-NOTES.md)** — Listener implementation details

### Quick Protocol Summary

1. **Hello** (UF → IX): 400-byte fixed struct with hostname/port
2. **Capabilities** (UF → IX): Variable-length frame ending with `\x00\x00\x00\x05_raw\x00`
3. **Control Response** (IX → UF): 163-byte canned response
4. **Event Stream** (UF → IX): Channel-multiplexed data, NOT 8-byte framed

Key insight: Events are in `_MetaData:Index` channel segments, marked with `\xa1\x01` or `\xca\x05` bytes.

## License

MIT
