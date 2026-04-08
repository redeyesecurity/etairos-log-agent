# Etairos Log Agent — Data Flow Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                         DATA SOURCES                                                     │
├─────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                          │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│   │  Linux       │    │  Windows     │    │  Network     │    │  Cloud       │    │  App         │      │
│   │  Servers     │    │  Servers     │    │  Devices     │    │  Services    │    │  Servers     │      │
│   │              │    │              │    │              │    │              │    │              │      │
│   │ • auth.log   │    │ • WinEvent   │    │ • Cisco ASA  │    │ • AWS VPC    │    │ • Apache     │      │
│   │ • syslog     │    │ • Security   │    │ • Palo Alto  │    │ • GCP Audit  │    │ • nginx      │      │
│   │ • auditd     │    │ • Sysmon     │    │ • Fortinet   │    │ • Azure AD   │    │ • IIS        │      │
│   └──────┬───────┘    └──────┬───────┘    └──────┬───────┘    └──────┬───────┘    └──────┬───────┘      │
│          │                   │                   │                   │                   │              │
└──────────┼───────────────────┼───────────────────┼───────────────────┼───────────────────┼──────────────┘
           │                   │                   │                   │                   │
           ▼                   ▼                   ▼                   ▼                   ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   SPLUNK UNIVERSAL FORWARDERS                                            │
├─────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                          │
│   ┌─────────────────────────────────────────────────────────────────────────────────────────────┐       │
│   │                              Splunk UF (existing infrastructure)                             │       │
│   │                                                                                              │       │
│   │    inputs.conf              outputs.conf                                                     │       │
│   │    ───────────              ────────────                                                     │       │
│   │    [monitor://...]          [tcpout:etairos]                                                │       │
│   │    sourcetype = ...         server = <agent-ip>:9997    ◄── ONLY CHANGE REQUIRED            │       │
│   │                             useACK = true (optional)                                         │       │
│   │                                                                                              │       │
│   └─────────────────────────────────────────────────────────────────────────────────────────────┘       │
│                                                                                                          │
│           │                                                                                              │
│           │ S2S Protocol (proprietary Splunk wire format)                                               │
│           │ • TLS optional (configurable)                                                                │
│           │ • ACK optional (agent fakes ACKs if needed)                                                  │
│           ▼                                                                                              │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────┘
           │
           │
           ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                                          │
│   ╔═════════════════════════════════════════════════════════════════════════════════════════════════╗   │
│   ║                                                                                                  ║   │
│   ║                               ETAIROS LOG AGENT                                                  ║   │
│   ║                               (Python 3.7+ / Docker)                                             ║   │
│   ║                                                                                                  ║   │
│   ╠══════════════════════════════════════════════════════════════════════════════════════════════════╣   │
│   ║                                                                                                  ║   │
│   ║   ┌─────────────────┐                                                                            ║   │
│   ║   │   LISTENER      │  Port 9997 (configurable)                                                  ║   │
│   ║   │   agent.py      │  • Decodes S2S wire protocol                                               ║   │
│   ║   │                 │  • Extracts: host, source, sourcetype, _time, _raw                         ║   │
│   ║   │                 │  • TLS termination (optional)                                              ║   │
│   ║   └────────┬────────┘                                                                            ║   │
│   ║            │                                                                                     ║   │
│   ║            ▼                                                                                     ║   │
│   ║   ┌─────────────────┐                                                                            ║   │
│   ║   │   ACK HANDLER   │  ack_handler.py                                                            ║   │
│   ║   │                 │  • Responds to useACK=true UFs                                             ║   │
│   ║   │                 │  • Prevents UF buffering/retransmit                                        ║   │
│   ║   │                 │  • Modes: auto | simple | extended                                         ║   │
│   ║   └────────┬────────┘                                                                            ║   │
│   ║            │                                                                                     ║   │
│   ║            ▼                                                                                     ║   │
│   ║   ┌─────────────────────────────────────────────────────────────────────────────────────────┐   ║   │
│   ║   │                            EVENT PROCESSING PIPELINE                                     │   ║   │
│   ║   │                                                                                          │   ║   │
│   ║   │   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐           │   ║   │
│   ║   │   │  DECODE     │────►│  NORMALIZE  │────►│  OCSF MAP   │────►│  DISPATCH   │           │   ║   │
│   ║   │   │             │     │             │     │             │     │             │           │   ║   │
│   ║   │   │ S2S binary  │     │ Parse _raw  │     │ ocsf_mapper │     │ Fan-out to  │           │   ║   │
│   ║   │   │ → structs   │     │ Extract     │     │ .py         │     │ all outputs │           │   ║   │
│   ║   │   │             │     │ fields      │     │             │     │             │           │   ║   │
│   ║   │   └─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘           │   ║   │
│   ║   │                                                                                          │   ║   │
│   ║   └─────────────────────────────────────────────────────────────────────────────────────────┘   ║   │
│   ║            │                                                                                     ║   │
│   ║            │                                                                                     ║   │
│   ║   ┌────────┴────────────────────────────────────────────────────────────────────────────────┐   ║   │
│   ║   │                                    OUTPUT FANOUT                                         │   ║   │
│   ║   │                        (all outputs can run simultaneously)                              │   ║   │
│   ║   └────────┬───────────────────────┬───────────────────────┬────────────────────────────────┘   ║   │
│   ║            │                       │                       │                                    ║   │
│   ╚════════════╪═══════════════════════╪═══════════════════════╪════════════════════════════════════╝   │
│                │                       │                       │                                        │
└────────────────┼───────────────────────┼───────────────────────┼────────────────────────────────────────┘
                 │                       │                       │
    ┌────────────┴────────────┐          │          ┌────────────┴────────────┐
    │                         │          │          │                         │
    ▼                         ▼          │          ▼                         ▼
┌─────────────────┐   ┌─────────────────┐│   ┌─────────────────┐   ┌─────────────────┐
│   OUTPUT 1      │   │   OUTPUT 2      ││   │   OUTPUT 3      │   │   OUTPUT 4      │
│   ───────────   │   │   ───────────   ││   │   ───────────   │   │   ───────────   │
│                 │   │                 ││   │                 │   │                 │
│   FORWARD TO    │   │   LOCAL FILE    ││   │   LOCAL         │   │   S3 PARQUET    │
│   SPLUNK        │   │   (decoded)     ││   │   PARQUET/JSON  │   │   ALTERNATE_STREAM     │
│                 │   │                 ││   │                 │   │                 │
│   Raw S2S       │   │   events.log    ││   │   OCSF format   │   │   OCSF format   │
│   passthrough   │   │   one-liner     ││   │   Hive partitions│  │   Hive partitions│
│                 │   │   per event     ││   │                 │   │                 │
│   forward:      │   │   output:       ││   │   alternate_stream:    │   │   alternate_stream:    │
│     enabled:    │   │     file:       ││   │     dest: local │   │     dest: s3    │
│     true        │   │     /var/log/.. ││   │     -parquet    │   │                 │
│                 │   │                 ││   │                 │   │                 │
└────────┬────────┘   └────────┬────────┘│   └────────┬────────┘   └────────┬────────┘
         │                     │         │            │                     │
         ▼                     ▼         │            ▼                     ▼
┌─────────────────┐   ┌─────────────────┐│   ┌─────────────────┐   ┌─────────────────────────────────┐
│                 │   │                 ││   │                 │   │                                 │
│  SPLUNK         │   │  LOCAL DISK     ││   │  LOCAL DISK     │   │  AWS S3 / MinIO / R2            │
│  INDEXER        │   │                 ││   │                 │   │                                 │
│                 │   │  /var/log/      ││   │  /var/log/      │   │  s3://bucket/prefix/            │
│  (unchanged     │   │  etairos/       ││   │  etairos/       │   │    class_uid=4002/              │
│   data flow)    │   │  events.log     ││   │  alternate_stream/     │   │      year=2026/                 │
│                 │   │                 ││   │    class_uid=   │   │        month=04/                │
│                 │   │  Format:        ││   │      4002/      │   │          day=07/                │
│                 │   │  [ts] host=     ││   │      year=      │   │            *.parquet            │
│                 │   │  source= |      ││   │        2026/... │   │                                 │
│                 │   │  raw_event      ││   │                 │   │                                 │
│                 │   │                 ││   │  *.parquet      │   │                                 │
│                 │   │                 ││   │  *.jsonl        │   │                                 │
└─────────────────┘   └─────────────────┘│   └─────────────────┘   └─────────────────────────────────┘
                                         │
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                                          │
│                                        OCSF EVENT CLASSES                                                │
│                                        (output schema)                                                   │
│                                                                                                          │
├─────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                          │
│   ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐                 │
│   │  AUTHENTICATION │   │  NETWORK        │   │  DNS ACTIVITY   │   │  HTTP ACTIVITY  │                 │
│   │  class_uid=4002 │   │  ACTIVITY       │   │  class_uid=3001 │   │  class_uid=3003 │                 │
│   │                 │   │  class_uid=3005 │   │                 │   │                 │                 │
│   │  • SSH login    │   │                 │   │  • DNS queries  │   │  • Web requests │                 │
│   │  • Windows auth │   │  • Firewall     │   │  • DNS answers  │   │  • API calls    │                 │
│   │  • LDAP bind    │   │  • VPN sessions │   │  • Umbrella     │   │  • Proxy logs   │                 │
│   │  • RADIUS       │   │  • NetFlow      │   │                 │   │                 │                 │
│   └─────────────────┘   └─────────────────┘   └─────────────────┘   └─────────────────┘                 │
│                                                                                                          │
│   ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐                 │
│   │  PROCESS        │   │  FILE SYSTEM    │   │  SECURITY       │   │  UNKNOWN        │                 │
│   │  ACTIVITY       │   │  ACTIVITY       │   │  FINDING        │   │  class_uid=0    │                 │
│   │  class_uid=6001 │   │  class_uid=1001 │   │  class_uid=2001 │   │                 │                 │
│   │                 │   │                 │   │                 │   │  • Unmapped     │                 │
│   │  • Process exec │   │  • File create  │   │  • IDS alerts   │   │    sourcetypes  │                 │
│   │  • Sysmon       │   │  • File modify  │   │  • EDR findings │   │  • Raw events   │                 │
│   │  • WinEvent     │   │  • auditd       │   │  • Snort/Suricata│  │    preserved    │                 │
│   └─────────────────┘   └─────────────────┘   └─────────────────┘   └─────────────────┘                 │
│                                                                                                          │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────┘


┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                                          │
│                                      DEPLOYMENT OPTIONS                                                  │
│                                                                                                          │
├─────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                          │
│   OPTION A: Shadow Mode (Dual-Write)                                                                    │
│   ───────────────────────────────────                                                                   │
│                                                                                                          │
│   ┌──────┐          ┌─────────────┐          ┌──────────────┐                                           │
│   │  UF  │ ───S2S──►│   Agent     │───S2S───►│   Splunk     │   ◄── Production unchanged               │
│   └──────┘          │             │          │   Indexer    │                                           │
│                     │             │          └──────────────┘                                           │
│                     │             │                                                                      │
│                     │             │───OCSF───►┌──────────────┐                                          │
│                     └─────────────┘           │   Alternate Stream  │   ◄── Test alternate_stream pipeline            │
│                                               └──────────────┘                                           │
│                                                                                                          │
│   Config:  forward.enabled: true  |  alternate_stream.enabled: true                                            │
│   Risk:    Zero — agent is transparent tee                                                               │
│                                                                                                          │
│                                                                                                          │
│   OPTION B: Alternate Stream Only (Post-Migration)                                                             │
│   ──────────────────────────────────────────                                                            │
│                                                                                                          │
│   ┌──────┐          ┌─────────────┐          ┌──────────────┐                                           │
│   │  UF  │ ───S2S──►│   Agent     │───OCSF──►│   Alternate Stream  │   ◄── All events to alternate_stream            │
│   └──────┘          └─────────────┘          └──────────────┘                                           │
│                                                                                                          │
│   Config:  forward.enabled: false  |  alternate_stream.enabled: true                                           │
│   Risk:    Low — rollback = repoint UF at indexer                                                        │
│                                                                                                          │
│                                                                                                          │
│   OPTION C: High Availability (Multi-Agent)                                                             │
│   ──────────────────────────────────────────                                                            │
│                                                                                                          │
│   ┌──────┐          ┌─────────────┐          ┌──────────────┐                                           │
│   │  UF  │ ──┬─────►│  Agent 1    │───OCSF──►│              │                                           │
│   └──────┘   │      └─────────────┘          │   Alternate Stream  │                                           │
│              │                               │   (S3)       │                                           │
│              │      ┌─────────────┐          │              │                                           │
│              └─────►│  Agent 2    │───OCSF──►│              │   ◄── Load balancer / DNS RR              │
│                     └─────────────┘          └──────────────┘                                           │
│                                                                                                          │
│   Config:  UF outputs.conf with multiple servers                                                         │
│   Risk:    Low — UF handles failover automatically                                                       │
│                                                                                                          │
│                                                                                                          │
│   OPTION D: Edge Deployment (On-Prem + Cloud)                                                           │
│   ───────────────────────────────────────────                                                           │
│                                                                                                          │
│   ┌────────────────────────────────────┐     ┌────────────────────────────────────┐                     │
│   │          ON-PREM DATACENTER        │     │              AWS / CLOUD           │                     │
│   │                                    │     │                                    │                     │
│   │  ┌──────┐     ┌─────────────┐      │     │      ┌─────────────────────────┐   │                     │
│   │  │  UF  │────►│   Agent     │──────┼─────┼─────►│   S3 Alternate Stream          │   │                     │
│   │  └──────┘     │  (local)    │      │     │      │   (cross-account OK)    │   │                     │
│   │               └─────────────┘      │     │      └─────────────────────────┘   │                     │
│   │                     │              │     │                                    │                     │
│   │                     ▼              │     │                                    │                     │
│   │               ┌─────────────┐      │     │                                    │                     │
│   │               │  Local JSON │      │     │                                    │                     │
│   │               │  (backup)   │      │     │                                    │                     │
│   │               └─────────────┘      │     │                                    │                     │
│   │                                    │     │                                    │                     │
│   └────────────────────────────────────┘     └────────────────────────────────────┘                     │
│                                                                                                          │
│   Config:  alternate_stream.destination: s3  |  output.file: /local/backup                                     │
│   Benefit: Local backup + cloud alternate_stream                                                                │
│                                                                                                          │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────┘


┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                                          │
│                                      TLS / SECURITY OPTIONS                                              │
│                                                                                                          │
├─────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                          │
│   ┌──────────────────────────────────────────────────────────────────────────────────────────────┐      │
│   │                                                                                               │      │
│   │    ┌──────┐         TLS (optional)         ┌─────────────┐        TLS (optional)            │      │
│   │    │  UF  │ ─────────────────────────────► │   Agent     │ ──────────────────────────►      │      │
│   │    └──────┘    listener.tls.enabled:true   │             │    forward.tls.enabled:true      │      │
│   │                                            │             │                                   │      │
│   │         Certs: server.crt, server.key      │             │     Certs: client.crt, client.key│      │
│   │         CA: ca.crt (mutual auth)           │             │     CA: ca.crt (verify indexer)  │      │
│   │                                            └─────────────┘                                   │      │
│   │                                                                                               │      │
│   └──────────────────────────────────────────────────────────────────────────────────────────────┘      │
│                                                                                                          │
│   MODES:                                                                                                 │
│   • No TLS (testing):     listener.tls.enabled: false, forward.tls.enabled: false                       │
│   • Inbound TLS only:     listener.tls.enabled: true,  forward.tls.enabled: false                       │
│   • Outbound TLS only:    listener.tls.enabled: false, forward.tls.enabled: true                        │
│   • Full TLS:             listener.tls.enabled: true,  forward.tls.enabled: true                        │
│   • Mutual Auth:          + listener.tls.verify_client: true                                            │
│                                                                                                          │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────┘


┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                                          │
│                                      FAILOVER BEHAVIOR                                                   │
│                                                                                                          │
├─────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                          │
│   FAIL-OPEN (default):                                                                                  │
│   ────────────────────                                                                                  │
│                                                                                                          │
│   ┌──────┐     ┌─────────────┐        ✗        ┌──────────────┐                                         │
│   │  UF  │────►│   Agent     │───────────────►│   Splunk     │   (indexer down)                         │
│   └──────┘     │             │                 └──────────────┘                                          │
│                │             │                                                                           │
│                │             │───OCSF───►┌──────────────┐                                               │
│                └─────────────┘           │   Alternate Stream  │   ◄── Events still flow here                  │
│                                          └──────────────┘                                                │
│                                                                                                          │
│   • Frames to indexer are DROPPED                                                                        │
│   • Alternate Stream and local file continue receiving events                                                   │
│   • UF receives ACKs — no buffering                                                                      │
│   • Use case: alternate_stream is primary, Splunk is optional                                                   │
│                                                                                                          │
│                                                                                                          │
│   FAIL-CLOSED:                                                                                           │
│   ────────────                                                                                           │
│                                                                                                          │
│   ┌──────┐     ┌─────────────┐        ✗        ┌──────────────┐                                         │
│   │  UF  │────►│   Agent     │───────────────►│   Splunk     │   (indexer down)                         │
│   └──────┘     │  [BUFFER]   │                 └──────────────┘                                          │
│                │   queue     │                        │                                                  │
│                │  100K max   │                        │ (reconnect loop)                                 │
│                │             │                        ▼                                                  │
│                │             │───OCSF───►┌──────────────┐                                               │
│                └─────────────┘           │   Alternate Stream  │   ◄── Events still flow here                  │
│                                          └──────────────┘                                                │
│                                                                                                          │
│   • Frames queued in memory (up to queue_max)                                                            │
│   • Agent retries indexer every reconnect_delay seconds                                                  │
│   • When indexer recovers, queue drains                                                                  │
│   • If queue full, oldest frames dropped                                                                 │
│   • Use case: Splunk is primary, must not lose events                                                    │
│                                                                                                          │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Quick Reference: Config → Behavior

| Goal | Config |
|------|--------|
| **UF multi-output** (recommended) | UF `outputs.conf` with two target groups; tee: `forward.enabled: false` |
| **Proxy mode** (inline forwarding) | `forward.enabled: true`, `forward.host: splunk-idx` |
| **Tee only** (no Splunk) | `forward.enabled: false`, `alternate_stream.enabled: true` |
| **Local files only** (debugging) | `forward.enabled: false`, `alternate_stream.enabled: false`, `output.file: /path` |
| **S3 lakehouse** | `alternate_stream.destination: s3`, fill `alternate_stream.s3.*` |
| **Local Parquet** | `alternate_stream.destination: local-parquet` |
| **Local JSON** | `alternate_stream.destination: local-json` |
| **Kafka** | `alternate_stream.destination: kafka`, fill `alternate_stream.kafka.*` |
| **TLS everywhere** | `listener.tls.enabled: true`, `forward.tls.enabled: true` |
| **Fail-closed** | `forward.failover.mode: fail-closed` |

## OCSF Class Mapping Summary

| Sourcetype Pattern | → OCSF Class (class_uid) |
|-------------------|--------------------------|
| `linux_secure`, `wineventlog:security`, SSH | Authentication (4002) |
| `cisco:asa`, `pan:traffic`, firewall | Network Activity (3005) |
| `stream:dns`, `cisco:umbrella:dns` | DNS Activity (3001) |
| `apache:access`, `nginx:access`, `iis` | HTTP Activity (3003) |
| `sysmon`, `wineventlog:system`, process | Process Activity (6001) |
| `auditd`, `linux:audit` | File System Activity (1001) |
| `snort`, `suricata`, `crowdstrike` | Security Finding (2001) |
| Everything else | Unknown (0) |
