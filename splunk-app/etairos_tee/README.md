# Etairos Tee - Splunk App

**S2S tee proxy that runs inside your Splunk Universal Forwarder.**

Intercepts UF output, forwards to your indexer unchanged, and simultaneously writes OCSF-formatted events to your lakehouse (S3, local Parquet, or local JSON).

## Why run inside the UF?

- **Single deployment** via Splunk Deployment Server
- **No separate service** to manage
- **Cross-platform** — same app works on Linux, Windows, macOS
- **Splunk handles restarts** and lifecycle
- **Uses UF's Python** — no additional runtime needed
- **Self-monitoring** — app logs are picked up by Splunk automatically

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SPLUNK UNIVERSAL FORWARDER                       │
│                                                                     │
│  ┌──────────────────┐      ┌────────────────────────────────────┐  │
│  │  inputs.conf     │      │  etairos_tee app                   │  │
│  │  [monitor://...] │      │                                    │  │
│  └────────┬─────────┘      │  bin/listener.py @ localhost:19997 │  │
│           │                │                                    │  │
│           ▼                │  • Receives S2S from UF            │  │
│  ┌──────────────────┐      │  • Forwards to real indexer        │  │
│  │  outputs.conf    │      │  • Maps to OCSF                    │  │
│  │  server=127.0.0.1│─────►│  • Writes to lakehouse             │  │
│  │  :19997          │      │                                    │  │
│  └──────────────────┘      └──────────────┬─────────────────────┘  │
│                                           │                        │
│  ┌──────────────────────────────────────┐ │                        │
│  │ var/log/splunk/etairos_tee.log      │◄┘  (self-monitoring)     │
│  └──────────────────────────────────────┘                          │
└───────────────────────────────────────────┬────────────────────────┘
                                            │
                    ┌───────────────────────┼───────────────────────┐
                    │                       │                       │
                    ▼                       ▼                       ▼
          ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
          │  Splunk Indexer  │   │  Local Parquet   │   │  S3 Lakehouse    │
          │  (unchanged)     │   │  /var/log/...    │   │  s3://bucket/... │
          └──────────────────┘   └──────────────────┘   └──────────────────┘
```

## Installation

### Option 1: Deployment Server (recommended)

1. Copy the `etairos_tee` folder to your deployment server:
   ```
   $SPLUNK_HOME/etc/deployment-apps/etairos_tee/
   ```

2. Create a serverclass for your UFs

3. Deploy — the app will start automatically

### Option 2: Manual install

1. Copy the `etairos_tee` folder to the UF:
   ```bash
   # Linux/macOS
   cp -r etairos_tee /opt/splunkforwarder/etc/apps/
   
   # Windows
   xcopy etairos_tee "C:\Program Files\SplunkUniversalForwarder\etc\apps\etairos_tee" /E /I
   ```

2. Edit configuration:
   ```bash
   cp /opt/splunkforwarder/etc/apps/etairos_tee/default/config.yaml \
      /opt/splunkforwarder/etc/apps/etairos_tee/local/config.yaml
   
   # Edit local/config.yaml — set your indexer host
   ```

3. Restart the UF:
   ```bash
   /opt/splunkforwarder/bin/splunk restart
   ```

## Configuration

Edit `local/config.yaml` (create from default if needed):

```yaml
listener:
  host: "127.0.0.1"
  port: 19997

forward:
  enabled: true
  host: "splunk-indexer.corp"   # REQUIRED
  port: 9997
  tls:
    enabled: false

lakehouse:
  enabled: true
  destination: "s3"             # s3 | local-parquet | local-json
  s3:
    bucket: "my-security-lake"
    prefix: "etairos/ocsf"
    region: "us-east-1"
  batch_size: 1000
  flush_interval: 60
```

### Destination options

| Destination | Dependencies | Use case |
|-------------|--------------|----------|
| `local-json` | None | Testing, small deployments |
| `local-parquet` | pyarrow | Local lakehouse, NAS |
| `s3` | pyarrow, boto3 | Cloud lakehouse |

### Installing dependencies

For Parquet/S3 support, install dependencies into the app's `lib/` folder:

```bash
# On a machine with pip
pip install pyarrow boto3 -t /path/to/etairos_tee/lib/

# Or download wheels and extract manually
```

## Logs

The app writes to `$SPLUNK_HOME/var/log/splunk/etairos_tee.log` which is automatically picked up by the UF's internal monitoring.

View logs:
```bash
# On the UF
tail -f /opt/splunkforwarder/var/log/splunk/etairos_tee.log

# Or in Splunk (after forwarding)
index=_internal sourcetype=etairos:tee:log
```

## Troubleshooting

### App not starting

Check the scripted input status:
```bash
/opt/splunkforwarder/bin/splunk list inputstatus
```

Check Splunk's logs:
```bash
tail -f /opt/splunkforwarder/var/log/splunk/splunkd.log | grep etairos
```

### Events not flowing

1. Verify the listener is running:
   ```bash
   netstat -tlnp | grep 19997
   ```

2. Check outputs.conf is pointing to the local listener:
   ```bash
   cat /opt/splunkforwarder/etc/apps/etairos_tee/default/outputs.conf
   ```

3. Check etairos_tee.log for errors

### Forward not working

Make sure `forward.host` is set in `local/config.yaml`

### S3 writes failing

- Check IAM permissions (s3:PutObject on your bucket)
- Or set explicit access_key/secret_key in config
- Check etairos_tee.log for boto3 errors

## Windows notes

- Same app structure works on Windows
- Paths use forward slashes in config (Python handles conversion)
- Logs go to: `C:\Program Files\SplunkUniversalForwarder\var\log\splunk\etairos_tee.log`
- Python path: `C:\Program Files\SplunkUniversalForwarder\bin\python.exe`

## Files

```
etairos_tee/
├── default/
│   ├── app.conf        # App metadata
│   ├── inputs.conf     # Starts listener + monitors logs
│   ├── outputs.conf    # Routes UF to local listener
│   ├── props.conf      # Log parsing
│   └── config.yaml     # Default configuration
├── local/
│   └── config.yaml     # Your overrides (create this)
├── bin/
│   ├── start_listener.py   # Splunk entry point
│   ├── listener.py         # Main tee logic
│   └── ocsf_mapper.py      # OCSF conversion
├── lib/                    # Vendored dependencies (pyarrow, boto3)
└── README.md
```

## License

MIT
