# etairos-log-agent

Splunk S2S tee proxy. Sits between your Universal Forwarders and your existing Splunk indexer. Receives the UF stream, writes events locally (for lakehouse migration, testing, etc.), and simultaneously forwards the raw byte stream to your real indexer — unchanged.

```
[Splunk UF] --> [etairos-log-agent :9997] --> [Real Splunk Indexer :9997]
                                           \-> [output file / S3 / lakehouse]
```

No Splunk license required. No changes to the UF except updating `outputs.conf` to point at this host. The indexer sees identical data.

## Requirements

- Python 3.7+
- No external dependencies (stdlib only)
- Linux host with network access to both UFs and the real indexer

## Quick Start

### 1. Update UF outputs.conf

```ini
[tcpout]
defaultGroup = etairos-tee

[tcpout:etairos-tee]
server = <log-agent-host-ip>:9997
```

Restart UF (`$SPLUNK_HOME/bin/splunk restart`). Events will flow through the agent.

### 2. Run the agent

**Unencrypted (testing):**
```bash
python3 agent.py \
  --port 9997 \
  --output /var/log/etairos/events.log \
  --forward splunk-indexer.corp:9997
```

**TLS inbound from UF, plain forward to indexer:**
```bash
python3 agent.py \
  --port 9997 \
  --output /var/log/etairos/events.log \
  --forward splunk-indexer.corp:9997 \
  --tls --cert server.crt --key server.key
```

**TLS both directions:**
```bash
python3 agent.py \
  --port 9997 \
  --output /var/log/etairos/events.log \
  --forward splunk-indexer.corp:9997 \
  --tls --cert server.crt --key server.key \
  --forward-tls --forward-cert client.crt --forward-key client.key --forward-ca ca.crt
```

**Local output only (no forwarding — for isolated testing):**
```bash
python3 agent.py --port 9997 --output /var/log/etairos/events.log
```

## Output Format

One line per event:
```
[2026-04-07T19:40:00+00:00] host=webserver01 source=/var/log/syslog sourcetype=syslog | Apr  7 14:38:01 webserver01 sshd[1234]: Accepted publickey for user
```

## Forwarding Behavior

| Situation | `--fail-open` (default) | `--fail-closed` |
|-----------|------------------------|-----------------|
| Indexer unreachable | Drop frames, keep writing locally | Buffer in memory until reconnect |
| Indexer recovers | Reconnects automatically | Drains buffer, then live |

The forwarder reconnects automatically on failure. Local file output is never interrupted by indexer connectivity issues.

## TLS Cert Generation (self-signed, for testing)

```bash
# CA
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -subj "/CN=EtairosCA"

# Server cert (for inbound from UF)
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=log-agent"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256

# Client cert (for outbound to indexer, if required)
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=etairos-agent"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256
```

## Run as a systemd Service

```ini
# /etc/systemd/system/etairos-log-agent.service
[Unit]
Description=Etairos Log Agent
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/etairos-log-agent/agent.py \
  --port 9997 \
  --output /var/log/etairos/events.log \
  --forward splunk-indexer.corp:9997
Restart=always
RestartSec=5
User=etairos
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now etairos-log-agent
sudo journalctl -u etairos-log-agent -f
```

## Migration Pattern (Splunk -> Lakehouse)

1. Deploy agent on a dedicated Linux host
2. Update UF `outputs.conf` to point at agent
3. Agent writes events to local file AND forwards to Splunk (no data loss)
4. Validate local file matches Splunk — compare event counts, spot-check events
5. When confident: update output destination (S3, Delta Lake, Iceberg, etc.)
6. Once lakehouse is validated: remove `--forward` to stop sending to Splunk
7. Decommission Splunk indexer on your timeline
