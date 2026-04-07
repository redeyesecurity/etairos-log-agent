#!/usr/bin/env python3
"""
Etairos Log Agent — S2S Tee Proxy
Sits between Splunk UF and your real indexer. Receives the UF stream,
decodes events for local output (file, future lakehouse), and simultaneously
forwards the raw bytes upstream to the real indexer unchanged.

Architecture:
  [Splunk UF] --> [etairos-log-agent :9997] --> [Real Splunk Indexer :9997]
                                             --> [output file / lakehouse]

Usage:
  python3 agent.py --config config.yaml
  python3 agent.py --config config.yaml --port 9998   # CLI overrides config
  python3 agent.py --help
"""

import socket
import ssl
import struct
import threading
import argparse
import logging
import os
import queue
import signal
import sys
import time
from datetime import datetime, timezone

# yaml is stdlib in Python 3.11+; fall back to a tiny inline parser for older versions
try:
    import yaml
    def load_yaml(path):
        with open(path) as f:
            return yaml.safe_load(f)
except ImportError:
    import re, json
    def load_yaml(path):
        # Minimal YAML -> dict for simple flat/nested key: value files
        # Handles strings, bools, ints; strips comments
        def parse_val(v):
            v = v.strip().strip('"').strip("'")
            if v.lower() == "true": return True
            if v.lower() == "false": return False
            try: return int(v)
            except ValueError: pass
            return v
        result = {}
        stack = [(result, -1)]
        with open(path) as f:
            for line in f:
                line = line.rstrip()
                if not line or line.lstrip().startswith("#"): continue
                indent = len(line) - len(line.lstrip())
                line = line.lstrip()
                if ":" not in line: continue
                key, _, val = line.partition(":")
                key = key.strip()
                val = val.strip()
                while len(stack) > 1 and stack[-1][1] >= indent:
                    stack.pop()
                parent = stack[-1][0]
                if not val or val.startswith("#"):
                    parent[key] = {}
                    stack.append((parent[key], indent))
                else:
                    val = val.split("#")[0].strip()
                    parent[key] = parse_val(val)
        return result


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)
log = logging.getLogger("etairos-log-agent")

S2S_SIGNATURE = b"--CH"
S2S_SIGNATURE_LEN = 128
shutdown_event = threading.Event()


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def deep_get(d, *keys, default=None):
    for k in keys:
        if not isinstance(d, dict): return default
        d = d.get(k, default)
    return d


class Config:
    def __init__(self, path=None, cli_args=None):
        raw = {}
        if path:
            raw = load_yaml(path)
            log.info(f"Loaded config from {path}")

        a = cli_args or {}

        # Inbound listener
        self.host       = a.get("host")    or deep_get(raw, "listener", "host",    default="0.0.0.0")
        self.port       = a.get("port")    or deep_get(raw, "listener", "port",    default=9997)

        # Inbound TLS
        itls = deep_get(raw, "listener", "tls") or {}
        self.tls            = a.get("tls")          or itls.get("enabled",      False)
        self.cert           = a.get("cert")          or itls.get("cert",         "")
        self.key            = a.get("key")           or itls.get("key",          "")
        self.ca             = a.get("ca")            or itls.get("ca",           "")
        self.verify_client  = itls.get("verify_client", False)
        self.ignore_ssl_in  = a.get("ignore_ssl")   or itls.get("ignore_ssl",   False)

        # Output
        out = deep_get(raw, "output") or {}
        self.output = a.get("output") or out.get("file", "extracted.log")

        # Forward
        fwd  = deep_get(raw, "forward")       or {}
        ftls = deep_get(raw, "forward", "tls") or {}
        fov  = deep_get(raw, "forward", "failover") or {}

        self.forward_enabled   = fwd.get("enabled", True) if not a.get("forward") else True
        _fwd_raw               = a.get("forward") or ""
        if _fwd_raw and ":" in _fwd_raw:
            fh, fp = _fwd_raw.rsplit(":", 1)
            self.forward_host  = fh
            self.forward_port  = int(fp)
        else:
            self.forward_host  = fwd.get("host", "")
            self.forward_port  = fwd.get("port", 9997)

        # Forward TLS
        self.forward_tls         = a.get("forward_tls")   or ftls.get("enabled",    False)
        self.forward_cert        = a.get("forward_cert")   or ftls.get("cert",       "")
        self.forward_key         = a.get("forward_key")    or ftls.get("key",        "")
        self.forward_ca          = a.get("forward_ca")     or ftls.get("ca",         "")
        self.forward_ignore_ssl  = a.get("ignore_ssl")     or ftls.get("ignore_ssl", False)

        # Failover
        self.fail_open         = (fov.get("mode", "fail-open") == "fail-open") \
                                  if not a.get("fail_closed") else False
        self.queue_max         = fov.get("queue_max",      100_000)
        self.reconnect_delay   = fov.get("reconnect_delay", 2)
        self.retry_forever     = fov.get("retry_forever",   True)
        self.max_retries       = fov.get("max_retries",     0)

        # Logging
        lg = deep_get(raw, "logging") or {}
        self.log_level    = lg.get("level",        "INFO")
        self.log_every_n  = lg.get("log_every_n",  500)

    def validate(self):
        if self.tls and (not self.cert or not self.key):
            raise ValueError("listener.tls.enabled requires cert and key paths")
        if self.forward_enabled and self.forward_host and self.forward_tls:
            if not self.forward_ignore_ssl and (not self.forward_cert or not self.forward_key):
                log.warning("forward.tls.enabled without cert/key — server auth only (no mutual TLS)")


# ---------------------------------------------------------------------------
# Socket helpers
# ---------------------------------------------------------------------------

def read_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionResetError("Connection closed mid-read")
        buf += chunk
    return buf


def send_all(sock, data):
    total = 0
    while total < len(data):
        sent = sock.send(data[total:])
        if sent == 0:
            raise ConnectionResetError("Forward socket closed")
        total += sent


# ---------------------------------------------------------------------------
# S2S decode
# ---------------------------------------------------------------------------

def decode_kv_block(data):
    fields = {}
    offset = 0
    while offset < len(data):
        if offset + 4 > len(data): break
        key_len = struct.unpack(">I", data[offset:offset+4])[0]
        offset += 4
        if key_len == 0 or offset + key_len > len(data): break
        key = data[offset:offset+key_len].decode("utf-8", errors="replace")
        offset += key_len
        if offset + 4 > len(data): break
        val_len = struct.unpack(">I", data[offset:offset+4])[0]
        offset += 4
        val = data[offset:offset+val_len].decode("utf-8", errors="replace")
        offset += val_len
        fields[key] = val
    return fields


def format_event(fields, fallback_ip):
    raw = fields.get("_raw", "") or \
          " | ".join(f"{k}={v}" for k, v in fields.items() if not k.startswith("_"))
    source     = fields.get("source",     "unknown")
    host       = fields.get("host",       fallback_ip)
    sourcetype = fields.get("sourcetype", "unknown")
    ts         = fields.get("_time", "") or datetime.now(timezone.utc).isoformat()
    return f"[{ts}] host={host} source={source} sourcetype={sourcetype} | {raw}\n"


# ---------------------------------------------------------------------------
# Forwarder
# ---------------------------------------------------------------------------

class Forwarder:
    def __init__(self, cfg: Config):
        self.host            = cfg.forward_host
        self.port            = cfg.forward_port
        self.tls             = cfg.forward_tls
        self.cert            = cfg.forward_cert
        self.key             = cfg.forward_key
        self.ca              = cfg.forward_ca
        self.ignore_ssl      = cfg.forward_ignore_ssl
        self.fail_open       = cfg.fail_open
        self.reconnect_delay = cfg.reconnect_delay
        self.retry_forever   = cfg.retry_forever
        self.max_retries     = cfg.max_retries
        self._q              = queue.Queue(maxsize=cfg.queue_max)
        self._sock           = None
        self._lock           = threading.Lock()
        self._attempt        = 0
        t = threading.Thread(target=self._drain, daemon=True, name="forwarder")
        t.start()

    def send(self, len_bytes, frame_data):
        payload = len_bytes + frame_data
        try:
            self._q.put_nowait(payload)
        except queue.Full:
            if self.fail_open:
                log.warning("Forward queue full — dropping frame (fail-open)")
            else:
                self._q.put(payload)

    def send_handshake(self, data):
        with self._lock:
            sock = self._connect()
            if sock:
                try:
                    send_all(sock, data)
                except Exception as e:
                    log.warning(f"Forwarder: handshake failed — {e}")
                    self._close()

    def _connect(self):
        if self._sock:
            return self._sock
        if not self.retry_forever and self._attempt >= self.max_retries > 0:
            return None
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(10)
            raw.connect((self.host, self.port))
            if self.tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                if self.ignore_ssl:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                elif self.ca:
                    ctx.load_verify_locations(self.ca)
                    ctx.verify_mode = ssl.CERT_REQUIRED
                else:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                if self.cert and self.key:
                    ctx.load_cert_chain(self.cert, self.key)
                raw = ctx.wrap_socket(raw, server_hostname=self.host)
            raw.settimeout(None)
            self._sock = raw
            self._attempt = 0
            log.info(f"Forwarder: connected to {self.host}:{self.port}")
        except Exception as e:
            self._attempt += 1
            log.warning(f"Forwarder: connect failed (attempt {self._attempt}) — {e}")
            self._sock = None
        return self._sock

    def _close(self):
        if self._sock:
            try: self._sock.close()
            except: pass
        self._sock = None

    def _drain(self):
        while not shutdown_event.is_set():
            try:
                payload = self._q.get(timeout=1)
            except queue.Empty:
                continue

            sent = False
            while not sent and not shutdown_event.is_set():
                with self._lock:
                    sock = self._connect()
                    if not sock:
                        if self.fail_open:
                            log.warning("Forwarder: no connection — dropping frame (fail-open)")
                            sent = True
                        else:
                            time.sleep(self.reconnect_delay)
                        continue
                    try:
                        send_all(sock, payload)
                        sent = True
                    except Exception as e:
                        log.warning(f"Forwarder: send error — {e} — reconnecting")
                        self._close()
                        time.sleep(self.reconnect_delay)


# ---------------------------------------------------------------------------
# Client handler
# ---------------------------------------------------------------------------

def handle_client(conn, addr, cfg: Config, lock, forwarder):
    log.info(f"UF connected: {addr[0]}:{addr[1]}")
    events_written = 0
    try:
        header = read_exactly(conn, S2S_SIGNATURE_LEN)
        if not header.startswith(S2S_SIGNATURE):
            log.warning(f"{addr}: Bad S2S signature {header[:4]!r} — dropping")
            return
        log.info(f"{addr}: S2S handshake OK")

        if forwarder:
            forwarder.send_handshake(header)

        while not shutdown_event.is_set():
            try:
                len_bytes = read_exactly(conn, 4)
            except ConnectionResetError:
                break

            frame_len = struct.unpack(">I", len_bytes)[0]

            if frame_len == 0:
                if forwarder:
                    forwarder.send(len_bytes, b"")
                continue

            if frame_len > 10 * 1024 * 1024:
                log.warning(f"{addr}: Oversized frame {frame_len}B — dropping")
                break

            frame_data = read_exactly(conn, frame_len)

            if forwarder:
                forwarder.send(len_bytes, frame_data)

            fields = decode_kv_block(frame_data)
            line   = format_event(fields, addr[0])

            with lock:
                with open(cfg.output, "a", encoding="utf-8") as f:
                    f.write(line)

            events_written += 1
            if events_written % cfg.log_every_n == 0:
                log.info(f"{addr}: {events_written} events written")

    except Exception as e:
        log.error(f"{addr}: {e}")
    finally:
        conn.close()
        log.info(f"{addr}: disconnected — {events_written} events written")


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

def make_server_ssl_ctx(cfg: Config):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if cfg.ignore_ssl_in:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(certfile=cfg.cert, keyfile=cfg.key)
    if cfg.ca and cfg.verify_client:
        ctx.load_verify_locations(cfg.ca)
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def run_server(cfg: Config):
    cfg.validate()

    forwarder = None
    if cfg.forward_enabled and cfg.forward_host:
        forwarder = Forwarder(cfg)
        mode_str = "fail-open" if cfg.fail_open else "fail-closed"
        log.info(f"Forwarding -> {cfg.forward_host}:{cfg.forward_port} "
                 f"[TLS={cfg.forward_tls}, ignore_ssl={cfg.forward_ignore_ssl}, {mode_str}]")
    else:
        log.info("Forward disabled — local output only")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((cfg.host, cfg.port))
    sock.listen(50)
    sock.settimeout(1.0)

    ssl_ctx = None
    if cfg.tls:
        ssl_ctx = make_server_ssl_ctx(cfg)
        log.info(f"Inbound TLS enabled [ignore_ssl={cfg.ignore_ssl_in}, verify_client={cfg.verify_client}]")

    os.makedirs(os.path.dirname(os.path.abspath(cfg.output)), exist_ok=True)
    lock = threading.Lock()

    log.setLevel(cfg.log_level)
    log.info(f"Listening on {cfg.host}:{cfg.port} — writing to {cfg.output}")

    def shutdown(sig, frame):
        log.info("Shutting down...")
        shutdown_event.set()
        sock.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    while not shutdown_event.is_set():
        try:
            conn, addr = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        if ssl_ctx:
            try:
                conn = ssl_ctx.wrap_socket(conn, server_side=True)
            except ssl.SSLError as e:
                log.warning(f"TLS handshake failed from {addr}: {e}")
                conn.close()
                continue

        t = threading.Thread(
            target=handle_client,
            args=(conn, addr, cfg, lock, forwarder),
            daemon=True
        )
        t.start()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="Etairos Log Agent — Splunk S2S tee proxy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 agent.py --config config.yaml
  python3 agent.py --config config.yaml --port 9998
  python3 agent.py --port 9997 --output events.log --forward splunk.corp:9997
  python3 agent.py --port 9997 --output events.log --forward splunk.corp:9997 \\
      --tls --cert server.crt --key server.key
"""
    )

    p.add_argument("--config",        metavar="FILE",      help="Path to config.yaml")

    # Inbound
    p.add_argument("--host",          default=None,        help="Bind address (default: 0.0.0.0)")
    p.add_argument("--port",          type=int,            help="Listen port (default: 9997)")
    p.add_argument("--output",        metavar="FILE",      help="Output log file path")
    p.add_argument("--tls",           action="store_true", help="Enable TLS on inbound listener")
    p.add_argument("--cert",          metavar="FILE",      help="Server TLS cert (PEM)")
    p.add_argument("--key",           metavar="FILE",      help="Server TLS key (PEM)")
    p.add_argument("--ca",            metavar="FILE",      help="CA cert for client auth")
    p.add_argument("--ignore-ssl",    action="store_true", help="Skip all SSL verification (testing only)")

    # Outbound
    p.add_argument("--forward",       metavar="HOST:PORT", help="Forward to this Splunk indexer")
    p.add_argument("--forward-tls",   action="store_true", help="Use TLS when connecting to indexer")
    p.add_argument("--forward-cert",  metavar="FILE",      help="Client cert for indexer TLS")
    p.add_argument("--forward-key",   metavar="FILE",      help="Client key for indexer TLS")
    p.add_argument("--forward-ca",    metavar="FILE",      help="CA cert to verify indexer")

    # Failover
    fg = p.add_mutually_exclusive_group()
    fg.add_argument("--fail-open",    action="store_true", default=True,
                    help="Drop frames if indexer unreachable (default)")
    fg.add_argument("--fail-closed",  action="store_true",
                    help="Buffer frames in memory until indexer recovers")

    args = p.parse_args()

    cli = {k: v for k, v in vars(args).items() if v is not None and v is not False}
    # Normalize flag names
    cli["ignore_ssl"]    = args.ignore_ssl
    cli["forward_tls"]   = args.forward_tls
    cli["forward_cert"]  = args.forward_cert
    cli["forward_key"]   = args.forward_key
    cli["forward_ca"]    = args.forward_ca
    cli["fail_closed"]   = args.fail_closed

    cfg = Config(path=args.config, cli_args=cli)
    run_server(cfg)


if __name__ == "__main__":
    main()
