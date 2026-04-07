#!/usr/bin/env python3
"""
Etairos Log Agent — S2S Tee Proxy
Sits between Splunk UF and your real indexer. Receives the UF stream,
decodes events for local output (file, future lakehouse), and simultaneously
forwards the raw bytes upstream to the real indexer unchanged.

Architecture:
  [Splunk UF] --> [etairos-log-agent :9997] --> [Real Splunk Indexer :9997]
                                             \-> [output file / lakehouse]

Usage:
  Plain (no TLS):
    python3 agent.py --port 9997 --output events.log --forward splunk-indexer.corp:9997

  TLS inbound + plain forward:
    python3 agent.py --port 9997 --output events.log --forward splunk-indexer.corp:9997 \
      --tls --cert server.crt --key server.key

  TLS both directions:
    python3 agent.py --port 9997 --output events.log --forward splunk-indexer.corp:9997 \
      --tls --cert server.crt --key server.key \
      --forward-tls --forward-cert client.crt --forward-key client.key [--forward-ca ca.crt]

outputs.conf on UF (change only the server address):
  [tcpout:etairos-tee]
  server = <this-host-ip>:9997
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
from datetime import datetime, timezone

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
# S2S decode (for local output only — forward uses raw bytes)
# ---------------------------------------------------------------------------

def decode_kv_block(data):
    fields = {}
    offset = 0
    while offset < len(data):
        if offset + 4 > len(data):
            break
        key_len = struct.unpack(">I", data[offset:offset+4])[0]
        offset += 4
        if key_len == 0 or offset + key_len > len(data):
            break
        key = data[offset:offset+key_len].decode("utf-8", errors="replace")
        offset += key_len
        if offset + 4 > len(data):
            break
        val_len = struct.unpack(">I", data[offset:offset+4])[0]
        offset += 4
        val = data[offset:offset+val_len].decode("utf-8", errors="replace")
        offset += val_len
        fields[key] = val
    return fields


def format_event(fields, fallback_ip):
    raw = fields.get("_raw", "")
    if not raw:
        raw = " | ".join(f"{k}={v}" for k, v in fields.items() if not k.startswith("_"))
    source = fields.get("source", "unknown")
    host = fields.get("host", fallback_ip)
    sourcetype = fields.get("sourcetype", "unknown")
    ts = fields.get("_time", "") or datetime.now(timezone.utc).isoformat()
    return f"[{ts}] host={host} source={source} sourcetype={sourcetype} | {raw}\n"


# ---------------------------------------------------------------------------
# Forward connection manager (reconnects on failure)
# ---------------------------------------------------------------------------

class Forwarder:
    """
    Maintains a persistent connection to the real indexer.
    Queues raw frame bytes; background thread drains the queue.
    fail_open=True: drop frames if indexer is unreachable (default).
    fail_open=False: buffer indefinitely (risk: memory growth if indexer is down long).
    """

    def __init__(self, host, port, tls=False, cert=None, key=None, ca=None,
                 fail_open=True, queue_max=100_000):
        self.host = host
        self.port = port
        self.tls = tls
        self.cert = cert
        self.key = key
        self.ca = ca
        self.fail_open = fail_open
        self._q = queue.Queue(maxsize=queue_max)
        self._sock = None
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._drain, daemon=True, name="forwarder")
        self._thread.start()

    def send(self, raw_header, frame_len_bytes, frame_data):
        """Enqueue a raw frame (header + length prefix + body) for forwarding."""
        payload = raw_header + frame_len_bytes + frame_data
        try:
            self._q.put_nowait(payload)
        except queue.Full:
            if self.fail_open:
                log.warning("Forward queue full — dropping frame (fail_open=True)")
            else:
                self._q.put(payload)  # block

    def send_handshake(self, handshake_bytes):
        """Send the raw S2S handshake to the indexer immediately (called once per UF conn)."""
        with self._lock:
            sock = self._connect()
            if sock:
                try:
                    send_all(sock, handshake_bytes)
                except Exception as e:
                    log.warning(f"Forwarder: handshake send failed — {e}")
                    self._sock = None

    def _connect(self):
        if self._sock:
            return self._sock
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(10)
            raw.connect((self.host, self.port))
            if self.tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                if self.ca:
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
            log.info(f"Forwarder: connected to {self.host}:{self.port}")
        except Exception as e:
            log.warning(f"Forwarder: cannot connect to {self.host}:{self.port} — {e}")
            self._sock = None
        return self._sock

    def _drain(self):
        while not shutdown_event.is_set():
            try:
                payload = self._q.get(timeout=1)
            except queue.Empty:
                continue
            while not shutdown_event.is_set():
                with self._lock:
                    sock = self._connect()
                    if not sock:
                        if self.fail_open:
                            log.warning("Forwarder: no connection, dropping frame")
                            break
                        else:
                            import time; time.sleep(2)
                            continue
                    try:
                        send_all(sock, payload)
                        break
                    except Exception as e:
                        log.warning(f"Forwarder: send failed — {e} — reconnecting")
                        self._sock = None


# ---------------------------------------------------------------------------
# Client handler
# ---------------------------------------------------------------------------

def handle_client(conn, addr, output_file, lock, forwarder):
    log.info(f"UF connected from {addr[0]}:{addr[1]}")
    events_written = 0
    try:
        # S2S handshake — read raw, relay to indexer, validate locally
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
                # Keepalive — forward it
                if forwarder:
                    forwarder.send(b"", len_bytes, b"")
                continue

            if frame_len > 10 * 1024 * 1024:
                log.warning(f"{addr}: Oversized frame {frame_len}B — dropping connection")
                break

            frame_data = read_exactly(conn, frame_len)

            # --- Forward raw bytes (unchanged, no re-encoding) ---
            if forwarder:
                forwarder.send(b"", len_bytes, frame_data)

            # --- Decode for local output ---
            fields = decode_kv_block(frame_data)
            line = format_event(fields, addr[0])

            with lock:
                with open(output_file, "a", encoding="utf-8") as f:
                    f.write(line)

            events_written += 1
            if events_written % 500 == 0:
                log.info(f"{addr}: {events_written} events written")

    except Exception as e:
        log.error(f"{addr}: {e}")
    finally:
        conn.close()
        log.info(f"{addr}: done — {events_written} events written")


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

def make_server_ssl_ctx(cert, key, ca=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    if ca:
        ctx.load_verify_locations(cafile=ca)
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def run_server(args):
    # Set up forwarder
    forwarder = None
    if args.forward:
        fwd_host, fwd_port = args.forward.rsplit(":", 1)
        fwd_port = int(fwd_port)
        forwarder = Forwarder(
            host=fwd_host,
            port=fwd_port,
            tls=args.forward_tls,
            cert=args.forward_cert,
            key=args.forward_key,
            ca=args.forward_ca,
            fail_open=args.fail_open,
        )
        log.info(f"Forwarding to {fwd_host}:{fwd_port} [TLS={args.forward_tls}, fail_open={args.fail_open}]")
    else:
        log.info("No --forward specified — local output only")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(50)
    sock.settimeout(1.0)

    ssl_ctx = None
    if args.tls:
        ssl_ctx = make_server_ssl_ctx(args.cert, args.key, args.ca)
        log.info(f"Inbound TLS enabled")

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    lock = threading.Lock()

    log.info(f"Listening on {args.host}:{args.port} — writing to {args.output}")

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
            args=(conn, addr, args.output, lock, forwarder),
            daemon=True
        )
        t.start()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="Etairos Log Agent — Splunk S2S tee proxy")

    # Inbound (from UF)
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=9997)
    p.add_argument("--output", default="extracted.log", help="Local output file")
    p.add_argument("--tls", action="store_true", help="Enable TLS on inbound listener")
    p.add_argument("--cert", help="Server TLS cert (PEM)")
    p.add_argument("--key", help="Server TLS key (PEM)")
    p.add_argument("--ca", help="CA cert for client auth (optional)")

    # Outbound (to real indexer)
    p.add_argument("--forward", metavar="HOST:PORT",
                   help="Forward raw stream to this Splunk indexer (e.g. splunk.corp:9997)")
    p.add_argument("--forward-tls", action="store_true", help="Use TLS when connecting to indexer")
    p.add_argument("--forward-cert", help="Client cert for indexer TLS auth")
    p.add_argument("--forward-key", help="Client key for indexer TLS auth")
    p.add_argument("--forward-ca", help="CA cert to verify indexer cert")
    p.add_argument("--fail-open", action="store_true", default=True,
                   help="Drop frames if indexer unreachable (default: true)")
    p.add_argument("--fail-closed", dest="fail_open", action="store_false",
                   help="Buffer frames until indexer recovers")

    args = p.parse_args()

    if args.tls and (not args.cert or not args.key):
        p.error("--tls requires --cert and --key")

    run_server(args)


if __name__ == "__main__":
    main()
