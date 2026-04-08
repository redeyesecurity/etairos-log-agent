#!/usr/bin/env python3
"""
Etairos Tee Listener - S2S protocol handler
Receives from UF, forwards to indexer, writes to alternate_stream
"""

import socket
import ssl
import struct
import threading
import queue
import time
import json
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

# Optional imports for alternate_stream
try:
    import pyarrow as pa
    import pyarrow.parquet as pq
    HAS_PARQUET = True
except ImportError:
    HAS_PARQUET = False

try:
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


class TeeListener:
    """Main S2S tee proxy listener"""
    
    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger
        self.running = False
        self.server_socket = None
        self.connections = []
        self.event_queue = queue.Queue(maxsize=100000)
        self.stats = {
            "events_received": 0,
            "events_forwarded": 0,
            "events_alternate_stream": 0,
            "errors": 0,
            "start_time": None
        }
        
        # Alternate Stream writer thread
        self.alternate_stream_thread = None
        self.alternate_stream_batch = []
        self.last_flush = time.time()
        
        # Import OCSF mapper
        try:
            from ocsf_mapper import OCSFMapper
            self.mapper = OCSFMapper()
        except ImportError:
            self.logger.warning("ocsf_mapper not found, OCSF mapping disabled")
            self.mapper = None
    
    def start(self):
        """Start the listener and all worker threads"""
        self.running = True
        self.stats["start_time"] = datetime.now(timezone.utc).isoformat()
        
        host = self.config.get("listener", {}).get("host", "127.0.0.1")
        port = self.config.get("listener", {}).get("port", 19997)
        
        # Create server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((host, port))
            self.server_socket.listen(50)
            self.server_socket.settimeout(1.0)  # Allow periodic shutdown check
            self.logger.info(f"Listening on {host}:{port}")
        except OSError as e:
            self.logger.error(f"Failed to bind to {host}:{port}: {e}")
            raise
        
        # Start alternate_stream writer thread
        if self.config.get("alternate_stream", {}).get("enabled"):
            self.alternate_stream_thread = threading.Thread(
                target=self._alternate_stream_writer_loop,
                name="alternate_stream-writer",
                daemon=True
            )
            self.alternate_stream_thread.start()
            self.logger.info("Alternate Stream writer started")
        
        # Start accept loop in main thread
        self._accept_loop()
    
    def stop(self):
        """Graceful shutdown"""
        self.logger.info("Stopping listener...")
        self.running = False
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        # Flush remaining alternate_stream batch
        if self.alternate_stream_batch:
            self._flush_alternate_stream()
        
        self.logger.info(f"Final stats: {json.dumps(self.stats)}")
    
    def _accept_loop(self):
        """Accept incoming connections"""
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                self.logger.info(f"Connection from {addr}")
                
                # Handle each connection in a thread
                handler = threading.Thread(
                    target=self._handle_connection,
                    args=(client_socket, addr),
                    name=f"conn-{addr[0]}:{addr[1]}",
                    daemon=True
                )
                handler.start()
                self.connections.append(handler)
                
            except socket.timeout:
                continue
            except OSError:
                if self.running:
                    self.logger.exception("Accept error")
                break
    
    def _handle_connection(self, client_socket: socket.socket, addr):
        """Handle a single UF connection"""
        # Connect to upstream indexer if forwarding enabled
        forward_socket = None
        if self.config.get("forward", {}).get("enabled"):
            forward_socket = self._connect_to_indexer()
        
        try:
            # ----------------------------------------------------------------
            # S2S v3 Handshake (wire-captured from real Splunk indexer):
            # Step 1: UF sends 400-byte struct (_signature[128] + _serverName[256] + _mgmtPort[16])
            # Step 2: UF sends 68-byte caps frame (__s2s_capabilities KV + _raw trailer)
            # Step 3: IX responds with 163-byte control_msg frame (cap_response=success...)
            # ----------------------------------------------------------------
            # Read UF hello (400 bytes)
            hs400 = self._recv_exact(client_socket, 400)
            if not hs400 or not hs400.startswith(b"--splunk-cooked-mode-v3--"):
                self.logger.warning(f"No S2S v3 handshake from {addr}, closing")
                return
            client_hostname = hs400[128:384].rstrip(b"\x00").decode("utf-8", errors="replace")
            client_port     = hs400[384:400].rstrip(b"\x00").decode("utf-8", errors="replace")
            # Read UF caps frame: variable-length KV frame ending with "_raw\x00" trailer
            # Format: type(4) + num_pairs(4) + KV_data + "\x00\x00\x00\x05_raw\x00" trailer
            # We read byte-by-byte until we hit the _raw\x00 terminus
            caps_buf = b""
            CAPS_TERMINATOR = bytes.fromhex("000000055f72617700")
            MAX_CAPS = 256
            caps_type_byte = self._recv_exact(client_socket, 1)
            if not caps_type_byte:
                self.logger.warning(f"No caps frame from {addr}, closing")
                return
            caps_buf = caps_type_byte
            for _ in range(MAX_CAPS):
                b = self._recv_exact(client_socket, 1)
                if not b:
                    break
                caps_buf += b
                if caps_buf.endswith(CAPS_TERMINATOR):
                    break
            self.logger.info(f"Caps frame consumed: {len(caps_buf)} bytes = {caps_buf.hex()}")
            self.logger.info(f"S2S v3 handshake from {addr}: host={client_hostname} mgmt={client_port}")
            # Send indexer response: 163-byte __s2s_control_msg frame (wire-captured from Splunk 9.1)
            ix_resp = bytes.fromhex(
                "0000009f00000001000000125f5f7332735f636f6e74726f6c5f6d73670000000074"
                "6361705f726573706f6e73653d737563636573733b6361705f666c7573685f6b65793d"
                "747275653b6964785f63616e5f73656e645f68623d747275653b6964785f63616e5f72"
                "6563765f746f6b656e3d747275653b76343d747275653b6368616e6e656c5f6c696d69"
                "743d3330303b706c3d360000000000000000055f72617700"
            )
            client_socket.sendall(ix_resp)
            self.logger.info(f"Sent S2S v3 control_msg response to {addr}")

            # ----------------------------------------------------------------
            # S2S v3 Data Phase: raw stream capture
            # S2S v3 uses channel-multiplexed frames with variable structure.
            # For the POC, we capture the raw post-handshake stream and parse
            # it with the s2s_parser module separately.
            # ----------------------------------------------------------------
            client_socket.settimeout(30)
            raw_buf = b""
            total_bytes = 0
            stream_dumped = False
            try:
                while self.running:
                    chunk = client_socket.recv(65536)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    raw_buf += chunk
                    # Dump first connection's stream for analysis
                    if not stream_dumped and total_bytes >= 4096:
                        with open('/tmp/s2s_live_stream.bin', 'wb') as _sf:
                            _sf.write(raw_buf[:32768])
                        self.logger.info(f"Stream dump written: {min(len(raw_buf),4096)} bytes")
                        stream_dumped = True
                    # Parse complete S2S frames from the buffer
                    raw_buf, events = self._parse_s2s_stream(raw_buf)
                    for event in events:
                        self.stats["events_received"] += 1
                        self.event_queue.put(event)
            except socket.timeout:
                pass
            self.logger.info(f"Connection done: {addr} total_bytes={total_bytes} remaining_buf={len(raw_buf)}")
        except Exception as e:
            self.logger.exception(f"Connection handler error: {e}")
        finally:
            client_socket.close()
            if forward_socket:
                forward_socket.close()
            self.logger.info(f"Connection closed: {addr}")
    
    def _recv_exact(self, sock: socket.socket, n: int) -> Optional[bytes]:
        """Receive exactly n bytes"""
        data = b""
        while len(data) < n:
            try:
                chunk = sock.recv(n - len(data))
                if not chunk:
                    return None
                data += chunk
            except socket.timeout:
                if not self.running:
                    return None
                continue
        return data
    
    def _connect_to_indexer(self) -> Optional[socket.socket]:
        """Connect to upstream Splunk indexer"""
        fwd_config = self.config.get("forward", {})
        host = fwd_config.get("host")
        port = fwd_config.get("port", 9997)
        
        if not host:
            return None
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            # TLS if configured
            if fwd_config.get("tls", {}).get("enabled"):
                context = ssl.create_default_context()
                if fwd_config["tls"].get("ignore_ssl"):
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                if fwd_config["tls"].get("ca"):
                    context.load_verify_locations(fwd_config["tls"]["ca"])
                if fwd_config["tls"].get("cert"):
                    context.load_cert_chain(
                        fwd_config["tls"]["cert"],
                        fwd_config["tls"].get("key")
                    )
                sock = context.wrap_socket(sock, server_hostname=host)
            
            sock.connect((host, port))
            self.logger.info(f"Connected to indexer {host}:{port}")
            return sock
            
        except Exception as e:
            self.logger.error(f"Failed to connect to indexer: {e}")
            return None
    
    def _parse_s2s_stream(self, buf: bytes):
        """
        Parse S2S v3 cooked event stream (wire-observed format).

        After the handshake, the UF sends channel-multiplexed data:
          1-byte channel_name_len + channel_name + event_data

        Known channels:
          _raw           : Raw log events (with \xff\xab\x14 timezone preamble)
          _path          : Source file path
          _MetaData:Index: Index name + \xa1\x01 + actual log event text
          _MetaData:*    : Other metadata fields

        Events are extracted from _MetaData:Index channel segments, which have:
          4-byte index_name_len + index_name + \xa1\x01 + log_line_text

        Returns (remaining_buf, list_of_event_dicts)
        """
        events = []
        offset = 0
        last_path = ""
        last_index = "main"

        while offset < len(buf):
            # Need at least 2 bytes (1 clen + 1 char of channel name)
            if offset + 2 > len(buf):
                break

            clen = buf[offset]
            # Valid channel name lengths are 1-32
            if clen == 0 or clen > 32:
                offset += 1
                continue

            # Need the full channel name
            if offset + 1 + clen > len(buf):
                break

            chan = buf[offset+1:offset+1+clen].rstrip(b"\x00").decode("utf-8", errors="replace")
            # Validate channel name (only known channels)
            if not (chan.startswith("_") and all(c.isalnum() or c in ":_-." for c in chan)):
                offset += 1
                continue

            # Found a valid channel
            data_start = offset + 1 + clen
            # Find the next channel marker
            next_marker = -1
            for j in range(data_start + 1, len(buf) - 1):
                nc = buf[j]
                if nc == 0 or nc > 32:
                    continue
                if j + 1 + nc > len(buf):
                    break
                nc_name = buf[j+1:j+1+nc].rstrip(b"\x00")
                if (nc_name.startswith(b"_") and
                    all(chr(b).isalnum() or chr(b) in ":_-." for b in nc_name)):
                    next_marker = j
                    break
            
            if next_marker == -1:
                # No next marker -- incomplete, keep remainder
                break

            segment = buf[data_start:next_marker]
            offset = next_marker

            # Extract events from the segment
            if chan == "_path" and segment:
                raw_path = segment.rstrip(b"\x00").decode("utf-8", errors="replace")
                # Strip length-byte prefix artifact — path always starts with /
                slash = raw_path.find("/")
                last_path = raw_path[slash:] if slash >= 0 else raw_path
            elif chan == "_MetaData:Index" and len(segment) > 6:
                # Format: 4-byte index_len + index_name + \xa1\x01 + log_text
                # Or sometimes: just \xa1\x01 + log_text (no index prefix)
                idx = 0
                # Try to find \xa1\x01 event markers
                # All known S2S v3 event start markers
                _markers = [bytes.fromhex(x) for x in ("a101","ca01","ca05","c101","c105","fe01","c1","b9","b7","ba","bb")]
                # Find first occurrence of any marker and use the most common one
                marker = bytes.fromhex("a101")
                _best_count = 0
                for _mk in _markers:
                    _cnt = segment.count(_mk)
                    if _cnt > _best_count:
                        _best_count = _cnt
                        marker = _mk
                if not _best_count:  # fallback: try single-byte 0xc1/0xca
                    for _mb in (b"\xca", b"\xc1", b"\xa1"):
                        if _mb in segment:
                            marker = _mb
                            break
                pos = 0
                while pos < len(segment):
                    m = segment.find(marker, pos)
                    if m == -1:
                        break
                    # Event text starts after marker
                    event_end = segment.find(marker, m + 2)
                    if event_end == -1:
                        event_end = len(segment)
                    raw_bytes = segment[m+2:event_end]
                    # Trim trailing binary metadata (everything after the last newline before control bytes)
                    # Find last printable newline position
                    last_nl = raw_bytes.rfind(b"\n")
                    if last_nl > 0:
                        tail = raw_bytes[last_nl+1:]
                        if tail and tail[0] in (0xc1, 0xca, 0xfe, 0xff, 0xa1, 0x1a, 0x1c):
                            raw_bytes = raw_bytes[:last_nl+1]
                    raw_text = raw_bytes.rstrip(b"\x00").decode("utf-8", errors="replace").strip()
                    if raw_text:
                        # Clean source path: strip leading fragment (channel re-use artifact)
                        src_path = last_path or "s2s"
                        # Remove trailing control bytes
                        src_path = src_path.rstrip("\x00\x01\x02\x03\x04\x05\x06\x07\x08")
                        # If it starts mid-path, fix it
                        if src_path and "/" in src_path and not src_path.startswith("/"):
                            src_path = "/" + src_path
                        # Only emit if the text is mostly printable ASCII (not binary)
                        printable_ratio = sum(1 for c in raw_text if c.isprintable() or c in "\n\t\r") / max(len(raw_text), 1)
                        if printable_ratio > 0.85 and len(raw_text) > 5:
                            events.append({
                                "_time": time.time(),
                                "_raw": raw_text,
                                "host": "Mac.lucashouse.info",
                                "source": src_path,
                                "sourcetype": "splunkd",
                                "index": last_index,
                            })
                    pos = event_end

        return buf[offset:], events


    def _decode_s2s_frame_v3(self, frame_type: int, data: bytes):
        """Decode a single S2S v3 frame into event dicts"""
        events = []
        if frame_type == 0x0c:
            # Standard event frame: series of length-prefixed field KVs
            # Field encoding: 1-byte field_id + length-prefixed value OR
            #                 field_id=4 + 2-byte name_len + name + value_len + value
            # Use the existing decoder
            try:
                evts = self._decode_s2s_frame(data)
                events.extend(evts)
            except Exception:
                pass
        elif frame_type == 0x0286:
            # Channel/ForwarderInfo frame: skip chan name, decode rest as event
            if len(data) > 4:
                chan_len = struct.unpack(">I", data[0:4])[0]
                if chan_len < len(data):
                    chan = data[4:4+chan_len].rstrip(b"\x00").decode("utf-8", errors="replace")
                    rest = data[4+chan_len:]
                    if rest and rest[0] == 0xc1:
                        # ForwarderInfo line
                        line = rest[1:].rstrip(b"\x00").decode("utf-8", errors="replace")
                        events.append({"_raw": line, "_meta": "ForwarderInfo", "channel": chan})
                    elif rest:
                        try:
                            evts = self._decode_s2s_frame(rest)
                            for e in evts:
                                e["channel"] = chan
                            events.extend(evts)
                        except Exception:
                            pass
        return events

    def _decode_s2s_frame(self, data: bytes) -> List[Dict[str, Any]]:
        """Decode S2S frame into events (simplified)"""
        # Real S2S decoding is complex - this is a placeholder
        # Full implementation would parse the cooked wire format
        events = []
        
        try:
            # Attempt to find event boundaries (simplified)
            # Real impl needs to parse Splunk's proprietary format
            
            # For now, treat entire payload as single event for testing
            event = {
                "_time": time.time(),
                "_raw": data.decode("utf-8", errors="replace"),
                "host": "unknown",
                "source": "s2s",
                "sourcetype": "raw"
            }
            events.append(event)
            
        except Exception as e:
            self.logger.warning(f"Decode error: {e}")
        
        return events
    
    def _send_ack(self, sock: socket.socket, header: bytes):
        """Send ACK response to UF"""
        try:
            # Simple ACK - echo sequence number
            # Real impl needs proper S2S ACK format
            ack = struct.pack(">I", 0) + header[:4]
            sock.sendall(ack)
        except:
            pass
    
    def _alternate_stream_writer_loop(self):
        """Background thread for batched alternate_stream writes"""
        batch_size = self.config.get("alternate_stream", {}).get("batch_size", 1000)
        flush_interval = self.config.get("alternate_stream", {}).get("flush_interval", 60)
        
        while self.running:
            try:
                # Get events from queue with timeout
                try:
                    event = self.event_queue.get(timeout=1.0)
                    
                    # Map to OCSF if mapper available
                    if self.mapper:
                        ocsf_event = self.mapper.map(event)
                    else:
                        ocsf_event = event
                    
                    self.alternate_stream_batch.append(ocsf_event)
                    
                except queue.Empty:
                    pass
                
                # Flush if batch full or interval elapsed
                now = time.time()
                if (len(self.alternate_stream_batch) >= batch_size or 
                    (self.alternate_stream_batch and now - self.last_flush >= flush_interval)):
                    self._flush_alternate_stream()
                    
            except Exception as e:
                self.logger.exception(f"Alternate Stream writer error: {e}")
                time.sleep(1)
    
    def _flush_alternate_stream(self):
        """Write batch to alternate_stream destination"""
        if not self.alternate_stream_batch:
            return
        
        destination = self.config.get("alternate_stream", {}).get("destination", "local-json")
        
        try:
            if destination == "local-json":
                self._write_local_json()
            elif destination == "local-parquet":
                self._write_local_parquet()
            elif destination == "s3":
                self._write_s3()
            
            self.stats["events_alternate_stream"] += len(self.alternate_stream_batch)
            self.logger.info(f"Flushed {len(self.alternate_stream_batch)} events to {destination}")
            
        except Exception as e:
            self.logger.error(f"Alternate Stream flush failed: {e}")
            self.stats["errors"] += 1
        
        self.alternate_stream_batch = []
        self.last_flush = time.time()
    
    def _write_local_json(self):
        """Write batch as JSON lines to local filesystem"""
        base_path = Path(self.config.get("alternate_stream", {}).get("path", "/var/log/etairos/alternate_stream"))
        partition = self.config.get("alternate_stream", {}).get("partition_by", "day")
        
        # Build partition path
        now = datetime.now(timezone.utc)
        if partition == "day":
            part_path = base_path / f"year={now.year}" / f"month={now.month:02d}" / f"day={now.day:02d}"
        elif partition == "hour":
            part_path = base_path / f"year={now.year}" / f"month={now.month:02d}" / f"day={now.day:02d}" / f"hour={now.hour:02d}"
        else:
            part_path = base_path
        
        part_path.mkdir(parents=True, exist_ok=True)
        
        # Write JSONL file
        filename = f"ocsf_{now.strftime('%Y%m%d_%H%M%S')}_{os.getpid()}.jsonl"
        filepath = part_path / filename
        
        self.logger.info(f"Writing {len(self.alternate_stream_batch)} events to {filepath}")
        with open(filepath, "w") as f:
            for event in self.alternate_stream_batch:
                f.write(json.dumps(event) + "\n")
        try:
            os.chmod(str(filepath), 0o644)
        except Exception:
            pass
        self.logger.info(f"Wrote {filepath}")
    
    def _write_local_parquet(self):
        """Write batch as Parquet to local filesystem"""
        if not HAS_PARQUET:
            self.logger.error("pyarrow not installed, cannot write Parquet")
            return
        
        # Similar to JSON but with Parquet output
        base_path = Path(self.config.get("alternate_stream", {}).get("path", "/var/log/etairos/alternate_stream"))
        now = datetime.now(timezone.utc)
        part_path = base_path / f"year={now.year}" / f"month={now.month:02d}" / f"day={now.day:02d}"
        part_path.mkdir(parents=True, exist_ok=True)
        
        filename = f"ocsf_{now.strftime('%Y%m%d_%H%M%S')}_{os.getpid()}.parquet"
        filepath = part_path / filename
        
        # Convert to PyArrow table and write
        table = pa.Table.from_pylist(self.alternate_stream_batch)
        pq.write_table(table, filepath)
    
    def _write_s3(self):
        """Write batch as Parquet to S3"""
        if not HAS_BOTO3:
            self.logger.error("boto3 not installed, cannot write to S3")
            return
        if not HAS_PARQUET:
            self.logger.error("pyarrow not installed, cannot write Parquet")
            return
        
        s3_config = self.config.get("alternate_stream", {}).get("s3", {})
        bucket = s3_config.get("bucket")
        prefix = s3_config.get("prefix", "etairos/ocsf")
        
        if not bucket:
            self.logger.error("S3 bucket not configured")
            return
        
        # Build S3 key with partitions
        now = datetime.now(timezone.utc)
        key = f"{prefix}/year={now.year}/month={now.month:02d}/day={now.day:02d}/ocsf_{now.strftime('%Y%m%d_%H%M%S')}_{os.getpid()}.parquet"
        
        # Write to temp file then upload
        import tempfile
        table = pa.Table.from_pylist(self.alternate_stream_batch)
        
        with tempfile.NamedTemporaryFile(suffix=".parquet", delete=False) as tmp:
            pq.write_table(table, tmp.name)
            
            # Upload
            s3 = boto3.client(
                "s3",
                region_name=s3_config.get("region", "us-east-1"),
                aws_access_key_id=s3_config.get("access_key") or None,
                aws_secret_access_key=s3_config.get("secret_key") or None
            )
            s3.upload_file(tmp.name, bucket, key)
            
            # Cleanup temp file
            os.unlink(tmp.name)
