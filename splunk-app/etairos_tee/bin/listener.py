#!/usr/bin/env python3
"""
Etairos Tee Listener - S2S protocol handler
Receives from UF, forwards to indexer, writes to lakehouse
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

# Optional imports for lakehouse
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
            "events_lakehouse": 0,
            "errors": 0,
            "start_time": None
        }
        
        # Lakehouse writer thread
        self.lakehouse_thread = None
        self.lakehouse_batch = []
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
        
        # Start lakehouse writer thread
        if self.config.get("lakehouse", {}).get("enabled"):
            self.lakehouse_thread = threading.Thread(
                target=self._lakehouse_writer_loop,
                name="lakehouse-writer",
                daemon=True
            )
            self.lakehouse_thread.start()
            self.logger.info("Lakehouse writer started")
        
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
        
        # Flush remaining lakehouse batch
        if self.lakehouse_batch:
            self._flush_lakehouse()
        
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
            while self.running:
                # Read S2S frame header (simplified - real impl needs full protocol)
                header = self._recv_exact(client_socket, 8)
                if not header:
                    break
                
                # Parse frame (simplified S2S structure)
                # Real S2S has: signature(4) + flags(4) + channel(4) + length(4) + data
                frame_len = struct.unpack(">I", header[4:8])[0]
                frame_data = self._recv_exact(client_socket, frame_len)
                if not frame_data:
                    break
                
                # Forward raw frame to indexer
                if forward_socket:
                    try:
                        forward_socket.sendall(header + frame_data)
                        self.stats["events_forwarded"] += 1
                    except:
                        self.logger.warning("Forward failed, reconnecting...")
                        forward_socket = self._connect_to_indexer()
                
                # Decode and queue for lakehouse
                events = self._decode_s2s_frame(frame_data)
                for event in events:
                    self.stats["events_received"] += 1
                    
                    if self.config.get("lakehouse", {}).get("enabled"):
                        try:
                            self.event_queue.put_nowait(event)
                        except queue.Full:
                            self.stats["errors"] += 1
                
                # Send ACK back to UF if configured
                if self.config.get("ack", {}).get("enabled") in (True, "auto"):
                    self._send_ack(client_socket, header)
                
                # Progress logging
                if self.stats["events_received"] % self.config.get("logging", {}).get("log_every_n", 500) == 0:
                    self.logger.info(f"Events: {self.stats['events_received']} received, "
                                   f"{self.stats['events_forwarded']} forwarded, "
                                   f"{self.stats['events_lakehouse']} to lakehouse")
        
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
    
    def _lakehouse_writer_loop(self):
        """Background thread for batched lakehouse writes"""
        batch_size = self.config.get("lakehouse", {}).get("batch_size", 1000)
        flush_interval = self.config.get("lakehouse", {}).get("flush_interval", 60)
        
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
                    
                    self.lakehouse_batch.append(ocsf_event)
                    
                except queue.Empty:
                    pass
                
                # Flush if batch full or interval elapsed
                now = time.time()
                if (len(self.lakehouse_batch) >= batch_size or 
                    (self.lakehouse_batch and now - self.last_flush >= flush_interval)):
                    self._flush_lakehouse()
                    
            except Exception as e:
                self.logger.exception(f"Lakehouse writer error: {e}")
                time.sleep(1)
    
    def _flush_lakehouse(self):
        """Write batch to lakehouse destination"""
        if not self.lakehouse_batch:
            return
        
        destination = self.config.get("lakehouse", {}).get("destination", "local-json")
        
        try:
            if destination == "local-json":
                self._write_local_json()
            elif destination == "local-parquet":
                self._write_local_parquet()
            elif destination == "s3":
                self._write_s3()
            
            self.stats["events_lakehouse"] += len(self.lakehouse_batch)
            self.logger.info(f"Flushed {len(self.lakehouse_batch)} events to {destination}")
            
        except Exception as e:
            self.logger.error(f"Lakehouse flush failed: {e}")
            self.stats["errors"] += 1
        
        self.lakehouse_batch = []
        self.last_flush = time.time()
    
    def _write_local_json(self):
        """Write batch as JSON lines to local filesystem"""
        base_path = Path(self.config.get("lakehouse", {}).get("path", "/var/log/etairos/lakehouse"))
        partition = self.config.get("lakehouse", {}).get("partition_by", "day")
        
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
        
        with open(filepath, "w") as f:
            for event in self.lakehouse_batch:
                f.write(json.dumps(event) + "\n")
    
    def _write_local_parquet(self):
        """Write batch as Parquet to local filesystem"""
        if not HAS_PARQUET:
            self.logger.error("pyarrow not installed, cannot write Parquet")
            return
        
        # Similar to JSON but with Parquet output
        base_path = Path(self.config.get("lakehouse", {}).get("path", "/var/log/etairos/lakehouse"))
        now = datetime.now(timezone.utc)
        part_path = base_path / f"year={now.year}" / f"month={now.month:02d}" / f"day={now.day:02d}"
        part_path.mkdir(parents=True, exist_ok=True)
        
        filename = f"ocsf_{now.strftime('%Y%m%d_%H%M%S')}_{os.getpid()}.parquet"
        filepath = part_path / filename
        
        # Convert to PyArrow table and write
        table = pa.Table.from_pylist(self.lakehouse_batch)
        pq.write_table(table, filepath)
    
    def _write_s3(self):
        """Write batch as Parquet to S3"""
        if not HAS_BOTO3:
            self.logger.error("boto3 not installed, cannot write to S3")
            return
        if not HAS_PARQUET:
            self.logger.error("pyarrow not installed, cannot write Parquet")
            return
        
        s3_config = self.config.get("lakehouse", {}).get("s3", {})
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
        table = pa.Table.from_pylist(self.lakehouse_batch)
        
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
