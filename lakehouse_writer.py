"""
lakehouse_writer.py — Batched OCSF output to S3 (Parquet) or local files (JSON/Parquet)

Destinations:
  local-json    Write newline-delimited JSON to a local directory (no extra deps)
  local-parquet Write Parquet to a local directory (requires pyarrow)
  s3            Write Parquet to S3 (requires pyarrow + boto3)

Files are rotated on:
  - batch_size events reached (default: 1000)
  - flush_interval seconds elapsed (default: 60)
  - Agent shutdown

File naming:
  ocsf_<class_uid>_<YYYYMMDD_HHMMSS>_<uuid4>.jsonl / .parquet

Configure in config.yaml under output.lakehouse.*
"""

import json
import logging
import os
import queue
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from ocsf_mapper import to_ocsf

log = logging.getLogger("etairos-log-agent.lakehouse")

# Optional heavy deps — imported lazily
_pyarrow_available = False
_boto3_available   = False

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
    _pyarrow_available = True
except ImportError:
    pass

try:
    import boto3
    _boto3_available = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

class LakehouseConfig:
    def __init__(self, raw: dict):
        self.enabled        = raw.get("enabled", False)
        self.destination    = raw.get("destination", "local-json").lower()
        self.path           = raw.get("path", "/var/log/etairos/lakehouse")
        self.batch_size     = raw.get("batch_size", 1000)
        self.flush_interval = raw.get("flush_interval", 60)
        self.partition_by   = raw.get("partition_by", "day")  # day | hour | none

        # S3
        s3 = raw.get("s3") or {}
        self.s3_bucket      = s3.get("bucket", "")
        self.s3_prefix      = s3.get("prefix", "etairos/ocsf/")
        self.s3_region      = s3.get("region", "us-east-1")
        self.s3_access_key  = s3.get("access_key", "")
        self.s3_secret_key  = s3.get("secret_key", "")

    def validate(self):
        if not self.enabled:
            return
        if self.destination in ("local-parquet", "s3") and not _pyarrow_available:
            raise RuntimeError(
                f"destination={self.destination} requires pyarrow. "
                "Install with: pip install pyarrow"
            )
        if self.destination == "s3":
            if not _boto3_available:
                raise RuntimeError("destination=s3 requires boto3. pip install boto3")
            if not self.s3_bucket:
                raise ValueError("output.lakehouse.s3.bucket is required for destination=s3")


# ---------------------------------------------------------------------------
# Writer base
# ---------------------------------------------------------------------------

class LakehouseWriter:
    """
    Receives decoded Splunk field dicts from the agent, maps them to OCSF,
    and flushes batches to the configured destination.
    """

    def __init__(self, cfg: LakehouseConfig, shutdown_event: threading.Event):
        self.cfg = cfg
        self._shutdown = shutdown_event
        self._q: queue.Queue = queue.Queue(maxsize=500_000)
        self._lock = threading.Lock()
        self._batch: list = []
        self._last_flush = time.monotonic()

        # Start background flush thread
        t = threading.Thread(target=self._run, daemon=True, name="lakehouse-writer")
        t.start()
        log.info(f"LakehouseWriter started: destination={cfg.destination} "
                 f"batch_size={cfg.batch_size} flush_interval={cfg.flush_interval}s")

    def write(self, splunk_fields: dict):
        """Enqueue a Splunk KV dict for OCSF mapping and batch write."""
        try:
            self._q.put_nowait(splunk_fields)
        except queue.Full:
            log.warning("Lakehouse queue full — dropping event")

    def _run(self):
        while not self._shutdown.is_set():
            try:
                item = self._q.get(timeout=1)
                self._batch.append(item)
            except queue.Empty:
                pass

            now = time.monotonic()
            should_flush = (
                len(self._batch) >= self.cfg.batch_size or
                (self._batch and now - self._last_flush >= self.cfg.flush_interval)
            )
            if should_flush:
                self._flush()

        # Drain remaining on shutdown
        while not self._q.empty():
            try:
                self._batch.append(self._q.get_nowait())
            except queue.Empty:
                break
        if self._batch:
            self._flush()

    def _flush(self):
        if not self._batch:
            return
        batch = self._batch
        self._batch = []
        self._last_flush = time.monotonic()

        ocsf_events = []
        for fields in batch:
            try:
                ocsf_events.append(to_ocsf(fields))
            except Exception as e:
                log.warning(f"OCSF map error: {e} — raw: {fields.get('_raw', '')[:80]}")

        if not ocsf_events:
            return

        dest = self.cfg.destination
        try:
            if dest == "local-json":
                self._write_local_json(ocsf_events)
            elif dest == "local-parquet":
                self._write_local_parquet(ocsf_events)
            elif dest == "s3":
                self._write_s3_parquet(ocsf_events)
            else:
                log.error(f"Unknown destination: {dest}")
        except Exception as e:
            log.error(f"Lakehouse flush failed ({dest}): {e}")

        log.info(f"Lakehouse: flushed {len(ocsf_events)} events -> {dest}")

    # -----------------------------------------------------------------------
    # Partition path helper
    # -----------------------------------------------------------------------

    def _partition_path(self, base: str, class_uid: int = 0) -> str:
        """
        Returns a path like:
          base/class_uid=3005/year=2026/month=04/day=07/
        Hive-style partitioning for Athena/Glue/Spark compatibility.
        """
        now = datetime.now(timezone.utc)
        parts = [base, f"class_uid={class_uid}"]
        if self.cfg.partition_by in ("day", "hour"):
            parts += [f"year={now.year:04d}", f"month={now.month:02d}", f"day={now.day:02d}"]
        if self.cfg.partition_by == "hour":
            parts.append(f"hour={now.hour:02d}")
        return os.path.join(*parts)

    def _filename(self, ext: str) -> str:
        ts  = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        uid = str(uuid.uuid4())[:8]
        return f"ocsf_{ts}_{uid}.{ext}"

    # -----------------------------------------------------------------------
    # local-json
    # -----------------------------------------------------------------------

    def _write_local_json(self, events: list):
        # Group by class_uid for cleaner partition dirs
        buckets: dict = {}
        for e in events:
            cid = e.get("class_uid", 0)
            buckets.setdefault(cid, []).append(e)

        for cid, evts in buckets.items():
            path = self._partition_path(self.cfg.path, cid)
            os.makedirs(path, exist_ok=True)
            fpath = os.path.join(path, self._filename("jsonl"))
            with open(fpath, "w", encoding="utf-8") as f:
                for e in evts:
                    f.write(json.dumps(e, default=str) + "\n")
            log.debug(f"Wrote {len(evts)} events -> {fpath}")

    # -----------------------------------------------------------------------
    # local-parquet
    # -----------------------------------------------------------------------

    def _write_local_parquet(self, events: list):
        buckets: dict = {}
        for e in events:
            cid = e.get("class_uid", 0)
            buckets.setdefault(cid, []).append(e)

        for cid, evts in buckets.items():
            path = self._partition_path(self.cfg.path, cid)
            os.makedirs(path, exist_ok=True)
            fpath = os.path.join(path, self._filename("parquet"))
            table = _events_to_arrow(evts)
            pq.write_table(table, fpath, compression="snappy")
            log.debug(f"Wrote {len(evts)} events -> {fpath}")

    # -----------------------------------------------------------------------
    # s3 (Parquet)
    # -----------------------------------------------------------------------

    def _write_s3_parquet(self, events: list):
        import io
        s3_client = boto3.client(
            "s3",
            region_name=self.cfg.s3_region,
            aws_access_key_id=self.cfg.s3_access_key     or None,
            aws_secret_access_key=self.cfg.s3_secret_key or None,
            # If no keys provided, boto3 falls back to IAM role / env vars
        )

        buckets: dict = {}
        for e in events:
            cid = e.get("class_uid", 0)
            buckets.setdefault(cid, []).append(e)

        for cid, evts in buckets.items():
            s3_path = self._partition_path(self.cfg.s3_prefix.rstrip("/"), cid)
            key     = f"{s3_path}/{self._filename('parquet')}"

            table  = _events_to_arrow(evts)
            buf    = io.BytesIO()
            pq.write_table(table, buf, compression="snappy")
            buf.seek(0)

            s3_client.put_object(
                Bucket=self.cfg.s3_bucket,
                Key=key,
                Body=buf.read(),
                ContentType="application/octet-stream",
            )
            log.debug(f"Uploaded {len(evts)} events -> s3://{self.cfg.s3_bucket}/{key}")


# ---------------------------------------------------------------------------
# Arrow table builder
# ---------------------------------------------------------------------------

def _events_to_arrow(events: list):
    """
    Convert list of OCSF dicts to a pyarrow Table.
    Nested dicts are JSON-stringified (Parquet supports nested via structs,
    but JSON strings are simpler for initial lakehouse ingestion — easy to
    evolve to nested structs later).
    """
    if not events:
        return pa.table({})

    # Collect all top-level keys
    all_keys = set()
    for e in events: all_keys.update(e.keys())
    all_keys = sorted(all_keys)

    columns = {k: [] for k in all_keys}
    for e in events:
        for k in all_keys:
            v = e.get(k)
            if isinstance(v, (dict, list)):
                v = json.dumps(v, default=str)
            elif v is None:
                v = ""
            else:
                v = str(v)
            columns[k].append(v)

    arrays = {k: pa.array(v, type=pa.string()) for k, v in columns.items()}
    return pa.table(arrays)
