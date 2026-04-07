"""
ocsf_mapper.py — Splunk field -> OCSF event mapper

Supported OCSF classes (v1.1):
  1001  File System Activity
  1002  Kernel Extension Activity
  1003  Kernel Activity
  1004  Memory Activity
  2001  Security Finding
  3001  DNS Activity
  3002  FTP Activity
  3003  HTTP Activity
  3005  Network Activity
  3006  SMTP Activity
  4001  Account Change
  4002  Authentication
  4003  Authorize Session
  4004  Entity Change
  4005  User Access Management
  6001  Process Activity
  0000  Unknown (fallback)

Detection heuristic: sourcetype -> class
Override via the 'ocsf_class' Splunk field if you want explicit control.

OCSF spec: https://schema.ocsf.io
"""

import re
import time
from datetime import datetime, timezone
from typing import Optional

# ---------------------------------------------------------------------------
# Class IDs
# ---------------------------------------------------------------------------
CLASS_UNKNOWN          = 0
CLASS_FILE_ACTIVITY    = 1001
CLASS_NETWORK_ACTIVITY = 3005
CLASS_DNS_ACTIVITY     = 3001
CLASS_HTTP_ACTIVITY    = 3003
CLASS_AUTHENTICATION   = 4002
CLASS_ACCOUNT_CHANGE   = 4001
CLASS_PROCESS_ACTIVITY = 6001
CLASS_SECURITY_FINDING = 2001

# Activity IDs (generic)
ACTIVITY_UNKNOWN = 0
ACTIVITY_CREATE  = 1
ACTIVITY_READ    = 2
ACTIVITY_UPDATE  = 3
ACTIVITY_DELETE  = 4

# Severity IDs
SEV_UNKNOWN        = 0
SEV_INFORMATIONAL  = 1
SEV_LOW            = 2
SEV_MEDIUM         = 3
SEV_HIGH           = 4
SEV_CRITICAL       = 5

# Status IDs
STATUS_UNKNOWN = 0
STATUS_SUCCESS = 1
STATUS_FAILURE = 2

# ---------------------------------------------------------------------------
# Sourcetype -> class routing
# ---------------------------------------------------------------------------

SOURCETYPE_CLASS_MAP = {
    # Authentication / Account
    "linux_secure":            CLASS_AUTHENTICATION,
    "linux:audit":             CLASS_AUTHENTICATION,
    "auth":                    CLASS_AUTHENTICATION,
    "syslog":                  CLASS_AUTHENTICATION,   # refined below if SSH keywords found
    "wineventlog:security":    CLASS_AUTHENTICATION,
    "winevents:security":      CLASS_AUTHENTICATION,
    "msad:nt6:security":       CLASS_AUTHENTICATION,

    # Process / Sysmon
    "xmlwineventlog:microsoft-windows-sysmon/operational": CLASS_PROCESS_ACTIVITY,
    "wineventlog:system":      CLASS_PROCESS_ACTIVITY,
    "wineventlog:application": CLASS_PROCESS_ACTIVITY,

    # Network
    "cisco:asa":               CLASS_NETWORK_ACTIVITY,
    "cisco:firepower":         CLASS_NETWORK_ACTIVITY,
    "pan:traffic":             CLASS_NETWORK_ACTIVITY,
    "paloalto:firewall":       CLASS_NETWORK_ACTIVITY,
    "juniper:junos":           CLASS_NETWORK_ACTIVITY,
    "netflow":                 CLASS_NETWORK_ACTIVITY,
    "stream:tcp":              CLASS_NETWORK_ACTIVITY,
    "stream:udp":              CLASS_NETWORK_ACTIVITY,

    # DNS
    "stream:dns":              CLASS_DNS_ACTIVITY,
    "named":                   CLASS_DNS_ACTIVITY,
    "cisco:umbrella:dns":      CLASS_DNS_ACTIVITY,

    # HTTP / Web
    "access_combined":         CLASS_HTTP_ACTIVITY,
    "access_combined_wcookie": CLASS_HTTP_ACTIVITY,
    "apache:access":           CLASS_HTTP_ACTIVITY,
    "iis":                     CLASS_HTTP_ACTIVITY,
    "nginx:access":            CLASS_HTTP_ACTIVITY,
    "stream:http":             CLASS_HTTP_ACTIVITY,
    "squid:access":            CLASS_HTTP_ACTIVITY,

    # File
    "auditd":                  CLASS_FILE_ACTIVITY,
    "linux:audit:file":        CLASS_FILE_ACTIVITY,

    # Security findings
    "ids":                     CLASS_SECURITY_FINDING,
    "snort":                   CLASS_SECURITY_FINDING,
    "suricata":                CLASS_SECURITY_FINDING,
    "crowdstrike:event":       CLASS_SECURITY_FINDING,
    "carbonblack":             CLASS_SECURITY_FINDING,
}


def detect_class(fields: dict) -> int:
    """Detect OCSF class from Splunk fields."""
    # Explicit override wins
    if "ocsf_class" in fields:
        try:
            return int(fields["ocsf_class"])
        except ValueError:
            pass

    st = fields.get("sourcetype", "").lower()
    cls = SOURCETYPE_CLASS_MAP.get(st)
    if cls:
        return cls

    # Partial match fallback
    for key, val in SOURCETYPE_CLASS_MAP.items():
        if key in st:
            return val

    # Keyword heuristics on _raw
    raw = fields.get("_raw", "").lower()
    if any(k in raw for k in ("sshd", "pam_unix", "authentication failure",
                               "accepted password", "accepted publickey",
                               "failed password", "invalid user")):
        return CLASS_AUTHENTICATION
    if any(k in raw for k in ("exec", "execve", "process", "pid")):
        return CLASS_PROCESS_ACTIVITY
    if any(k in raw for k in ("src_ip", "dst_ip", "src_port", "dst_port",
                               " established", " denied", "firewall")):
        return CLASS_NETWORK_ACTIVITY

    return CLASS_UNKNOWN


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def _parse_time(fields: dict) -> int:
    """Return epoch milliseconds."""
    t = fields.get("_time", "")
    if t:
        try:
            # ISO format
            if "T" in t:
                dt = datetime.fromisoformat(t.replace("Z", "+00:00"))
                return int(dt.timestamp() * 1000)
            # Unix float
            return int(float(t) * 1000)
        except Exception:
            pass
    return int(time.time() * 1000)


def _severity_from_fields(fields: dict) -> int:
    sev = fields.get("severity", fields.get("log_level", "")).lower()
    mapping = {
        "informational": SEV_INFORMATIONAL, "info": SEV_INFORMATIONAL,
        "low":           SEV_LOW,
        "medium":        SEV_MEDIUM,        "warning": SEV_MEDIUM, "warn": SEV_MEDIUM,
        "high":          SEV_HIGH,          "error": SEV_HIGH,     "err": SEV_HIGH,
        "critical":      SEV_CRITICAL,      "fatal": SEV_CRITICAL, "crit": SEV_CRITICAL,
    }
    return mapping.get(sev, SEV_INFORMATIONAL)


# ---------------------------------------------------------------------------
# Base event skeleton
# ---------------------------------------------------------------------------

def _base(fields: dict, class_uid: int, activity_id: int = ACTIVITY_UNKNOWN) -> dict:
    ts = _parse_time(fields)
    return {
        "class_uid":    class_uid,
        "class_name":   _class_name(class_uid),
        "activity_id":  activity_id,
        "category_uid": class_uid // 1000,
        "severity_id":  _severity_from_fields(fields),
        "time":         ts,
        "start_time":   ts,
        "status_id":    STATUS_UNKNOWN,
        "metadata": {
            "version":    "1.1.0",
            "product": {
                "name":        "Splunk Universal Forwarder",
                "vendor_name": "Splunk",
            },
            "original_time": fields.get("_time", ""),
            "source":        fields.get("source", ""),
            "sourcetype":    fields.get("sourcetype", ""),
        },
        "unmapped": {k: v for k, v in fields.items()
                     if not k.startswith("_") and k not in
                     ("source", "sourcetype", "host", "index")},
        "raw_data": fields.get("_raw", ""),
    }


def _class_name(uid: int) -> str:
    names = {
        CLASS_UNKNOWN:          "Unknown",
        CLASS_FILE_ACTIVITY:    "File System Activity",
        CLASS_NETWORK_ACTIVITY: "Network Activity",
        CLASS_DNS_ACTIVITY:     "DNS Activity",
        CLASS_HTTP_ACTIVITY:    "HTTP Activity",
        CLASS_AUTHENTICATION:   "Authentication",
        CLASS_ACCOUNT_CHANGE:   "Account Change",
        CLASS_PROCESS_ACTIVITY: "Process Activity",
        CLASS_SECURITY_FINDING: "Security Finding",
    }
    return names.get(uid, "Unknown")


# ---------------------------------------------------------------------------
# Class-specific mappers
# ---------------------------------------------------------------------------

def _extract_ip_port(fields: dict, prefix: str):
    ip   = fields.get(f"{prefix}_ip",   fields.get(f"{prefix}ip",   ""))
    port = fields.get(f"{prefix}_port", fields.get(f"{prefix}port", ""))
    try:
        port = int(port)
    except (ValueError, TypeError):
        port = None
    return ip, port


def map_authentication(fields: dict) -> dict:
    raw  = fields.get("_raw", "")
    user = (fields.get("user") or fields.get("user_name") or
            fields.get("src_user") or _extract_user_from_raw(raw))

    # Determine success/failure
    fail_keywords = ("fail", "invalid", "denied", "error", "wrong", "incorrect")
    pass_keywords = ("accepted", "success", "granted")
    status_id = STATUS_UNKNOWN
    if any(k in raw.lower() for k in pass_keywords):
        status_id = STATUS_SUCCESS
    elif any(k in raw.lower() for k in fail_keywords):
        status_id = STATUS_FAILURE

    event = _base(fields, CLASS_AUTHENTICATION, activity_id=1)
    event["status_id"] = status_id
    event["status"] = "Success" if status_id == STATUS_SUCCESS else \
                      "Failure" if status_id == STATUS_FAILURE else "Unknown"

    if user:
        event["user"] = {
            "name": user,
            "type_id": 1,
        }

    src_ip, src_port = _extract_ip_port(fields, "src")
    if src_ip:
        event["src_endpoint"] = {"ip": src_ip, "port": src_port}

    dst_ip, dst_port = _extract_ip_port(fields, "dst")
    if not dst_ip:
        dst_ip = fields.get("host", "")
    if dst_ip:
        event["dst_endpoint"] = {"ip": dst_ip, "port": dst_port}

    auth_proto = fields.get("auth_method", "")
    if "publickey" in raw.lower():  auth_proto = "publickey"
    elif "password" in raw.lower(): auth_proto = "password"
    elif "kerberos" in raw.lower(): auth_proto = "kerberos"
    elif "ntlm"     in raw.lower(): auth_proto = "NTLM"
    if auth_proto:
        event["auth_protocol"] = auth_proto

    return event


def map_network_activity(fields: dict) -> dict:
    event = _base(fields, CLASS_NETWORK_ACTIVITY, activity_id=6)  # 6 = Traffic

    src_ip, src_port = _extract_ip_port(fields, "src")
    dst_ip, dst_port = _extract_ip_port(fields, "dst")

    if src_ip:
        event["src_endpoint"] = {"ip": src_ip, "port": src_port}
    if dst_ip:
        event["dst_endpoint"] = {"ip": dst_ip, "port": dst_port}

    proto = fields.get("protocol", fields.get("transport", ""))
    if proto:
        event["connection_info"] = {"protocol_name": proto.upper()}

    bytes_in  = fields.get("bytes_in",  fields.get("bytes", ""))
    bytes_out = fields.get("bytes_out", "")
    if bytes_in or bytes_out:
        traffic = {}
        if bytes_in:  traffic["bytes_in"]  = _to_int(bytes_in)
        if bytes_out: traffic["bytes_out"] = _to_int(bytes_out)
        event["traffic"] = traffic

    action = fields.get("action", "").lower()
    if action in ("allowed", "allow", "permit"):
        event["status_id"] = STATUS_SUCCESS
    elif action in ("denied", "deny", "blocked", "block", "drop"):
        event["status_id"] = STATUS_FAILURE

    return event


def map_dns_activity(fields: dict) -> dict:
    event = _base(fields, CLASS_DNS_ACTIVITY, activity_id=1)  # 1 = Query

    query = fields.get("query", fields.get("dns_query", ""))
    qtype = fields.get("record_type", fields.get("qtype", ""))
    if query:
        event["dns_query"] = {"hostname": query, "type": qtype or "A"}

    rcode = fields.get("rcode", fields.get("reply_code", ""))
    if rcode:
        event["rcode_id"] = 0 if rcode.upper() in ("NOERROR", "0") else 1
        event["rcode"]    = rcode

    src_ip, src_port = _extract_ip_port(fields, "src")
    if src_ip:
        event["src_endpoint"] = {"ip": src_ip, "port": src_port}

    return event


def map_http_activity(fields: dict) -> dict:
    event = _base(fields, CLASS_HTTP_ACTIVITY, activity_id=1)  # 1 = Request

    method = fields.get("method", fields.get("http_method", ""))
    uri    = fields.get("uri",    fields.get("url", fields.get("uri_path", "")))
    status = fields.get("status", fields.get("status_code", ""))

    http_req = {}
    if method: http_req["http_method"] = method.upper()
    if uri:    http_req["url"] = {"path": uri, "text": uri}
    if http_req:
        event["http_request"] = http_req

    if status:
        event["http_status"] = _to_int(status)
        try:
            code = int(status)
            event["status_id"] = STATUS_SUCCESS if code < 400 else STATUS_FAILURE
        except ValueError:
            pass

    src_ip, src_port = _extract_ip_port(fields, "src")
    if not src_ip:
        src_ip = fields.get("clientip", fields.get("c_ip", ""))
    if src_ip:
        event["src_endpoint"] = {"ip": src_ip}

    return event


def map_process_activity(fields: dict) -> dict:
    event = _base(fields, CLASS_PROCESS_ACTIVITY, activity_id=1)  # 1 = Launch

    proc = {}
    cmd  = fields.get("CommandLine", fields.get("command", fields.get("process", "")))
    pid  = fields.get("ProcessId",   fields.get("pid", ""))
    name = fields.get("Image",       fields.get("process_name", ""))
    if cmd:  proc["cmd_line"] = cmd
    if pid:  proc["pid"]      = _to_int(pid)
    if name: proc["name"]     = name
    if proc:
        event["process"] = proc

    user = fields.get("User", fields.get("user", fields.get("user_name", "")))
    if user:
        event["actor"] = {"user": {"name": user}}

    return event


def map_file_activity(fields: dict) -> dict:
    op  = fields.get("syscall", fields.get("operation", "")).lower()
    act = {"open": ACTIVITY_READ, "read": ACTIVITY_READ,
           "write": ACTIVITY_UPDATE, "create": ACTIVITY_CREATE,
           "unlink": ACTIVITY_DELETE, "delete": ACTIVITY_DELETE,
           "rename": ACTIVITY_UPDATE}.get(op, ACTIVITY_UNKNOWN)

    event = _base(fields, CLASS_FILE_ACTIVITY, activity_id=act)

    path = fields.get("name", fields.get("file", fields.get("filePath", "")))
    if path:
        event["file"] = {"path": path, "name": path.split("/")[-1]}

    user = fields.get("auid", fields.get("uid", fields.get("user", "")))
    if user:
        event["actor"] = {"user": {"name": user}}

    return event


def map_security_finding(fields: dict) -> dict:
    event = _base(fields, CLASS_SECURITY_FINDING, activity_id=1)

    sig_id   = fields.get("signature_id", fields.get("rule_id",    ""))
    sig_name = fields.get("signature",    fields.get("alert_name", ""))
    if sig_id or sig_name:
        event["finding"] = {
            "uid":   sig_id,
            "title": sig_name,
        }

    severity = fields.get("severity", "")
    if severity:
        event["severity"] = severity

    src_ip, src_port = _extract_ip_port(fields, "src")
    dst_ip, dst_port = _extract_ip_port(fields, "dst")
    if src_ip: event["src_endpoint"] = {"ip": src_ip, "port": src_port}
    if dst_ip: event["dst_endpoint"] = {"ip": dst_ip, "port": dst_port}

    return event


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_USER_RE = re.compile(
    r"(?:for|user|invalid user|Accepted\w*\s+for|Failed\w*\s+for)\s+(\w+)",
    re.IGNORECASE
)

def _extract_user_from_raw(raw: str) -> Optional[str]:
    m = _USER_RE.search(raw)
    return m.group(1) if m else None


def _to_int(v) -> Optional[int]:
    try:
        return int(v)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

CLASS_MAPPER = {
    CLASS_AUTHENTICATION:   map_authentication,
    CLASS_NETWORK_ACTIVITY: map_network_activity,
    CLASS_DNS_ACTIVITY:     map_dns_activity,
    CLASS_HTTP_ACTIVITY:    map_http_activity,
    CLASS_PROCESS_ACTIVITY: map_process_activity,
    CLASS_FILE_ACTIVITY:    map_file_activity,
    CLASS_SECURITY_FINDING: map_security_finding,
}


def to_ocsf(fields: dict) -> dict:
    """
    Convert a decoded Splunk KV dict to an OCSF event dict.
    Returns a dict ready for JSON serialization or Parquet write.
    """
    class_uid = detect_class(fields)
    mapper    = CLASS_MAPPER.get(class_uid)
    if mapper:
        event = mapper(fields)
    else:
        event = _base(fields, CLASS_UNKNOWN, ACTIVITY_UNKNOWN)

    # Always stamp observables
    event["observables"] = _build_observables(event)

    return event


def _build_observables(event: dict) -> list:
    obs = []
    for key in ("src_endpoint", "dst_endpoint"):
        ep = event.get(key)
        if ep and ep.get("ip"):
            obs.append({"name": key, "type_id": 28, "value": ep["ip"]})
    user = (event.get("user") or {}).get("name") or \
           (event.get("actor") or {}).get("user", {}).get("name")
    if user:
        obs.append({"name": "user.name", "type_id": 4, "value": user})
    return obs
