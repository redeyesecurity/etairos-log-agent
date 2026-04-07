#!/usr/bin/env python3
"""
OCSF Event Mapper - Converts Splunk events to OCSF v1.1 schema
"""

import re
import time
from typing import Dict, Any, Optional


class OCSFMapper:
    """Maps Splunk events to OCSF event classes"""
    
    # OCSF class UIDs
    CLASS_UNKNOWN = 0
    CLASS_FILE_SYSTEM = 1001
    CLASS_SECURITY_FINDING = 2001
    CLASS_DNS = 3001
    CLASS_HTTP = 3003
    CLASS_NETWORK = 3005
    CLASS_AUTHENTICATION = 4002
    CLASS_PROCESS = 6001
    
    # Sourcetype to OCSF class mapping
    SOURCETYPE_MAP = {
        # Authentication
        "linux_secure": CLASS_AUTHENTICATION,
        "linux:auth": CLASS_AUTHENTICATION,
        "wineventlog:security": CLASS_AUTHENTICATION,
        "WinEventLog:Security": CLASS_AUTHENTICATION,
        
        # Network
        "cisco:asa": CLASS_NETWORK,
        "cisco:firepower": CLASS_NETWORK,
        "pan:traffic": CLASS_NETWORK,
        "pan:threat": CLASS_NETWORK,
        "fortinet:traffic": CLASS_NETWORK,
        "netflow": CLASS_NETWORK,
        "stream:tcp": CLASS_NETWORK,
        "stream:udp": CLASS_NETWORK,
        
        # DNS
        "stream:dns": CLASS_DNS,
        "cisco:umbrella:dns": CLASS_DNS,
        "infoblox:dns": CLASS_DNS,
        "ms:dns": CLASS_DNS,
        
        # HTTP
        "apache:access": CLASS_HTTP,
        "nginx:access": CLASS_HTTP,
        "iis": CLASS_HTTP,
        "stream:http": CLASS_HTTP,
        "access_combined": CLASS_HTTP,
        
        # Process
        "sysmon": CLASS_PROCESS,
        "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational": CLASS_PROCESS,
        "wineventlog:system": CLASS_PROCESS,
        "ps:process": CLASS_PROCESS,
        
        # File System
        "auditd": CLASS_FILE_SYSTEM,
        "linux:audit": CLASS_FILE_SYSTEM,
        
        # Security Finding
        "snort": CLASS_SECURITY_FINDING,
        "suricata": CLASS_SECURITY_FINDING,
        "crowdstrike:events": CLASS_SECURITY_FINDING,
        "symantec:ep": CLASS_SECURITY_FINDING,
    }
    
    # Keyword patterns for fallback classification
    AUTH_KEYWORDS = re.compile(
        r"(sshd|login|logout|auth|pam|sudo|su\[|accepted|failed password|invalid user|"
        r"authentication|logon|logoff|kerberos|ntlm|ldap)",
        re.IGNORECASE
    )
    NETWORK_KEYWORDS = re.compile(
        r"(firewall|denied|permitted|connection|src_ip|dst_ip|src_port|dst_port|"
        r"bytes_in|bytes_out|session|vpn|ipsec)",
        re.IGNORECASE
    )
    DNS_KEYWORDS = re.compile(
        r"(dns|query|response|nxdomain|servfail|a record|aaaa|cname|mx record)",
        re.IGNORECASE
    )
    HTTP_KEYWORDS = re.compile(
        r'(GET |POST |PUT |DELETE |HEAD |OPTIONS |"GET |"POST |http/1\.|http/2|'
        r"user-agent|referer|status=\d{3})",
        re.IGNORECASE
    )
    
    def __init__(self):
        self.version = "1.1.0"
    
    def map(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Map a Splunk event to OCSF format"""
        sourcetype = event.get("sourcetype", "")
        raw = event.get("_raw", "")
        
        # Determine OCSF class
        class_uid = self._classify(sourcetype, raw)
        class_name = self._class_name(class_uid)
        
        # Build base OCSF event
        ocsf = {
            "class_uid": class_uid,
            "class_name": class_name,
            "activity_id": 0,  # Unknown activity
            "status_id": 0,   # Unknown status
            "time": int(event.get("_time", time.time()) * 1000),  # OCSF uses milliseconds
            "metadata": {
                "version": self.version,
                "product": {
                    "name": "Splunk",
                    "vendor_name": "Splunk Inc."
                },
                "original_time": event.get("_time"),
                "source": event.get("source", ""),
                "sourcetype": sourcetype,
                "host": event.get("host", "")
            },
            "raw_data": raw,
            "observables": []
        }
        
        # Class-specific enrichment
        if class_uid == self.CLASS_AUTHENTICATION:
            ocsf = self._enrich_auth(ocsf, event)
        elif class_uid == self.CLASS_NETWORK:
            ocsf = self._enrich_network(ocsf, event)
        elif class_uid == self.CLASS_DNS:
            ocsf = self._enrich_dns(ocsf, event)
        elif class_uid == self.CLASS_HTTP:
            ocsf = self._enrich_http(ocsf, event)
        
        return ocsf
    
    def _classify(self, sourcetype: str, raw: str) -> int:
        """Determine OCSF class from sourcetype and content"""
        # Check explicit sourcetype mapping
        if sourcetype in self.SOURCETYPE_MAP:
            return self.SOURCETYPE_MAP[sourcetype]
        
        # Partial match on sourcetype
        st_lower = sourcetype.lower()
        for pattern, class_uid in self.SOURCETYPE_MAP.items():
            if pattern.lower() in st_lower:
                return class_uid
        
        # Keyword-based fallback
        if self.AUTH_KEYWORDS.search(raw):
            return self.CLASS_AUTHENTICATION
        if self.DNS_KEYWORDS.search(raw):
            return self.CLASS_DNS
        if self.HTTP_KEYWORDS.search(raw):
            return self.CLASS_HTTP
        if self.NETWORK_KEYWORDS.search(raw):
            return self.CLASS_NETWORK
        
        return self.CLASS_UNKNOWN
    
    def _class_name(self, class_uid: int) -> str:
        """Get OCSF class name from UID"""
        names = {
            0: "Unknown",
            1001: "File System Activity",
            2001: "Security Finding",
            3001: "DNS Activity",
            3003: "HTTP Activity",
            3005: "Network Activity",
            4002: "Authentication",
            6001: "Process Activity"
        }
        return names.get(class_uid, "Unknown")
    
    def _enrich_auth(self, ocsf: Dict, event: Dict) -> Dict:
        """Enrich authentication events"""
        raw = event.get("_raw", "")
        
        # Try to extract user
        user_match = re.search(r"(?:user[=:\s]+|for\s+)([^\s,;]+)", raw, re.IGNORECASE)
        if user_match:
            ocsf["user"] = {"name": user_match.group(1), "type_id": 1}
            ocsf["observables"].append({
                "name": "user.name",
                "type_id": 4,
                "value": user_match.group(1)
            })
        
        # Determine success/failure
        if re.search(r"(accepted|success|succeeded)", raw, re.IGNORECASE):
            ocsf["activity_id"] = 1  # Logon
            ocsf["status_id"] = 1    # Success
            ocsf["status"] = "Success"
        elif re.search(r"(failed|failure|denied|invalid)", raw, re.IGNORECASE):
            ocsf["activity_id"] = 1  # Logon
            ocsf["status_id"] = 2    # Failure
            ocsf["status"] = "Failure"
        
        # Extract source IP
        ip_match = re.search(r"(?:from|src|source)[=:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", raw, re.IGNORECASE)
        if ip_match:
            ocsf["src_endpoint"] = {"ip": ip_match.group(1)}
            ocsf["observables"].append({
                "name": "src_endpoint.ip",
                "type_id": 2,
                "value": ip_match.group(1)
            })
        
        return ocsf
    
    def _enrich_network(self, ocsf: Dict, event: Dict) -> Dict:
        """Enrich network activity events"""
        raw = event.get("_raw", "")
        
        # Extract IPs
        src_ip = re.search(r"(?:src|source|src_ip)[=:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", raw, re.IGNORECASE)
        dst_ip = re.search(r"(?:dst|dest|dst_ip|destination)[=:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", raw, re.IGNORECASE)
        
        if src_ip:
            ocsf["src_endpoint"] = {"ip": src_ip.group(1)}
        if dst_ip:
            ocsf["dst_endpoint"] = {"ip": dst_ip.group(1)}
        
        # Extract ports
        src_port = re.search(r"(?:src_port|sport)[=:\s]+(\d+)", raw, re.IGNORECASE)
        dst_port = re.search(r"(?:dst_port|dport)[=:\s]+(\d+)", raw, re.IGNORECASE)
        
        if src_port:
            ocsf.setdefault("src_endpoint", {})["port"] = int(src_port.group(1))
        if dst_port:
            ocsf.setdefault("dst_endpoint", {})["port"] = int(dst_port.group(1))
        
        # Action
        if re.search(r"(denied|blocked|drop)", raw, re.IGNORECASE):
            ocsf["activity_id"] = 5  # Refuse
            ocsf["status_id"] = 2
        elif re.search(r"(permitted|allowed|accept)", raw, re.IGNORECASE):
            ocsf["activity_id"] = 1  # Open
            ocsf["status_id"] = 1
        
        return ocsf
    
    def _enrich_dns(self, ocsf: Dict, event: Dict) -> Dict:
        """Enrich DNS activity events"""
        raw = event.get("_raw", "")
        
        # Extract query
        query_match = re.search(r"(?:query|name)[=:\s]+([^\s,;]+)", raw, re.IGNORECASE)
        if query_match:
            ocsf["query"] = {"hostname": query_match.group(1)}
            ocsf["observables"].append({
                "name": "query.hostname",
                "type_id": 1,
                "value": query_match.group(1)
            })
        
        # Query type
        type_match = re.search(r"(?:type|qtype)[=:\s]+(A|AAAA|CNAME|MX|PTR|TXT|NS|SOA)", raw, re.IGNORECASE)
        if type_match:
            ocsf.setdefault("query", {})["type"] = type_match.group(1).upper()
        
        return ocsf
    
    def _enrich_http(self, ocsf: Dict, event: Dict) -> Dict:
        """Enrich HTTP activity events"""
        raw = event.get("_raw", "")
        
        # Extract method
        method_match = re.search(r'"?(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)', raw)
        if method_match:
            ocsf["http_request"] = {"http_method": method_match.group(1)}
        
        # Extract URL/path
        url_match = re.search(r'(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s"]+)', raw)
        if url_match:
            ocsf.setdefault("http_request", {})["url"] = {"path": url_match.group(1)}
        
        # Extract status code
        status_match = re.search(r'(?:status[=:\s]+|HTTP/\d\.\d"\s+)(\d{3})', raw)
        if status_match:
            code = int(status_match.group(1))
            ocsf["http_response"] = {"code": code}
            if 200 <= code < 300:
                ocsf["status_id"] = 1  # Success
            elif 400 <= code < 500:
                ocsf["status_id"] = 2  # Failure
            elif code >= 500:
                ocsf["status_id"] = 3  # Error
        
        # Extract user agent
        ua_match = re.search(r'(?:user-agent|useragent)[=:\s]+"?([^"]+)"?', raw, re.IGNORECASE)
        if ua_match:
            ocsf.setdefault("http_request", {})["user_agent"] = ua_match.group(1)
        
        return ocsf
