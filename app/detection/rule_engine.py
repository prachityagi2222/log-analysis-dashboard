import re
from collections import defaultdict
from typing import List, Dict, Any
from app.detection.mitre import MITRE_TACTICS


class RuleEngine:
    def __init__(self):
        # Web Attack Patterns
        self.sqli_patterns = [
            re.compile(r"(\%27)|(\')|(\-\-)|(\%23)|(#)", re.IGNORECASE),
            re.compile(r"\b(UNION(?:\s+ALL)?\s+SELECT|SELECT\s+.*\s+FROM|INSERT\s+INTO|DROP\s+TABLE|WAITFOR\s+DELAY|SLEEP\(\d+\))\b", re.IGNORECASE),
            re.compile(r"(\bor\b|\band\b)\s+['\"0-9a-z]+\s*=\s*['\"0-9a-z]+", re.IGNORECASE),
            re.compile(r"information_schema", re.IGNORECASE)
        ]
        
        self.traversal_patterns = [
            re.compile(r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e\/)", re.IGNORECASE),
            re.compile(r"(?:/etc/passwd|/etc/shadow|win\.ini|boot\.ini)", re.IGNORECASE),
        ]
        
        self.cmd_patterns = [
            re.compile(r"(?:;\s*(?:cat|ls|id|whoami|net\s+user|rm|curl|wget|powershell|cmd\.exe|/bin/sh|/bin/bash))", re.IGNORECASE),
            re.compile(r"(\||`|\$\()", re.IGNORECASE),
        ]

        self.scanner_paths = [
            "/.env", "/wp-login.php", "/wp-admin", "/phpmyadmin", "/.git",
            "/config.php", "/xmlrpc.php", "/admin.php", "/shell.php",
            "/actuator/env", "/solr/", "/cgi-bin/"
        ]

        self.suspicious_ports = {4444, 1337, 31337, 8888, 6667, 5555, 9999}

    def run(self, log_type: str, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        detections = []
        if not events:
            return detections

        if log_type == "ssh":
            detections.extend(self._detect_ssh_rules(events))
        elif log_type == "web":
            detections.extend(self._detect_web_rules(events))
        elif log_type == "firewall":
            detections.extend(self._detect_firewall_rules(events))
        else:
            detections.extend(self._detect_ssh_rules(events))

        return detections

    def _detect_ssh_rules(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        detections = []
        
        # 1. SSH Brute Force
        failed_by_ip = defaultdict(list)
        invalid_by_ip = defaultdict(list)
        root_attempts = []

        for ev in events:
            idx = ev["index"]
            ip = ev.get("source_ip") or "unknown"
            action = ev.get("action")
            user = ev.get("user") or ""

            if action in ("failed_login", "invalid_user") or ev.get("status") == "failure":
                failed_by_ip[ip].append(idx)

            if ev.get("is_invalid_user"):
                invalid_by_ip[ip].append(idx)

            if user.lower() == "root":
                root_attempts.append(idx)

        # Evaluate Brute Force threshold (>= 3 failed attempts)
        for ip, indices in failed_by_ip.items():
            if ip != "unknown" and len(indices) >= 3:
                severity = "critical" if len(indices) >= 10 else "high"
                detections.append({
                    "method": "rule",
                    "name": "brute_force",
                    "severity": severity,
                    "description": f"Potential SSH brute force attack detected ({len(indices)} failed attempts from {ip})",
                    "mitre_tactic": MITRE_TACTICS["CREDENTIAL_ACCESS"],
                    "indices": indices
                })

        # Evaluate Invalid Users (>= 2)
        for ip, indices in invalid_by_ip.items():
            if ip != "unknown" and len(indices) >= 2:
                detections.append({
                    "method": "rule",
                    "name": "invalid_user_enumeration",
                    "severity": "medium",
                    "description": f"User enumeration activity: {len(indices)} attempts with non-existent usernames from {ip}",
                    "mitre_tactic": MITRE_TACTICS["CREDENTIAL_ACCESS"],
                    "indices": indices
                })

        # Evaluate Root logins
        if root_attempts:
            detections.append({
                "method": "rule",
                "name": "root_login_attempt",
                "severity": "medium",
                "description": f"Direct root account login attempts detected ({len(root_attempts)} events)",
                "mitre_tactic": MITRE_TACTICS["VALID_ACCOUNTS"] if "VALID_ACCOUNTS" in MITRE_TACTICS else "Initial Access",
                "indices": root_attempts
            })

        return detections

    def _detect_web_rules(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        detections = []
        sqli_indices = []
        traversal_indices = []
        cmd_indices = []
        scanner_indices = []
        ip_req_indices = defaultdict(list)

        for ev in events:
            idx = ev["index"]
            raw = ev.get("raw", "")
            url = ev.get("url", "")
            ip = ev.get("source_ip") or "unknown"
            ip_req_indices[ip].append(idx)

            # SQLi Check
            if any(p.search(url) or p.search(raw) for p in self.sqli_patterns):
                sqli_indices.append(idx)

            # Path Traversal Check
            if any(p.search(url) or p.search(raw) for p in self.traversal_patterns):
                traversal_indices.append(idx)

            # Command Injection Check
            if any(p.search(url) for p in self.cmd_patterns):
                cmd_indices.append(idx)

            # Scanner Path Check
            url_lower = url.lower()
            if any(probe in url_lower for probe in self.scanner_paths):
                scanner_indices.append(idx)

        if sqli_indices:
            detections.append({
                "method": "rule",
                "name": "web_sql_injection",
                "severity": "critical",
                "description": f"SQL Injection patterns detected in {len(sqli_indices)} HTTP requests",
                "mitre_tactic": MITRE_TACTICS["INITIAL_ACCESS"],
                "indices": sqli_indices
            })

        if traversal_indices:
            detections.append({
                "method": "rule",
                "name": "web_path_traversal",
                "severity": "high",
                "description": f"Directory traversal / LFI attempts detected in {len(traversal_indices)} HTTP requests",
                "mitre_tactic": MITRE_TACTICS["INITIAL_ACCESS"],
                "indices": traversal_indices
            })

        if cmd_indices:
            detections.append({
                "method": "rule",
                "name": "web_command_injection",
                "severity": "critical",
                "description": f"Operating system command injection signatures detected in {len(cmd_indices)} requests",
                "mitre_tactic": MITRE_TACTICS["EXECUTION"],
                "indices": cmd_indices
            })

        if scanner_indices:
            detections.append({
                "method": "rule",
                "name": "web_vulnerability_probe",
                "severity": "medium",
                "description": f"Automated vulnerability scanner probes targeting sensitive endpoints in {len(scanner_indices)} requests",
                "mitre_tactic": MITRE_TACTICS["RECONNAISSANCE"],
                "indices": scanner_indices
            })

        # Request volume / DoS probe check
        for ip, indices in ip_req_indices.items():
            if ip != "unknown" and len(indices) >= 20:
                detections.append({
                    "method": "rule",
                    "name": "high_volume_traffic",
                    "severity": "medium",
                    "description": f"Anomalously high volume of requests ({len(indices)}) originated from {ip}",
                    "mitre_tactic": MITRE_TACTICS["IMPACT"],
                    "indices": indices
                })

        return detections

    def _detect_firewall_rules(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        detections = []
        ip_ports = defaultdict(set)
        ip_port_indices = defaultdict(list)
        ip_blocked_indices = defaultdict(list)
        suspicious_port_indices = []

        for ev in events:
            idx = ev["index"]
            src_ip = ev.get("source_ip") or "unknown"
            dst_port = ev.get("dest_port")

            if dst_port:
                ip_ports[src_ip].add(dst_port)
                ip_port_indices[src_ip].append(idx)
                if dst_port in self.suspicious_ports:
                    suspicious_port_indices.append(idx)

            if ev.get("is_blocked"):
                ip_blocked_indices[src_ip].append(idx)

        # Port Scan Check: single IP hitting >= 5 distinct ports
        for ip, ports in ip_ports.items():
            if ip != "unknown" and len(ports) >= 5:
                detections.append({
                    "method": "rule",
                    "name": "port_scan",
                    "severity": "high",
                    "description": f"Port scan detected from {ip} probing {len(ports)} distinct ports",
                    "mitre_tactic": MITRE_TACTICS["DISCOVERY"],
                    "indices": ip_port_indices[ip]
                })

        # Excessive blocked traffic flood
        for ip, indices in ip_blocked_indices.items():
            if ip != "unknown" and len(indices) >= 10:
                detections.append({
                    "method": "rule",
                    "name": "firewall_traffic_flood",
                    "severity": "high",
                    "description": f"Excessive blocked network traffic from {ip} ({len(indices)} dropped packets)",
                    "mitre_tactic": MITRE_TACTICS["IMPACT"],
                    "indices": indices
                })

        # Suspicious destination ports
        if suspicious_port_indices:
            detections.append({
                "method": "rule",
                "name": "firewall_suspicious_port",
                "severity": "medium",
                "description": f"Inbound connections targeting suspicious malware/backdoor ports in {len(suspicious_port_indices)} events",
                "mitre_tactic": MITRE_TACTICS["COMMAND_AND_CONTROL"],
                "indices": suspicious_port_indices
            })

        return detections
