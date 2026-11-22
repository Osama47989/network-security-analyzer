"""
NETWORK SECURITY ANALYZER - VERSION 1.0

A Windows-focused, host-based network security
monitoring and baseline comparison application.

Features:
- TCP connection monitoring
- Process identification
- Windows Firewall investigation
- Network baseline comparison
- Security alert generation
- Alert severity classification
- JSON and TXT reporting
- Automated self-testing
- Command-line interface

This application performs read-only network
inspection during normal scans.
"""

import argparse
import base64
import ipaddress
import json
import os
import platform
import shutil
import socket
import subprocess

from datetime import datetime
from pathlib import Path

import psutil


# ==========================================
# CONFIGURATION
# ==========================================

VERSION = "1.0"

ROOT = Path(__file__).resolve().parent

REPORT_DIR = ROOT / "reports"

BASELINE_FILE = REPORT_DIR / "baseline.json"


# These ports deserve additional review.
# Their presence does not prove a vulnerability.

REVIEW_PORTS = {
    135: "Windows RPC",
    139: "NetBIOS / File Sharing",
    445: "SMB File Sharing",
    7070: "Remote access (verify application)",
}


# ==========================================
# FUNCTION 1: CURRENT TIMESTAMP
# ==========================================

def timestamp():

    return datetime.now().astimezone().isoformat(
        timespec="seconds"
    )


# ==========================================
# FUNCTION 2: SYSTEM INFORMATION
# ==========================================

def system_info():

    hostname = socket.gethostname()

    try:

        ipv4 = socket.gethostbyname(hostname)

    except socket.gaierror:

        ipv4 = "Unavailable"

    return {
        "os": platform.system(),
        "hostname": hostname,
        "ipv4": ipv4,
    }


# ==========================================
# FUNCTION 3: PROCESS IDENTIFICATION
# ==========================================

def process_name(pid, cache):

    if pid is None:
        return "Unknown"

    if pid not in cache:

        try:

            cache[pid] = psutil.Process(pid).name()

        except (psutil.Error, OSError):

            cache[pid] = "Unavailable"

    return cache[pid]


# ==========================================
# FUNCTION 4: FORMAT NETWORK ENDPOINTS
# ==========================================

def endpoint(ip, port):

    if not ip or port is None:
        return "Unavailable"

    if ":" in ip:
        return f"[{ip}]:{port}"

    return f"{ip}:{port}"


# ==========================================
# FUNCTION 5: COLLECT TCP CONNECTIONS
# ==========================================

def collect_connections(scan):

    try:

        connections = psutil.net_connections(
            kind="tcp"
        )

    except (psutil.Error, OSError) as exc:

        scan["errors"].append(
            f"TCP collection failed: {exc}"
        )

        return

    cache = {}

    for conn in connections:

        if conn.status not in (
            psutil.CONN_LISTEN,
            psutil.CONN_ESTABLISHED
        ):
            continue

        item = {

            "local_ip": (
                conn.laddr.ip if conn.laddr else None
            ),

            "local_port": (
                conn.laddr.port if conn.laddr else None
            ),

            "remote_ip": (
                conn.raddr.ip if conn.raddr else None
            ),

            "remote_port": (
                conn.raddr.port if conn.raddr else None
            ),

            "pid": conn.pid,

            "process": process_name(
                conn.pid,
                cache
            ),

            "status": str(conn.status),
        }

        if conn.status == psutil.CONN_LISTEN:

            scan["listening"].append(item)

        else:

            scan["established"].append(item)

    scan["listening"].sort(
        key=lambda c: (
            c["local_port"] or 0,
            c["local_ip"] or ""
        )
    )

    scan["established"].sort(
        key=lambda c: (
            c["remote_ip"] or "",
            c["remote_port"] or 0
        )
    )

    scan["connections_collected"] = True


# ==========================================
# FUNCTION 6: GROUP LISTENING PORTS
# ==========================================

def listening_by_port(connections):

    groups = {}

    for conn in connections:

        if not isinstance(conn, dict):
            continue

        port = conn.get("local_port")

        if type(port) is not int:
            continue

        if not 1 <= port <= 65535:
            continue

        group = groups.setdefault(
            port,
            {
                "addresses": set(),
                "processes": set()
            }
        )

        group["addresses"].add(
            conn.get("local_ip") or "Unknown"
        )

        group["processes"].add(
            conn.get("process") or "Unknown"
        )

    return {

        port: {

            "addresses": sorted(
                value["addresses"]
            ),

            "processes": sorted(
                value["processes"]
            ),
        }

        for port, value in groups.items()
    }


# ==========================================
# FUNCTION 7: NETWORK SECURITY REVIEW
# ==========================================

def build_findings(scan):

    grouped = listening_by_port(
        scan["listening"]
    )

    matching_ports = (
        grouped.keys() & REVIEW_PORTS.keys()
    )

    for port in sorted(matching_ports):

        scan["findings"].append({

            "port": port,

            "service_hint": REVIEW_PORTS[port],

            "listening_addresses": (
                grouped[port]["addresses"]
            ),

            "processes": (
                grouped[port]["processes"]
            ),

            "assessment": (
                "Review only; vulnerability or "
                "network reachability not established"
            ),
        })


# ==========================================
# FUNCTION 8: WINDOWS FIREWALL PROFILE
# ==========================================

def collect_firewall_profile(scan):

    try:

        result = subprocess.run(
            [
                "netsh",
                "advfirewall",
                "show",
                "currentprofile"
            ],

            capture_output=True,
            text=True,
            errors="replace",
            timeout=20
        )

        if result.returncode == 0:

            scan["firewall_profile"] = (
                result.stdout.strip()
            )

        else:

            message = (
                result.stderr.strip()
                or str(result.returncode)
            )

            scan["errors"].append(
                "Firewall profile query failed: "
                + message
            )

    except (
        OSError,
        subprocess.TimeoutExpired
    ) as exc:

        scan["errors"].append(
            f"Firewall profile query failed: {exc}"
        )


# ==========================================
# FUNCTION 9: FIREWALL RULE INVESTIGATION
# ==========================================

def collect_firewall_rules(scan):

    # These PowerShell commands only read
    # Windows Firewall configuration.
    #
    # Candidate firewall rules do not prove
    # that a network port is reachable.

    lines = [

        "$ErrorActionPreference = 'Stop'",

        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)",

        "$targets = @('135','139','445','7070')",

        "$results = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound | ForEach-Object {",

        "    $rule = $_",

        "    $filters = @($rule | Get-NetFirewallPortFilter)",

        "    $apps = @($rule | Get-NetFirewallApplicationFilter)",

        "    $ports = @($filters | ForEach-Object { $_.LocalPort })",

        "    $protocols = @($filters | ForEach-Object { [string]$_.Protocol })",

        "    $programs = @($apps | ForEach-Object { [string]$_.Program })",

        "    $portMatch = $false",

        "    foreach ($filter in $filters) {",

        "        if ([string]$filter.Protocol -notin @('TCP','6','Any')) { continue }",

        "        foreach ($port in @($filter.LocalPort)) {",

        "            if ($targets -contains [string]$port) { $portMatch = $true }",

        "        }",

        "    }",

        "    $appMatch = ([string]$rule.DisplayName -match 'AnyDesk')",

        "    foreach ($program in $programs) {",

        "        if ($program -match 'AnyDesk') { $appMatch = $true }",

        "    }",

        "    if ($portMatch -or $appMatch) {",

        "        [PSCustomObject]@{",

        "            Name = [string]$rule.DisplayName",

        "            Enabled = [string]$rule.Enabled",

        "            Direction = [string]$rule.Direction",

        "            Action = [string]$rule.Action",

        "            Profile = [string]$rule.Profile",

        "            Protocol = ($protocols -join ', ')",

        "            LocalPort = ($ports -join ', ')",

        "            Program = ($programs -join ', ')",

        "        }",

        "    }",

        "})",

        "ConvertTo-Json -InputObject @($results) -Depth 4 -Compress",
    ]

    script = "\n".join(lines)

    encoded = base64.b64encode(
        script.encode("utf-16le")
    ).decode("ascii")

    try:

        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                encoded
            ],

            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=90
        )

        if result.returncode != 0:

            message = (
                result.stderr.strip()
                or str(result.returncode)
            )

            scan["errors"].append(
                "Firewall rule query failed: "
                + message
            )

            return

        raw = json.loads(
            result.stdout.strip()
        )

        if isinstance(raw, dict):
            raw = [raw]

        if not isinstance(raw, list):

            raise ValueError(
                "Unexpected firewall rule response"
            )

        if not all(
            isinstance(item, dict)
            for item in raw
        ):

            raise ValueError(
                "Invalid firewall rule entries"
            )

        scan["firewall_rules"] = raw

    except (
        OSError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
        ValueError
    ) as exc:

        scan["errors"].append(
            f"Firewall rule query failed: {exc}"
        )


# ==========================================
# FUNCTION 10: VALIDATE BASELINE
# ==========================================

def validate_baseline(baseline, hostname):

    if not isinstance(baseline, dict):

        raise ValueError(
            "Baseline must be a JSON object"
        )

    system = baseline.get("system")

    if not isinstance(system, dict):

        raise ValueError(
            "Baseline is missing system information"
        )

    if system.get("hostname") != hostname:

        raise ValueError(
            "Baseline belongs to a different hostname"
        )

    listening = baseline.get("listening")

    if not isinstance(listening, list):

        raise ValueError(
            "Baseline must contain a listening list"
        )

    for item in listening:

        if not isinstance(item, dict):

            raise ValueError(
                "Invalid baseline connection entry"
            )

        port = item.get("local_port")

        if type(port) is not int:

            raise ValueError(
                "Invalid baseline port type"
            )

        if not 1 <= port <= 65535:

            raise ValueError(
                "Invalid baseline port number"
            )

        if not isinstance(
            item.get("local_ip"),
            str
        ):

            raise ValueError(
                "Invalid baseline listening address"
            )

        if not isinstance(
            item.get("process"),
            str
        ):

            raise ValueError(
                "Invalid baseline process information"
            )

    return baseline


# ==========================================
# FUNCTION 11: LOAD NETWORK BASELINE
# ==========================================

def load_baseline(hostname):

    if not BASELINE_FILE.is_file():

        return (
            None,
            f"Baseline not found: {BASELINE_FILE}"
        )

    try:

        baseline = json.loads(
            BASELINE_FILE.read_text(
                encoding="utf-8"
            )
        )

        validated = validate_baseline(
            baseline,
            hostname
        )

        return validated, None

    except (OSError, ValueError) as exc:

        return (
            None,
            f"Could not load baseline: {exc}"
        )


# ==========================================
# FUNCTION 12: COMPARE LISTENING PORTS
# ==========================================

def compare_listeners(
    old_listening,
    new_listening
):

    old = listening_by_port(
        old_listening
    )

    new = listening_by_port(
        new_listening
    )

    # Identify newly observed ports.

    added = [

        {
            "port": port,
            **new[port]
        }

        for port in sorted(
            new.keys() - old.keys()
        )
    ]

    # Identify ports no longer observed.

    disappeared = [

        {
            "port": port,
            **old[port]
        }

        for port in sorted(
            old.keys() - new.keys()
        )
    ]

    # Identify changed listening services.

    changed = [

        {
            "port": port,
            "before": old[port],
            "after": new[port]
        }

        for port in sorted(
            old.keys() & new.keys()
        )

        if old[port] != new[port]
    ]

    return {

        "new_ports": added,

        "no_longer_observed": disappeared,

        "changed_ports": changed,
    }


# ==========================================
# FUNCTION 13: BASELINE COMPARISON
# ==========================================

def compare_with_baseline(scan):

    if not scan["connections_collected"]:

        scan["change_detection"] = {

            "status": "skipped",

            "message": (
                "TCP collection failed; "
                "comparison skipped"
            ),
        }

        return

    baseline, error = load_baseline(
        scan["system"]["hostname"]
    )

    if error:

        scan["change_detection"] = {

            "status": "unavailable",

            "message": error,
        }

        return

    changes = compare_listeners(
        baseline["listening"],
        scan["listening"]
    )

    scan["change_detection"] = {

        "status": "compared",

        "baseline_time": baseline.get(
            "scan_time",
            "Unknown"
        ),

        **changes,
    }


# ==========================================
# FUNCTION 14: LOOPBACK ADDRESS CHECK
# ==========================================

def loopback_only(addresses):

    if not addresses:
        return False

    try:

        ips = [
            ipaddress.ip_address(address)
            for address in addresses
        ]

    except ValueError:
        return False

    for ip in ips:

        if isinstance(
            ip,
            ipaddress.IPv6Address
        ):

            ip = ip.ipv4_mapped or ip

        if not ip.is_loopback:
            return False

    return True


# ==========================================
# FUNCTION 15: SECURITY ALERT ENGINE
# ==========================================

def evaluate_alerts(changes):

    empty_summary = {
        "total": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    if changes.get("status") != "compared":

        return [], empty_summary

    alerts = []

    # Create a structured security alert.

    def add_alert(
        rule,
        severity,
        category,
        port,
        processes,
        addresses,
        description,
        action
    ):

        alerts.append({

            "rule_id": rule,

            "severity": severity,

            "category": category,

            "protocol": "TCP",

            "port": port,

            "processes": processes,

            "listening_addresses": addresses,

            "description": description,

            "recommended_action": action,

            "baseline_time": changes.get(
                "baseline_time"
            ),
        })

    # ======================================
    # RULE 1: NEW LISTENING PORTS
    # ======================================

    for item in changes["new_ports"]:

        addresses = item["addresses"]

        processes = item["processes"]

        if loopback_only(addresses):

            severity = "INFO"

            rule = "NEW_LOOPBACK_LISTENER"

        elif any(
            name in ("Unknown", "Unavailable")
            for name in processes
        ):

            severity = "MEDIUM"

            rule = "NEW_LISTENER_UNIDENTIFIED_PROCESS"

        else:

            severity = "LOW"

            rule = "NEW_NON_LOOPBACK_LISTENER"

        add_alert(

            rule,

            severity,

            "New listening port",

            item["port"],

            processes,

            addresses,

            (
                "Listening port not present "
                "in the saved baseline."
            ),

            (
                "Confirm the service is authorized; "
                "inspect its binding and firewall policy."
            )
        )

    # ======================================
    # RULE 2: DISAPPEARED LISTENING PORTS
    # ======================================

    for item in changes["no_longer_observed"]:

        add_alert(

            "LISTENER_DISAPPEARED",

            "INFO",

            "Port no longer observed",

            item["port"],

            item["processes"],

            item["addresses"],

            (
                "A baseline listening port "
                "is not present in this scan."
            ),

            (
                "Check whether the service stopped "
                "or was reconfigured intentionally."
            )
        )

    # ======================================
    # RULE 3: CHANGED LISTENING SERVICES
    # ======================================

    for item in changes["changed_ports"]:

        before = item["before"]

        after = item["after"]

        expanded = (
            loopback_only(before["addresses"])
            and not loopback_only(after["addresses"])
        )

        if expanded:

            severity = "LOW"

            rule = "BINDING_EXPANDED"

        else:

            severity = "INFO"

            rule = "LISTENER_CHANGED"

        add_alert(

            rule,

            severity,

            "Listening service changed",

            item["port"],

            after["processes"],

            after["addresses"],

            (
                f"Before: {before}; "
                f"After: {after}."
            ),

            (
                "Verify whether the process "
                "and listening addresses are expected."
            )
        )

    # ======================================
    # SORT ALERTS BY SEVERITY
    # ======================================

    priority = {
        "MEDIUM": 0,
        "LOW": 1,
        "INFO": 2,
    }

    alerts.sort(
        key=lambda alert: (

            priority.get(
                alert["severity"],
                9
            ),

            alert["port"],

            alert["rule_id"],
        )
    )

    # Assign alert IDs after sorting.

    for index, alert in enumerate(
        alerts,
        1
    ):

        alert["id"] = (
            f"NSA-{index:03d}"
        )

    # ======================================
    # CREATE ALERT SUMMARY
    # ======================================

    summary = {
        "total": len(alerts)
    }

    for severity in (
        "MEDIUM",
        "LOW",
        "INFO"
    ):

        summary[severity] = sum(
            alert["severity"] == severity
            for alert in alerts
        )

    return alerts, summary


# ==========================================
# FUNCTION 16: GENERATE TEXT REPORT
# ==========================================

def text_report(scan):

    system = scan["system"]

    lines = [

        f"NETWORK SECURITY ANALYZER v{VERSION}",

        "=" * 64,

        f"Scan: {scan['scan_time']}",

        (
            f"System: {system['hostname']} | "
            f"{system['os']} | "
            f"IPv4: {system['ipv4']}"
        ),

        (
            "TCP listening endpoints: "
            + str(len(scan["listening"]))
        ),

        (
            "TCP established connections: "
            + str(len(scan["established"]))
        ),

        "",

        "LISTENING ENDPOINTS",

        "-" * 64,
    ]

    # ======================================
    # LISTENING PORTS
    # ======================================

    for conn in scan["listening"]:

        lines.append(

            f"{endpoint(conn['local_ip'], conn['local_port'])} | "

            f"PID {conn['pid']} | "

            f"{conn['process']}"
        )

    # ======================================
    # ESTABLISHED CONNECTIONS
    # ======================================

    lines += [
        "",
        "ESTABLISHED CONNECTIONS",
        "-" * 64
    ]

    for conn in scan["established"]:

        lines.append(

            f"{endpoint(conn['local_ip'], conn['local_port'])} -> "

            f"{endpoint(conn['remote_ip'], conn['remote_port'])} | "

            f"{conn['process']}"
        )

    # ======================================
    # SECURITY REVIEW
    # ======================================

    lines += [
        "",
        "PORTS FOR REVIEW",
        "-" * 64
    ]

    for item in scan["findings"]:

        lines.append(

            f"TCP {item['port']} | "

            f"{item['service_hint']} | "

            f"{item['processes']} | "

            f"{item['listening_addresses']}"
        )

        lines.append(
            item["assessment"]
        )

    # ======================================
    # FIREWALL PROFILE
    # ======================================

    lines += [

        "",

        "WINDOWS FIREWALL PROFILE",

        "-" * 64,

        scan["firewall_profile"] or "Unavailable",
    ]

    # ======================================
    # FIREWALL RULES
    # ======================================

    lines += [

        "",

        "CANDIDATE INBOUND FIREWALL RULES",

        "-" * 64,
    ]

    for item in scan["firewall_rules"]:

        fields = (
            "Name",
            "Enabled",
            "Action",
            "Profile",
            "Protocol",
            "LocalPort",
            "Program",
        )

        lines.append(
            " | ".join(

                f"{key}={item.get(key, '')}"

                for key in fields
            )
        )

    if not scan["firewall_rules"]:

        lines.append(
            "No candidate rules returned. "
            "Check collection errors."
        )

    # ======================================
    # BASELINE COMPARISON
    # ======================================

    changes = scan["change_detection"]

    lines += [

        "",

        "BASELINE COMPARISON",

        "-" * 64,

        (
            "Status: "
            + changes.get("status", "unknown")
        ),
    ]

    if changes.get("status") == "compared":

        lines.append(
            f"Baseline scan: {changes['baseline_time']}"
        )

        for field in (
            "new_ports",
            "no_longer_observed",
            "changed_ports"
        ):

            lines.append(
                f"{field}: {len(changes[field])}"
            )

            for item in changes[field]:

                lines.append(
                    f"  {item}"
                )

    else:

        lines.append(
            changes.get(
                "message",
                "No comparison result"
            )
        )

    # ======================================
    # SECURITY ALERTS
    # ======================================

    lines += [

        "",

        "SECURITY ALERTS",

        "-" * 64,

        (
            "Alert summary: "
            + str(scan["alert_summary"])
        ),
    ]

    for alert in scan["alerts"]:

        lines += [

            (
                f"[{alert['severity']}] "
                f"{alert['id']} | "
                f"{alert['rule_id']} | "
                f"TCP {alert['port']}"
            ),

            f"Category: {alert['category']}",

            (
                "Processes: "
                + ", ".join(alert["processes"])
            ),

            (
                "Addresses: "
                + ", ".join(
                    alert["listening_addresses"]
                )
            ),

            (
                "Description: "
                + alert["description"]
            ),

            (
                "Recommendation: "
                + alert["recommended_action"]
            ),

            "",
        ]

    # ======================================
    # LIMITATIONS AND ERRORS
    # ======================================

    lines += [

        "",

        "LIMITATIONS",

        "-" * 64,

        (
            "Snapshot comparison; this program "
            "is not continuous monitoring."
        ),

        (
            "New ports and alert priorities do not "
            "prove compromise or vulnerability."
        ),

        (
            "Non-loopback listeners are not "
            "necessarily reachable through the firewall."
        ),

        (
            "Candidate firewall rules do not "
            "establish effective reachability."
        ),

        "",

        "COLLECTION ERRORS",

        "-" * 64,
    ]

    lines.extend(
        scan["errors"] or ["None reported"]
    )

    return "\n".join(lines) + "\n"


# ==========================================
# FUNCTION 17: SAVE SECURITY REPORTS
# ==========================================

def save_reports(scan):

    try:

        REPORT_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        stamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S_%f"
        )

        json_path = REPORT_DIR / (
            f"security_report_{stamp}.json"
        )

        txt_path = REPORT_DIR / (
            f"security_report_{stamp}.txt"
        )

        # Save structured JSON report.

        json_path.write_text(

            json.dumps(
                scan,
                indent=2,
                ensure_ascii=False
            ),

            encoding="utf-8"
        )

        # Save human-readable TXT report.

        txt_path.write_text(

            text_report(scan),

            encoding="utf-8"
        )

        print(
            "\n[+] REPORTS GENERATED SUCCESSFULLY"
        )

        print(
            "JSON:",
            json_path
        )

        print(
            "TEXT:",
            txt_path
        )

        return True

    except OSError as exc:

        print(
            "[!] Failed to save reports:",
            exc
        )

        return False


# ==========================================
# FUNCTION 18: CREATE SCAN STRUCTURE
# ==========================================

def new_scan():

    return {

        "version": VERSION,

        "scan_time": timestamp(),

        "system": system_info(),

        "listening": [],

        "established": [],

        "connections_collected": False,

        "findings": [],

        "firewall_profile": "",

        "firewall_rules": [],

        "change_detection": {},

        "alerts": [],

        "alert_summary": {},

        "errors": [],
    }


# ==========================================
# FUNCTION 19: RUN NETWORK ANALYSIS
# ==========================================

def run_scan(verbose=False):

    scan = new_scan()

    print("=" * 54)

    print(
        "    NETWORK SECURITY ANALYZER v1.0"
    )

    print("=" * 54)

    # ======================================
    # SYSTEM INFORMATION
    # ======================================

    print("\n[+] SYSTEM INFORMATION")

    print(
        "Computer:",
        scan["system"]["hostname"]
    )

    print(
        "Operating System:",
        scan["system"]["os"]
    )

    print(
        "Hostname-resolved IPv4:",
        scan["system"]["ipv4"]
    )

    # ======================================
    # TCP CONNECTION COLLECTION
    # ======================================

    collect_connections(scan)

    build_findings(scan)

    print("\n[+] TCP CONNECTION ANALYSIS")

    print(
        "Listening endpoints:",
        len(scan["listening"])
    )

    print(
        "Established connections:",
        len(scan["established"])
    )

    # Print detailed connections if requested.

    if verbose:

        print("\n[+] LISTENING PORTS")

        for conn in scan["listening"]:

            print(

                f"{endpoint(conn['local_ip'], conn['local_port'])} | "

                f"PID: {conn['pid']} | "

                f"Process: {conn['process']}"
            )

        print("\n[+] ESTABLISHED CONNECTIONS")

        for conn in scan["established"]:

            print(

                f"{endpoint(conn['local_ip'], conn['local_port'])} -> "

                f"{endpoint(conn['remote_ip'], conn['remote_port'])} | "

                f"{conn['process']}"
            )

    # ======================================
    # NETWORK SECURITY REVIEW
    # ======================================

    print("\n[+] NETWORK SECURITY REVIEW")

    for item in scan["findings"]:

        print(

            f"[REVIEW] TCP {item['port']}: "

            f"{item['service_hint']} | "

            f"{', '.join(item['processes'])}"
        )

    print(
        "Unique review ports:",
        len(scan["findings"])
    )

    # ======================================
    # WINDOWS FIREWALL ANALYSIS
    # ======================================

    if platform.system() == "Windows":

        collect_firewall_profile(scan)

        collect_firewall_rules(scan)

    else:

        scan["errors"].append(
            "Windows firewall queries "
            "are unavailable on this OS"
        )

    print("\n[+] WINDOWS FIREWALL")

    if scan["firewall_profile"]:

        print("Profile query: Collected")

    else:

        print("Profile query: Unavailable")

    print(
        "Candidate inbound rules:",
        len(scan["firewall_rules"])
    )

    if verbose:

        print(
            scan["firewall_profile"]
            or "No firewall profile output"
        )

        for rule in scan["firewall_rules"]:

            print(

                f"Rule: {rule.get('Name')} | "

                f"Enabled: {rule.get('Enabled')} | "

                f"Profile: {rule.get('Profile')} | "

                f"Port: {rule.get('LocalPort')} | "

                f"Program: {rule.get('Program')}"
            )

    # ======================================
    # NETWORK BASELINE COMPARISON
    # ======================================

    compare_with_baseline(scan)

    changes = scan["change_detection"]

    print("\n[+] NETWORK BASELINE COMPARISON")

    if changes.get("status") == "compared":

        print(
            "Baseline:",
            changes["baseline_time"]
        )

        print(
            "New listening ports:",
            len(changes["new_ports"])
        )

        for item in changes["new_ports"]:

            print(

                f"[NEW] TCP {item['port']} | "

                f"{', '.join(item['processes'])}"
            )

        print(
            "Ports no longer observed:",
            len(changes["no_longer_observed"])
        )

        for item in changes["no_longer_observed"]:

            print(
                f"[GONE] TCP {item['port']}"
            )

        print(
            "Changed listening ports:",
            len(changes["changed_ports"])
        )

        for item in changes["changed_ports"]:

            print(
                f"[CHANGED] TCP {item['port']}"
            )

    else:

        print(
            changes.get(
                "message",
                "Comparison unavailable"
            )
        )

    # ======================================
    # SECURITY ALERT ENGINE
    # ======================================

    alerts, summary = evaluate_alerts(
        changes
    )

    scan["alerts"] = alerts

    scan["alert_summary"] = summary

    print("\n[+] SECURITY ALERT ENGINE")

    print(
        "Alerts generated:",
        summary["total"]
    )

    print(
        "Priority breakdown:",
        f"MEDIUM={summary['MEDIUM']},",
        f"LOW={summary['LOW']},",
        f"INFO={summary['INFO']}"
    )

    for alert in scan["alerts"]:

        print(

            f"\n[{alert['severity']}] "

            f"{alert['id']} | "

            f"{alert['rule_id']} | "

            f"TCP {alert['port']}"
        )

        print(
            "Processes:",
            ", ".join(alert["processes"])
        )

        print(
            "Addresses:",
            ", ".join(
                alert["listening_addresses"]
            )
        )

        print(
            "Action:",
            alert["recommended_action"]
        )

    if not scan["alerts"]:

        print(
            "No baseline-change alerts generated."
        )

        print(
            "This does not guarantee the host is safe."
        )

    # ======================================
    # COLLECTION WARNINGS
    # ======================================

    if scan["errors"]:

        print("\n[!] COLLECTION WARNINGS")

        for error in scan["errors"]:

            print("-", error)

    # ======================================
    # GENERATE SECURITY REPORTS
    # ======================================

    saved = save_reports(scan)

    print(
        "\nNetwork analysis completed."
    )

    if saved and scan["connections_collected"]:

        return 0

    return 1


# ==========================================
# FUNCTION 20: DISPLAY BASELINE INFO
# ==========================================

def show_baseline_info():

    baseline, error = load_baseline(
        socket.gethostname()
    )

    if error:

        print("[!]", error)

        return 1

    print(
        "Baseline file:",
        BASELINE_FILE
    )

    print(
        "Baseline time:",
        baseline.get("scan_time", "Unknown")
    )

    print(
        "Hostname:",
        baseline["system"]["hostname"]
    )

    print(
        "Listening endpoints:",
        len(baseline["listening"])
    )

    print(
        "Unique TCP ports:",
        len(
            listening_by_port(
                baseline["listening"]
            )
        )
    )

    return 0


# ==========================================
# FUNCTION 21: BASELINE MANAGEMENT
# ==========================================

def write_baseline(replace=False):

    if BASELINE_FILE.exists() and not replace:

        print(
            "[!] Baseline already exists."
        )

        print(
            "Nothing was overwritten."
        )

        print(
            "Use --replace-baseline only after "
            "reviewing and approving changes."
        )

        return 1

    scan = new_scan()

    collect_connections(scan)

    if not scan["connections_collected"]:

        print(
            "[!] Cannot write baseline."
        )

        print(
            scan["errors"]
        )

        return 1

    baseline = {

        "version": VERSION,

        "scan_time": scan["scan_time"],

        "system": scan["system"],

        "listening": scan["listening"],
    }

    try:

        REPORT_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        # Preserve the existing baseline
        # when an intentional update is made.

        if BASELINE_FILE.exists():

            backup_name = (

                "baseline_backup_"

                + datetime.now().strftime(
                    "%Y%m%d_%H%M%S_%f"
                )

                + ".json"
            )

            backup = REPORT_DIR / backup_name

            shutil.copy2(
                BASELINE_FILE,
                backup
            )

            print(
                "Previous baseline backed up:",
                backup
            )

        # Write to a temporary file first.

        temporary = (
            REPORT_DIR / "baseline.json.tmp"
        )

        temporary.write_text(

            json.dumps(
                baseline,
                indent=2
            ),

            encoding="utf-8"
        )

        os.replace(
            temporary,
            BASELINE_FILE
        )

    except OSError as exc:

        print(
            "[!] Unable to write baseline:",
            exc
        )

        return 1

    print(
        "[+] Baseline saved:",
        BASELINE_FILE
    )

    print(
        "Listening endpoints:",
        len(scan["listening"])
    )

    print(
        "Only update baselines after "
        "confirming the configuration is trusted."
    )

    return 0


# ==========================================
# FUNCTION 22: AUTOMATED SELF-TESTING
# ==========================================

def run_self_tests():

    # These tests use simulated connection
    # information.
    #
    # They do not open network ports,
    # change firewall rules, or write files.

    passed = 0

    def check(condition, label):

        nonlocal passed

        if not condition:

            raise AssertionError(label)

        passed += 1

        print(
            f"[PASS] {label}"
        )

    # Create simulated listening connections.

    def listener(port, ip, process):

        return {

            "local_port": port,

            "local_ip": ip,

            "process": process,
        }

    # ======================================
    # SIMULATED PREVIOUS BASELINE
    # ======================================

    previous = [

        listener(
            8765,
            "127.0.0.1",
            "python.exe"
        ),

        listener(
            7070,
            "127.0.0.1",
            "AnyDesk.exe"
        ),
    ]

    # ======================================
    # SIMULATED CURRENT NETWORK STATE
    # ======================================

    current = [

        listener(
            7070,
            "0.0.0.0",
            "AnyDesk.exe"
        ),

        listener(
            9001,
            "127.0.0.1",
            "python.exe"
        ),

        listener(
            9002,
            "0.0.0.0",
            "Unknown"
        ),

        listener(
            9003,
            "192.168.1.10",
            "example.exe"
        ),
    ]

    # ======================================
    # TEST BASELINE COMPARISON
    # ======================================

    result = compare_listeners(
        previous,
        current
    )

    added_ports = {
        item["port"]
        for item in result["new_ports"]
    }

    check(
        added_ports == {9001, 9002, 9003},
        "New ports detected"
    )

    disappeared_ports = [
        item["port"]
        for item in result["no_longer_observed"]
    ]

    check(
        disappeared_ports == [8765],
        "Disappeared port detected"
    )

    changed_ports = [
        item["port"]
        for item in result["changed_ports"]
    ]

    check(
        changed_ports == [7070],
        "Changed listener detected"
    )

    # ======================================
    # TEST ALERT ENGINE
    # ======================================

    changes = {

        "status": "compared",

        "baseline_time": "test",

        **result,
    }

    alerts, summary = evaluate_alerts(
        changes
    )

    expected_summary = {

        "total": 5,

        "MEDIUM": 1,

        "LOW": 2,

        "INFO": 2,
    }

    check(
        summary == expected_summary,
        "Alert priorities correct"
    )

    # ======================================
    # TEST DETECTION RULES
    # ======================================

    actual_rules = {
        alert["rule_id"]
        for alert in alerts
    }

    expected_rules = {

        "NEW_LOOPBACK_LISTENER",

        "NEW_LISTENER_UNIDENTIFIED_PROCESS",

        "NEW_NON_LOOPBACK_LISTENER",

        "LISTENER_DISAPPEARED",

        "BINDING_EXPANDED",
    }

    check(
        actual_rules == expected_rules,
        "All five alert rules triggered"
    )

    # ======================================
    # TEST ALERT IDENTIFIERS
    # ======================================

    actual_ids = [
        alert["id"]
        for alert in alerts
    ]

    expected_ids = [
        f"NSA-{i:03d}"
        for i in range(1, 6)
    ]

    check(
        actual_ids == expected_ids,
        "Alert IDs assigned correctly"
    )

    # ======================================
    # TEST UNCHANGED NETWORK STATE
    # ======================================

    unchanged = compare_listeners(
        previous,
        previous
    )

    expected_unchanged = {

        "new_ports": [],

        "no_longer_observed": [],

        "changed_ports": [],
    }

    check(
        unchanged == expected_unchanged,
        "Unchanged baseline generates no changes"
    )

    # ======================================
    # TEST LOOPBACK CLASSIFICATION
    # ======================================

    loopback_test = (

        loopback_only(
            ["127.2.3.4", "::1"]
        )

        and not loopback_only(
            ["0.0.0.0"]
        )
    )

    check(
        loopback_test,
        "Loopback address classification"
    )

    # ======================================
    # FINAL TEST SUMMARY
    # ======================================

    print(
        f"\n[+] SELF-TEST PASSED: "
        f"{passed}/{passed} checks"
    )

    return 0


# ==========================================
# FUNCTION 23: COMMAND-LINE INTERFACE
# ==========================================

def main():

    parser = argparse.ArgumentParser(

        description=(
            "Host TCP monitoring, network baseline "
            "comparison, and security alerts."
        )
    )

    modes = parser.add_mutually_exclusive_group()

    # Automated testing mode.

    modes.add_argument(

        "--self-test",

        action="store_true",

        help=(
            "Test detection rules "
            "without changing files"
        )
    )

    # Display existing baseline.

    modes.add_argument(

        "--baseline-info",

        action="store_true",

        help="Display saved baseline information"
    )

    # Create baseline if missing.

    modes.add_argument(

        "--create-baseline",

        action="store_true",

        help="Create a baseline only if missing"
    )

    # Intentionally replace baseline.

    modes.add_argument(

        "--replace-baseline",

        action="store_true",

        help=(
            "Back up and replace "
            "a trusted baseline"
        )
    )

    # Detailed output.

    parser.add_argument(

        "--verbose",

        action="store_true",

        help=(
            "Print all connections "
            "and candidate firewall rules"
        )
    )

    # Display application version.

    parser.add_argument(

        "--version",

        action="version",

        version=(
            f"Network Security Analyzer {VERSION}"
        )
    )

    args = parser.parse_args()

    # ======================================
    # COMMAND SELECTION
    # ======================================

    if args.self_test:

        return run_self_tests()

    if args.baseline_info:

        return show_baseline_info()

    if args.create_baseline:

        return write_baseline(
            replace=False
        )

    if args.replace_baseline:

        return write_baseline(
            replace=True
        )

    # Default: perform full security analysis.

    return run_scan(
        verbose=args.verbose
    )


# ==========================================
# PROGRAM ENTRY POINT
# ==========================================

if __name__ == "__main__":

    raise SystemExit(main())