"""
NetShield :: modules/firewall
-------------------------------------------------
Windows Firewall event monitoring.
Attempts to query the live Windows Filtering Platform (WFP) logs (Event IDs 5156/5157)
from the Security event log. Falls back gracefully to parsing active TCP connections via
`netstat -ano` if security log permissions are denied (standard privilege mode).
"""

import subprocess
import json
import re
import datetime
from database.database import get_connection
from detection.alerts import raise_alert

# Cache for netstat connection signatures to prevent database bloat
_netstat_cache = set()

def harvest_firewall_events():
    """Ingest firewall WFP events from Windows Security logs, falling back to netstat if unauthorized."""
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    events_inserted = 0

    # 1. Attempt to query Security log via PowerShell (needs elevated privileges)
    # We query logs starting from 15 seconds ago to capture recent activity
    start_time = (datetime.datetime.now() - datetime.timedelta(seconds=15)).strftime("%Y-%m-%d %H:%M:%S")
    ps_cmd = (
        f"Get-WinEvent -FilterHashtable @{{LogName='Security';ID=5156,5157;StartTime=[datetime]::Parse('{start_time}')}} "
        f"-MaxEvents 50 -ErrorAction SilentlyContinue | "
        f"Select-Object @{{Name='TimeCreated';Expression={{$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}}}, Id, Message | "
        f"ConvertTo-Json"
    )

    success = False
    try:
        res = subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, text=True, timeout=5.0)
        output = res.stdout.strip()
        if output:
            data = json.loads(output)
            events = data if isinstance(data, list) else [data]
            for ev in events:
                msg = ev.get("Message", "")
                evt_id = ev.get("Id")
                evt_time = ev.get("TimeCreated", now_str)

                # Extract details
                src_match = re.search(r"Source Address:\s*([\d.]+)", msg)
                dst_match = re.search(r"Destination Address:\s*([\d.]+)", msg)
                dst_port_match = re.search(r"Destination Port:\s*(\d+)", msg)
                rule_match = re.search(r"Filter Name:\s*([^\r\n]+)", msg)

                if src_match and dst_match:
                    src_ip = src_match.group(1)
                    dst_ip = dst_match.group(1)
                    dst_port = dst_port_match.group(1) if dst_port_match else "0"
                    destination = f"{dst_ip}:{dst_port}"
                    action = "ALLOWED" if evt_id == 5156 else "BLOCKED"
                    rule = rule_match.group(1).strip() if rule_match else ("Allow Rule" if evt_id == 5156 else "Block Rule")

                    # Deduplicate in DB
                    dup = conn.execute(
                        "SELECT id FROM firewall_events WHERE event_time = ? AND source_ip = ? AND destination = ? AND action = ?",
                        (evt_time, src_ip, destination, action)
                    ).fetchone()

                    if not dup:
                        conn.execute(
                            "INSERT INTO firewall_events (event_time, source_ip, destination, action, rule_name) VALUES (?, ?, ?, ?, ?)",
                            (evt_time, src_ip, destination, action, rule)
                        )
                        events_inserted += 1
            success = True
    except Exception:
        pass

    # 2. Fall back to parsing netstat active connections (works for non-admin)
    if not success or events_inserted == 0:
        try:
            res = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=2.0)
            for line in res.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 4 and parts[0] in ["TCP", "UDP"]:
                    local = parts[1]
                    remote = parts[2]
                    state = parts[3] if parts[0] == "TCP" else "UDP"

                    # Only capture established TCP or active UDP
                    if parts[0] == "TCP" and state != "ESTABLISHED":
                        continue

                    # Parse IP and port
                    if "]:" in local:
                        local_ip, local_port = local.rsplit(":", 1)
                    else:
                        local_ip, local_port = local.split(":", 1) if ":" in local else (local, "0")

                    if "]:" in remote:
                        remote_ip, remote_port = remote.rsplit(":", 1)
                    elif ":" in remote:
                        remote_ip, remote_port = remote.split(":", 1)
                    else:
                        remote_ip, remote_port = remote, "0"

                    # Exclude local/loopback traffic
                    if remote_ip in ["*", "0.0.0.0", "[::]", "127.0.0.1", "localhost"]:
                        continue

                    destination = f"{remote_ip}:{remote_port}"
                    sig = (local_ip, destination, state)

                    if sig not in _netstat_cache:
                        action = "ALLOWED"
                        rule = "Active TCP Link (Netstat)"

                        # Check for suspicious ports
                        if remote_port in ["4444", "1337", "31337"]:
                            action = "SUSPICIOUS"
                            rule = "Suspicious Outbound Target"
                            raise_alert(
                                "HIGH",
                                f"Suspicious connection to Port {remote_port}",
                                "Firewall Monitor",
                                f"Active connection detected from {local_ip} to suspicious target {destination} ({rule})."
                            )
                            conn.execute(
                                "INSERT INTO siem_events (source, event, severity, event_time) VALUES (?, ?, ?, ?)",
                                ("Firewall Monitor", f"Suspicious socket link to C2 target {destination}", "HIGH", now_str)
                            )

                        conn.execute(
                            "INSERT INTO firewall_events (event_time, source_ip, destination, action, rule_name) VALUES (?, ?, ?, ?, ?)",
                            (now_str, local_ip, destination, action, rule)
                        )
                        _netstat_cache.add(sig)
                        events_inserted += 1
        except Exception as e:
            print(f"Fallback Netstat parsing error: {e}")

    conn.commit()
    conn.close()

    # Prevent cache memory leak
    if len(_netstat_cache) > 1000:
        _netstat_cache.clear()

def get_recent_events(limit=25):
    """Retrieve firewall logs from SQLite."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM firewall_events ORDER BY event_time DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_counts():
    """Aggregate total allowed, blocked, and suspicious connections."""
    conn = get_connection()
    row = conn.execute(
        "SELECT "
        " COALESCE(SUM(CASE WHEN action='ALLOWED' THEN 1 ELSE 0 END), 0) AS allowed,"
        " COALESCE(SUM(CASE WHEN action='BLOCKED' THEN 1 ELSE 0 END), 0) AS blocked,"
        " COALESCE(SUM(CASE WHEN action='SUSPICIOUS' THEN 1 ELSE 0 END), 0) AS suspicious,"
        " COUNT(*) AS total "
        "FROM firewall_events"
    ).fetchone()
    conn.close()
    return dict(row)

