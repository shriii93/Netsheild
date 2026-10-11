"""
NetShield :: modules/dns
-------------------------------------------------
DNS query monitoring.
Queries the live Windows DNS Client operational log (`Microsoft-Windows-DNS-Client/Operational`, Event ID 3008)
using PowerShell to capture real-time DNS lookups and flag anomalous or suspicious resolution behavior.
"""

import subprocess
import json
import re
import datetime
from database.database import get_connection
from detection.rules import is_suspicious_domain

def harvest_dns_queries():
    """Query and ingest Windows DNS Client resolution events (Event ID 3008)."""
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()

    # Query logs from the last 15 seconds
    start_time = (datetime.datetime.now() - datetime.timedelta(seconds=15)).strftime("%Y-%m-%d %H:%M:%S")
    ps_cmd = (
        f"Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-DNS-Client/Operational';ID=3008;StartTime=[datetime]::Parse('{start_time}')}} "
        f"-MaxEvents 50 -ErrorAction SilentlyContinue | "
        f"Select-Object @{{Name='TimeCreated';Expression={{$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}}}, Message | "
        f"ConvertTo-Json"
    )

    TYPE_MAP = {1: "A", 28: "AAAA", 15: "MX", 16: "TXT", 5: "CNAME", 12: "PTR", 2: "NS", 6: "SOA"}

    try:
        res = subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, text=True, timeout=5.0)
        output = res.stdout.strip()
        if output:
            data = json.loads(output)
            events = data if isinstance(data, list) else [data]
            for ev in events:
                msg = ev.get("Message", "")
                queried_at = ev.get("TimeCreated", now_str)

                # Extract Domain and Record Type
                name_match = re.search(r"Query (?:name|Name):\s*([^\s,\r\n]+)", msg)
                type_match = re.search(r"Query (?:type|Type):\s*(\d+)", msg)

                if name_match:
                    domain = name_match.group(1).strip().rstrip(".")
                    # Skip reverse lookup or local host resolution queries
                    if domain.endswith(".arpa") or domain.startswith("127.") or not domain:
                        continue

                    raw_type = int(type_match.group(1)) if type_match else 1
                    query_type = TYPE_MAP.get(raw_type, f"TYPE-{raw_type}")

                    # Classify safety status based on keyword matching rules
                    if is_suspicious_domain(domain):
                        if any(k in domain.lower() for k in ["tunnel", "c2"]):
                            status = "BLOCKED"
                        else:
                            status = "REVIEW"
                    else:
                        status = "NORMAL"

                    # Deduplicate queries in DB
                    dup = conn.execute(
                        "SELECT id FROM dns_queries WHERE queried_at = ? AND domain = ?",
                        (queried_at, domain)
                    ).fetchone()

                    if not dup:
                        conn.execute(
                            "INSERT INTO dns_queries (domain, query_type, status, queried_at) VALUES (?, ?, ?, ?)",
                            (domain, query_type, status, queried_at)
                        )

                        # Trigger alerts for non-normal domains
                        if status in ["REVIEW", "BLOCKED"]:
                            alert_sev = "MEDIUM" if status == "BLOCKED" else "LOW"
                            from detection.alerts import raise_alert
                            raise_alert(
                                alert_sev,
                                f"Suspicious DNS query: {domain}",
                                "DNS Monitor",
                                f"Client resolved suspicious domain {domain} (classified as {status})."
                            )
                            conn.execute(
                                "INSERT INTO siem_events (source, event, severity, event_time) VALUES (?, ?, ?, ?)",
                                ("DNS Monitor", f"Suspicious DNS query resolved: {domain} ({status})", alert_sev, queried_at)
                            )
    except Exception:
        pass

    conn.commit()
    conn.close()

def get_recent_queries(limit=30):
    """Retrieve captured DNS query logs."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM dns_queries ORDER BY queried_at DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_counts():
    """Sum totals for normal, review-flagged, and blocked queries."""
    conn = get_connection()
    row = conn.execute(
        "SELECT "
        " COALESCE(SUM(CASE WHEN status='NORMAL' THEN 1 ELSE 0 END), 0) AS normal,"
        " COALESCE(SUM(CASE WHEN status='REVIEW' THEN 1 ELSE 0 END), 0) AS review,"
        " COALESCE(SUM(CASE WHEN status='BLOCKED' THEN 1 ELSE 0 END), 0) AS blocked,"
        " COUNT(*) AS total "
        "FROM dns_queries"
    ).fetchone()
    conn.close()
    return dict(row)

def flagged_domains():
    """Retrieve distinct flagged domain names."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT DISTINCT domain, status FROM dns_queries WHERE status != 'NORMAL'"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

