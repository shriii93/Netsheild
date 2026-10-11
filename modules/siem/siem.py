"""
NetShield :: modules/siem
-------------------------------------------------
The SIEM (Security Information and Event Management) layer.
Correlates logs from different modules (Firewall, DNS, Authentication attempts)
running threshold-based alerts to detect and aggregate security threats (brute force, network scans).
"""

import datetime
from database.database import get_connection
from detection.alerts import raise_alert
from detection.rules import classify_failed_logins

def correlate_and_alert():
    """Correlate security logs, check threshold rules, and generate alerts/SIEM events."""
    conn = get_connection()
    now = datetime.datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")

    # 1. Brute-force correlation (failed logons)
    # Search auth_attempts in the last 5 minutes
    five_mins_ago = (now - datetime.timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
    failed_logons = conn.execute(
        "SELECT account, source_ip, COUNT(*) as c FROM auth_attempts "
        "WHERE success = 0 AND attempt_time >= ? "
        "GROUP BY account, source_ip", (five_mins_ago,)
    ).fetchall()

    for row in failed_logons:
        account = row["account"]
        src_ip = row["source_ip"]
        count = row["c"]

        if count >= 3:  # warning threshold
            severity = classify_failed_logins(count)
            title = f"Possible brute-force attack on '{account}'"
            desc = f"{count} failed login attempts against '{account}' from {src_ip} in a 5-minute window."

            # Check if this alert has been raised in the last 5 minutes
            dup = conn.execute(
                "SELECT id FROM alerts WHERE title = ? AND created_at >= ?",
                (title, five_mins_ago)
            ).fetchone()

            if not dup:
                # Insert the alert
                conn.execute(
                    "INSERT INTO alerts (severity, title, source, description, status, created_at) "
                    "VALUES (?, ?, 'Windows Security / Auth Monitor', ?, 'open', ?)",
                    (severity, title, desc, now_str)
                )
                # Ingest into SIEM events stream
                conn.execute(
                    "INSERT INTO siem_events (source, event, severity, event_time) VALUES (?, ?, ?, ?)",
                    ("Windows Security", f"Brute-force logon attempts detected on '{account}' from {src_ip}", severity, now_str)
                )

    # 2. Firewall blocked connection spikes (Reconnaissance / Port scans)
    # Search blocked firewall events in the last 2 minutes
    two_mins_ago = (now - datetime.timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S")
    blocked_spikes = conn.execute(
        "SELECT source_ip, COUNT(*) as c FROM firewall_events "
        "WHERE action = 'BLOCKED' AND event_time >= ? "
        "GROUP BY source_ip", (two_mins_ago,)
    ).fetchall()

    for row in blocked_spikes:
        src_ip = row["source_ip"]
        count = row["c"]

        if count >= 20:  # Block spike threshold
            title = f"Suspicious firewall block spike from {src_ip}"
            desc = f"{count} connections blocked from {src_ip} in a 2-minute window. Possible network scanning."

            dup = conn.execute(
                "SELECT id FROM alerts WHERE title = ? AND created_at >= ?",
                (title, five_mins_ago)
            ).fetchone()

            if not dup:
                # Insert the alert
                conn.execute(
                    "INSERT INTO alerts (severity, title, source, description, status, created_at) "
                    "VALUES ('MEDIUM', ?, 'Firewall Monitor', ?, 'open', ?)",
                    (title, desc, now_str)
                )
                conn.execute(
                    "INSERT INTO siem_events (source, event, severity, event_time) VALUES (?, ?, ?, ?)",
                    ("Firewall", f"Firewall blocked {count} packets from {src_ip} (potential port scanning)", "MEDIUM", now_str)
                )

    conn.commit()
    conn.close()

def get_events(limit=100, severity=None, source=None):
    """Retrieve correlated SIEM events."""
    conn = get_connection()
    query = "SELECT * FROM siem_events WHERE 1=1"
    params = []
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if source:
        query += " AND source = ?"
        params.append(source)
    query += " ORDER BY event_time DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def event_counts():
    """Return counts of total events collected and alerts raised."""
    conn = get_connection()
    total_events = conn.execute("SELECT COUNT(*) AS c FROM siem_events").fetchone()["c"]
    alerts_generated = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
    conn.close()
    return {"events_collected": total_events, "alerts_generated": alerts_generated}

def sources():
    """List unique event sources feeding the SIEM stream."""
    conn = get_connection()
    rows = conn.execute("SELECT DISTINCT source FROM siem_events ORDER BY source").fetchall()
    conn.close()
    return [r["source"] for r in rows]

