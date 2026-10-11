"""
NetShield :: detection/alerts.py
-------------------------------------------------
The alert engine. Every module can call raise_alert() when it detects
something noteworthy; this file is the single funnel that writes the
alert to the database and (in a fuller build) would fan it out to the
SIEM stream and notification channels.
"""

import datetime
from database.database import get_connection
from detection.severity import normalize_severity


def raise_alert(severity, title, source, description):
    """Insert a new alert into the alerts table."""
    severity = normalize_severity(severity)
    conn = get_connection()
    conn.execute(
        "INSERT INTO alerts (severity, title, source, description, status, created_at) "
        "VALUES (?, ?, ?, ?, 'open', ?)",
        (severity, title, source, description,
         datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    )
    conn.commit()
    conn.close()


def get_alerts(limit=50, status=None):
    """Return the most recent alerts, optionally filtered by status."""
    conn = get_connection()
    if status:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE status = ? ORDER BY created_at DESC LIMIT ?",
            (status, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_alert_status(alert_id, status):
    """Mark an alert as reviewed / resolved / open."""
    conn = get_connection()
    conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
    conn.commit()
    conn.close()


def alert_summary():
    """Counts of open alerts by severity — used on the dashboard cards."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT severity, COUNT(*) AS c FROM alerts WHERE status = 'open' GROUP BY severity"
    ).fetchall()
    conn.close()
    summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in rows:
        summary[r["severity"]] = r["c"]
    summary["total"] = sum(summary.values())
    return summary
