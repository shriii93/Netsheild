"""
NetShield :: modules/monitoring
-------------------------------------------------
Host connectivity monitoring: status, latency, and packet loss.
Integrates live ping monitoring via subprocess calling Windows ping,
persisting and serving these results through the SQLite database.
"""

import subprocess
import re
import datetime
from database.database import get_connection

def ping_host(host, count=3, timeout_ms=500):
    """Ping a host using the Windows ping utility and return (latency_ms, packet_loss_pct, status)."""
    cmd = ["ping", "-n", str(count), "-w", str(timeout_ms), host]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=(timeout_ms * count) / 1000.0 + 2.0)
        output = res.stdout
        
        # Parse packet loss
        # e.g., "Packets: Sent = 3, Received = 3, Lost = 0 (0% loss)" or matching equivalent
        loss_match = re.search(r"Lost = (\d+) \((\d+)% loss\)", output)
        loss = float(loss_match.group(2)) if loss_match else 100.0
        
        # Parse average round trip time
        # e.g., "Minimum = 4ms, Maximum = 7ms, Average = 5ms"
        avg_match = re.search(r"Average = (\d+)ms", output)
        
        if avg_match:
            latency = float(avg_match.group(1))
            status = "online" if loss < 100.0 else "offline"
            return latency, loss, status
        elif "Reply from" in output:
            # Fallback search for any single reply time
            match = re.search(r"time[=<]([\d.]+)ms", output)
            latency = float(match.group(1)) if match else 1.0
            status = "online" if loss < 100.0 else "offline"
            return latency, loss, status
        else:
            return None, 100.0, "offline"
    except Exception:
        return None, 100.0, "offline"

def get_monitored_hosts():
    """Return the current status snapshot for all monitored hosts using the latest database records."""
    conn = get_connection()
    # Query join showing latest monitoring sample for each known device
    query = """
        WITH latest_history AS (
            SELECT host, latency_ms, packet_loss, status, recorded_at,
                   ROW_NUMBER() OVER (PARTITION BY host ORDER BY recorded_at DESC) as rn
            FROM monitoring_history
        )
        SELECT d.ip_address, d.hostname, d.status AS dev_status,
               lh.latency_ms, lh.packet_loss, lh.status AS ping_status
        FROM devices d
        LEFT JOIN latest_history lh ON d.ip_address = lh.host AND lh.rn = 1
        ORDER BY d.ip_address
    """
    rows = conn.execute(query).fetchall()
    conn.close()

    hosts = []
    for r in rows:
        # Determine current status based on latest ping or fallback to device status
        status = r["ping_status"] if r["ping_status"] is not None else r["dev_status"]
        hosts.append({
            "host": r["ip_address"],
            "hostname": r["hostname"],
            "status": status,
            "latency_ms": r["latency_ms"],
            "packet_loss": r["packet_loss"] if r["packet_loss"] is not None else (0.0 if status == "online" else 100.0),
        })
    return hosts

def get_latency_history():
    """Return the latency time series (last 30 samples per host) used
    to render the network performance chart on the dashboard."""
    conn = get_connection()
    # We query the last 120 samples and filter in Python to ensure each host gets its chronological series
    rows = conn.execute(
        "SELECT host, latency_ms, recorded_at FROM monitoring_history "
        "ORDER BY recorded_at ASC"
    ).fetchall()
    conn.close()

    series = {}
    for r in rows:
        # Only include hosts that are in devices
        series.setdefault(r["host"], {"labels": [], "data": []})
        series[r["host"]]["labels"].append(r["recorded_at"][-8:])  # HH:MM:SS
        series[r["host"]]["data"].append(r["latency_ms"])
        
    # Cap each series at 30 items
    for h in series:
        series[h]["labels"] = series[h]["labels"][-30:]
        series[h]["data"] = series[h]["data"][-30:]
        
    return series

def average_latency():
    hosts = [h for h in get_monitored_hosts() if h["latency_ms"] is not None]
    if not hosts:
        return 0
    return round(sum(h["latency_ms"] for h in hosts) / len(hosts), 1)

def record_sample(host, latency_ms, packet_loss=0.0, status="online"):
    """Persist a new monitoring sample."""
    conn = get_connection()
    conn.execute(
        "INSERT INTO monitoring_history (host, latency_ms, packet_loss, status, recorded_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (host, latency_ms, packet_loss, status,
         datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    )
    # Also update the devices status to keep the LAN view consistent
    conn.execute(
        "UPDATE devices SET status = ?, last_seen = ? WHERE ip_address = ?",
        (status, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), host)
    )
    conn.commit()
    conn.close()

