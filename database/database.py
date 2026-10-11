"""
NetShield :: database.py
-------------------------------------------------
Central SQLite access layer for the whole platform.

Every module (monitoring, discovery, vulnerability, pcap, firewall,
brute_force, dns, siem) reads/writes through the helpers in this file
so there is exactly one place that knows about table schemas.
"""

import sqlite3
import os
import random
import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "netshield.db")


def get_connection():
    """Return a SQLite connection with dict-like row access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Enforce foreign keys for referential integrity
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


SCHEMA = """
-- Devices discovered on the LAN
CREATE TABLE IF NOT EXISTS devices (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address  TEXT NOT NULL,
    hostname    TEXT,
    mac_address TEXT,
    status      TEXT DEFAULT 'online',      -- online / offline
    last_seen   TEXT
);

-- Host latency / packet-loss monitoring history
CREATE TABLE IF NOT EXISTS monitoring_history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host         TEXT NOT NULL,
    latency_ms   REAL,
    packet_loss  REAL,
    status       TEXT,
    recorded_at  TEXT
);

-- Vulnerability / port scan results
CREATE TABLE IF NOT EXISTS scan_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,
    port        INTEGER,
    service     TEXT,
    port_status TEXT,
    finding     TEXT,
    risk_level  TEXT,
    scanned_at  TEXT
);

-- PCAP analysis summaries
CREATE TABLE IF NOT EXISTS pcap_analysis (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    file_name       TEXT,
    packets_total   INTEGER,
    tcp_count       INTEGER,
    udp_count       INTEGER,
    dns_count       INTEGER,
    findings        TEXT,       -- JSON-encoded list of findings
    analyzed_at     TEXT
);

-- Windows Firewall event log (simulated)
CREATE TABLE IF NOT EXISTS firewall_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_time  TEXT,
    source_ip   TEXT,
    destination TEXT,
    action      TEXT,       -- ALLOWED / BLOCKED / SUSPICIOUS
    rule_name   TEXT
);

-- Authentication attempts (for brute-force detection)
CREATE TABLE IF NOT EXISTS auth_attempts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account     TEXT,
    source_ip   TEXT,
    success     INTEGER,     -- 0 / 1
    attempt_time TEXT
);

-- DNS query log
CREATE TABLE IF NOT EXISTS dns_queries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT,
    query_type  TEXT,
    status      TEXT,        -- NORMAL / REVIEW / BLOCKED
    queried_at  TEXT
);

-- Central SIEM event stream (correlated from every module)
CREATE TABLE IF NOT EXISTS siem_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source      TEXT,
    event       TEXT,
    severity    TEXT,        -- LOW / MEDIUM / HIGH / CRITICAL
    event_time  TEXT
);

-- Alerts raised by the detection engine (aggregated from all modules)
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    severity    TEXT,
    title       TEXT,
    source      TEXT,
    description TEXT,
    status      TEXT DEFAULT 'open',   -- open / reviewed / resolved
    created_at  TEXT
);

-- Generated reports metadata
CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT,
    summary     TEXT,
    file_path   TEXT,
    created_at  TEXT
);

-- Performance Indexes
CREATE INDEX IF NOT EXISTS idx_monitoring_host_time ON monitoring_history (host, recorded_at);
CREATE INDEX IF NOT EXISTS idx_firewall_time ON firewall_events (event_time);
CREATE INDEX IF NOT EXISTS idx_auth_time ON auth_attempts (attempt_time);
CREATE INDEX IF NOT EXISTS idx_dns_time ON dns_queries (queried_at);
CREATE INDEX IF NOT EXISTS idx_siem_time ON siem_events (event_time);
CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts (created_at);
"""


def init_db(seed=True):
    """Create all tables and, optionally, seed them with demo data."""
    conn = get_connection()
    conn.executescript(SCHEMA)
    conn.commit()

    if seed:
        cur = conn.execute("SELECT COUNT(*) AS c FROM devices")
        if cur.fetchone()["c"] == 0:
            _seed_demo_data(conn)

    conn.close()


def _now(offset_minutes=0):
    return (datetime.datetime.now() -
            datetime.timedelta(minutes=offset_minutes)).strftime("%Y-%m-%d %H:%M:%S")


def _seed_demo_data(conn):
    """Populate the database with realistic-looking simulated data so the
    dashboard is fully populated on first run."""

    # --- Devices -----------------------------------------------------
    devices = [
        ("192.168.1.1", "Router", "AA:BB:CC:00:11:22", "online"),
        ("192.168.1.5", "Laptop-Engineer", "AA:BB:CC:00:11:23", "online"),
        ("192.168.1.8", "Phone-Android", "AA:BB:CC:00:11:24", "online"),
        ("192.168.1.12", "Workstation-01", "AA:BB:CC:00:11:25", "online"),
        ("192.168.1.15", "Printer-HP", "AA:BB:CC:00:11:26", "online"),
        ("192.168.1.20", "Smart-TV", "AA:BB:CC:00:11:27", "online"),
        ("192.168.1.34", "IoT-Camera", "AA:BB:CC:00:11:28", "offline"),
        ("8.8.8.8", "Public-DNS-Uplink", "-", "online"),
    ]
    for ip, host, mac, status in devices:
        conn.execute(
            "INSERT INTO devices (ip_address, hostname, mac_address, status, last_seen) "
            "VALUES (?, ?, ?, ?, ?)",
            (ip, host, mac, status, _now(random.randint(0, 15))),
        )

    # --- Monitoring history (latency chart) ---------------------------
    hosts = ["192.168.1.1", "192.168.1.5", "192.168.1.12", "8.8.8.8"]
    for i in range(30, 0, -1):
        for h in hosts:
            base = {"192.168.1.1": 2, "192.168.1.5": 8, "192.168.1.12": 12, "8.8.8.8": 22}[h]
            latency = max(1, base + random.uniform(-3, 6))
            conn.execute(
                "INSERT INTO monitoring_history (host, latency_ms, packet_loss, status, recorded_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (h, round(latency, 1), 0.0, "online", _now(i)),
            )

    # --- Vulnerability scan results -----------------------------------
    scan_rows = [
        ("192.168.1.5", 80, "HTTP", "OPEN", "Web service detected", "LOW"),
        ("192.168.1.5", 443, "HTTPS", "OPEN", "HTTPS available (TLS enforced)", "LOW"),
        ("192.168.1.5", 22, "SSH", "CLOSED", "SSH not exposed", "LOW"),
        ("192.168.1.12", 445, "SMB", "OPEN", "SMB file-sharing exposed to LAN", "MEDIUM"),
        ("192.168.1.12", 3389, "RDP", "OPEN", "Remote Desktop reachable on LAN", "MEDIUM"),
    ]
    for target, port, service, pstatus, finding, risk in scan_rows:
        conn.execute(
            "INSERT INTO scan_results (target, port, service, port_status, finding, risk_level, scanned_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (target, port, service, pstatus, finding, risk, _now(random.randint(5, 60))),
        )

    # --- PCAP analysis ---------------------------------------------------
    conn.execute(
        "INSERT INTO pcap_analysis (file_name, packets_total, tcp_count, udp_count, dns_count, findings, analyzed_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("network_capture.pcap", 48293, 31221, 14821, 2251,
         "Normal traffic baseline|Unusual connection pattern to 203.0.113.44|Possible port-scan behaviour from 192.168.1.34",
         _now(20)),
    )

    # --- Firewall events --------------------------------------------------
    fw_rows = [
        ("192.168.1.5", "192.168.1.12:445", "BLOCKED", "Block-LAN-SMB"),
        ("192.168.1.8", "8.8.8.8:443", "ALLOWED", "Allow-Outbound-HTTPS"),
        ("192.168.1.5", "203.0.113.44:4444", "BLOCKED", "Block-Suspicious-Port"),
        ("192.168.1.34", "192.168.1.0/24", "SUSPICIOUS", "Detect-Port-Scan"),
        ("192.168.1.12", "192.168.1.1:53", "ALLOWED", "Allow-DNS"),
    ]
    for src, dst, action, rule in fw_rows:
        conn.execute(
            "INSERT INTO firewall_events (event_time, source_ip, destination, action, rule_name) "
            "VALUES (?, ?, ?, ?, ?)",
            (_now(random.randint(1, 90)), src, dst, action, rule),
        )
    # bulk allowed/blocked noise so the counters look realistic
    for _ in range(978):
        conn.execute(
            "INSERT INTO firewall_events (event_time, source_ip, destination, action, rule_name) "
            "VALUES (?, ?, ?, 'ALLOWED', 'Allow-Standard-Traffic')",
            (_now(random.randint(1, 480)), random.choice(hosts), "8.8.8.8:443"),
        )
    for _ in range(259):
        conn.execute(
            "INSERT INTO firewall_events (event_time, source_ip, destination, action, rule_name) "
            "VALUES (?, ?, ?, 'BLOCKED', 'Block-Default-Deny')",
            (_now(random.randint(1, 480)), "192.168.1.34", "0.0.0.0:0"),
        )

    # --- Auth attempts (brute force) --------------------------------------
    for _ in range(18):
        conn.execute(
            "INSERT INTO auth_attempts (account, source_ip, success, attempt_time) VALUES (?, ?, 0, ?)",
            ("administrator", "192.168.1.34", _now(random.randint(1, 5))),
        )
    for _ in range(5):
        conn.execute(
            "INSERT INTO auth_attempts (account, source_ip, success, attempt_time) VALUES (?, ?, 0, ?)",
            ("user1", "192.168.1.8", _now(random.randint(5, 30))),
        )
    for _ in range(2):
        conn.execute(
            "INSERT INTO auth_attempts (account, source_ip, success, attempt_time) VALUES (?, ?, 1, ?)",
            ("user2", "192.168.1.5", _now(random.randint(30, 60))),
        )

    # --- DNS queries -------------------------------------------------------
    normal_domains = ["example.com", "company.local", "microsoft.com",
                       "windowsupdate.com", "office.com", "github.com"]
    for _ in range(60):
        conn.execute(
            "INSERT INTO dns_queries (domain, query_type, status, queried_at) VALUES (?, 'A', 'NORMAL', ?)",
            (random.choice(normal_domains), _now(random.randint(1, 480))),
        )
    for d in ["unusual-domain.test", "xj29-c2-relay.biz", "dns-tunnel-test.io"]:
        conn.execute(
            "INSERT INTO dns_queries (domain, query_type, status, queried_at) VALUES (?, 'A', 'REVIEW', ?)",
            (d, _now(random.randint(1, 60))),
        )

    # --- SIEM correlated events ---------------------------------------------
    siem_rows = [
        ("Windows Security", "Brute-force attempt detected on 'administrator'", "HIGH"),
        ("Firewall", "Repeated connection blocked from 192.168.1.34", "MEDIUM"),
        ("PCAP Analyzer", "Traffic anomaly: possible port-scan behaviour", "MEDIUM"),
        ("LAN Scanner", "New device joined the network", "LOW"),
        ("DNS Monitor", "Unusual domain queried: dns-tunnel-test.io", "LOW"),
    ]
    for source, event, sev in siem_rows:
        conn.execute(
            "INSERT INTO siem_events (source, event, severity, event_time) VALUES (?, ?, ?, ?)",
            (source, event, sev, _now(random.randint(1, 30))),
        )

    # --- Alerts --------------------------------------------------------------
    alert_rows = [
        ("HIGH", "Possible brute-force attack", "Windows Security / Auth Monitor",
         "18 failed login attempts against 'administrator' from 192.168.1.34 in a 5-minute window."),
        ("MEDIUM", "Suspicious network traffic", "PCAP Analyzer",
         "Unusual connection pattern and possible port-scan behaviour observed in latest capture."),
        ("LOW", "New device detected", "LAN Scanner",
         "A previously unseen device (192.168.1.34) joined the network."),
    ]
    for sev, title, source, desc in alert_rows:
        conn.execute(
            "INSERT INTO alerts (severity, title, source, description, status, created_at) "
            "VALUES (?, ?, ?, ?, 'open', ?)",
            (sev, title, source, desc, _now(random.randint(1, 20))),
        )

    conn.commit()


if __name__ == "__main__":
    init_db()
    print(f"NetShield database initialized at {DB_PATH}")
