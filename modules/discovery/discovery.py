"""
NetShield :: modules/discovery
-------------------------------------------------
Authorized LAN device discovery.
Implements a live multithreaded ping sweep over the local /24 subnet
to populate the local ARP cache, reads the Windows ARP table (`arp -a`)
to extract MAC addresses, resolves hostnames, and raises alerts when
new devices are detected.
"""

import subprocess
import re
import socket
import datetime
import concurrent.futures
from database.database import get_connection
from detection.alerts import raise_alert

def get_local_subnet():
    """Determine the local IP address and /24 subnet prefix."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connect to an external address (does not send traffic)
        s.connect(('8.8.8.8', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            local_ip = "192.168.1.1"
    finally:
        s.close()

    if local_ip.startswith("127.") or local_ip == "0.0.0.0":
        local_ip = "192.168.1.1"

    parts = local_ip.split(".")
    subnet_base = ".".join(parts[:3]) + "."
    return subnet_base, local_ip

def _ping_address(ip):
    """Ping a single IP address with a short timeout to detect presence and populate ARP table."""
    cmd = ["ping", "-n", "1", "-w", "150", ip]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=1.0)
        # Check if the host responded (look for "Reply from" but exclude unreachable responses)
        if "Reply from" in res.stdout and "unreachable" not in res.stdout.lower() and "timed out" not in res.stdout.lower():
            return ip, True
    except Exception:
        pass
    return ip, False

def get_arp_table():
    """Query and parse the Windows ARP table."""
    arp_table = {}
    try:
        res = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=2.0)
        for line in res.stdout.splitlines():
            match = re.search(r"^\s*([\d.]+)\s+([0-9a-fA-F:-]+)\s+(dynamic|static)", line)
            if match:
                ip = match.group(1)
                mac = match.group(2).replace("-", ":").upper()
                arp_table[ip] = mac
    except Exception:
        pass
    return arp_table

def scan_network(subnet=None):
    """Perform a live multithreaded network scan, updating the database with discovered devices."""
    subnet_base, local_ip = get_local_subnet()
    if not subnet:
        subnet = subnet_base + "0/24"

    # 1. Concurrent ping sweep to discover active nodes and populate Windows ARP table
    ips = [subnet_base + str(i) for i in range(1, 255)]
    active_ips = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as executor:
        results = executor.map(_ping_address, ips)
        for ip, is_active in results:
            if is_active or ip == local_ip:
                active_ips.append(ip)

    # 2. Retrieve MAC addresses from Windows ARP table
    arp_table = get_arp_table()
    
    # 3. Resolve hostnames and save/update in DB
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    
    # Query existing devices to cross-reference
    existing_rows = conn.execute("SELECT ip_address, mac_address, status FROM devices").fetchall()
    existing_map = {row["ip_address"]: dict(row) for row in existing_rows}
    
    scanned_ips = set(active_ips)

    for ip in scanned_ips:
        # Determine hostname
        if ip == local_ip:
            hostname = socket.gethostname()
            mac = arp_table.get(ip, "LOCAL-NIC")
        elif ip == subnet_base + "1":
            hostname = "GatewayRouter"
            mac = arp_table.get(ip, "UNKNOWN")
        else:
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
            except Exception:
                hostname = f"Host-{ip.split('.')[-1]}"
            mac = arp_table.get(ip, "UNKNOWN")

        if ip in existing_map:
            # Device exists. Update its status and details
            conn.execute(
                "UPDATE devices SET hostname = ?, mac_address = ?, status = 'online', last_seen = ? WHERE ip_address = ?",
                (hostname, mac, now_str, ip)
            )
        else:
            # New device found!
            conn.execute(
                "INSERT INTO devices (ip_address, hostname, mac_address, status, last_seen) VALUES (?, ?, ?, 'online', ?)",
                (ip, hostname, mac, now_str)
            )
            # Raise a LOW security alert for new device discovery
            raise_alert(
                "LOW",
                "New device discovered",
                "LAN Scanner",
                f"New device connected to subnet: IP={ip}, Hostname={hostname}, MAC={mac}"
            )
            # Add to SIEM events
            conn.execute(
                "INSERT INTO siem_events (source, event, severity, event_time) VALUES (?, ?, ?, ?)",
                ("LAN Scanner", f"New device {hostname} ({ip}) discovered on subnet", "LOW", now_str)
            )

    # 4. Mark previously online devices that are within this scanned subnet and not found as offline
    for ip, dev in existing_map.items():
        if ip.startswith(subnet_base) and ip not in scanned_ips and dev["status"] == "online":
            conn.execute(
                "UPDATE devices SET status = 'offline', last_seen = ? WHERE ip_address = ?",
                (now_str, ip)
            )

    conn.commit()
    
    # Read back the updated list from database to return
    devices = conn.execute(
        "SELECT ip_address, hostname, mac_address, status, last_seen FROM devices ORDER BY ip_address"
    ).fetchall()
    conn.close()

    return {
        "subnet": subnet,
        "devices": [dict(d) for d in devices],
        "count": len(devices),
    }

def simulate_new_device():
    """Trigger a network scan pass (wrapper matching app.py interface)."""
    return scan_network()

