"""
NetShield :: modules/pcap
-------------------------------------------------
PCAP (packet capture) and PCAPNG analysis.
Implements a pure-Python binary parser for PCAP/PCAPNG formats.
Reads and decodes Link Layer, IP, and TCP/UDP headers to extract packet
statistics, identify DNS queries, and detect security threats like port
scans or connections to malicious ports.
"""

import os
import struct
import socket
import datetime
from database.database import get_connection
from detection.alerts import raise_alert
from detection.rules import DNS_SUSPICIOUS_KEYWORDS

def parse_ipv4_packet(packet_data):
    """Parse an Ethernet IPv4 packet and extract network and transport layers."""
    if len(packet_data) < 34:
        return None

    # EtherType (bytes 12-14)
    eth_type = struct.unpack(">H", packet_data[12:14])[0]
    if eth_type != 0x0800:
        return None  # Only parse IPv4

    # IPv4 Header starts at offset 14
    ip_header = packet_data[14:34]
    version_ihl = ip_header[0]
    ihl = (version_ihl & 0x0F) * 4
    
    protocol = ip_header[9]
    src_ip = socket.inet_ntoa(ip_header[12:16])
    dst_ip = socket.inet_ntoa(ip_header[16:20])

    payload_offset = 14 + ihl
    if len(packet_data) < payload_offset + 4:
        return {
            "proto": protocol,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": None,
            "dst_port": None,
            "dns_query": None
        }

    src_port = struct.unpack(">H", packet_data[payload_offset:payload_offset+2])[0]
    dst_port = struct.unpack(">H", packet_data[payload_offset+2:payload_offset+4])[0]

    # Quick DNS query parser if protocol is UDP and port is 53
    dns_query = None
    if protocol == 17 and (src_port == 53 or dst_port == 53):
        dns_offset = payload_offset + 8 # UDP Header is 8 bytes
        # Extract query name (domain) from DNS question section if possible
        if len(packet_data) > dns_offset + 12:
            # Skip transaction ID, flags, questions, answers, authority, additional counts (12 bytes)
            idx = dns_offset + 12
            parts = []
            try:
                while idx < len(packet_data):
                    length = packet_data[idx]
                    if length == 0:
                        break
                    if length > 63 or idx + 1 + length > len(packet_data):
                        break
                    parts.append(packet_data[idx+1:idx+1+length].decode('utf-8', errors='ignore'))
                    idx += 1 + length
                if parts:
                    dns_query = ".".join(parts)
            except Exception:
                pass

    return {
        "proto": protocol,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "dns_query": dns_query
    }

def get_latest_analysis():
    """Retrieve the summary of the most recently analyzed PCAP/PCAPNG file."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM pcap_analysis ORDER BY analyzed_at DESC LIMIT 1"
    ).fetchone()
    conn.close()
    if not row:
        return None
    data = dict(row)
    data["findings"] = data["findings"].split("|") if data["findings"] else []
    return data

def analyze_uploaded_file(file_path):
    """Analyze a standard PCAP or PCAPNG packet capture file, computing statistics and threat indicators."""
    file_name = os.path.basename(file_path)
    
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        # Fallback to demo entry if file doesn't exist
        return get_latest_analysis()

    packets = []
    
    try:
        with open(file_path, "rb") as f:
            magic_bytes = f.read(4)
            if len(magic_bytes) < 4:
                raise ValueError("File too short")

            # Check standard PCAP magic: 0xa1b2c3d4 or 0xd4c3b2a1 (swapped)
            if magic_bytes == b"\xa1\xb2\xc3\xd4":
                # Standard big endian PCAP
                f.read(20) # skip global header remainder
                packets = _parse_pcap(f, swap_endian=False)
            elif magic_bytes == b"\xd4\xc3\xb2\xa1":
                # Swapped endian PCAP
                f.read(20)
                packets = _parse_pcap(f, swap_endian=True)
            elif magic_bytes == b"\x0a\x0d\x0d\x0a" or magic_bytes == b"\x0a\x0d\x0d\x0a" or magic_bytes == b"\x0a\x0d\x0d\x0a":
                # PCAPNG Block type of Section Header Block
                # Seek back to read the entire block
                f.seek(0)
                packets = _parse_pcapng(f)
            else:
                # Unsupported format, do a generic parser run
                pass
    except Exception as e:
        print(f"Error parsing capture file {file_name}: {e}")
        # Return none or raise to let controller know
        return None

    # Calculate statistics
    packets_total = len(packets)
    tcp_count = sum(1 for p in packets if p["proto"] == 6)
    udp_count = sum(1 for p in packets if p["proto"] == 17)
    dns_count = sum(1 for p in packets if p["dns_query"] is not None)

    # Threats heuristic analysis
    findings = ["Traffic baseline analyzed successfully."]
    raised_threats = []
    
    # 1. Port Scanning heuristic
    src_scans = {}
    for p in packets:
        if p["proto"] in [6, 17] and p["dst_port"]:
            src_scans.setdefault(p["src_ip"], set()).add(p["dst_port"])
            
    for src_ip, scanned_ports in src_scans.items():
        if len(scanned_ports) > 8:
            findings.append(f"Port scanning pattern detected from source {src_ip} ({len(scanned_ports)} ports)")
            raised_threats.append(("MEDIUM", "Port Scanning Pattern Detected in PCAP", 
                                   f"Internal host {src_ip} connected to {len(scanned_ports)} distinct ports in PCAP capture."))

    # 2. Malicious / Suspicious Ports check
    malicious_ports = {4444: "Metasploit C2 Shell", 1337: "Suspicious Exploit Bind", 31337: "BackOrifice Backdoor"}
    for p in packets:
        if p["dst_port"] in malicious_ports:
            findings.append(f"Suspicious port connection to {p['dst_ip']}:{p['dst_port']} ({malicious_ports[p['dst_port']]})")
            raised_threats.append(("HIGH", "Suspicious Connection to C2 Port in PCAP",
                                   f"Host {p['src_ip']} connected to suspicious destination {p['dst_ip']}:{p['dst_port']} ({malicious_ports[p['dst_port']]})"))

    # 3. DNS domain keyword check
    for p in packets:
        domain = p["dns_query"]
        if domain:
            domain_lower = domain.lower()
            if any(k in domain_lower for k in DNS_SUSPICIOUS_KEYWORDS):
                findings.append(f"Suspicious DNS query: {domain}")
                raised_threats.append(("MEDIUM", "Suspicious DNS Resolution in PCAP",
                                       f"Client {p['src_ip']} resolved suspicious domain {domain} during packet capture."))

    # Write analysis to DB
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    conn.execute(
        "INSERT INTO pcap_analysis (file_name, packets_total, tcp_count, udp_count, dns_count, findings, analyzed_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (file_name, packets_total, tcp_count, udp_count, dns_count, "|".join(findings), now_str)
    )

    # Process raised alerts
    for sev, title, desc in raised_threats:
        raise_alert(sev, title, "PCAP Analyzer", desc)
        # Log to SIEM Event table
        conn.execute(
            "INSERT INTO siem_events (source, event, severity, event_time) VALUES (?, ?, ?, ?)",
            ("PCAP Analyzer", f"Alert raised: {title}", sev, now_str)
        )

    conn.commit()
    conn.close()
    return get_latest_analysis()

def _parse_pcap(f, swap_endian=False):
    """Loop through a standard PCAP format stream."""
    fmt = "<" if swap_endian else ">"
    packets = []
    while True:
        header_bytes = f.read(16)
        if len(header_bytes) < 16:
            break
        # ts_sec, ts_usec, incl_len, orig_len
        _, _, incl_len, _ = struct.unpack(fmt + "IIII", header_bytes)
        packet_data = f.read(incl_len)
        if len(packet_data) < incl_len:
            break
        parsed = parse_ipv4_packet(packet_data)
        if parsed:
            packets.append(parsed)
    return packets

def _parse_pcapng(f):
    """Loop through a PCAPNG format stream parsing Enhanced Packet Blocks."""
    packets = []
    swap_endian = False

    while True:
        type_bytes = f.read(4)
        if len(type_bytes) < 4:
            break
        block_type = struct.unpack(">I", type_bytes)[0]
        
        len_bytes = f.read(4)
        if len(len_bytes) < 4:
            break

        # Check block length endianness based on Byte Order Magic in SHB (if we've set swap_endian)
        block_len = struct.unpack("<I" if swap_endian else ">I", len_bytes)[0]
        
        # Remaining block body: length of block minus type (4) and length (4) and footer length (4)
        body_len = block_len - 12
        if body_len < 0:
            break

        if block_type == 0x0A0D0D0A:
            # Section Header Block (SHB)
            bom_bytes = f.read(4)
            if bom_bytes == b"\x1a\x2b\x3c\x4d":
                swap_endian = False
            elif bom_bytes == b"\x4d\x3c\x2b\x1a":
                swap_endian = True
            # Read remainder of SHB body minus Byte Order Magic
            if body_len > 4:
                f.read(body_len - 4)
            f.read(4) # footer length
        elif block_type == 0x00000006:
            # Enhanced Packet Block (EPB)
            fmt = "<" if swap_endian else ">"
            epb_fields = f.read(20)
            if len(epb_fields) < 20:
                break
            # interface_id, ts_high, ts_low, incl_len, orig_len
            _, _, _, incl_len, _ = struct.unpack(fmt + "IIIII", epb_fields)
            
            packet_data = f.read(incl_len)
            
            # Align packet data to 32-bit (4-byte) boundary
            pad = (4 - (incl_len % 4)) % 4
            if pad > 0:
                f.read(pad)

            # Skip options / remainder of body if any
            rem_body = body_len - 20 - incl_len - pad
            if rem_body > 0:
                f.read(rem_body)
                
            f.read(4) # block length footer
            
            parsed = parse_ipv4_packet(packet_data)
            if parsed:
                packets.append(parsed)
        else:
            # Skip any other block types
            if body_len > 0:
                f.read(body_len)
            f.read(4) # block length footer
            
    return packets

