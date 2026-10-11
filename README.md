# 🛡️ NetShield

**Integrated Windows Network Security Monitoring & Threat Detection Platform**

Discover. Monitor. Detect. Analyze. Protect.

NetShield is a single Flask web application that unifies eight security modules — network monitoring, LAN discovery, vulnerability assessment, PCAP analysis, Windows Firewall monitoring, brute-force / authentication detection, DNS security monitoring, and a Windows SIEM correlation layer — behind one dashboard and one alert engine.

Unlike static mock platforms, this version of NetShield interacts directly with the hosting Windows 10/11 operating system and local network interfaces, harvesting live event logs, monitoring real connection links, performing active port scans, and parsing uploaded network captures.

---

## 1. System Requirements

* **Operating System**: Windows 10 or Windows 11.
* **Environment**: Python 3.10+ (No complex virtual machine setups or external OS packages required).
* **Dependencies**: Flask (only).

---

## 2. Setup Instructions

Open PowerShell (or Command Prompt) inside the `NetShield` project directory:

```powershell
# 1. Create and activate a Python virtual environment
python -m venv venv
venv\Scripts\activate

# 2. Install Flask
pip install flask
```

---

## 3. Running the Platform

Depending on what level of telemetry logging you wish to capture, you can run NetShield in one of two modes:

### Mode A: Elevated Mode (Fully Featured - Recommended)
To capture **Windows Firewall events** (allowed/blocked connections via WFP) and **Failed Logon attempts (Event ID 4625)**, the application needs to read the Windows Security Event Log. This requires Administrator privileges.

1. Search for **PowerShell** in the Start Menu.
2. Right-click and choose **Run as Administrator**.
3. Navigate to the project folder and run:
   ```powershell
   venv\Scripts\activate
   python app.py
   ```

### Mode B: Standard Mode (User Level)
If run without Administrator privileges, NetShield falls back gracefully:
* It reads live DNS queries resolved by the system (Event ID 3008, which is user-accessible).
* It harvests active network connections using `netstat -ano` and translates them into allowed firewall logs.
* It displays a status warning badge in the header: **Standard Privileges (No Logs)**.

To launch in standard mode, simply run:
```powershell
python app.py
```

Once running, navigate your web browser to:
```
http://127.0.0.1:5000
```

---

## 4. Live Module Walkthrough

1. **SOC Dashboard**: Displays your overall security score, a live latency performance chart (updated every 10 seconds by background ping probes), active alerts, and firewall metrics.
2. **LAN Scan**: Scan your network subnet in real time. It performs a multi-threaded ping sweep to discover online nodes and queries the Windows ARP table (`arp -a`) to fetch MAC addresses. It raises a security alert if a new device joins the LAN.
3. **Monitoring**: Track live round-trip latency and packet loss metrics of devices.
4. **Security Assessment**: Type any local IP address (e.g. `127.0.0.1` or a LAN node) and click **⚡ Run Scan**. The platform will concurrently scan 15 common ports, identify running services, and trigger a security alert if dangerous services (like Telnet 23 or SMB 445) are exposed.
5. **PCAP Threat Analyzer**: Upload raw network capture files (`.pcap` or `.pcapng`). A custom binary parser extracts packet numbers, protocol breakdowns (TCP vs. UDP), DNS queries, and checks for threats (e.g., C2 port connections or scanning patterns).
6. **Firewall Monitor**: Lists live allowed, blocked, and suspicious network traffic.
7. **Brute-Force Detection**: Tallies failed Windows authentication attempts and generates a **HIGH** severity alert if a threshold is crossed (e.g. >= 3 logon failures in 5 minutes).
8. **DNS Security**: Monitors lookup domains resolved by the DNS Client service. Flags requests matching keywords in `detection/rules.py` (such as "tunnel", "relay", "c2") as suspicious.
9. **SIEM Event Stream**: The central correlation console. Correlates all events, runs rule thresholds, and records security alert classifications in the SQLite backend.
10. **Reports**: Compiles all collected alerts and metrics, allowing you to export a text-based security report.

---

## 5. Security & Ethics Note
NetShield is intended for authorized network auditing and local security configuration management. Only run vulnerability scans or network sweeps on hosts you own or are explicitly authorized to audit. Keep that scope enforced in your deployment — this is a defensive monitoring tool.
