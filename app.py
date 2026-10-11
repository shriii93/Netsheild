"""
NetShield :: app.py
-------------------------------------------------
Entry point for the Flask web application. Wires together the eight
security modules, the detection/alert engine, and the SQLite database
behind a single dashboard.

Run with:
    python app.py
Then open:
    http://127.0.0.1:5000
"""

import os
import csv
import io
import datetime
import socket
import ctypes
import threading
import time
import concurrent.futures
from flask import (
    Flask, render_template, jsonify, request, redirect,
    url_for, flash, send_file
)

from database.database import init_db, DB_PATH, get_connection
from detection.alerts import get_alerts, alert_summary, update_alert_status, raise_alert
from detection.severity import style_for

from modules.monitoring import monitoring
from modules.discovery import discovery
from modules.vulnerability import vulnerability
from modules.pcap import pcap_analyzer
from modules.firewall import firewall
from modules.brute_force import brute_force
from modules.dns import dns_monitor
from modules.siem import siem

def is_admin():
    """Check if the current process is running with Administrator rights on Windows."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def background_worker():
    """Background telemetry harvesting loop running every 10 seconds."""
    print("[NetShield Daemon] Background telemetry harvester started.")
    while True:
        try:
            # 1. Harvest Firewall Events (WFP logs / fallback to netstat)
            firewall.harvest_firewall_events()
            
            # 2. Harvest DNS Client resolution logs
            dns_monitor.harvest_dns_queries()
            
            # 3. Harvest Security logon failure logs
            brute_force.harvest_failed_logons()
            
            # 4. Run central correlation rules
            siem.correlate_and_alert()
            
            # 5. Ping all monitored hosts to keep status and performance history fresh
            conn = get_connection()
            devices = conn.execute("SELECT ip_address FROM devices").fetchall()
            conn.close()
            
            # Ping each device and record the result
            for d in devices:
                ip = d["ip_address"]
                # Perform a single ping probe
                lat, loss, status = monitoring.ping_host(ip, count=1, timeout_ms=300)
                monitoring.record_sample(ip, lat, loss, status)
                
        except Exception as e:
            print(f"[NetShield Daemon Error] Loop exception: {e}")
            
        time.sleep(10)

app = Flask(__name__)
# Load secret key from environment variable, falling back to a dev key for testing/dev environments
app.secret_key = os.environ.get("NETSHIELD_SECRET_KEY", "netshield-dev-secret-key-fallback")

@app.context_processor
def inject_privileges():
    return dict(is_admin=is_admin())

def start_daemon():
    """Start background harvester thread if running in main reloader process."""
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug:
        worker = threading.Thread(target=background_worker, daemon=True)
        worker.start()


# Initialize the shared SQLite store when the app is imported as well as
# when it is launched directly. This keeps routes and Flask's test client
# usable without requiring a separate database setup command.
init_db(seed=not os.path.exists(DB_PATH))

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# Make severity styling available inside every Jinja template
app.jinja_env.globals.update(style_for=style_for)


# ----------------------------------------------------------------------
# Dashboard (home)
# ----------------------------------------------------------------------
@app.route("/")
def dashboard():
    hosts = monitoring.get_monitored_hosts()
    devices_online = sum(1 for h in hosts if h["status"] == "online")

    fw_counts = firewall.get_counts()
    dns_counts = dns_monitor.get_counts()
    scan_results = vulnerability.get_scan_results()
    risk = vulnerability.overall_risk_level(scan_results)
    alerts = get_alerts(limit=5)
    a_summary = alert_summary()
    pcap = pcap_analyzer.get_latest_analysis()

    # Rough "security score" for the headline card
    security_score = 100
    security_score -= a_summary["HIGH"] * 15
    security_score -= a_summary["MEDIUM"] * 7
    security_score -= a_summary["LOW"] * 2
    security_score = max(40, min(100, security_score))

    return render_template(
        "dashboard.html",
        active="dashboard",
        hosts=hosts,
        devices_online=devices_online,
        devices_total=len(hosts),
        avg_latency=monitoring.average_latency(),
        fw_counts=fw_counts,
        dns_counts=dns_counts,
        risk=risk,
        alerts=alerts,
        alert_summary=a_summary,
        pcap=pcap,
        security_score=security_score,
    )


# ----------------------------------------------------------------------
# Monitoring
# ----------------------------------------------------------------------
@app.route("/monitoring")
def monitoring_page():
    hosts = monitoring.get_monitored_hosts()
    return render_template(
        "monitoring.html", active="monitoring",
        hosts=hosts, avg_latency=monitoring.average_latency()
    )


@app.route("/api/monitoring/history")
def api_monitoring_history():
    return jsonify(monitoring.get_latency_history())


# ----------------------------------------------------------------------
# LAN Discovery
# ----------------------------------------------------------------------
@app.route("/discovery")
def discovery_page():
    result = discovery.scan_network()
    return render_template("scanner.html", active="discovery", result=result)


@app.route("/discovery/scan", methods=["POST"])
def discovery_scan():
    discovery.simulate_new_device()
    flash("Network scan complete.", "success")
    return redirect(url_for("discovery_page"))


@app.route("/discovery/export")
def discovery_export():
    result = discovery.scan_network()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["IP Address", "Hostname", "MAC Address", "Status", "Last Seen"])
    for d in result["devices"]:
        writer.writerow([d["ip_address"], d["hostname"], d["mac_address"],
                          d["status"], d["last_seen"]])
    mem = io.BytesIO(buf.getvalue().encode("utf-8"))
    return send_file(mem, mimetype="text/csv", as_attachment=True,
                      download_name="netshield_devices.csv")


# ----------------------------------------------------------------------
# Vulnerability Assessment
# ----------------------------------------------------------------------
@app.route("/vulnerability")
def vulnerability_page():
    targets = vulnerability.known_targets()
    selected = request.args.get("target", targets[0] if targets else None)
    rows = vulnerability.get_scan_results(selected)
    return render_template(
        "vulnerability.html", active="vulnerability",
        targets=targets, selected=selected, rows=rows,
        risk=vulnerability.overall_risk_level(rows),
        flagged=vulnerability.flag_high_risk_ports(rows),
    )


@app.route("/vulnerability/scan", methods=["POST"])
def vulnerability_scan():
    target = request.form.get("target_ip")
    if target:
        target = target.strip()
        try:
            socket.gethostbyname(target)
            vulnerability.run_port_scan(target)
            flash(f"Security assessment complete for {target}.", "success")
        except Exception as e:
            flash(f"Invalid host or IP address format: {target}. Error: {e}", "danger")
    else:
        flash("Please enter a target IP address.", "danger")
    return redirect(url_for("vulnerability_page", target=target))


# ----------------------------------------------------------------------
# PCAP Analysis
# ----------------------------------------------------------------------
@app.route("/pcap")
def pcap_page():
    analysis = pcap_analyzer.get_latest_analysis()
    return render_template("pcap.html", active="pcap", analysis=analysis)


@app.route("/pcap/upload", methods=["POST"])
def pcap_upload():
    uploaded = request.files.get("pcap_file")
    if uploaded and uploaded.filename:
        uploads_dir = os.path.join(app.root_path, "static", "uploads")
        os.makedirs(uploads_dir, exist_ok=True)
        file_path = os.path.join(uploads_dir, uploaded.filename)
        uploaded.save(file_path)
        
        # Call the binary parser
        analysis = pcap_analyzer.analyze_uploaded_file(file_path)
        
        try:
            os.remove(file_path)
        except Exception:
            pass
            
        if analysis:
            flash(f"Analysis complete for {uploaded.filename}.", "success")
        else:
            flash(f"Error parsing packet capture {uploaded.filename}.", "danger")
    else:
        flash("No file selected or invalid file.", "danger")
    return redirect(url_for("pcap_page"))


# ----------------------------------------------------------------------
# Windows Firewall Monitoring
# ----------------------------------------------------------------------
@app.route("/firewall")
def firewall_page():
    events = firewall.get_recent_events()
    counts = firewall.get_counts()
    return render_template("firewall.html", active="firewall", events=events, counts=counts)


# ----------------------------------------------------------------------
# Brute-Force / Authentication Monitoring
# ----------------------------------------------------------------------
@app.route("/brute-force")
def brute_force_page():
    summary = brute_force.get_account_summary()
    offender = brute_force.top_offender()
    return render_template(
        "brute_force.html", active="brute_force",
        summary=summary, offender=offender,
        total_failed=brute_force.total_failed_today(),
    )


@app.route("/brute-force/investigate/<account>", methods=["POST"])
def brute_force_investigate(account):
    raise_alert("HIGH", f"Brute-force investigation opened for '{account}'",
                "Auth Monitor", f"Analyst opened an investigation into repeated failed logins for {account}.")
    flash(f"Investigation opened for '{account}'.", "success")
    return redirect(url_for("brute_force_page"))


# ----------------------------------------------------------------------
# DNS Security Monitoring
# ----------------------------------------------------------------------
@app.route("/dns")
def dns_page():
    queries = dns_monitor.get_recent_queries()
    counts = dns_monitor.get_counts()
    return render_template("dns.html", active="dns", queries=queries, counts=counts)


# ----------------------------------------------------------------------
# Windows SIEM
# ----------------------------------------------------------------------
@app.route("/siem")
def siem_page():
    severity = request.args.get("severity") or None
    source = request.args.get("source") or None
    events = siem.get_events(severity=severity, source=source)
    return render_template(
        "siem.html", active="siem", events=events,
        counts=siem.event_counts(), sources=siem.sources(),
        selected_severity=severity, selected_source=source,
    )


# ----------------------------------------------------------------------
# Alerts
# ----------------------------------------------------------------------
@app.route("/alerts")
def alerts_page():
    status = request.args.get("status") or None
    alerts = get_alerts(limit=100, status=status)
    return render_template(
        "alerts.html", active="alerts",
        alerts=alerts, summary=alert_summary(), selected_status=status,
    )


@app.route("/alerts/<int:alert_id>/status", methods=["POST"])
def alert_update_status(alert_id):
    new_status = request.form.get("status", "reviewed")
    update_alert_status(alert_id, new_status)
    flash("Alert updated.", "success")
    return redirect(url_for("alerts_page"))


# ----------------------------------------------------------------------
# Reports
# ----------------------------------------------------------------------
@app.route("/reports")
def reports_page():
    return render_template(
        "reports.html", active="reports",
        alert_summary=alert_summary(),
        fw_counts=firewall.get_counts(),
        dns_counts=dns_monitor.get_counts(),
        siem_counts=siem.event_counts(),
    )


@app.route("/reports/generate", methods=["POST"])
def reports_generate():
    """Generate a plain-text security summary report and offer it as a
    download — a stand-in for a full PDF report generator."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    a_summary = alert_summary()
    fw_counts = firewall.get_counts()
    dns_counts = dns_monitor.get_counts()
    siem_counts = siem.event_counts()

    lines = [
        "NETSHIELD SECURITY SUMMARY REPORT",
        "=" * 40,
        f"Generated: {now}",
        "",
        "OPEN ALERTS",
        f"  High:   {a_summary['HIGH']}",
        f"  Medium: {a_summary['MEDIUM']}",
        f"  Low:    {a_summary['LOW']}",
        "",
        "FIREWALL",
        f"  Allowed:    {fw_counts['allowed']}",
        f"  Blocked:    {fw_counts['blocked']}",
        f"  Suspicious: {fw_counts['suspicious']}",
        "",
        "DNS",
        f"  Normal:  {dns_counts['normal']}",
        f"  Review:  {dns_counts['review']}",
        f"  Blocked: {dns_counts['blocked']}",
        "",
        "SIEM",
        f"  Events collected: {siem_counts['events_collected']}",
        f"  Alerts generated: {siem_counts['alerts_generated']}",
        "",
        "Recent Alerts:",
    ]
    for a in get_alerts(limit=10):
        lines.append(f"  [{a['severity']}] {a['title']} ({a['source']}) - {a['created_at']}")

    content = "\n".join(lines)
    mem = io.BytesIO(content.encode("utf-8"))
    filename = f"netshield_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    return send_file(mem, mimetype="text/plain", as_attachment=True, download_name=filename)


# ----------------------------------------------------------------------
# Settings (placeholder screen)
# ----------------------------------------------------------------------
@app.route("/settings")
def settings_page():
    return render_template("settings.html", active="settings")


# ----------------------------------------------------------------------
# Lightweight JSON APIs used for auto-refreshing dashboard widgets
# ----------------------------------------------------------------------
@app.route("/api/alerts/summary")
def api_alert_summary():
    return jsonify(alert_summary())


@app.route("/api/status")
def api_status():
    hosts = monitoring.get_monitored_hosts()
    return jsonify({
        "system": "online",
        "devices_online": sum(1 for h in hosts if h["status"] == "online"),
        "devices_total": len(hosts),
        "avg_latency": monitoring.average_latency(),
    })


if __name__ == "__main__":
    host = os.environ.get("NETSHIELD_HOST", "0.0.0.0")
    port = int(os.environ.get("NETSHIELD_PORT", "5000"))
    
    # Start background daemon collector
    start_daemon()
    
    print(f"NetShield is running at http://127.0.0.1:{port}")
    if host == "0.0.0.0":
        print(f"Network access: http://<this-computer-ip>:{port}")
    app.run(debug=True, host=host, port=port)
