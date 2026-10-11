"""
NetShield :: modules/brute_force
-------------------------------------------------
Authentication monitoring & brute-force detection.
Queries live Windows Security Event Log (Event ID 4625) via PowerShell
to parse failed login attempts, target accounts, and source IP addresses.
"""

import subprocess
import json
import re
import datetime
from database.database import get_connection
from detection.rules import classify_failed_logins, BRUTE_FORCE_ATTEMPT_THRESHOLD

def harvest_failed_logons():
    """Query and ingest Windows Event ID 4625 (Failed Logon) from the Security log."""
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    
    # Query logs from the last 15 seconds
    start_time = (datetime.datetime.now() - datetime.timedelta(seconds=15)).strftime("%Y-%m-%d %H:%M:%S")
    ps_cmd = (
        f"Get-WinEvent -FilterHashtable @{{LogName='Security';ID=4625;StartTime=[datetime]::Parse('{start_time}')}} "
        f"-MaxEvents 50 -ErrorAction SilentlyContinue | "
        f"Select-Object @{{Name='TimeCreated';Expression={{$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}}}, Message | "
        f"ConvertTo-Json"
    )

    try:
        res = subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, text=True, timeout=5.0)
        output = res.stdout.strip()
        if output:
            data = json.loads(output)
            events = data if isinstance(data, list) else [data]
            for ev in events:
                msg = ev.get("Message", "")
                attempt_time = ev.get("TimeCreated", now_str)

                # Extract Target account and Source IP
                acc_match = re.search(r"Account For Which Logon Failed:[\s\S]+?Account Name:\s*([^\s\r\n]+)", msg)
                ip_match = re.search(r"Source Network Address:\s*([^\s\r\n]+)", msg)

                if acc_match:
                    account = acc_match.group(1).strip()
                    source_ip = ip_match.group(1).strip() if ip_match else "127.0.0.1"
                    if source_ip == "-" or not source_ip:
                        source_ip = "127.0.0.1"

                    # Check for duplicates
                    dup = conn.execute(
                        "SELECT id FROM auth_attempts WHERE attempt_time = ? AND account = ? AND source_ip = ?",
                        (attempt_time, account, source_ip)
                    ).fetchone()

                    if not dup:
                        conn.execute(
                            "INSERT INTO auth_attempts (account, source_ip, success, attempt_time) VALUES (?, ?, 0, ?)",
                            (account, source_ip, attempt_time)
                        )
                        # SIEM Log is inserted here as well in the main app event loop
    except Exception:
        pass

    conn.commit()
    conn.close()

def get_account_summary():
    """Return the list of accounts with their failed and succeeded auth count summary."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT account, "
        " SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS failed, "
        " SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS succeeded, "
        " COUNT(*) AS total "
        "FROM auth_attempts GROUP BY account ORDER BY failed DESC"
    ).fetchall()
    conn.close()

    summary = []
    for r in rows:
        summary.append({
            "account": r["account"],
            "failed": r["failed"],
            "succeeded": r["succeeded"],
            "total": r["total"],
            "status": classify_failed_logins(r["failed"]),
        })
    return summary

def total_failed_today():
    """Count of total failed logins in the database."""
    conn = get_connection()
    row = conn.execute(
        "SELECT COUNT(*) AS c FROM auth_attempts WHERE success = 0"
    ).fetchone()
    conn.close()
    return row["c"]

def top_offender():
    """Return the account with the most failed attempts, if it clears the brute-force threshold."""
    summary = get_account_summary()
    if not summary:
        return None
    top = summary[0]
    if top["failed"] >= BRUTE_FORCE_ATTEMPT_THRESHOLD:
        return top
    return None

