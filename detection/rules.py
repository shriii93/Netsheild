"""
NetShield :: detection/rules.py
-------------------------------------------------
Simple, explainable threshold rules used across modules. In a
production build these would be tunable from the Settings screen and
persisted to the database; here they are constants so the detection
logic is easy to follow and demo.
"""

# Brute-force detection
BRUTE_FORCE_ATTEMPT_THRESHOLD = 10       # failed attempts...
BRUTE_FORCE_WINDOW_MINUTES = 5           # ...within this many minutes -> HIGH
BRUTE_FORCE_WARNING_THRESHOLD = 3        # fewer failed attempts -> WARNING

# Network monitoring
LATENCY_WARNING_MS = 80
LATENCY_CRITICAL_MS = 200
PACKET_LOSS_WARNING_PCT = 2.0
PACKET_LOSS_CRITICAL_PCT = 10.0

# Firewall
FIREWALL_BLOCK_SPIKE_THRESHOLD = 50      # blocked events from one source -> SUSPICIOUS

# DNS
DNS_SUSPICIOUS_KEYWORDS = ["tunnel", "relay", "c2", "xn--", "test"]

# Vulnerability assessment — ports considered higher-risk when exposed
HIGH_RISK_PORTS = {
    23: "Telnet (unencrypted remote access)",
    445: "SMB (file sharing exposed to network)",
    3389: "RDP (remote desktop exposed)",
    21: "FTP (unencrypted file transfer)",
}


def classify_failed_logins(count):
    """Return a severity label for a number of failed login attempts."""
    if count >= BRUTE_FORCE_ATTEMPT_THRESHOLD:
        return "HIGH"
    if count >= BRUTE_FORCE_WARNING_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def classify_latency(ms):
    if ms >= LATENCY_CRITICAL_MS:
        return "HIGH"
    if ms >= LATENCY_WARNING_MS:
        return "MEDIUM"
    return "LOW"


def is_suspicious_domain(domain):
    domain_lower = domain.lower()
    return any(keyword in domain_lower for keyword in DNS_SUSPICIOUS_KEYWORDS)
