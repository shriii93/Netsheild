"""
NetShield :: detection/severity.py
-------------------------------------------------
Small helper module that keeps severity labels consistent everywhere
(UI badges, database rows, SIEM correlation).
"""

VALID_SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Maps severity -> (badge color class, icon) used by the templates
SEVERITY_STYLE = {
    "LOW":      {"class": "sev-low",      "icon": "🟡", "color": "#D29922"},
    "MEDIUM":   {"class": "sev-medium",   "icon": "🟠", "color": "#DB7B2B"},
    "HIGH":     {"class": "sev-high",     "icon": "🔴", "color": "#F85149"},
    "CRITICAL": {"class": "sev-critical", "icon": "🟣", "color": "#B855F0"},
}


def normalize_severity(value):
    """Uppercase and validate a severity string, defaulting to LOW."""
    if not value:
        return "LOW"
    value = str(value).strip().upper()
    return value if value in VALID_SEVERITIES else "LOW"


def style_for(severity):
    return SEVERITY_STYLE.get(normalize_severity(severity), SEVERITY_STYLE["LOW"])
