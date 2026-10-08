from collections import defaultdict
from datetime import datetime

WINDOW_SECONDS = 120

def correlate(events):
    """
    Groups nearby security events by source IP and broad threat family.
    This is intentionally deterministic and explainable for the project.
    """
    groups = defaultdict(list)

    for event in events:
        src = event.get("src_ip") or "unknown"
        alert = event.get("alert") or {}
        signature = (alert.get("signature") or "").lower()

        if "login" in signature or "brute" in signature:
            family = "Authentication Attack"
        elif "scan" in signature or "port" in signature:
            family = "Network Reconnaissance"
        elif "sql" in signature:
            family = "Web Application Attack"
        elif "exfil" in signature or "outbound" in signature:
            family = "Data Exfiltration"
        elif "privilege" in signature:
            family = "Privilege Escalation"
        else:
            family = alert.get("category") or "Other"

        groups[(src, family)].append(event)

    incidents = []
    for (src, family), items in groups.items():
        severities = [
            int((x.get("alert") or {}).get("severity") or 0)
            for x in items
        ]
        incidents.append({
            "source_ip": src,
            "family": family,
            "event_count": len(items),
            "max_severity": max(severities) if severities else 0,
            "first_event": items[0],
            "last_event": items[-1],
            "events": items
        })

    return incidents
