TECHNIQUES = {
    "Brute Force": {
        "mitre": "T1110",
        "name": "Brute Force",
        "use_case": "Detect repeated failed authentication attempts from the same source."
    },
    "Port Scan": {
        "mitre": "T1046",
        "name": "Network Service Scanning",
        "use_case": "Detect repeated connections to multiple destination ports."
    },
    "SQL Injection": {
        "mitre": "T1190",
        "name": "Exploit Public-Facing Application",
        "use_case": "Detect suspicious web requests targeting application input fields."
    },
    "Unauthorized Access": {
        "mitre": "T1078",
        "name": "Valid Accounts",
        "use_case": "Detect unusual access using authenticated application identities."
    },
    "Privilege Escalation": {
        "mitre": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "use_case": "Detect behavior indicating an attempt to gain higher privileges."
    },
    "Data Exfiltration": {
        "mitre": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "use_case": "Detect unusual outbound transfer volume or destinations."
    }
}

def calculate_coverage(incidents):
    observed = set()
    for incident in incidents:
        threat = incident.get("threat") or incident.get("family")
        for key in TECHNIQUES:
            if key.lower() in threat.lower():
                observed.add(key)

    rows = []
    for threat, data in TECHNIQUES.items():
        rows.append({
            "threat": threat,
            "mitre": data["mitre"],
            "technique": data["name"],
            "use_case": data["use_case"],
            "covered": threat in observed
        })

    covered = sum(1 for x in rows if x["covered"])
    total = len(rows)
    return {
        "percentage": round((covered / total) * 100, 1) if total else 0,
        "covered": covered,
        "total": total,
        "rows": rows,
        "gaps": [x for x in rows if not x["covered"]]
    }
