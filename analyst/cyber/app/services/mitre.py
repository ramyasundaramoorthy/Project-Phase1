MAPPINGS = {
    "Brute Force": ("T1110","Brute Force","Repeated authentication activity against the login endpoint."),
    "Port Scan": ("T1046","Network Service Scanning","Multiple connection attempts indicate service discovery behavior."),
    "SQL Injection": ("T1190","Exploit Public-Facing Application","Suspicious web request pattern targets the application."),
    "Unauthorized Access": ("T1078","Valid Accounts","Activity is associated with access using an account context."),
    "Privilege Escalation": ("T1068","Exploitation for Privilege Escalation","Observed activity is categorized as possible privilege escalation."),
    "Data Exfiltration": ("T1041","Exfiltration Over C2 Channel","Observed transfer pattern is treated as possible data exfiltration."),
    "Normal": ("N/A","No ATT&CK mapping","Normal activity does not require a threat technique mapping.")
}
def map_threat(threat):
    return MAPPINGS.get(threat,MAPPINGS["Normal"])
