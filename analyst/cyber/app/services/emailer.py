import os
import smtplib
from email.message import EmailMessage

STABLE_RECOMMENDATION = "Validate the source activity, review relevant application/authentication logs, preserve evidence, and escalate or close after analyst review."


def _as_incident_dict(incident):
    if incident is None:
        return {}
    if isinstance(incident, dict):
        return incident
    try:
        return dict(incident)
    except (TypeError, ValueError):
        return {}


def email_configured():
    return all([
        os.getenv("EMAIL_SENDER", "").strip(),
        os.getenv("EMAIL_PASSWORD", "").strip(),
        os.getenv("EMAIL_RECEIVER", "").strip()
    ])


def build_body(incident):
    incident = _as_incident_dict(incident)
    portal = os.getenv("SECURITY_PORTAL_URL", "http://127.0.0.1:5000/security")
    recommendation = str(incident.get("ai_recommendations") or STABLE_RECOMMENDATION).strip() or STABLE_RECOMMENDATION
    summary = str(incident.get("ai_summary") or "Activity was classified as suspicious and requires analyst review.").strip()
    findings = str(incident.get("ai_findings") or "The system detected repeated anomalous activity consistent with malicious or unauthorized behavior.").strip()
    return f"""CyberAnalyst AI - High Risk Security Alert

Incident ID: INC-{int(incident["id"]):04d}
Threat: {incident["threat"]}
Risk Score: {incident["risk_score"]}/100
Severity: {incident["severity"]}
Source IP: {incident["source_ip"]}
Event Count: {incident["event_count"]}
ML Confidence: {incident["ml_confidence"]}

What triggered this alert:
This event was flagged because the system detected suspicious or anomalous activity matching the identified threat pattern. The current incident has been correlated against telemetry, anomaly detection, model confidence, and MITRE mapping.

MITRE ATT&CK:
{incident["mitre_id"]} - {incident["mitre_name"]}
Mapping reason: {incident["mapping_reason"]}

AI Investigation:
{summary}

Findings:
{findings}

Recommended Actions:
{recommendation}

Operational guidance:
Validate the source activity, review relevant application and authentication logs, preserve evidence, and escalate or close after analyst review.

SOC Dashboard:
{portal}
"""

def send_high_risk(incident):
    if not email_configured():
        return False, "Email not configured"

    sender = os.getenv("EMAIL_SENDER").strip()
    password = os.getenv("EMAIL_PASSWORD").strip()
    receiver = os.getenv("EMAIL_RECEIVER").strip()

    msg = EmailMessage()
    msg["Subject"] = (
        f"[CyberAnalyst] HIGH RISK INC-{int(incident['id']):04d} "
        f"- {incident['threat']}"
    )
    msg["From"] = sender
    msg["To"] = receiver
    msg.set_content(build_body(incident))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=20) as smtp:
        smtp.login(sender, password)
        smtp.send_message(msg)

    return True, "Sent"
