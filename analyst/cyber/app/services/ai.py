import os
import json
import requests

DEFAULT_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
STABLE_RECOMMENDATION = "Validate the source activity, review relevant application/authentication logs, preserve evidence, and escalate or close after analyst review."


def build_soc_recommendations(threat):
    threat_name = str(threat or "Unknown").strip()
    normalized = threat_name.lower()

    if "normal" in normalized or "benign" in normalized:
        return (
            "REAL-TIME RESPONSE\n"
            "Activity appears normal. No immediate containment action is recommended.\n\n"
            "INVESTIGATION\n"
            "- Continue normal monitoring.\n"
            "- Close the incident if analyst review confirms benign activity.\n\n"
            "ANALYST APPROVAL REQUIRED"
        )

    if "brute" in normalized:
        return (
            "REAL-TIME RESPONSE\n"
            "1. Temporarily block or restrict the suspicious source IP.\n"
            "2. Review repeated failed authentication attempts.\n"
            "3. Check whether a successful login occurred after the failed attempts.\n"
            "4. Temporarily lock or protect the affected account if necessary.\n"
            "5. Monitor the source IP for continued authentication activity.\n\n"
            "INVESTIGATION\n"
            "- Review authentication logs.\n"
            "- Identify affected accounts.\n"
            "- Check related incidents from the same source IP.\n"
            "- Check for successful authentication after repeated failures.\n\n"
            "ANALYST APPROVAL REQUIRED"
        )

    if "scan" in normalized:
        return (
            "REAL-TIME RESPONSE\n"
            "1. Monitor or temporarily restrict the suspicious source IP.\n"
            "2. Identify the ports and services targeted.\n"
            "3. Check whether the source continued scanning.\n"
            "4. Review related network events.\n\n"
            "INVESTIGATION\n"
            "- Identify exposed services.\n"
            "- Check for subsequent exploitation attempts.\n"
            "- Correlate events from the same source IP.\n\n"
            "ANALYST APPROVAL REQUIRED"
        )

    if "sql" in normalized:
        return (
            "REAL-TIME RESPONSE\n"
            "1. Restrict the suspicious source/request if appropriate.\n"
            "2. Identify the affected application endpoint.\n"
            "3. Review the suspicious request and parameters.\n"
            "4. Check whether database access occurred.\n\n"
            "INVESTIGATION\n"
            "- Review application and database logs.\n"
            "- Check whether patient records were accessed or modified.\n"
            "- Verify parameterized queries and input validation.\n"
            "- Look for additional suspicious requests.\n\n"
            "ANALYST APPROVAL REQUIRED"
        )

    if "unauthorized" in normalized:
        return (
            "REAL-TIME RESPONSE\n"
            "1. Review the affected account or session.\n"
            "2. Restrict the suspicious session if necessary.\n"
            "3. Verify whether the access was authorized.\n"
            "4. Check what resources were accessed.\n\n"
            "INVESTIGATION\n"
            "- Review authentication and authorization logs.\n"
            "- Identify affected patient records or resources.\n"
            "- Check for related activity from the same account or IP.\n\n"
            "ANALYST APPROVAL REQUIRED"
        )

    if "privilege" in normalized:
        return (
            "REAL-TIME RESPONSE\n"
            "1. Restrict the affected session or account if necessary.\n"
            "2. Verify the user's expected privilege level.\n"
            "3. Identify the privilege change.\n"
            "4. Review actions performed after privilege escalation.\n\n"
            "INVESTIGATION\n"
            "- Review authentication and authorization logs.\n"
            "- Identify the privilege escalation event.\n"
            "- Check for sensitive-resource access afterward.\n"
            "- Correlate related activity.\n\n"
            "ANALYST APPROVAL REQUIRED"
        )

    if "exfil" in normalized or "data" in normalized:
        return (
            "REAL-TIME RESPONSE\n"
            "1. Restrict the suspicious session or transfer if appropriate.\n"
            "2. Identify what data was accessed or exported.\n"
            "3. Review the destination and transfer volume.\n"
            "4. Preserve relevant audit evidence.\n\n"
            "INVESTIGATION\n"
            "- Identify affected patient records.\n"
            "- Review export or download activity.\n"
            "- Check for additional transfers.\n"
            "- Correlate related user and network activity.\n\n"
            "ANALYST APPROVAL REQUIRED"
        )

    return (
        "REAL-TIME RESPONSE\n"
        "1. Validate the source activity.\n"
        "2. Review relevant application and authentication logs.\n"
        "3. Preserve evidence and capture supporting telemetry.\n\n"
        "INVESTIGATION\n"
        "- Verify the event against related telemetry.\n"
        "- Check whether the source IP or account is involved in other suspicious activity.\n"
        "- Escalate or close the incident after analyst review.\n\n"
        "ANALYST APPROVAL REQUIRED"
    )


def _fallback(incident):
    threat = incident.get("threat", "Unknown")
    risk = incident.get("risk_score", 0)
    src = incident.get("source_ip", "Unknown")
    return {
        "summary": f"CyberAnalyst correlated activity classified as {threat} from {src}. Current risk score is {risk}/100.",
        "findings": "The incident was evaluated using security telemetry, anomaly analysis, supervised classification and correlation evidence.",
        "evidence": f"Source IP: {src}; threat classification: {threat}; risk score: {risk}/100.",
        "mitre_explanation": f"The current incident has been mapped to {incident.get('mitre_id','N/A')} - {incident.get('mitre_name','No mapping')}.",
        "recommendations": build_soc_recommendations(threat)
    }

def investigate(incident):
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        return _fallback(incident)

    prompt = f"""
You are assisting a cybersecurity analyst in an authorized local healthcare
application lab. Analyze the structured incident below. Do not invent evidence.

Return ONLY valid JSON with these keys:
summary, findings, evidence, mitre_explanation, recommendations

Incident:
{json.dumps(dict(incident), default=str, indent=2)}
"""

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{DEFAULT_MODEL}:generateContent"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "responseMimeType": "application/json"
        }
    }

    try:
        response = requests.post(
            url,
            params={"key": api_key},
            json=payload,
            timeout=30
        )
        response.raise_for_status()
        data = response.json()
        text = data["candidates"][0]["content"]["parts"][0]["text"]
        result = json.loads(text)

        required = ["summary", "findings", "evidence", "mitre_explanation", "recommendations"]
        if not all(k in result for k in required):
            raise ValueError("Gemini response is missing required fields")

        result["recommendations"] = build_soc_recommendations(incident.get("threat", "Unknown"))
        return result
    except Exception as exc:
        result = _fallback(incident)
        result["ai_error"] = str(exc)
        return result

def gemini_available():
    return bool(os.getenv("GEMINI_API_KEY", "").strip())
