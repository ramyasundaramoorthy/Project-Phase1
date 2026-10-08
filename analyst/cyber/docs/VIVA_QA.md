# CyberAnalyst AI — Viva Questions and Answers

## Why use both Isolation Forest and XGBoost?

Isolation Forest is useful for identifying behavior that is unusual compared
with normal activity. XGBoost is supervised and can classify activity into
known threat categories when labelled training data is available.

They answer different questions:

```text
Isolation Forest → Is this behavior anomalous?
XGBoost          → What known category does it resemble?
```

## Why is Suricata used?

Suricata is a network security monitoring/IDS engine. Its EVE JSON output gives
the application a structured source of network security telemetry.

CyberAnalyst also has Demo Mode so the complete project can be demonstrated
without requiring a packet-capture environment.

## Why MITRE ATT&CK?

MITRE ATT&CK provides a standardized vocabulary for describing adversary
techniques. Mapping incidents to techniques makes the investigation easier to
communicate and supports detection-coverage analysis.

## Why Gemini?

Gemini is used for analyst assistance rather than primary detection. Structured
incident evidence is supplied to the model and the resulting summary,
findings and recommended actions are shown to the analyst.

## Why is human approval necessary?

Generative AI and automated detection can make mistakes. Human review provides
a control point before an incident is treated as resolved or escalated.

## What is the risk score?

The risk score is an application-defined prioritization value derived from
security attributes such as severity, anomaly information and threat context.
It is intended to help analysts prioritize investigation, not to represent a
universal security standard.

## What does detection coverage mean?

Coverage represents which defined security use cases have corresponding
detections represented in the project. The system also identifies currently
unrepresented use cases as gaps.

## Can the model accuracy be called real-world accuracy?

No. Metrics obtained from controlled synthetic telemetry describe that
evaluation dataset only. Public network datasets and independently collected
healthcare telemetry should be evaluated separately before making real-world
claims.

## What happens if Gemini is unavailable?

The project has a deterministic local fallback so the core demonstration does
not depend entirely on the external AI service.

## What happens if Suricata is unavailable?

Demo Mode generates Suricata-shaped EVE JSON locally. The downstream pipeline
is the same.

## Is CyberAnalyst AI a SIEM replacement?

No. It is an analyst-assistance and correlation layer. Suricata and other
security sensors remain important sources of telemetry.

## What database is used?

SQLite is used because it is simple, portable and appropriate for the local
project demonstration.

## What happens during a high-risk incident?

The system can create an incident, calculate risk, generate an investigation,
and send a structured Gmail notification when email is configured. The analyst
can then review and approve, edit, or close the incident.

## What is the main contribution of the project?

The contribution is the integration of multiple security-analysis stages into a
single analyst workflow:

```text
Telemetry
→ Detection
→ Classification
→ Correlation
→ Risk
→ MITRE
→ GenAI Investigation
→ Human Review
→ Audit
```
