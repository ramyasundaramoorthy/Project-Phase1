# CyberAnalyst AI — Project Overview

## 1. Problem Statement

Healthcare applications process sensitive patient information and therefore need
continuous visibility into suspicious authentication, network, application and
data-access activity.

Traditional security monitoring can produce large volumes of events that require
manual investigation. CyberAnalyst AI is designed as an analyst-assistance layer
that collects security telemetry, detects anomalous behavior, classifies known
threat patterns, correlates events into incidents, maps activity to MITRE ATT&CK,
generates an AI-assisted investigation summary, and presents the result to a
human analyst.

## 2. Objective

The system aims to:

1. Collect security events from a simulated healthcare application and optional
   local Suricata telemetry.
2. Detect unusual behavior with Isolation Forest.
3. Classify known threat categories with XGBoost.
4. Correlate related events into incidents.
5. Calculate an explainable risk score.
6. Map incidents to MITRE ATT&CK techniques.
7. Generate structured AI investigation output with Gemini.
8. Recommend detection use cases and identify coverage gaps.
9. Notify analysts about high-risk incidents through Gmail.
10. Preserve analyst actions in an audit log.

## 3. Human-in-the-loop principle

CyberAnalyst AI does not automatically make irreversible security decisions.
AI output is presented as investigation assistance. The analyst can review,
edit, approve, or close an incident.

## 4. Controlled-lab scope

The simulator is intended for an authorized local demonstration environment.
It generates controlled telemetry for the project's own application and is not
intended as a real-world attack tool.
