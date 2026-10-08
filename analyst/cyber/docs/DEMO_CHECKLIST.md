# CyberAnalyst AI — Final Demo Checklist

## Before the demo

- [ ] Create/activate Python virtual environment.
- [ ] Install `requirements.txt`.
- [ ] Copy `.env.example` to `.env`.
- [ ] Set `DETECTION_MODE=demo`.
- [ ] Add Gemini key only if AI live generation is being demonstrated.
- [ ] Configure Gmail App Password only if email demonstration is required.
- [ ] Run `python ml/train_models.py`.
- [ ] Run `python ml/evaluate_models.py`.
- [ ] Run `python run.py`.

## Demonstration sequence

### 1. Healthcare portal
Show:
- Admin login
- Patient History
- Search
- View
- Add
- Modify
- Delete

### 2. SOC dashboard
Show:
- Event count
- Anomaly count
- Incident count
- Risk levels
- Sensor status
- ML status
- Gemini status

### 3. Controlled simulation
Run one scenario such as:
- Brute Force
- Port Scan
- SQL Injection
- Unauthorized Access
- Privilege Escalation
- Data Exfiltration

### 4. Investigation
Open the generated incident and show:

```text
Threat
Risk Score
ML Confidence
Evidence
MITRE ATT&CK
AI Summary
AI Findings
Recommended Actions
```

### 5. Analyst decision
Demonstrate:
- Edit analyst notes
- Approve
- Close

### 6. Audit
Show that the analyst action is recorded.

### 7. Optional email
Trigger a high-risk notification and show the structured alert.

## Recommended presentation statement

"CyberAnalyst AI is an analyst-assistance platform. It combines deterministic
security telemetry, machine learning, threat intelligence mapping and generative
AI, while keeping the final incident decision with a human analyst."
