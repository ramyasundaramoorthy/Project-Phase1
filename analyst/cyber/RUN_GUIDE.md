# CyberAnalyst AI — Final Run Guide

## Install
```bat
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Configure
Copy `.env.example` to `.env`.

Demo mode:
```text
DETECTION_MODE=demo
SURICATA_EVE_PATH=data/eve.json
```

Optional Gemini:
```text
GEMINI_API_KEY=your_private_key
GEMINI_MODEL=gemini-2.5-flash
```

Optional Gmail:
```text
EMAIL_SENDER=your_gmail_address
EMAIL_PASSWORD=your_gmail_app_password
EMAIL_RECEIVER=recipient_address
SECURITY_PORTAL_URL=http://127.0.0.1:5000/security
```

Never commit `.env` or an App Password.

## Train and evaluate
```bat
python ml\train_models.py
python ml\evaluate_models.py
```

The ML metrics are controlled/synthetic evaluation results and must not be
presented as production or real-world cybersecurity performance.

## Run
```bat
python run.py
```

Open `http://127.0.0.1:5000`.

## Demonstration
1. Login to the healthcare portal.
2. Open Patient History.
3. Open the SOC Dashboard.
4. Run a controlled Attack Simulator scenario.
5. View Live Security Events.
6. Inspect the generated incident.
7. Review ML prediction and confidence.
8. Review MITRE ATT&CK mapping.
9. Review Gemini investigation.
10. Approve, edit, or close the incident.
11. Check Audit Logs.
12. For a configured high-risk incident, verify the email alert.

## Detection modes

Demo mode requires no Suricata installation:
```text
DETECTION_MODE=demo
```

Real local Suricata EVE JSON:
```text
DETECTION_MODE=suricata
SURICATA_EVE_PATH=C:/path/to/eve.json
```

Both modes feed the same normalization, ML, correlation, MITRE, risk,
Gemini, dashboard, alert, and audit pipeline.
