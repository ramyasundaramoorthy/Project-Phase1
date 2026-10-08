# CyberAnalyst AI

AI-assisted cybersecurity analyst platform for a controlled simulated healthcare environment.

## Architecture

Healthcare Login -> Patient Portal -> Security Dashboard

Telemetry:
- Demo/Suricata simulator -> eve.json
- Optional real Suricata -> eve.json

Analysis:
EVE JSON -> Event Adapter -> Rules + Isolation Forest + XGBoost -> Incident Correlation
-> Risk Score -> MITRE ATT&CK -> Detection Coverage -> Gemini investigation -> Analyst review

## Important

This project is designed for an authorized local lab. The simulation mode generates telemetry; it does not attack external systems.

## Quick start

Windows:

    py -m venv .venv
    .venv\Scripts\activate
    python -m pip install -r requirements.txt
    copy .env.example .env
    python run.py

Open:
    http://127.0.0.1:5000/

Default demo credentials:
    admin
    admin@123

## Simulation

Use the SOC > Attack Simulator page or:

    python simulations/suricata_simulator.py

Events are written to data/eve.json.

## Real Suricata

Set DETECTION_MODE=suricata and point the event collector at a real Suricata EVE JSON file.
The application does not require Suricata for demo mode.

## AI and email

Gemini and Gmail are optional integrations. Keep secrets in .env.


## Train the ML models

After installing requirements:

    python ml/train_models.py

This creates:

    ml/models/isolation_forest.joblib
    ml/models/xgboost_classifier.joblib
    ml/models/model_metadata.json

The application automatically loads these models for live predictions.

The included training data is controlled synthetic telemetry so the project is immediately runnable. For the final academic evaluation, add a documented public network dataset and a separately documented healthcare-app dataset, with explicit label mapping and train/test separation.


## Gemini integration

Set in `.env`:

    GEMINI_API_KEY=your_private_key
    GEMINI_MODEL=gemini-2.5-flash

The key is never stored in source code. If no key is configured, CyberAnalyst
uses its deterministic local investigation fallback so the demo still works.

## Analyst review

Incident pages now support:
- Approve
- Reject and delete
- Edit analyst notes
- Close

Approvals are marked on the incident. Rejected incidents are deleted from the queue, and the decision remains in the audit log.

## Gmail

High-risk incidents can send a Gmail SMTP alert if EMAIL_SENDER,
EMAIL_PASSWORD (Gmail App Password), and EMAIL_RECEIVER are configured.
Do not put a normal Gmail password in the project.


## Real Suricata EVE JSON adapter

Set:

    DETECTION_MODE=suricata
    SURICATA_EVE_PATH=C:/path/to/eve.json

CyberAnalyst normalizes common Suricata EVE fields into its internal event
schema. The same downstream ML, correlation, MITRE, risk and AI pipeline can
therefore consume either demo events or real local Suricata telemetry.

For demonstrations where Suricata is unavailable:

    DETECTION_MODE=demo

The built-in simulator remains the recommended presentation mode because it
does not require administrator privileges or a packet-capture driver.


## Real-time SOC and detection coverage

The SOC now exposes:
- `/security/events` for recent live telemetry
- `/security/coverage` for detection coverage and gaps
- `/security/suricata` for sensor mode/status

The live event page uses a lightweight polling fallback so it remains usable
even when Flask-SocketIO is unavailable. Flask-SocketIO can be enabled later
for push-based updates.

Detection coverage is derived from observed incident categories and produces
explainable recommendations for missing security use cases.


## Phase 7: Email + ML evaluation

Train:

    python ml/train_models.py

Evaluate:

    python ml/evaluate_models.py

The ML page exposes the saved evaluation report. The report explicitly labels
the evaluation as controlled synthetic telemetry; these values must not be
presented as production or real-world accuracy.

High-risk incidents can trigger one automatic Gmail notification. A manual
"Send High-Risk Email" action is also available from an incident page.

For Gmail, use a Gmail App Password in `.env`. Never commit `.env` or expose
the App Password in source control.


## Project documentation

See the `docs/` directory for:
- Project overview
- Requirement-to-module mapping
- Final demonstration checklist
- Viva questions and answers
- Limitations and future work
- Architecture diagram in text form


## Quick start

```bat
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python ml\train_models.py
python ml\evaluate_models.py
python run.py
```

Open `http://127.0.0.1:5000`.
