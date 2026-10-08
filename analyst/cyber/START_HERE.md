# CyberAnalyst AI — Complete Build

This folder is the complete integrated source package for the CyberAnalyst AI final-year project.

## Included
- Healthcare admin portal
- Patient management pages
- CyberAnalyst SOC dashboard
- Demo attack simulator
- Suricata EVE JSON adapter
- Event processor and background correlation
- Isolation Forest anomaly detection
- XGBoost classification
- MITRE ATT&CK mapping
- Risk scoring
- Gemini AI investigation + deterministic fallback
- Human analyst review / approval / closure
- Audit logs
- Detection coverage
- Gmail high-risk alert integration
- ML training/evaluation scripts and saved model artifacts
- Documentation, viva questions, demo checklist
- Final project report (.docx)
- Final presentation (.pptx)

## Windows setup
```bat
cd CyberAnalyst_AI
python -m venv .venv
.venv\\Scripts\\activate
pip install -r requirements.txt
copy .env.example .env
python tests\\self_check.py
python ml\\train_models.py
python ml\\evaluate_models.py
python run.py
```

Open http://127.0.0.1:5000

Demo login: `admin` / `admin@123`

## Important
Keep API keys and Gmail App Passwords only in `.env`. Do not commit or share `.env`.

The attack simulations are for a controlled local lab and are not intended for attacking third-party systems.
