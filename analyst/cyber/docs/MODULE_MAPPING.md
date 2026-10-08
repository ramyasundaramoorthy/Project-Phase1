# CyberAnalyst AI — Module Mapping

| Project Requirement | Implementation |
|---|---|
| Healthcare application | Flask + SQLite patient portal |
| Event collection | Application events + Suricata EVE JSON |
| Controlled simulation | `app/services/simulator.py` |
| Real sensor adapter | `app/services/suricata.py` |
| Anomaly detection | `app/services/ml_engine.py` + Isolation Forest |
| Threat classification | XGBoost |
| Incident correlation | `app/services/correlation.py` |
| Risk scoring | `app/services/risk.py` |
| MITRE mapping | `app/services/mitre.py` |
| AI investigation | `app/services/ai.py` |
| Detection coverage | `app/services/coverage.py` |
| Email notification | `app/services/emailer.py` |
| Auditability | SQLite audit logs |
| Analyst review | Approve / Edit / Close |
| Live telemetry | `/security/events` |
| ML evaluation | `ml/evaluate_models.py` |
| Data preparation | `ml/prepare_public_dataset.py` |
| Healthcare telemetry | `ml/generate_healthcare_dataset.py` |

## Main data flow

```text
Healthcare App
      ↓
Demo Simulator / Suricata
      ↓
EVE JSON
      ↓
Normalization
      ↓
ML + Correlation
      ↓
Risk
      ↓
MITRE
      ↓
Gemini
      ↓
Analyst Dashboard
      ↓
Audit
```
