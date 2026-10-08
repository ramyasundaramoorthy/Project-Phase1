# Limitations and Future Work

## Current limitations

1. The project is designed primarily as a controlled local demonstration.
2. Demo telemetry is synthetic and does not represent production traffic.
3. Public network datasets may not match healthcare application behavior.
4. MITRE mappings are rule-based project mappings and should be reviewed by a
   security analyst.
5. Risk scoring is an application prioritization mechanism rather than an
   industry-standard risk model.
6. Gemini output depends on the configured API/service.
7. SQLite is appropriate for the demonstration but not intended as a
   high-scale security-event store.
8. The current live-events page has a polling fallback.

## Future improvements

- Kafka or another event-streaming platform for high-volume ingestion.
- PostgreSQL/OpenSearch for larger event storage.
- Stronger event correlation using time windows and entity relationships.
- Calibrated probability/confidence analysis.
- More rigorous evaluation on independent public datasets.
- Independently collected healthcare-app telemetry.
- Full WebSocket push for all dashboard widgets.
- Role-based analyst access control.
- Secure deployment behind HTTPS and a production identity provider.
- Expanded MITRE technique coverage.
- Automated detection-rule generation with human approval.
