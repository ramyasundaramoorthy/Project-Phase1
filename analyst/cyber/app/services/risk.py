def calculate(severity, anomaly, confidence):
    base={1:85,2:65,3:15,4:5}.get(int(severity or 3),20)
    anomaly_bonus=10 if anomaly=="Anomaly" else 0
    confidence_bonus=round(float(confidence or 0)*10)
    return min(100, base+anomaly_bonus+confidence_bonus)
