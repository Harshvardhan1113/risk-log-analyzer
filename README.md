# Risk Log Analyzer 

This tool analyzes server access logs and flags suspicious behavior using customizable scoring logic.

## Sample Use Case

### Input: [logs/sample_case.log](../logs/sample_case.log)
Contains:
- Brute-force login attempt (192.168.0.101)
- Unauthorized admin access (203.0.113.55)
- Normal user activity (172.16.0.9)

### Output: [outputs/sample_alerts.json](../outputs/sample_alerts.json)
```json
[
  {
    "ip": "192.168.0.101",
    "risk_score": 16,
    "risk_level": "Medium"
  },
  {
    "ip": "203.0.113.55",
    "risk_score": 12,
    "risk_level": "Medium"
  }
]
