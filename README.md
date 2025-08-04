# Risk Log Analyzer 

This tool analyzes server access logs and flags suspicious behavior using customizable scoring logic.

## Sample Use Case

### Input: [logs/new_log_1.log]
Contains:
- Brute-force login attempt (192.168.1.10)
- Unauthorized admin access (203.0.113.21)
- Normal user activity (172.16.1.14)

### Output:
```json
[
    {
        "ip": "192.168.1.10",
        "risk_score": 16,
        "risk_level": "Medium"
    },
    {
        "ip": "203.0.113.21",
        "risk_score": 17,
        "risk_level": "Medium"
    },
    {
        "ip": "10.0.0.5",
        "risk_score": 19,
        "risk_level": "Medium"
    },
    {
        "ip": "198.51.100.6",
        "risk_score": 17,
        "risk_level": "Medium"
    }
]




