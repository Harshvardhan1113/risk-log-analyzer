# Risk Log Analyzer – Project Report

---

## Overview
**Risk Log Analyzer** is a Python-based CLI tool designed to parse access logs, identify malicious behavior (like brute-force attacks, unauthorized access), and generate structured alerts based on risk scores.

---

## Objectives
- Detect brute-force login attempts
- Identify access to sensitive endpoints
- Assign risk scores per IP/session
- Export alerts in JSON/CSV
- Use CLI arguments for custom runs

---

## Log Format Example
```log
192.168.0.101 - - [03/Aug/2025:09:00:00 +0530] "POST /login HTTP/1.1" 401 - "Mozilla/5.0"
```

---

## Architecture
```text
1. Log Parser       → Extract fields via regex
2. Session Grouper  → Group logs by IP
3. Threat Analyzer  → Identify brute-force & unauthorized access
4. Scoring Engine   → Assign risk scores
5. Exporter         → Output JSON/CSV alerts
```

### Scoring Logic
| Behavior                                | Score |
|-----------------------------------------|--------|
| Failed login (401)                      | +3     |
| Brute-force (2+ 401s → 200)             | +10    |
| Access to /admin, /.env, /etc          | +7     |
| 403/401 on restricted endpoints         | +5     |

### 🔐 Risk Levels
| Score Range | Level   |
|-------------|---------|
| 0–10        | Low     |
| 11–20       | Medium  |
| 21+         | High    |

---

## CLI Usage
```bash
python analyzer.py --input logs/sample_case.log --threshold 10 --format json
```

### Arguments:
- `--input`: Log file path
- `--threshold`: Min risk score to include
- `--format`: `json` or `csv`

---

## Example Results

### Input: `logs/sample_case.log`
```log
192.168.0.101 - - [03/Aug/2025:09:00:00 +0530] "POST /login HTTP/1.1" 401 - "Mozilla/5.0"
192.168.0.101 - - [03/Aug/2025:09:00:03 +0530] "POST /login HTTP/1.1" 401 - "Mozilla/5.0"
192.168.0.101 - - [03/Aug/2025:09:00:07 +0530] "POST /login HTTP/1.1" 200 - "Mozilla/5.0"
203.0.113.55 - - [03/Aug/2025:09:01:00 +0530] "GET /admin HTTP/1.1" 403 - "curl/7.68.0"
```

### Output: `outputs/sample_alerts.json`
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
```
---

## Use Cases
- Simulate real-world log analysis
- Demonstrate CLI security tool design
- Practice SOC-style risk classification
- Resume-ready for security internships

---

## Future Upgrades
- Docker support
- CLI colorization (colorama)
- Automated log generation
- GitHub Actions testing + release

---


