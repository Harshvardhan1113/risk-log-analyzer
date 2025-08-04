import re
import argparse
import json
import csv
import os
from datetime import datetime
from collections import defaultdict

LOG_PATTERN = r'(?P<ip>\S+) - - \[(?P<timestamp>.+?)\] "(?P<method>\S+) (?P<endpoint>\S+) HTTP/\d\.\d" (?P<status>\d{3}) - "(?P<user_agent>.+?)"'

RESTRICTED_PATHS = ['/admin', '/etc', '/wp-admin', '/config', '/.env']

def parse_log_line(line):
    match = re.match(LOG_PATTERN, line)
    if match:
        return match.groupdict()
    return None

def export_alerts(risk_scores, format='json', threshold=15):
    alerts = []
    for ip, info in risk_scores.items():
        score = int(info['score'])  # Ensure numeric
        if score >= threshold:
            alerts.append({
                'ip': ip,
                'risk_score': score,
                'risk_level': info['level']
            })

    if not alerts:
        print("\n No high-risk alerts to export.")
        return

    os.makedirs("exports", exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"exports/alerts_{timestamp}.{format}"

    if format == 'json':
        with open(filename, 'w') as f:
            json.dump(alerts, f, indent=4)
    elif format == 'csv':
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=alerts[0].keys())
            writer.writeheader()
            writer.writerows(alerts)

    print(f"\n Alerts exported to: {filename}")

if __name__ == "__main__":
    # CLI arguments
    parser = argparse.ArgumentParser(description="Risk Log Analyzer CLI")
    parser.add_argument('--input', type=str, default='logs/access_sample.log', help='Path to log file')
    parser.add_argument('--threshold', type=int, default=15, help='Risk score threshold')
    parser.add_argument('--format', type=str, choices=['json', 'csv'], default='json', help='Export format')
    args = parser.parse_args()

    # Parse logs
    parsed_logs = []
    with open(args.input, 'r') as f:
        for line in f:
            parsed = parse_log_line(line.strip())
            if parsed:
                parsed_logs.append(parsed)

    print(f"\n Total parsed entries: {len(parsed_logs)}")

    # Group by IP
    sessions = defaultdict(list)
    for entry in parsed_logs:
        sessions[entry['ip']].append(entry)

    # Brute-force detection
    print("\n Brute-force Login Attempts Detected:")
    for ip, events in sessions.items():
        fail_count = 0
        for e in events:
            if e['endpoint'] == '/login':
                if e['status'] == '401':
                    fail_count += 1
                elif e['status'] == '200' and fail_count >= 2:
                    print(f"[!] Brute-force detected from IP: {ip} → {fail_count} failures before success")
                    break

    # Unauthorized access
    print("\n Unauthorized Access Attempts Detected:")
    for entry in parsed_logs:
        if entry['status'] in ['401', '403'] or any(path in entry['endpoint'] for path in RESTRICTED_PATHS):
            print(f"[!] {entry['ip']} tried to access {entry['endpoint']} → Status {entry['status']}")

    # Risk scoring
    print("\n Risk Scoring Summary:")
    risk_scores = {}

    for ip, entries in sessions.items():
        score = 0
        brute_force_detected = False
        failed_logins = 0

        for e in entries:
            endpoint = e['endpoint']
            status = e['status']

            if endpoint == "/login" and status == '401':
                failed_logins += 1
                score += 3

            if endpoint == "/login" and status == '200' and failed_logins >= 2 and not brute_force_detected:
                score += 10
                brute_force_detected = True

            if status in ['403', '401'] and any(p in endpoint for p in RESTRICTED_PATHS):
                score += 5

        for e in entries:
            if any(p in e['endpoint'] for p in RESTRICTED_PATHS):
                score += 7
                break

        if score <= 10:
            level = "Low"
        elif score <= 20:
            level = "Medium"
        else:
            level = "High"

        risk_scores[ip] = {"score": score, "level": level}
        print(f"[{level}] {ip} → Risk Score: {score}")

    # Export alerts
    export_alerts(risk_scores, format=args.format, threshold=args.threshold)
