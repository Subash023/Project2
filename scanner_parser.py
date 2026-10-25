import json
import sys
import requests

def analyze_report(json_file):
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    critical_count = 0
    high_count = 0
    vulns_summary = []

    # Parse vulnerabilities
    for result in data.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            severity = vuln.get('Severity')
            if severity == 'CRITICAL':
                critical_count += 1
            elif severity == 'HIGH':
                high_count += 1
                
    print(f"Scan Results - Critical: {critical_count}, High: {high_count}")
    
    # Send Slack Alert if issues are found
    if critical_count > 0 or high_count > 5:
        send_slack_alert(critical_count, high_count)
        # Exit with error code to fail the CI/CD pipeline
        sys.exit(1) 
    
    sys.exit(0)

def send_slack_alert(critical, high):
    webhook_url = "https://slack.com"
    payload = {
        "text": f"🚨 *Security Vulnerability Alert!* 🚨\n"
                f"A container image failed the security scan.\n"
                f"🔴 *Critical:* {critical}\n"
                f"🟠 *High:* {high}\n"
                f"Please check the CI/CD logs immediately."
    }
    requests.post(webhook_url, json=payload)

if __name__ == "__main__":
    analyze_report('report.json')
