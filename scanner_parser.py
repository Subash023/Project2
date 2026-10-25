import json
import os
import sys
import requests
from prometheus_client import CollectorRegistry, Gauge, push_to_gateway # type: ignore

def main():
    report_file = 'report.json'
    gateway_url = 'localhost:9091'  # Update this with your Pushgateway host/port
    
    if not os.path.exists(report_file):
        print(f"Error: {report_file} not found.")
        sys.exit(1)
        
    with open(report_file, 'r') as f:
        data = json.load(f)
    
    critical_count = 0
    high_count = 0
    vulns_summary = []

    # Parse Trivy JSON structure safely
    if "Results" in data:
        for result in data["Results"]:
            if "Vulnerabilities" in result:
                for vuln in result["Vulnerabilities"]:
                    severity = vuln.get("Severity", "").upper()
                    if severity == "CRITICAL":
                        critical_count += 1
                    elif severity == "HIGH":
                        high_count += 1

    print(f"Scan Results - Critical: {critical_count}, High: {high_count}")

    # --- Prometheus Setup ---
    registry = CollectorRegistry()
    
    # Define Gauges (ideal for point-in-time metrics like scan results)
    gauge_critical = Gauge(
        'vulnerability_critical_total', 
        'Total number of critical vulnerabilities found', 
        ['image_name'], 
        registry=registry
    )
    gauge_high = Gauge(
        'vulnerability_high_total', 
        'Total number of high vulnerabilities found', 
        ['image_name'], 
        registry=registry
    )
    
    # Extract image name from report or use fallback for labelling
    image_name = data.get("ArtifactName", "unknown_image")
    
    # Set the values
    gauge_critical.labels(image_name=image_name).set(critical_count)
    gauge_high.labels(image_name=image_name).set(high_count)
    
    # Push to gateway under a specific grouping job identifier
    try:
        push_to_gateway(gateway_url='https://derby-earthen-subwoofer.ngrok-free.dev/query', job='trivy_security_scan', registry=registry)
        print("Successfully pushed metrics to Prometheus Pushgateway.")
    except Exception as e:
        print(f"Failed to push metrics: {e}")

    # Retain the exit code logic from your pipeline if desired
    if critical_count > 0 or high_count > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()