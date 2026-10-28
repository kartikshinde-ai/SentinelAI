import json
from pathlib import Path

from read_logs import log_file, read_security_logs
from detect_suspicious import detect_failed_then_success


# Find the main SentinelAI project folder
project_root = Path(__file__).resolve().parent.parent

# Define where the JSON report will be saved
report_file = project_root / "reports" / "alerts_report.json"


def create_alert_report(logs):
    """Detect suspicious login patterns and return an analyst-friendly report."""

    # Run the existing detection function
    alerts = detect_failed_then_success(logs)

    # Add analyst-focused context to each detected alert
    enriched_alerts = []

    for alert in alerts:
        failed_attempts = alert["failed_attempts"]

        # Assign a simple severity label based on the number of failures.
        # This is a demo rule, not a definitive risk assessment.
        if failed_attempts >= 5:
            severity = "High"
        elif failed_attempts >= 3:
            severity = "Medium"
        else:
            severity = "Low"

        enriched_alert = {
            **alert,
            "severity": severity,
            "finding": (
                f"{failed_attempts} failed login attempt(s) were followed "
                f"by a successful login for user '{alert['username']}'."
            ),
            "investigation_steps": [
                "Verify whether the successful login was expected by the user.",
                "Review the source IP address and login time.",
                "Check whether other accounts had similar failed login activity.",
                "Confirm the finding with additional authorized log sources."
            ],
            "assessment_note": (
                "This alert identifies a pattern for review. "
                "It does not confirm that an account was compromised."
            ),
        }

        enriched_alerts.append(enriched_alert)

    # Build the final report
    report = {
        "report_title": "SentinelAI Security Alert Report",
        "total_log_records": len(logs),
        "total_alerts": len(enriched_alerts),
        "alerts": enriched_alerts,
    }

    return report

    return report


def save_report(report, file_path: Path):
    """Save the report dictionary as a readable JSON file."""

    # Create the reports folder if it does not already exist
    file_path.parent.mkdir(parents=True, exist_ok=True)

    # Write the report to a JSON file
    with file_path.open(mode="w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)


def main():
    # Read security events from the sample CSV
    logs = read_security_logs(log_file)

    # Create a report from the logs
    report = create_alert_report(logs)

    # Save the report to disk
    save_report(report, report_file)

    # Display a short confirmation in the terminal
    print(f"Input CSV: {log_file}")
    print(f"Total log records: {report['total_log_records']}")
    print(f"Total alerts: {report['total_alerts']}")
    print(f"JSON report saved to: {report_file}")


if __name__ == "__main__":
    main()