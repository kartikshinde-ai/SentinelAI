import json
from pathlib import Path


# Locate the SentinelAI project directory
project_root = Path(__file__).resolve().parent.parent

# Input JSON report and output text report paths
json_report_file = project_root / "reports" / "alerts_report.json"
text_report_file = project_root / "reports" / "alerts_report.txt"


def format_report(report):
    """Convert the JSON alert report into a readable text report."""

    lines = [
        report.get("report_title", "SentinelAI Alert Report"),
        "=" * 60,
        f"Total log records: {report.get('total_log_records', 0)}",
        f"Total alerts: {report.get('total_alerts', 0)}",
        "",
    ]

    for number, alert in enumerate(report.get("alerts", []), start=1):
        lines.extend([
            f"ALERT #{number}",
            "-" * 60,
            f"Username: {alert.get('username', 'Unknown')}",
            f"Severity: {alert.get('severity', 'Unassigned')}",
            f"Finding: {alert.get('finding', 'No finding provided')}",
            f"Failed attempts: {alert.get('failed_attempts', 0)}",
            f"First failure: {alert.get('first_failure', 'N/A')}",
            f"Last failure: {alert.get('last_failure', 'N/A')}",
            f"Successful login: {alert.get('successful_login', 'N/A')}",
            f"Successful login source IP: {alert.get('source_ip', 'N/A')}",
            "",
            "Investigation steps:",
        ])

        for step_number, step in enumerate(
            alert.get("investigation_steps", []), start=1
        ):
            lines.append(f"  {step_number}. {step}")

        lines.extend([
            "",
            "Assessment note:",
            f"  {alert.get('assessment_note', 'No assessment note provided')}",
            "",
            "Evidence:",
        ])

        for record in alert.get("evidence", []):
            lines.append(
                "  "
                f"Time: {record.get('timestamp', '')} | "
                f"User: {record.get('username', '')} | "
                f"IP: {record.get('source_ip', '')} | "
                f"Event: {record.get('event_type', '')} | "
                f"Status: {record.get('status', '')}"
            )

        lines.append("")

    return "\n".join(lines)


def main():
    # Read the previously generated JSON report
    with json_report_file.open("r", encoding="utf-8") as file:
        report = json.load(file)

    # Convert it to readable text
    text_report = format_report(report)

    # Save the text report
    text_report_file.parent.mkdir(parents=True, exist_ok=True)
    text_report_file.write_text(text_report, encoding="utf-8")

    print(f"Text report saved to: {text_report_file}")


if __name__ == "__main__":
    main()