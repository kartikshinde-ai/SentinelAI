from datetime import datetime, timedelta

from read_logs import log_file, read_security_logs


# Maximum allowed time between a failed login and a successful login.
TIME_WINDOW_MINUTES = 15


def calculate_risk_score(failed_attempts):
    """
    Calculate a simple heuristic risk score from failed login attempts.

    This is a project-defined score, not a validated industry-standard score.
    """
    if failed_attempts >= 10:
        return 90
    elif failed_attempts >= 5:
        return 75
    elif failed_attempts >= 3:
        return 55
    elif failed_attempts >= 2:
        return 35
    else:
        return 20


def get_severity(risk_score):
    """Map the heuristic risk score to a severity label."""
    if risk_score >= 75:
        return "High"
    elif risk_score >= 50:
        return "Medium"
    else:
        return "Low"


def detect_failed_then_success(logs):
    """
    Detect failed login attempts followed by a successful login
    within the configured time window.
    """

    # Sort records chronologically without modifying the original list.
    sorted_logs = sorted(
        logs,
        key=lambda log: datetime.fromisoformat(log["timestamp"]),
    )

    failed_logins_by_user = {}
    alerts = []
    time_window = timedelta(minutes=TIME_WINDOW_MINUTES)

    for log in sorted_logs:
        username = log.get("username", "").strip()
        event_type = log.get("event_type", "").strip().lower()
        status = log.get("status", "").strip().lower()

        if not username or event_type != "login":
            continue

        timestamp = datetime.fromisoformat(log["timestamp"])

        if status == "failure":
            failed_logins_by_user.setdefault(username, []).append(log)

        elif status == "success":
            previous_failures = failed_logins_by_user.get(username, [])

            # Keep only failures within the configured time window.
            recent_failures = [
                failure
                for failure in previous_failures
                if timedelta(0)
                <= timestamp - datetime.fromisoformat(failure["timestamp"])
                <= time_window
            ]

            if recent_failures:
                failed_attempts = len(recent_failures)
                risk_score = calculate_risk_score(failed_attempts)
                severity = get_severity(risk_score)

                alert = {
                    "username": username,
                    "failed_attempts": failed_attempts,
                    "first_failure": recent_failures[0]["timestamp"],
                    "last_failure": recent_failures[-1]["timestamp"],
                    "successful_login": log["timestamp"],
                    "source_ip": log.get("source_ip", ""),
                    "time_window_minutes": TIME_WINDOW_MINUTES,
                    "risk_score": risk_score,
                    "severity": severity,
                    "finding": (
                        f"{failed_attempts} failed login attempt(s) were "
                        f"followed by a successful login for user "
                        f"'{username}' within "
                        f"{TIME_WINDOW_MINUTES} minutes."
                    ),
                    "evidence": recent_failures + [log],
                    "assessment_note": (
                        "This alert identifies a login pattern for review. "
                        "It does not confirm that an account was compromised. "
                        "The risk score is a heuristic and requires validation."
                    ),
                }

                alerts.append(alert)

            # Clear tracked failures after a successful login.
            failed_logins_by_user[username] = []

    return alerts


def main():
    """Run detection against the sample CSV file."""

    logs = read_security_logs(log_file)
    alerts = detect_failed_then_success(logs)

    print(f"CSV file: {log_file}")
    print(f"Total log records: {len(logs)}")
    print(f"Total alerts: {len(alerts)}")

    for index, alert in enumerate(alerts, start=1):
        print(f"\nAlert #{index}")
        print(f"Username: {alert['username']}")
        print(f"Severity: {alert['severity']}")
        print(f"Risk score: {alert['risk_score']}/100")
        print(f"Finding: {alert['finding']}")
        print(f"Failed login attempts: {alert['failed_attempts']}")
        print(f"First failure: {alert['first_failure']}")
        print(f"Last failure: {alert['last_failure']}")
        print(f"Successful login: {alert['successful_login']}")
        print(f"Source IP of successful login: {alert['source_ip']}")
        print(
            f"Detection time window: "
            f"{alert['time_window_minutes']} minutes"
        )

        print("Evidence records:")

        for record in alert["evidence"]:
            print(
                f"  Time: {record.get('timestamp', '')} | "
                f"User: {record.get('username', '')} | "
                f"IP: {record.get('source_ip', '')} | "
                f"Event: {record.get('event_type', '')} | "
                f"Status: {record.get('status', '')}"
            )

        print(f"Assessment: {alert['assessment_note']}")


if __name__ == "__main__":
    main()

