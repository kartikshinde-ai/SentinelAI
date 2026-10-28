import sys
import unittest
import tempfile

from pathlib import Path

# Allow this test file to import modules from the src directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from detect_suspicious import (
    detect_failed_then_success,
    calculate_risk_score,
    get_severity,
    TIME_WINDOW_MINUTES,
)
from read_logs import read_security_logs


def make_log(timestamp, username="alex", status="failure",
             source_ip="192.0.2.10", event_type="login"):
    """Create a synthetic security log record for testing."""
    return {
        "timestamp": timestamp,
        "username": username,
        "source_ip": source_ip,
        "event_type": event_type,
        "status": status,
    }


class TestSuspiciousLoginDetection(unittest.TestCase):

    def test_failed_logins_followed_by_success(self):
        """An alert should be generated after failed logins and success."""
        logs = [
            make_log("2026-10-23T09:00:00"),
            make_log("2026-10-23T09:01:00"),
            make_log("2026-10-23T09:02:00", status="success"),
        ]

        alerts = detect_failed_then_success(logs)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["username"], "alex")
        self.assertEqual(alerts[0]["failed_attempts"], 2)
        self.assertEqual(len(alerts[0]["evidence"]), 3)

    def test_success_without_previous_failure(self):
        """No alert should be generated without previous failures."""
        logs = [
            make_log("2026-10-23T09:00:00", status="success")
        ]

        self.assertEqual(detect_failed_then_success(logs), [])

    def test_empty_log_list(self):
        """An empty list should produce no alerts."""
        self.assertEqual(detect_failed_then_success([]), [])

    def test_success_within_time_window(self):
        """A success within 15 minutes should generate an alert."""
        logs = [
            make_log("2026-10-23T09:00:00"),
            make_log("2026-10-23T09:14:59", status="success"),
        ]

        alerts = detect_failed_then_success(logs)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["failed_attempts"], 1)

    def test_success_exactly_at_time_window_boundary(self):
        """A success exactly 15 minutes later should generate an alert."""
        logs = [
            make_log("2026-10-23T09:00:00"),
            make_log("2026-10-23T09:15:00", status="success"),
        ]

        alerts = detect_failed_then_success(logs)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["failed_attempts"], 1)

    def test_success_outside_time_window(self):
        """A success after 15 minutes should not use the old failure."""
        logs = [
            make_log("2026-10-23T09:00:00"),
            make_log("2026-10-23T09:15:01", status="success"),
        ]

        alerts = detect_failed_then_success(logs)

        self.assertEqual(len(alerts), 0)

    def test_only_recent_failures_are_counted(self):
        """Only failures inside the time window should be counted."""
        logs = [
            make_log("2026-10-23T09:00:00"),
            make_log("2026-10-23T09:10:00"),
            make_log("2026-10-23T09:20:00", status="success"),
        ]

        alerts = detect_failed_then_success(logs)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["failed_attempts"], 1)
        self.assertEqual(
            alerts[0]["first_failure"],
            "2026-10-23T09:10:00",
        )

    def test_users_are_tracked_separately(self):
        """Failures for one user must not affect another user."""
        logs = [
            make_log("2026-10-23T09:00:00", username="alex"),
            make_log("2026-10-23T09:01:00", username="sam",
                     status="success"),
            make_log("2026-10-23T09:02:00", username="alex",
                     status="success"),
        ]

        alerts = detect_failed_then_success(logs)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["username"], "alex")

    def test_detection_does_not_modify_original_list(self):
        """Detection should not reorder the original input list."""
        first = make_log("2026-10-23T09:02:00", status="success")
        second = make_log("2026-10-23T09:00:00")
        logs = [first, second]

        detect_failed_then_success(logs)

        self.assertIs(logs[0], first)
        self.assertIs(logs[1], second)

    def test_alert_contains_risk_and_window_fields(self):
        """An alert should contain risk score and window information."""
        logs = [
            make_log("2026-10-23T09:00:00"),
            make_log("2026-10-23T09:01:00"),
            make_log("2026-10-23T09:02:00", status="success"),
        ]

        alerts = detect_failed_then_success(logs)

        self.assertEqual(alerts[0]["risk_score"], 35)
        self.assertEqual(alerts[0]["severity"], "Low")
        self.assertEqual(
            alerts[0]["time_window_minutes"],
            TIME_WINDOW_MINUTES,
        )


class TestRiskScoring(unittest.TestCase):

    def test_risk_score_thresholds(self):
        """Failed attempt counts should map to the defined scores."""
        expected_scores = {
            1: 20,
            2: 35,
            3: 55,
            4: 55,
            5: 75,
            9: 75,
            10: 90,
            15: 90,
        }

        for attempts, expected in expected_scores.items():
            with self.subTest(attempts=attempts):
                self.assertEqual(
                    calculate_risk_score(attempts),
                    expected,
                )

    def test_severity_thresholds(self):
        """Risk scores should map to the expected severity labels."""
        expected_severities = {
            0: "Low",
            35: "Low",
            49: "Low",
            50: "Medium",
            55: "Medium",
            74: "Medium",
            75: "High",
            100: "High",
        }

        for score, expected in expected_severities.items():
            with self.subTest(score=score):
                self.assertEqual(get_severity(score), expected)


class TestCSVValidation(unittest.TestCase):

    def create_csv(self, content):
        """Create a temporary CSV file for validation tests."""
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)

        csv_path = Path(temp_dir.name) / "test_logs.csv"
        csv_path.write_text(content, encoding="utf-8")

        return csv_path

    def test_csv_missing_required_column(self):
        csv_path = self.create_csv(
            "timestamp,username,source_ip,event_type\n"
            "2026-10-23T09:00:00,alex,192.0.2.10,login\n"
        )

        with self.assertRaisesRegex(ValueError, "missing required columns"):
            read_security_logs(csv_path)

    def test_csv_without_data_records(self):
        csv_path = self.create_csv(
            "timestamp,username,source_ip,event_type,status\n"
        )

        with self.assertRaisesRegex(ValueError, "no data records"):
            read_security_logs(csv_path)

    def test_csv_empty_required_value(self):
        csv_path = self.create_csv(
            "timestamp,username,source_ip,event_type,status\n"
            "2026-10-23T09:00:00,,192.0.2.10,login,failure\n"
        )

        with self.assertRaisesRegex(ValueError, "empty value"):
            read_security_logs(csv_path)

    def test_csv_invalid_timestamp(self):
        csv_path = self.create_csv(
            "timestamp,username,source_ip,event_type,status\n"
            "not-a-timestamp,alex,192.0.2.10,login,failure\n"
        )

        with self.assertRaisesRegex(ValueError, "invalid timestamp"):
            read_security_logs(csv_path)

    def test_csv_invalid_status(self):
        csv_path = self.create_csv(
            "timestamp,username,source_ip,event_type,status\n"
            "2026-10-23T09:00:00,alex,192.0.2.10,login,unknown\n"
        )

        with self.assertRaisesRegex(ValueError, "unsupported status"):
            read_security_logs(csv_path)

    def test_csv_invalid_event_type(self):
        csv_path = self.create_csv(
            "timestamp,username,source_ip,event_type,status\n"
            "2026-10-23T09:00:00,alex,192.0.2.10,logout,success\n"
        )

        with self.assertRaisesRegex(ValueError, "unsupported event_type"):
            read_security_logs(csv_path)

    def test_csv_malformed_row(self):
        csv_path = self.create_csv(
            "timestamp,username,source_ip,event_type,status\n"
            "2026-10-23T09:00:00,alex,192.0.2.10,login\n"
        )

        with self.assertRaisesRegex(ValueError, "malformed number of fields"):
            read_security_logs(csv_path)

    def test_csv_normalizes_spaces_and_case(self):
        csv_path = self.create_csv(
            " timestamp , username , source_ip , event_type , status \n"
            " 2026-10-23T09:00:00 , alex , 192.0.2.10 , LOGIN , FAILURE \n"
        )

        logs = read_security_logs(csv_path)

        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["username"], "alex")
        self.assertEqual(logs[0]["event_type"], "login")
        self.assertEqual(logs[0]["status"], "failure")


if __name__ == "__main__":
    unittest.main(verbosity=2)

