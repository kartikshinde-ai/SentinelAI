import unittest

from claim_validation import (
    count_failed_logins,
    extract_failed_login_claims,
    validate_failed_login_count,
)


class TestClaimValidation(unittest.TestCase):

    def setUp(self):
        self.evidence = [
            {"event_type": "login", "status": "failure", "username": "alex"},
            {"event_type": "login", "status": "failure", "username": "alex"},
            {"event_type": "login", "status": "success", "username": "alex"},
        ]

    def test_count_failed_logins(self):
        self.assertEqual(count_failed_logins(self.evidence), 2)

    def test_count_is_case_insensitive(self):
        evidence = [
            {"event_type": "LOGIN", "status": "FAILURE"},
            {"event_type": "login", "status": "failed"},
            {"event_type": "login", "status": "success"},
        ]
        self.assertEqual(count_failed_logins(evidence), 2)

    def test_extract_failed_login_claim(self):
        self.assertEqual(
            extract_failed_login_claims("The logs show 5 failed login attempts."),
            [5],
        )

    def test_extract_word_based_count(self):
        self.assertEqual(
            extract_failed_login_claims("The logs show three failed login attempts."),
            [3],
        )

    def test_extract_word_based_mismatch(self):
        result = validate_failed_login_count(
            "The logs show five failed login attempts.",
            self.evidence,
        )
        self.assertTrue(result["checked"])
        self.assertFalse(result["valid"])
        self.assertEqual(result["expected_count"], 2)
        self.assertEqual(result["reported_counts"], [5])

    def test_correct_count_passes(self):
        result = validate_failed_login_count(
            "The logs show two failed login attempts.",
            self.evidence,
        )
        self.assertTrue(result["valid"])
        self.assertEqual(result["expected_count"], 2)
        self.assertEqual(result["reported_counts"], [2])
        self.assertEqual(result["mismatches"], [])

    def test_incorrect_count_is_detected(self):
        result = validate_failed_login_count(
            "The logs show 5 failed login attempts.",
            self.evidence,
        )
        self.assertFalse(result["valid"])
        self.assertEqual(result["expected_count"], 2)
        self.assertEqual(
            result["mismatches"],
            [{"reported_count": 5, "expected_count": 2}],
        )

    def test_dashboard_validation_detects_wrong_failed_login_count(self):
        result = validate_failed_login_count(
            "The logs show 5 failed login attempts.",
            self.evidence,
        )
        self.assertTrue(result["checked"])
        self.assertFalse(result["valid"])
        self.assertEqual(result["expected_count"], 2)
        self.assertEqual(result["reported_counts"], [5])
        self.assertEqual(
            result["mismatches"],
            [{"reported_count": 5, "expected_count": 2}],
        )

    def test_no_count_claim_is_reported_as_unchecked(self):
        result = validate_failed_login_count(
            "The login activity looks suspicious.",
            self.evidence,
        )
        self.assertIsNone(result["valid"])
        self.assertFalse(result["checked"])

    def test_empty_evidence(self):
        result = validate_failed_login_count(
            "The logs show zero failed login attempts.",
            [],
        )
        self.assertTrue(result["valid"])
        self.assertEqual(result["expected_count"], 0)

    def test_invalid_summary_type(self):
        result = validate_failed_login_count(None, self.evidence)
        self.assertFalse(result["valid"])
        self.assertIn("Summary", result["error"])

    def test_invalid_evidence_type(self):
        result = validate_failed_login_count(
            "The logs show 2 failed login attempts.",
            "not a list",
        )
        self.assertFalse(result["valid"])
        self.assertIn("Evidence", result["error"])

    def test_ignores_non_login_events(self):
        evidence = [
            {"event_type": "login", "status": "failure"},
            {"event_type": "file_access", "status": "failure"},
        ]
        self.assertEqual(count_failed_logins(evidence), 1)


if __name__ == "__main__":
    unittest.main()

