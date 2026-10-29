"""Tests for SentinelAI evidence validation."""

import unittest

from src.validate_ai_summary import validate_ai_summary


class TestValidateAISummary(unittest.TestCase):

    def setUp(self):
        self.evidence = [
            {
                "timestamp": "2026-10-23T09:00:00",
                "username": "alex",
                "source_ip": "192.0.2.10",
                "event_type": "login",
                "status": "failure",
            },
            {
                "timestamp": "2026-10-23T09:03:00",
                "username": "alex",
                "source_ip": "192.0.2.10",
                "event_type": "login",
                "status": "success",
            },
        ]

    def test_supported_ip_and_timestamp(self):
        summary = (
            "User alex logged in from 192.0.2.10 "
            "at 2026-10-23T09:03:00."
        )

        result = validate_ai_summary(summary, self.evidence)

        self.assertTrue(result["valid"])
        self.assertEqual(result["unsupported"]["ip_addresses"], [])
        self.assertEqual(result["unsupported"]["timestamps"], [])
        self.assertEqual(result["unsupported"]["usernames"], [])

    def test_unsupported_ip(self):
        summary = "The login came from 203.0.113.99."

        result = validate_ai_summary(summary, self.evidence)

        self.assertFalse(result["valid"])
        self.assertIn(
            "203.0.113.99",
            result["unsupported"]["ip_addresses"],
        )

    def test_invalid_ip_format(self):
        summary = "The login came from 999.999.999.999."

        result = validate_ai_summary(summary, self.evidence)

        self.assertFalse(result["valid"])
        self.assertIn(
            "999.999.999.999",
            result["unsupported"]["ip_addresses"],
        )
        self.assertIsNotNone(result["error"])

    def test_unsupported_timestamp(self):
        summary = "The event happened at 2026-10-23T10:30:00."

        result = validate_ai_summary(summary, self.evidence)

        self.assertFalse(result["valid"])
        self.assertIn(
            "2026-10-23T10:30:00",
            result["unsupported"]["timestamps"],
        )

    def test_invalid_timestamp_date(self):
        summary = "The event happened at 2026-13-40T25:61:61."

        result = validate_ai_summary(summary, self.evidence)

        self.assertFalse(result["valid"])
        self.assertIsNotNone(result["error"])

    def test_unsupported_username(self):
        summary = (
            "User kartik logged in from 192.0.2.10 "
            "at 2026-10-23T09:03:00."
        )

        result = validate_ai_summary(summary, self.evidence)

        self.assertFalse(result["valid"])
        self.assertIn(
            "kartik",
            result["unsupported"]["usernames"],
        )

    def test_username_matching_is_case_insensitive(self):
        summary = "User ALEX logged in from 192.0.2.10."

        result = validate_ai_summary(summary, self.evidence)

        self.assertTrue(result["valid"])
        self.assertEqual(result["unsupported"]["usernames"], [])

    def test_empty_summary(self):
        result = validate_ai_summary("", self.evidence)

        self.assertFalse(result["valid"])
        self.assertIsNotNone(result["error"])

    def test_whitespace_summary(self):
        result = validate_ai_summary("   ", self.evidence)

        self.assertFalse(result["valid"])
        self.assertIsNotNone(result["error"])

    def test_empty_evidence(self):
        summary = (
            "User alex logged in from 203.0.113.99 "
            "at 2026-10-23T10:30:00."
        )

        result = validate_ai_summary(summary, [])

        self.assertFalse(result["valid"])
        self.assertIn(
            "203.0.113.99",
            result["unsupported"]["ip_addresses"],
        )
        self.assertIn(
            "alex",
            result["unsupported"]["usernames"],
        )

    def test_invalid_evidence_type(self):
        result = validate_ai_summary("A summary", None)

        self.assertFalse(result["valid"])
        self.assertIsNotNone(result["error"])

    def test_invalid_evidence_record(self):
        result = validate_ai_summary("A summary", ["not a dictionary"])

        self.assertFalse(result["valid"])
        self.assertIsNotNone(result["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

