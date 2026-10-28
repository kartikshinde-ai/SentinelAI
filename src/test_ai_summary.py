"""Unit tests for SentinelAI AI investigation summaries."""

import unittest
from unittest.mock import Mock, patch

import requests

from src.ai_summary import (
    generate_investigation_summary,
    generate_cached_investigation_summary,
)


class TestAISummary(unittest.TestCase):
    def setUp(self):
        self.alert = {
            "username": "sam",
            "severity": "Low",
            "risk_score": 35,
            "finding": (
                "2 failed login attempts followed by "
                "a successful login within 3 minutes."
            ),
            "evidence": [
                {
                    "timestamp": "2026-10-27T09:05:00",
                    "username": "sam",
                    "source_ip": "192.0.2.20",
                    "event_type": "login",
                    "status": "failure",
                },
                {
                    "timestamp": "2026-10-27T09:08:00",
                    "username": "sam",
                    "source_ip": "192.0.2.20",
                    "event_type": "login",
                    "status": "success",
                },
            ],
            "investigation_steps": [
                "Verify whether the successful login was expected."
            ],
        }

    @patch("src.ai_summary.requests.post")
    def test_successful_ai_summary(self, mock_post):
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "message": {
                "content": "Summary\nTest summary"
            }
        }
        mock_post.return_value = mock_response

        result = generate_investigation_summary(self.alert)

        self.assertTrue(result["success"])
        self.assertEqual(result["summary"], "Summary\nTest summary")
        self.assertIsNone(result["error"])

    @patch("src.ai_summary.requests.post")
    def test_empty_ai_response(self, mock_post):
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "message": {"content": ""}
        }
        mock_post.return_value = mock_response

        result = generate_investigation_summary(self.alert)

        self.assertFalse(result["success"])
        self.assertEqual(result["summary"], "")
        self.assertIn("empty response", result["error"])

    @patch("src.ai_summary.requests.post")
    def test_ollama_connection_error(self, mock_post):
        mock_post.side_effect = requests.exceptions.ConnectionError(
            "Ollama unavailable"
        )

        result = generate_investigation_summary(self.alert)

        self.assertFalse(result["success"])
        self.assertEqual(result["summary"], "")
        self.assertIn("Could not connect to Ollama", result["error"])

    @patch("src.ai_summary.requests.post")
    def test_ollama_timeout(self, mock_post):
        mock_post.side_effect = requests.exceptions.Timeout(
            "Request timed out"
        )

        result = generate_investigation_summary(self.alert)

        self.assertFalse(result["success"])
        self.assertEqual(result["summary"], "")
        self.assertIn("too long to respond", result["error"])


class TestCachedAISummary(unittest.TestCase):
    def setUp(self):
        self.alert = {
            "username": "sam",
            "severity": "Low",
            "risk_score": 35,
            "finding": "Two failures followed by a successful login.",
            "evidence": [
                {
                    "timestamp": "2026-10-27T09:05:00",
                    "username": "sam",
                    "source_ip": "192.0.2.20",
                    "event_type": "login",
                    "status": "failure",
                }
            ],
            "investigation_steps": [],
        }

        self.fake_session_state = {}

    def run_with_fake_session(self, function):
        with patch(
            "src.ai_summary.st.session_state",
            self.fake_session_state,
        ):
            return function()

    @patch("src.ai_summary.generate_investigation_summary")
    def test_same_alert_uses_cached_result(self, mock_generate):
        mock_generate.return_value = {
            "success": True,
            "summary": "Test summary",
            "error": None,
        }

        def run_test():
            first = generate_cached_investigation_summary(self.alert)
            second = generate_cached_investigation_summary(self.alert)
            return first, second

        first, second = self.run_with_fake_session(run_test)

        self.assertEqual(first, second)
        self.assertEqual(first["summary"], "Test summary")
        mock_generate.assert_called_once_with(self.alert)

    @patch("src.ai_summary.generate_investigation_summary")
    def test_changed_alert_has_separate_cache_entry(self, mock_generate):
        mock_generate.side_effect = [
            {
                "success": True,
                "summary": "First summary",
                "error": None,
            },
            {
                "success": True,
                "summary": "Updated summary",
                "error": None,
            },
        ]

        changed_alert = {
            **self.alert,
            "risk_score": 60,
        }

        def run_test():
            first = generate_cached_investigation_summary(self.alert)
            second = generate_cached_investigation_summary(
                changed_alert
            )
            return first, second

        first, second = self.run_with_fake_session(run_test)

        self.assertEqual(first["summary"], "First summary")
        self.assertEqual(second["summary"], "Updated summary")
        self.assertEqual(mock_generate.call_count, 2)

    @patch("src.ai_summary.generate_investigation_summary")
    def test_failed_summary_is_not_cached(self, mock_generate):
        mock_generate.side_effect = [
            {
                "success": False,
                "summary": "",
                "error": "Ollama unavailable",
            },
            {
                "success": True,
                "summary": "Recovered summary",
                "error": None,
            },
        ]

        def run_test():
            first = generate_cached_investigation_summary(self.alert)
            second = generate_cached_investigation_summary(self.alert)
            return first, second

        first, second = self.run_with_fake_session(run_test)

        self.assertFalse(first["success"])
        self.assertTrue(second["success"])
        self.assertEqual(second["summary"], "Recovered summary")
        self.assertEqual(mock_generate.call_count, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)