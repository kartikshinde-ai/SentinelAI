"""Evidence validation utilities for SentinelAI AI summaries."""

import re
from typing import Any


IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

TIMESTAMP_PATTERN = re.compile(
    r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\b"
)


def validate_ai_summary(
    summary: str,
    evidence: list[dict],
) -> dict:
    """
    Check whether IP addresses and timestamps in an AI summary
    are supported by the supplied security log evidence.

    This is a basic consistency check, not proof of factual correctness.
    """

    checked = {
        "ip_addresses": [],
        "timestamps": [],
        "usernames": [],
    }

    unsupported = {
        "ip_addresses": [],
        "timestamps": [],
        "usernames": [],
    }

    if not isinstance(summary, str) or not summary.strip():
        return {
            "valid": False,
            "error": "AI summary is empty or invalid.",
            "checked": checked,
            "unsupported": unsupported,
        }

    if not isinstance(evidence, list):
        return {
            "valid": False,
            "error": "Evidence must be a list of log records.",
            "checked": checked,
            "unsupported": unsupported,
        }

    if not all(isinstance(record, dict) for record in evidence):
        return {
            "valid": False,
            "error": "Every evidence record must be a dictionary.",
            "checked": checked,
            "unsupported": unsupported,
        }

    evidence_text = " ".join(
        str(value)
        for record in evidence
        for value in record.values()
    )

    summary_ips = sorted(set(IP_PATTERN.findall(summary)))
    evidence_ips = set(IP_PATTERN.findall(evidence_text))

    summary_timestamps = sorted(
        set(TIMESTAMP_PATTERN.findall(summary))
    )
    evidence_timestamps = set(
        TIMESTAMP_PATTERN.findall(evidence_text)
    )

    evidence_usernames = {
        str(record["username"])
        for record in evidence
        if record.get("username") is not None
    }

    summary_usernames = sorted(
        username
        for username in evidence_usernames
        if re.search(
            rf"(?<![\w.-]){re.escape(username)}(?![\w.-])",
            summary,
            flags=re.IGNORECASE,
        )
    )

    unsupported_ips = sorted(
        set(summary_ips) - evidence_ips
    )

    unsupported_timestamps = sorted(
        set(summary_timestamps) - evidence_timestamps
    )

    checked = {
        "ip_addresses": summary_ips,
        "timestamps": summary_timestamps,
        "usernames": summary_usernames,
    }

    unsupported = {
        "ip_addresses": unsupported_ips,
        "timestamps": unsupported_timestamps,
        "usernames": [],
    }

    has_unsupported = any(
        unsupported[key]
        for key in ("ip_addresses", "timestamps")
    )

    return {
        "valid": not has_unsupported,
        "error": (
            "Some IP addresses or timestamps are not present in evidence."
            if has_unsupported
            else None
        ),
        "checked": checked,
        "unsupported": unsupported,
    }

