"""
Evidence validation utilities for SentinelAI AI summaries.

These checks identify unsupported IP addresses, timestamps, and usernames.
They are basic consistency checks, not proof of complete factual correctness.
"""

import ipaddress
import re
from datetime import datetime
from typing import Any


IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

TIMESTAMP_PATTERN = re.compile(
    r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\b"
)


def is_valid_ipv4(value: str) -> bool:
    """Check whether a value is a valid IPv4 address."""
    try:
        return isinstance(
            ipaddress.ip_address(value),
            ipaddress.IPv4Address,
        )
    except ValueError:
        return False


def is_valid_timestamp(value: str) -> bool:
    """Check whether a timestamp has a valid date and time."""
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")
        return True
    except ValueError:
        return False


def validate_ai_summary(
    summary: str,
    evidence: list[dict[str, Any]],
) -> dict:
    """
    Check IP addresses, timestamps, and explicitly mentioned usernames
    against supplied evidence.

    This function does not verify every natural-language claim.
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

    # Extract evidence from the relevant fields only.
    evidence_ips = {
        str(record["source_ip"]).strip()
        for record in evidence
        if record.get("source_ip") is not None
    }

    evidence_timestamps = {
        str(record["timestamp"]).strip()
        for record in evidence
        if record.get("timestamp") is not None
    }

    evidence_usernames = {
        str(record["username"]).strip()
        for record in evidence
        if record.get("username") is not None
        and str(record["username"]).strip()
    }

    # Extract IP addresses mentioned in the summary.
    summary_ips = sorted(set(IP_PATTERN.findall(summary)))

    invalid_ips = {
        ip for ip in summary_ips
        if not is_valid_ipv4(ip)
    }

    unsupported_ips = {
        ip for ip in summary_ips
        if ip not in evidence_ips or ip in invalid_ips
    }

    # Extract timestamps mentioned in the summary.
    summary_timestamps = sorted(
        set(TIMESTAMP_PATTERN.findall(summary))
    )

    invalid_timestamps = {
        timestamp
        for timestamp in summary_timestamps
        if not is_valid_timestamp(timestamp)
    }

    unsupported_timestamps = {
        timestamp
        for timestamp in summary_timestamps
        if timestamp not in evidence_timestamps
        or timestamp in invalid_timestamps
    }

    # Find evidence usernames mentioned as complete words.
    summary_usernames = sorted(
        username
        for username in evidence_usernames
        if re.search(
            rf"(?<![\w.-]){re.escape(username)}(?![\w.-])",
            summary,
            flags=re.IGNORECASE,
        )
    )

    # Check usernames explicitly introduced as a user, username, or account.
    username_candidates = set(
        re.findall(
            r"""(?i)\b(?:user|username|account)\s+['"]?([a-z0-9_.-]+)""",
            summary,
        )
    )

    unsupported_usernames = {
        candidate
        for candidate in username_candidates
        if not any(
            candidate.casefold() == known.casefold()
            for known in evidence_usernames
        )
    }

    checked = {
        "ip_addresses": summary_ips,
        "timestamps": summary_timestamps,
        "usernames": summary_usernames,
    }

    unsupported = {
        "ip_addresses": sorted(unsupported_ips),
        "timestamps": sorted(unsupported_timestamps),
        "usernames": sorted(unsupported_usernames),
    }

    errors = []

    if invalid_ips:
        errors.append("One or more IP addresses have an invalid format.")

    if invalid_timestamps:
        errors.append("One or more timestamps contain an invalid date or time.")

    if unsupported_ips:
        errors.append("Some IP addresses are not present in evidence.")

    if unsupported_timestamps:
        errors.append("Some timestamps are not present in evidence.")

    if unsupported_usernames:
        errors.append("Some usernames are not present in evidence.")

    valid = not any(unsupported.values())

    return {
        "valid": valid,
        "error": " ".join(errors) if errors else None,
        "checked": checked,
        "unsupported": unsupported,
    }

