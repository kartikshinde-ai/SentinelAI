import re
from typing import Any


# Supports numeric counts and common English number words.
NUMBER_WORDS = {
    "zero": 0,
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
    "eleven": 11,
    "twelve": 12,
    "thirteen": 13,
    "fourteen": 14,
    "fifteen": 15,
    "sixteen": 16,
    "seventeen": 17,
    "eighteen": 18,
    "nineteen": 19,
    "twenty": 20,
}

NUMBER_PATTERN = (
    r"\d+|" + "|".join(NUMBER_WORDS.keys())
)

FAILED_LOGIN_COUNT_PATTERN = re.compile(
    rf"\b({NUMBER_PATTERN})\s+"
    r"(?:failed\s+)?login\s+(?:attempts?|failures?)\b"
    rf"|\b({NUMBER_PATTERN})\s+failed\s+logins?\b",
    re.IGNORECASE,
)


def parse_count(value: str) -> int:
    """Convert a numeric string or supported number word into an integer."""
    value = value.strip().lower()

    if value.isdigit():
        return int(value)

    return NUMBER_WORDS[value]


def count_failed_logins(evidence: list[dict[str, Any]]) -> int:
    """Count login events whose status indicates failure."""
    count = 0

    for record in evidence:
        if not isinstance(record, dict):
            continue

        event_type = str(record.get("event_type", "")).strip().lower()
        status = str(record.get("status", "")).strip().lower()

        if event_type == "login" and status in {"failure", "failed"}:
            count += 1

    return count


def extract_failed_login_claims(summary: str) -> list[int]:
    """Extract numeric or supported word-based failed-login counts."""
    if not isinstance(summary, str):
        return []

    counts = []

    for match in FAILED_LOGIN_COUNT_PATTERN.finditer(summary):
        value = match.group(1) or match.group(2)

        if value is not None:
            counts.append(parse_count(value))

    return counts


def validate_failed_login_count(
    summary: str,
    evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compare failed-login counts in a summary against log evidence."""
    if not isinstance(summary, str):
        return {
            "valid": False,
            "checked": False,
            "error": "Summary must be a string.",
            "expected_count": None,
            "reported_counts": [],
            "mismatches": [],
        }

    if not isinstance(evidence, list):
        return {
            "valid": False,
            "checked": False,
            "error": "Evidence must be a list.",
            "expected_count": None,
            "reported_counts": [],
            "mismatches": [],
        }

    expected_count = count_failed_logins(evidence)
    reported_counts = extract_failed_login_claims(summary)

    if not reported_counts:
        return {
            "valid": None,
            "checked": False,
            "error": None,
            "message": (
                "No supported failed-login count claim was found."
            ),
            "expected_count": expected_count,
            "reported_counts": [],
            "mismatches": [],
        }

    mismatches = [
        {
            "reported_count": reported_count,
            "expected_count": expected_count,
        }
        for reported_count in reported_counts
        if reported_count != expected_count
    ]

    return {
        "valid": len(mismatches) == 0,
        "checked": True,
        "error": None,
        "expected_count": expected_count,
        "reported_counts": reported_counts,
        "mismatches": mismatches,
    }

