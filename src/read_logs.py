from pathlib import Path
from datetime import datetime
import csv


# Find the main SentinelAI project folder.
project_root = Path(__file__).resolve().parent.parent

# Define the path to the sample security log file.
log_file = project_root / "data" / "sample_security_logs.csv"

# Define the required CSV columns.
REQUIRED_COLUMNS = {
    "timestamp",
    "username",
    "source_ip",
    "event_type",
    "status",
}

# Define the supported event types and login statuses for V1.
ALLOWED_EVENT_TYPES = {"login"}
ALLOWED_STATUSES = {"success", "failure"}


def _validate_logs(reader):
    """Validate CSV headers and records, then return normalized logs."""

    if not reader.fieldnames:
        raise ValueError(
            "The CSV file is empty or has no header row."
        )

    # Normalize column names.
    reader.fieldnames = [
        column.strip() if column else ""
        for column in reader.fieldnames
    ]

    # Check required columns.
    actual_columns = set(reader.fieldnames)
    missing_columns = REQUIRED_COLUMNS - actual_columns

    if missing_columns:
        raise ValueError(
            f"CSV is missing required columns: "
            f"{sorted(missing_columns)}"
        )

    # Read all records.
    logs = list(reader)

    if not logs:
        raise ValueError(
            "The CSV file contains a header but no data records."
        )

    # Validate each record.
    for row_number, log in enumerate(logs, start=2):

        # Reject rows with missing or extra fields.
        if None in log or any(
            value is None for value in log.values()
        ):
            raise ValueError(
                f"CSV row {row_number} has a malformed number of fields."
            )

        # Normalize values.
        for column in log:
            log[column] = log[column].strip()

        # Check required values.
        for column in REQUIRED_COLUMNS:
            if not log[column]:
                raise ValueError(
                    f"CSV row {row_number} has an empty value "
                    f"in column '{column}'."
                )

        # Validate timestamp.
        try:
            datetime.fromisoformat(log["timestamp"])
        except ValueError as error:
            raise ValueError(
                f"CSV row {row_number} has an invalid timestamp: "
                f"{log['timestamp']!r}. "
                "Use ISO 8601 format, for example "
                "'2026-10-23T09:00:00'."
            ) from error

        # Normalize event type and status.
        event_type = log["event_type"].lower()
        status = log["status"].lower()

        # Validate event type.
        if event_type not in ALLOWED_EVENT_TYPES:
            raise ValueError(
                f"CSV row {row_number} has an unsupported event_type: "
                f"{log['event_type']!r}. "
                f"Allowed values: {sorted(ALLOWED_EVENT_TYPES)}"
            )

        # Validate login status.
        if status not in ALLOWED_STATUSES:
            raise ValueError(
                f"CSV row {row_number} has an unsupported status: "
                f"{log['status']!r}. "
                f"Allowed values: {sorted(ALLOWED_STATUSES)}"
            )

        # Save normalized values.
        log["event_type"] = event_type
        log["status"] = status

    return logs


def read_security_logs(file_path: Path):
    """Read and validate security logs from a CSV file path."""

    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"Log file not found: {file_path}"
        )

    if not file_path.is_file():
        raise ValueError(
            f"The provided path is not a file: {file_path}"
        )

    with file_path.open(
        mode="r",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        reader = csv.DictReader(file)
        return _validate_logs(reader)


def read_security_logs_from_stream(stream):
    """Validate security logs from an uploaded text stream."""

    reader = csv.DictReader(stream)
    return _validate_logs(reader)


# Run this demonstration only when the file is executed directly.
if __name__ == "__main__":
    logs = read_security_logs(log_file)

    print(f"CSV file: {log_file}")
    print(f"Total log records: {len(logs)}")

    print("\nFirst record:")
    print(logs[0])

