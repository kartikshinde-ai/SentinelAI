from pathlib import Path
import csv

# Project root folder शोधतो
project_root = Path(__file__).resolve().parent.parent

# CSV file चा path तयार करतो
log_file = project_root / "data" / "sample_security_logs.csv"

# CSV मधील rows वाचतो
with log_file.open(mode="r", encoding="utf-8", newline="") as file:
    reader = csv.DictReader(file)

    for row in reader:
        print(row)