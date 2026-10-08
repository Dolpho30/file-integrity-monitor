
import csv
from collections import Counter
from pathlib import Path


# Files are located in the same folder as this script
BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "security_alerts.log"
CSV_FILE = BASE_DIR / "security_summary.csv"


def export_csv_report(severity_counts, event_counts, file_counts):
    """Export security statistics to a CSV file."""

    with CSV_FILE.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        writer.writerow(["Category", "Name", "Count"])

        writer.writerow(["Summary", "Total Events", sum(event_counts.values())])
        writer.writerow(["Summary", "Critical Alerts", severity_counts["HIGH"]])

        for severity in ("LOW", "MEDIUM", "HIGH"):
            writer.writerow([
                "Severity",
                severity,
                severity_counts[severity]
            ])

        for event_type in ("CREATED", "MODIFIED", "DELETED"):
            writer.writerow([
                "Event Type",
                event_type,
                event_counts[event_type]
            ])

        for filename, count in file_counts.most_common():
            writer.writerow([
                "Modified File",
                filename,
                count
            ])

    print(f"\nCSV report generated: {CSV_FILE.name}")


def analyze_security_logs():
    """Read security logs and generate a security summary."""

    print("=== SECURITY REPORT ANALYZER ===")

    if not LOG_FILE.exists():
        print(f"\nERROR: Log file not found: {LOG_FILE}")
        return

    severity_counts = Counter()
    event_counts = Counter()
    file_counts = Counter()

    valid_severities = {"LOW", "MEDIUM", "HIGH"}
    valid_events = {"CREATED", "MODIFIED", "DELETED"}

    with LOG_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            parts = [part.strip() for part in line.split("|")]

            # Expected format:
            # timestamp | severity | event_type | filename | details
            if len(parts) < 4:
                continue

            severity = parts[1].upper()
            event_type = parts[2].upper()
            filename = parts[3]

            # Skip older or malformed log entries
            if severity not in valid_severities:
                continue

            if event_type not in valid_events:
                continue

            severity_counts[severity] += 1
            event_counts[event_type] += 1

            if event_type == "MODIFIED":
                file_counts[filename] += 1

    total_events = sum(event_counts.values())

    print("\n=== SECURITY SUMMARY ===")
    print(f"\nTotal Events: {total_events}")

    print()
    for severity in ("LOW", "MEDIUM", "HIGH"):
        print(f"{severity}: {severity_counts[severity]}")

    print()
    for event_type in ("CREATED", "MODIFIED", "DELETED"):
        print(f"{event_type.title()}: {event_counts[event_type]}")

    print(f"\nCritical Alerts: {severity_counts['HIGH']}")

    print("\n=== MOST MODIFIED FILES ===")

    if file_counts:
        for filename, count in file_counts.most_common():
            print(f"{filename}: {count} modifications")
    else:
        print("No file modifications detected.")

    # Generate CSV report
    export_csv_report(
        severity_counts,
        event_counts,
        file_counts
    )


if __name__ == "__main__":
    analyze_security_logs()


