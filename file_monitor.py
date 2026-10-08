import hashlib
import os
import time
from datetime import datetime


MONITORED_FOLDER = "monitored_files"
LOG_FILE = "security_alerts.log"
CHECK_INTERVAL = 5

# Files considered especially important
CRITICAL_FILES = {
    "config.txt",
    "important_file.txt"
}


def calculate_hash(file_path):
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            while True:
                chunk = file.read(4096)

                if not chunk:
                    break

                sha256.update(chunk)

        return sha256.hexdigest()

    except (FileNotFoundError, PermissionError):
        return None


def get_file_hashes(folder):
    file_hashes = {}

    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)

        if os.path.isfile(file_path):
            file_hash = calculate_hash(file_path)

            if file_hash is not None:
                file_hashes[filename] = file_hash

    return file_hashes


def get_severity(event_type, filename):
    # Deleting a monitored file is always HIGH
    if event_type == "DELETED":
        return "HIGH"

    # Modification of a critical file is HIGH
    if event_type == "MODIFIED" and filename in CRITICAL_FILES:
        return "HIGH"

    # Normal file modification is MEDIUM
    if event_type == "MODIFIED":
        return "MEDIUM"

    # New files are LOW
    if event_type == "CREATED":
        return "LOW"

    return "UNKNOWN"


def log_security_event(event_type, filename, details=""):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    severity = get_severity(event_type, filename)

    log_entry = (
        f"{timestamp} | {severity} | "
        f"{event_type} | {filename}"
    )

    if details:
        log_entry += f" | {details}"

    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        log_file.write(log_entry + "\n")


def display_alert(event_type, filename, details=None):
    severity = get_severity(event_type, filename)

    print("\n=== SECURITY ALERT ===")
    print(f"Severity: {severity}")
    print(f"Event: {event_type}")
    print(f"File: {filename}")

    if filename in CRITICAL_FILES:
        print("Critical File: YES")
    else:
        print("Critical File: NO")

    if details:
        for detail in details:
            print(detail)


def main():
    print("=== FILE INTEGRITY MONITOR ===")
    print(f"Monitoring folder: {MONITORED_FOLDER}")
    print(f"Check interval: {CHECK_INTERVAL} seconds")
    print(f"Security log: {LOG_FILE}")

    print("\nCritical files:")
    for filename in sorted(CRITICAL_FILES):
        print(f"  - {filename}")

    print("\nPress CTRL+C to stop.\n")

    if not os.path.exists(MONITORED_FOLDER):
        os.makedirs(MONITORED_FOLDER)
        print(f"Created monitoring folder: {MONITORED_FOLDER}")

    baseline = get_file_hashes(MONITORED_FOLDER)

    print(f"Baseline created for {len(baseline)} file(s).")
    print("Monitoring started...\n")

    try:
        while True:
            time.sleep(CHECK_INTERVAL)

            current_state = get_file_hashes(MONITORED_FOLDER)

            # Detect modified files
            for filename in baseline:
                if filename in current_state:
                    if baseline[filename] != current_state[filename]:

                        old_hash = baseline[filename]
                        new_hash = current_state[filename]

                        display_alert(
                            "MODIFIED",
                            filename,
                            [
                                f"Old SHA-256: {old_hash}",
                                f"New SHA-256: {new_hash}"
                            ]
                        )

                        log_security_event(
                            "MODIFIED",
                            filename,
                            f"Old SHA-256: {old_hash} | "
                            f"New SHA-256: {new_hash}"
                        )

            # Detect deleted files
            for filename in baseline:
                if filename not in current_state:

                    display_alert(
                        "DELETED",
                        filename,
                        [
                            f"Previous SHA-256: "
                            f"{baseline[filename]}"
                        ]
                    )

                    log_security_event(
                        "DELETED",
                        filename,
                        f"Previous SHA-256: "
                        f"{baseline[filename]}"
                    )

            # Detect newly created files
            for filename in current_state:
                if filename not in baseline:

                    display_alert(
                        "CREATED",
                        filename,
                        [
                            f"SHA-256: "
                            f"{current_state[filename]}"
                        ]
                    )

                    log_security_event(
                        "CREATED",
                        filename,
                        f"SHA-256: "
                        f"{current_state[filename]}"
                    )

            # Update baseline
            baseline = current_state

    except KeyboardInterrupt:
        print("\n\nFile Integrity Monitor stopped.")


if __name__ == "__main__":
    main()