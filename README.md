
# File Integrity Monitor

A Python cybersecurity project that monitors files for
unauthorized changes using SHA-256 hashing.

## Features

- SHA-256 file integrity verification
- Continuous directory monitoring
- File creation detection
- File modification detection
- File deletion detection
- Security severity classification
- Security event logging
- CSV security summary reports
- Identification of frequently modified files

## Technologies

- Python 3
- hashlib
- pathlib
- collections
- csv
- datetime

## Project Files

- `file_monitor.py` - Monitors file integrity
- `security_report.py` - Analyzes security events
- `monitored_files/` - Directory used for monitoring
- `security_alerts.log` - Generated security events
- `security_summary.csv` - Generated security report

## How to Run

1. Run `file_monitor.py` to begin monitoring.
2. Add, modify, or delete files in `monitored_files/`.
3. Review the generated security alerts.
4. Run `security_report.py` to generate a security summary.

## Cybersecurity Applications

This project demonstrates file integrity monitoring,
security event detection, incident logging, and
basic security analysis.

It is designed as a cybersecurity learning and
portfolio project.
