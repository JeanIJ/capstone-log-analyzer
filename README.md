# Authentication Log Analyzer

**Code:You Cybersecurity Capstone -- Part I: Python Automation Track**
------------------------------------------------------------------

## Purpose

This Python CLI tool analyzes system authentication logs to identify suspicious activity. It was built as
---------------------------------------------------------------------------------------------------------

## What It Detects

1. **Repeated Failed Logins** -- Flags usernames or IP addresses with 5 or more failed authentication att
2. **Suspicious IP Activity** -- Flags IPs with excessive failed logins or attempts against multiple user
3. **Privilege Escalation Indicators** -- Flags `PRIV_CHANGE` events and messages containing privilege-re

---

## How to Run

1. Open a terminal in the project folder.
2. Activate the virtual environment:

```bash
source venv/bin/activate
```

3. Run the analyzer:

```bash
python3 log_analyzer.py sample_log.txt
```

4. Optional -- export findings to CSV:

```bash
python3 log_analyzer.py sample_log.txt --csv findings.csv
```

---

## Files Included

| File                | Description                                                   |
| ------------------- | ------------------------------------------------------------- |
| `log_analyzer.py` | Main CLI script -- loads logs, runs detections, prints report |
| `log_parser.py`   | Parses raw log lines into Python dictionaries                 |
| `detectors.py`    | Contains the three detection rule functions                   |
| `sample_log.txt`  | Sample dataset provided for testing                           |
| `README.md`       | Project documentation (this file)                             |
| `report.md`       | Analyst findings report                                       |
| `findings.csv`    | Optional exported results                                     |

---

## Requirements

- Python 3.x
- No external packages required (uses only the Python standard library: `argparse`, `csv`, `collections`
