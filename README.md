
# Authentication Log Analyzer

**Code:You Cybersecurity Capstone — Part I: Python Automation Track**

By Jean

---

## Overview

This tool was created to quickly analyze authentication logs and find suspicious activity. I built it because manually reading through 1,000+ log lines is basically impossible for a human, but Python can do it in under a second.

The tool reads a log file, counts events, detects repeated failed logins, flags suspicious IPs, and spots privilege escalation indicators. It prints everything to the terminal and can also export to CSV.

---

## How to Use This Tool

### Requirements

- Python 3.x (I built this on Ubuntu with Python 3.14)
- No extra packages needed — everything uses the Python standard library

### Running the Tool

1. Open a terminal in the project folder
2. Activate the virtual environment:

   ```bash
   source venv/bin/activate
   ```
3. Run the basic analysis:

   ```bash
   python3 log_analyzer.py sample_log.txt
   ```
4. Optional — export to CSV:

   ```bash
   python3 log_analyzer.py sample_log.txt --csv findings.csv
   ```
5. Optional — change the threshold (default is 5):

   ```bash
   python3 log_analyzer.py sample_log.txt --threshold 3
   ```



1. Repeated Failed Logins
   The script counts how many times each username and each IP fails to log in. If the count hits the threshold (default 5), it gets flagged. This catches brute-force attacks.
2. Suspicious IP Activity
   The script flags IPs that:
   Generate too many failed logins (volume attack)
   Try to log in as many different usernames (credential stuffing)
3. Privilege Escalation Indicators
   The script automatically flags all PRIV_CHANGE events. It also scans messages for keywords like sudo, root, admin, chmod, and chown to catch unauthorized permission changes.


## Log Source


The dataset is `sample_log.txt`, a synthetic authentication log with:

* `AUTH_SUCCESS` — normal logins
* `AUTH_FAIL` — failed password attempts
* `PRIV_CHANGE` — permission changes (sudo, admin, root)

Each line has a timestamp, event type, username, IP address, and message.

## Detection Logic

1. Repeated Failed Logins
   The script counts how many times each username and each IP fails to log in. If the count hits the threshold (default 5), it gets flagged. This catches brute-force attacks.
2. Suspicious IP Activity
   The script flags IPs that:
   Generate too many failed logins (volume attack)
   Try to log in as many different usernames (credential stuffing)
3. Privilege Escalation Indicators
   The script automatically flags all PRIV_CHANGE events. It also scans messages for keywords like sudo, root, admin, chmod, and chown to catch unauthorized permission changes.


## Files in This Project



| File                | What It Does                                                                 |
| ------------------- | ---------------------------------------------------------------------------- |
| `log_analyzer.py` | The main script you run from the terminal                                    |
| `log_parser.py`   | Reads the log file and turns lines into dictionaries                         |
| `detectors.py`    | The three detection rules (failed logins, suspicious IPs, privilege changes) |
| `sample_log.txt`  | The test dataset                                                             |
| `README.md`       | This file                                                                    |
| `report.md`       | My analyst findings and recommendations                                      |


## What I Learned



**What worked well:** Breaking the code into three files made it way easier to test. When something broke, I knew exactly which file to check.

**What was challenging:** Learning how `Counter` and `set` work in Python took some time. I also had to figure out why the parser crashed on empty lines — turns out `.strip()` was the fix.

**What I would improve:** I would add a rule for unusual login hours (like logins at 3 AM) and maybe colorize the terminal output so critical flags stand out in red.
