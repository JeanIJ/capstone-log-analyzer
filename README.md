Authentication Log Analyzer

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
- No extra packages needed. Everything uses the Python standard library

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
4. Optional: export to CSV

   ```bash
   python3 log_analyzer.py sample_log.txt --csv findings.csv
   ```
5. Optional: change the threshold (default is 5)

   ```bash
   python3 log_analyzer.py sample_log.txt --threshold 3
   ```

## Log Source

The dataset is `sample_log.txt`, a synthetic authentication log with:

* `AUTH_SUCCESS` — normal logins
* `AUTH_FAIL` — failed password attempts
* `PRIV_CHANGE` — permission changes (sudo, admin, root)

Each line has a timestamp, event type, username, IP address, and message.

## Detection Logic

The tool runs five rules. Each flag is tagged with a MITRE ATT&CK technique ID, the same IDs real SOC alerts use:

1. **Repeated failed logins (T1110, MEDIUM):** counts failed logins per username. One account hitting the threshold (default 5) gets flagged as possible brute force.
2. **Suspicious IP activity (T1110 / T1110.004, MEDIUM–HIGH):** one flag per IP combining two checks: lots of failures from the same address (volume attack), and one address trying many different usernames (credential stuffing).
3. **Privilege events, tiered (LOW to HIGH):** every PRIV_CHANGE event gets flagged, with severity based on what happened. Sudo grants and admin-group adds are HIGH, root logins MEDIUM, failed chmod/chown attempts LOW. A keyword scan also catches privilege hints in other event types.
4. **Brute force followed by a success (T1078, CRITICAL):** if an account racks up 5+ failed logins and then a login succeeds, the attacker may have guessed the password. This is the only CRITICAL rule, and it's what caught jdoe.
5. **Odd-hour activity (T1078, MEDIUM):** logins or privilege changes between 00:00 and 05:00, but only for users/IPs already flagged by another rule, so normal night-shift activity doesn't set off alarms.

Every flag records the first and last timestamp of the evidence, and all flags print sorted by severity so the worst alerts are at the top.

## Files in This Project

| File                | What It Does                                                                                                    |
| ------------------- | --------------------------------------------------------------------------------------------------------------- |
| `log_analyzer.py` | The main script you run from the terminal                                                                       |
| `log_parser.py`   | Reads the log file and turns lines into dictionaries                                                            |
| `detectors.py`    | The five detection rules (failed logins, suspicious IPs, privilege events, brute-force-then-success, odd hours) |
| `sample_log.txt`  | The test dataset                                                                                                |
| `findings.csv`    | The 108 flagged events exported by the tool                                                                     |
| `screenshots/`    | Annotated screenshots of the tool in action                                                                     |
| `README.md`       | This file                                                                                                       |
| `report.md`       | My analyst findings and recommendations                                                                         |

## AI Usage

AI tools were used while building this project, as the Code:You AI policy allows. How I used them:

- Generating and iterating on code for the parser, the detection rules, and the CLI
- Reviewing the detection rules for false positives

## What I Learned

**What worked well:** Breaking the code into three files made it way easier to test. When something broke, I knew exactly which file to check.

**What was challenging:** Learning how `Counter` and `set` work in Python took some time. I also had to figure out why the parser crashed on empty lines. Turns out `.strip()` was the fix.

**What I would improve:** Support for real Linux auth.log files, geolocation on IP addresses to automatically label internal vs. external sources, and a time-window check so only rapid bursts of failures count as brute force (right now 5 failures spread over a whole week would still trigger).
