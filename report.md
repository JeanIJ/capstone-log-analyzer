Log Analyzer — Analyst Report
Code:You Cybersecurity Capstone — Part I: Python Automation Track
Analyst: Jean

1. Overview
   This report documents the findings of a Python-based log analysis tool built
   for a simulated SOC investigation. The organization experienced suspicious
   account activity, and leadership asked the security team to review
   authentication and system logs for signs of malicious behavior. The tool
   (log_analyzer.py) parses an authentication log, applies five detection
   rules, and produces a severity-sorted alert list with supporting evidence —
   the same output a Tier 1 SOC analyst would use to start triage.
2. Log Source
   The dataset is sample_log.txt, a synthetic authentication log covering
   March 10–18, 2026. Each line is tab-separated and contains a timestamp,
   event type, username, source IP, and message. Three event types appear:
   AUTH_SUCCESS (successful login), AUTH_FAIL (failed password), and
   PRIV_CHANGE (privilege-related changes such as sudo grants or group
   modifications). The file contained 1,235 raw lines; the parser removed
   2 exact duplicate lines and skipped 1 empty line, leaving 1,232 unique
   events (970 successful logins, 169 failed logins, 93 privilege events).
   Removing duplicates matters: identical repeated lines are usually a logging
   error, and counting them twice would inflate the numbers.
3. Detection Logic
   The tool runs five rules, each tagged with its MITRE ATT&CK technique:
   Rule A — Brute force per account (T1110, MEDIUM): flags any username
   with 5+ failed logins.
   Rule B — Suspicious IPs (T1110 / T1110.004, MEDIUM–HIGH): one flag
   per IP, combining volume (5+ failures) with spray behavior (3+ different
   usernames tried, i.e., credential stuffing).
   Rule C — Privilege escalation, tiered (HIGH/MEDIUM/LOW): "Granted sudo
   privileges" (T1548.003) and "added to administrators group" (T1098) are
   HIGH; "Logged in as root" (T1078) is MEDIUM; failed chmod/chown attempts
   (T1222) are LOW. A keyword fallback scans all other event types.
   Rule D — Brute force followed by success (T1078, CRITICAL): if an
   account accumulated 5+ failures before a successful login, the account
   may be compromised.
   Rule E — Odd-hour correlation (T1078, MEDIUM): successful logins or
   privilege changes between 00:00–04:59, but only for users/IPs already
   flagged by another rule, to avoid false alarms on normal night activity.
   Every flag records first-seen and last-seen timestamps as evidence, and all
   flags are sorted by severity (CRITICAL first) for triage.
4. Findings
   The analysis produced 108 flags: 1 CRITICAL, 42 HIGH, 22 MEDIUM, 43 LOW.
   CRITICAL — possible compromise of jdoe: the account suffered 10
   failed logins from three internal IPs, followed by a successful login
   from a completely different, external IP (100.108.103.43) on March 14
   at 13:12 UTC. The failures and the success coming from different sources
   strongly suggests an attacker gained access.
   HIGH — credential stuffing from 51.185.130.223: this external IP
   generated 80 failed logins across 72 different usernames, including
   gibberish (@@@*$)!^) and email-style (maryborris25@yahoo.com) names —
   a classic automated credential-stuffing pattern.
   HIGH — brute force from INSIDE the network: 192.168.1.15,
   192.168.1.17, and 10.0.2.87 are private/internal addresses, yet each
   generated 28–32 failures against five accounts (root, admin, jdoe, jtoll,
   tbraxter). This points to a compromised internal host or insider activity
   rather than an outside attack.
   Privilege abuse: 38 HIGH privilege events, including numerous
   "Granted sudo privileges" and "User added to administrators group"
   actions. Rule E correlated several of these to odd hours: root was
   granted sudo at 01:27, root was added to administrators at 00:02,
   and evazquez35 was added to administrators at 02:44 from
   10.0.2.87 — the same internal IP conducting brute-force attacks.
5. Recommendations
   Immediately reset the jdoe password and enforce MFA (multi-factor
   authentication); review everything the account touched after March 14.
   Lock or closely monitor the accounts root, admin, jtoll, and tbraxter.
   Block 51.185.130.223 at the network firewall and check whether any of
   its 72 targeted usernames ever succeeded.
   Investigate the three internal hosts (192.168.1.15, 192.168.1.17,
   10.0.2.87) for malware or unauthorized use — internal brute-force sources
   are a serious escalation.
   Audit every sudo grant and administrators-group change, especially
   those occurring between 00:00 and 05:00; revoke any that lack a change
   ticket.
   Forward these logs to a SIEM with alert rules matching the logic
   above so detection happens continuously, not once.
6. Reflection
   What worked well: splitting the code into three modules (parser,
   detectors, main) made testing easy, and using Counter, sets, and
   dictionaries kept the logic short and readable.
   What was challenging: designing the rules so the same IP was not flagged
   twice, and scoping the odd-hours rule so it correlated with existing flags
   instead of crying wolf on normal night activity. Both problems taught me
   that good detection engineering is mostly about reducing noise.
   What I would improve next: support for additional log formats (e.g., real
   Linux auth.log), IP reputation/geolocation enrichment to automatically
   label internal vs. external sources, and a time-window check so only
   rapid bursts of failures count as brute force.
