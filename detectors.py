"""
detectors.py
This file holds the detection rules — the logic that decides which log
entries look suspicious. Each function is one rule, like what a SOC
analyst would write in a SIEM.

(SIEM = Security Information and Event Management: the main console a
Security Operations Center uses to collect logs and raise alerts.)

Every flag a rule creates is a dictionary with these keys:
    user, ip, event, severity, mitre, first_seen, last_seen, reason

- severity is CRITICAL / HIGH / MEDIUM / LOW so the worst alerts can be
  reviewed first (sorting alerts like this is called "triage")
- mitre is the MITRE ATT&CK technique ID. ATT&CK is a public knowledge
  base of attacker tactics and techniques, and real detection rules get
  tagged with these IDs, so I did the same.
"""

from collections import Counter

# used to sort alerts so the most urgent one prints first
# (smaller number = higher priority)
SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}


def _first_last(timestamps):
    """
    Return the (earliest, latest) timestamp from a list.
    Our timestamps are ISO format ('2026-03-17T23:13:01Z'), which sorts
    correctly as plain text: min() = oldest, max() = newest.
    """
    return min(timestamps), max(timestamps)


def detect_failed_logins(parsed_logs, threshold=5):
    """
    RULE A — repeated failed logins against ONE account.

    Lots of failed passwords on a single username = classic brute force
    (an attacker guessing the password over and over).

    I keep a list of failure timestamps per username so the flag can show
    WHEN the attack started and ended, not just "it happened".
    MITRE ATT&CK: T1110 (Brute Force). Severity: MEDIUM.
    """
    # keep only the failed-login events
    failed = [log for log in parsed_logs if log['event'] == 'AUTH_FAIL']

    # build a map: username -> list of its failure timestamps
    # setdefault(key, []) gives me the list that's already there,
    # or a new empty one if this username hasn't failed before
    fails_by_user = {}
    for log in failed:
        fails_by_user.setdefault(log['user'], []).append(log['timestamp'])

    flagged = []
    for user, times in fails_by_user.items():
        if len(times) >= threshold:
            first, last = _first_last(times)
            flagged.append({
                'user': user,
                'ip': 'N/A',
                'event': 'AUTH_FAIL',
                'severity': 'MEDIUM',
                'mitre': 'T1110',
                'first_seen': first,
                'last_seen': last,
                'reason': (f'Brute force: account "{user}" had {len(times)} '
                           f'failed logins (threshold: {threshold}) '
                           f'[T1110 Brute Force]')
            })
    return flagged


def detect_suspicious_ips(parsed_logs, fail_threshold=5, username_threshold=3):
    """
    RULE B — suspicious IP addresses (ONE flag per IP, reasons combined).

    Each IP gets a single flag, with every reason that applies combined
    into it. That keeps the alert list free of near-duplicate flags all
    pointing at the same address:

      1. VOLUME — lots of failed logins from the same IP
         -> T1110 (Brute Force), severity MEDIUM
      2. SPRAY — one IP trying MANY DIFFERENT usernames
         (that's credential stuffing: trying a list of guessed or leaked
         usernames hoping one works)
         -> T1110.004 (Credential Stuffing), severity HIGH
    """
    failed = [log for log in parsed_logs if log['event'] == 'AUTH_FAIL']

    # two maps built side by side:
    #   times_by_ip: ip -> list of failure timestamps
    #   users_by_ip: ip -> SET of usernames tried
    #   (a set automatically drops duplicates, so each username counts once)
    times_by_ip = {}
    users_by_ip = {}
    for log in failed:
        times_by_ip.setdefault(log['ip'], []).append(log['timestamp'])
        users_by_ip.setdefault(log['ip'], set()).add(log['user'])

    flagged = []
    for ip, times in times_by_ip.items():
        reasons = []
        tags = []
        severity = None

        if len(times) >= fail_threshold:
            reasons.append(f'{len(times)} failed logins (threshold: {fail_threshold})')
            tags.append('T1110')
            severity = 'MEDIUM'

        users_tried = users_by_ip.get(ip, set())
        if len(users_tried) >= username_threshold:
            reasons.append(f'tried {len(users_tried)} different usernames '
                           f'(threshold: {username_threshold})')
            tags.append('T1110.004')
            severity = 'HIGH'   # credential stuffing is the nastier behavior

        if reasons:
            first, last = _first_last(times)
            flagged.append({
                'user': 'N/A',
                'ip': ip,
                'event': 'AUTH_FAIL',
                'severity': severity,
                'mitre': ', '.join(tags),
                'first_seen': first,
                'last_seen': last,
                'reason': (f'Suspicious IP "{ip}": ' + ' + '.join(reasons) +
                           f' [{", ".join(tags)}]')
            })
    return flagged


def detect_privilege_events(parsed_logs):
    """
    RULE C — privilege escalation indicators, tiered by severity.

    Flagging every privilege event at the same severity would bury the
    dangerous ones in a wall of nearly a hundred identical alerts, so
    each event gets a severity based on what actually happened:

      HIGH   : 'Granted sudo privileges'  -> T1548.003 (abusing sudo)
               'added to administrators'  -> T1098 (account manipulation)
      MEDIUM : 'Logged in as root'        -> T1078 (valid accounts)
      LOW    : FAILED chmod/chown attempts -> T1222 (permission modification)
               (a failed attempt matters less than a successful change)

    I also scan the messages of all the OTHER event types for privilege
    keywords, just in case privilege activity hides somewhere unexpected.
    """
    privilege_keywords = [
        'sudo', 'admin', 'administrator', 'root', 'privilege',
        'elevated', 'added to group', 'chmod', 'chown'
    ]

    flagged = []

    for log in parsed_logs:
        message = log.get('message', '')
        lower = message.lower()   # .lower() makes the checks case-insensitive

        # fields that are the same no matter which branch flags this line
        base = {
            'user': log['user'],
            'ip': log['ip'],
            'event': log['event'],
            'first_seen': log['timestamp'],
            'last_seen': log['timestamp'],
        }

        if log['event'] == 'PRIV_CHANGE':
            # pick the severity tier based on what actually happened
            if 'granted sudo' in lower:
                severity, tag = 'HIGH', 'T1548.003'
            elif 'added to administrators' in lower:
                severity, tag = 'HIGH', 'T1098'
            elif 'logged in as root' in lower:
                severity, tag = 'MEDIUM', 'T1078'
            elif 'chmod' in lower or 'chown' in lower:
                severity, tag = 'LOW', 'T1222'
            else:
                severity, tag = 'MEDIUM', 'T1098'

            flagged.append({**base,
                            'severity': severity,
                            'mitre': tag,
                            'reason': f'Privilege event: {message} [{tag}]'})
            continue   # this line is handled, move to the next one

        # keyword fallback for privilege hints in other event types
        for keyword in privilege_keywords:
            if keyword in lower:
                flagged.append({**base,
                                'severity': 'MEDIUM',
                                'mitre': 'T1078',
                                'reason': (f'Privilege keyword detected '
                                           f'("{keyword}"): {message}')})
                break   # flag each line only once, even if 2 keywords match

    return flagged


def detect_brute_force_success(parsed_logs, threshold=5):
    """
    RULE D — brute force FOLLOWED BY A SUCCESS (possible compromise).

    The scariest pattern in an authentication log: an account racks up a
    bunch of failed logins... and then a login SUCCEEDS. That can mean the
    attacker finally guessed the password.

    How it works: for every AUTH_SUCCESS, count how many failures that
    same account had BEFORE the success. If the count >= threshold, alert.
    (ISO timestamps compare correctly as text, so t < success works.)

    My dataset actually has one of these: jdoe failed 10 times from
    internal IPs, then succeeded from a totally different external IP.
    MITRE: T1078 (Valid Accounts — attacker using a real account).
    Severity: CRITICAL — this is the alert you page people about.
    """
    # map: username -> list of ALL its failure timestamps
    fails_by_user = {}
    for log in parsed_logs:
        if log['event'] == 'AUTH_FAIL':
            fails_by_user.setdefault(log['user'], []).append(log['timestamp'])

    flagged = []
    for log in parsed_logs:
        if log['event'] != 'AUTH_SUCCESS':
            continue

        user = log['user']
        fail_times = fails_by_user.get(user, [])

        # only the failures that happened EARLIER than this success
        earlier_fails = [t for t in fail_times if t < log['timestamp']]

        if len(earlier_fails) >= threshold:
            first, _ = _first_last(earlier_fails)
            flagged.append({
                'user': user,
                'ip': log['ip'],
                'event': 'AUTH_SUCCESS',
                'severity': 'CRITICAL',
                'mitre': 'T1078',
                'first_seen': first,              # first failed attempt
                'last_seen': log['timestamp'],    # the successful login
                'reason': (f'POSSIBLE COMPROMISE: account "{user}" had '
                           f'{len(earlier_fails)} failed logins BEFORE a '
                           f'successful login from {log["ip"]} '
                           f'[T1078 Valid Accounts]')
            })
    return flagged


def detect_odd_hours(parsed_logs, flagged_users, flagged_ips,
                     start_hour=0, end_hour=5):
    """
    RULE E — odd-hour activity by users/IPs that were ALREADY flagged.

    Successful logins or privilege changes between 00:00 and 04:59 are
    worth a second look — but only when the user or IP already got flagged
    by another rule. That limit is on purpose: it's called correlation
    (connecting two weak signals into one stronger one). Without it, this
    rule would cry wolf on every night-shift worker in the company.

    flagged_users / flagged_ips are sets built in main() from rules A, B, D.
    Severity: MEDIUM. MITRE: T1078.
    """
    flagged = []
    for log in parsed_logs:
        if log['event'] not in ('AUTH_SUCCESS', 'PRIV_CHANGE'):
            continue

        # the timestamp looks like '2026-03-17T23:13:01Z'
        # -> characters 11 and 12 are the hour ('23' here)
        hour = int(log['timestamp'][11:13])

        if start_hour <= hour < end_hour and \
           (log['user'] in flagged_users or log['ip'] in flagged_ips):
            flagged.append({
                'user': log['user'],
                'ip': log['ip'],
                'event': log['event'],
                'severity': 'MEDIUM',
                'mitre': 'T1078',
                'first_seen': log['timestamp'],
                'last_seen': log['timestamp'],
                'reason': (f'Odd-hour activity at {hour:02d}:00 by user/IP '
                           f'already flagged in this investigation: '
                           f'{log.get("message", "")} [T1078]')
            })
    return flagged


def get_top_users(parsed_logs, n=10):
    """
    Extra analytics: the N most active usernames (suspicious or not).
    Counter is a special dictionary that does the counting for me, and
    .most_common(n) returns the top n as (item, count) pairs.
    """
    user_counts = Counter(log['user'] for log in parsed_logs if log['user'])
    return user_counts.most_common(n)


def get_top_ips(parsed_logs, n=5):
    """Extra analytics: the N most active source IP addresses."""
    ip_counts = Counter(log['ip'] for log in parsed_logs if log['ip'])
    return ip_counts.most_common(n)