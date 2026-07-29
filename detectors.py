"""
detectors.py
This module contains the "detection rules" — the logic that decides which log entries are suspicious.
Think of each function as a security rule that a SOC analyst might write.
"""

from collections import Counter


def detect_failed_logins(parsed_logs, threshold=5):
    """
    Rule A: Repeated Failed Login Attempts
    
    This rule counts how many times each username and each IP address failed to log in.
    If the count reaches the 'threshold' (default 5), we flag it as suspicious.
    
    In a real SOC, this helps identify brute-force attacks or stolen credentials being tested.
    """
    # First, filter the logs to keep only AUTH_FAIL events
    failed_events = [log for log in parsed_logs if log['event'] == 'AUTH_FAIL']
    
    # Counter is a special dictionary that automatically counts things for us
    user_failures = Counter(log['user'] for log in failed_events)
    ip_failures = Counter(log['ip'] for log in failed_events)
    
    flagged = []  # A list to store everything we find suspicious
    
    # Check each username's failure count
    for user, count in user_failures.items():
        if count >= threshold:
            flagged.append({
                'timestamp': 'N/A (spread across multiple events)',
                'user': user,
                'ip': 'N/A',
                'event': 'AUTH_FAIL',
                'reason': f'User "{user}" had {count} failed login attempts (threshold: {threshold})'
            })
    
    # Check each IP's failure count
    for ip, count in ip_failures.items():
        if count >= threshold:
            flagged.append({
                'timestamp': 'N/A (spread across multiple events)',
                'user': 'N/A',
                'ip': ip,
                'event': 'AUTH_FAIL',
                'reason': f'IP "{ip}" had {count} failed login attempts (threshold: {threshold})'
            })
    
    return flagged


def detect_suspicious_ips(parsed_logs, fail_threshold=5, username_threshold=3):
    """
    Rule B: Suspicious IP Activity
    
    This rule looks for IPs that behave unusually:
    1. An IP with many failed logins (possible brute force).
    2. An IP that tries to log in as many different usernames (credential stuffing).
    """
    failed_events = [log for log in parsed_logs if log['event'] == 'AUTH_FAIL']
    
    # Count how many failures came from each IP
    ip_failures = Counter(log['ip'] for log in failed_events)
    
    # Build a map: IP -> set of usernames it tried
    ip_to_users = {}
    for log in failed_events:
        ip = log['ip']
        user = log['user']
        if ip not in ip_to_users:
            ip_to_users[ip] = set()  # A set automatically prevents duplicate usernames
        ip_to_users[ip].add(user)
    
    flagged = []
    flagged_ips = set()  # Keep track so we don't flag the same IP twice for the same reason
    
    # Flag 1: IPs with too many failed attempts
    for ip, count in ip_failures.items():
        if count >= fail_threshold:
            flagged.append({
                'timestamp': 'N/A (spread across multiple events)',
                'user': 'N/A',
                'ip': ip,
                'event': 'AUTH_FAIL',
                'reason': f'Suspicious IP: "{ip}" generated {count} failed logins'
            })
            flagged_ips.add(ip)
    
    # Flag 2: IPs that touched many different usernames
    for ip, users in ip_to_users.items():
        if len(users) >= username_threshold:
            if ip not in flagged_ips:
                flagged.append({
                    'timestamp': 'N/A (spread across multiple events)',
                    'user': 'N/A',
                    'ip': ip,
                    'event': 'AUTH_FAIL',
                    'reason': f'Suspicious IP: "{ip}" attempted access to {len(users)} different usernames'
                })
                flagged_ips.add(ip)
    
    return flagged


def detect_privilege_events(parsed_logs):
    """
    Rule C: Privilege Escalation Indicators
    
    This rule looks for any sign that someone is trying to gain higher-level access.
    We flag:
    - Any event with type PRIV_CHANGE
    - Any message containing keywords like 'sudo', 'root', 'admin', etc.
    """
    # These words suggest someone is messing with permissions
    privilege_keywords = [
        'sudo', 'admin', 'administrator', 'root', 'privilege',
        'elevated', 'added to group', 'chmod', 'chown'
    ]
    
    flagged = []
    
    for log in parsed_logs:
        event = log['event']
        message = log.get('message', '').lower()  # .lower() makes the check case-insensitive
        user = log['user']
        ip = log['ip']
        timestamp = log['timestamp']
        
        # If the event type is PRIV_CHANGE, flag it immediately
        if event == 'PRIV_CHANGE':
            flagged.append({
                'timestamp': timestamp,
                'user': user,
                'ip': ip,
                'event': event,
                'reason': f'Privilege escalation event: {log.get("message", "")}'
            })
            continue  # Move to the next log entry
        
        # Otherwise, check if the message contains any privilege keyword
        for keyword in privilege_keywords:
            if keyword in message:
                flagged.append({
                    'timestamp': timestamp,
                    'user': user,
                    'ip': ip,
                    'event': event,
                    'reason': f'Privilege keyword detected ("{keyword}"): {log.get("message", "")}'
                })
                break  # Only flag this entry once, even if multiple keywords match
    
    return flagged


def get_top_users(parsed_logs, n=10):
    """
    Extra Analytics: Top N Most Active Usernames
    
    This shows which usernames appear most often in the log,
    regardless of whether their activity was suspicious.
    
    'n' is how many usernames to return (default 10).
    This helps the analyst understand normal vs. unusual account usage.
    """
    # Count every login event per username
    user_counts = Counter(log['user'] for log in parsed_logs if log['user'])
    
    # .most_common(n) returns the top n items as a list of (item, count) tuples
    return user_counts.most_common(n)


def get_top_ips(parsed_logs, n=5):
    """
    Extra Analytics: Top N Most Active IP Addresses
    
    This shows which source IPs appear most often in the log.
    'n' is how many IPs to return (default 5).
    This helps the analyst spot unusual traffic sources.
    """
    ip_counts = Counter(log['ip'] for log in parsed_logs if log['ip'])
    return ip_counts.most_common(n)