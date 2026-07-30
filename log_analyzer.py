#!/usr/bin/env python3
"""
log_analyzer.py
The main script you run from the terminal.
It loads the log file, runs all five detection rules, and prints a
severity-sorted report (worst alerts first).

Usage:
    python3 log_analyzer.py sample_log.txt
    python3 log_analyzer.py sample_log.txt --csv findings.csv
    python3 log_analyzer.py sample_log.txt --txt report_output.txt
    python3 log_analyzer.py sample_log.txt --threshold 3 --csv findings.csv
    python3 log_analyzer.py sample_log.txt --no-color
"""

import csv
import sys
import argparse

# import our helper modules from the same folder
from log_parser import load_log_file
from detectors import (
    detect_failed_logins,
    detect_suspicious_ips,
    detect_privilege_events,
    detect_brute_force_success,
    detect_odd_hours,
    get_top_users,
    get_top_ips,
    SEVERITY_ORDER
)

# -------------------------------------------------------------------------
# COLORS
# ANSI escape codes are invisible characters that tell the terminal to
# change text color. They're built into the terminal itself, so this needs
# no extra packages. '\033[91m' turns the following text red, '\033[0m'
# resets it back to normal.
# -------------------------------------------------------------------------
COLORS = {
    'CRITICAL': '\033[91m',   # bright red
    'HIGH':     '\033[93m',   # yellow
    'MEDIUM':   '\033[96m',   # cyan
    'LOW':      '\033[90m',   # dim gray
}
RESET = '\033[0m'

# main() flips this off if the user passes --no-color
USE_COLOR = True


def colorize(text, severity):
    """Wrap text in the color that matches its severity (if color is on)."""
    if USE_COLOR and severity in COLORS:
        return f"{COLORS[severity]}{text}{RESET}"
    return text


def print_summary(parsed_logs, skipped, duplicates, all_flags):
    """
    Print the big-picture numbers a SOC analyst reads first,
    plus a breakdown of flags BY SEVERITY (the triage view).
    """
    total_lines = len(parsed_logs)
    total_fails = len([l for l in parsed_logs if l['event'] == 'AUTH_FAIL'])
    total_success = len([l for l in parsed_logs if l['event'] == 'AUTH_SUCCESS'])
    total_priv = len([l for l in parsed_logs if l['event'] == 'PRIV_CHANGE'])

    # count how many flags there are per severity level
    sev_counts = {}
    for flag in all_flags:
        sev = flag['severity']
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    print("=" * 64)
    print("LOG ANALYZER - SUMMARY REPORT")
    print("=" * 64)
    print(f"Total log lines processed:   {total_lines}")
    print(f"Total successful logins:     {total_success}")
    print(f"Total failed logins:         {total_fails}")
    print(f"Total privilege events:      {total_priv}")
    print("-" * 64)
    print("LOG INTEGRITY")
    print(f"  Empty/malformed lines skipped:   {skipped}")
    print(f"  Exact duplicate lines removed:   {duplicates}")
    print("-" * 64)
    print("FLAGS BY SEVERITY")
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        label = colorize(f"{sev:<9}", sev)
        print(f"  {label}: {sev_counts.get(sev, 0)}")
    print("-" * 64)
    print(f"Total flagged events:        {len(all_flags)}")
    print("=" * 64)


def print_top_activity(parsed_logs):
    """
    Extra analytics: top users and top IPs. Gives the analyst context
    about what's normal in the environment before judging what's weird.
    """
    top_users = get_top_users(parsed_logs, n=10)
    top_ips = get_top_ips(parsed_logs, n=5)

    print("\n" + "=" * 64)
    print("EXTRA ANALYTICS")
    print("=" * 64)

    print("\nTop 10 Most Active Usernames:")
    for user, count in top_users:
        print(f"  {count:4d}  {user}")

    print("\nTop 5 Most Active IP Addresses:")
    for ip, count in top_ips:
        print(f"  {count:4d}  {ip}")

    print("=" * 64)


def print_flagged_events(all_flags):
    """
    Print every suspicious event, sorted so the most urgent alerts
    (CRITICAL first, LOW last) are at the top.
    """
    if not all_flags:
        print("\nNo suspicious activity detected.")
        return

    # sort by severity rank first (0-3), then by time inside each severity
    sorted_flags = sorted(
        all_flags,
        key=lambda f: (SEVERITY_ORDER[f['severity']], f['first_seen'])
    )

    print("\n" + "=" * 64)
    print("FLAGGED EVENTS (sorted by severity)")
    print("=" * 64)

    for i, event in enumerate(sorted_flags, 1):
        sev_label = colorize(f"[{event['severity']}]", event['severity'])
        print(f"\nFlag #{i}  {sev_label}")
        print(f"  Window:    {event['first_seen']}  ->  {event['last_seen']}")
        print(f"  User:      {event['user']}")
        print(f"  IP:        {event['ip']}")
        print(f"  Event:     {event['event']}")
        print(f"  MITRE:     {event['mitre']}")
        print(f"  Reason:    {event['reason']}")

    print("\n" + "=" * 64)


def export_csv(all_flags, filename):
    """
    Write all flagged events to a CSV file.
    CSV = Comma-Separated Values — opens straight into Excel or Google
    Sheets, which is handy for attaching findings to a ticket.
    """
    if not all_flags:
        print(f"\nNo events to export to {filename}.")
        return

    sorted_flags = sorted(
        all_flags,
        key=lambda f: (SEVERITY_ORDER[f['severity']], f['first_seen'])
    )

    # column headers for the spreadsheet
    fieldnames = ['severity', 'first_seen', 'last_seen', 'user', 'ip',
                  'event', 'mitre', 'reason']

    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for event in sorted_flags:
            writer.writerow(event)

    print(f"\nFindings exported to CSV: {filename}")


def export_txt(parsed_logs, skipped, duplicates, all_flags, filename):
    """
    Write a plain-text version of the full report to a file.
    Note: no color codes in here on purpose — ANSI codes show up as
    garbage characters in a text file. Colors are for the screen only.
    """
    sorted_flags = sorted(
        all_flags,
        key=lambda f: (SEVERITY_ORDER[f['severity']], f['first_seen'])
    )
    total_lines = len(parsed_logs)
    total_fails = len([l for l in parsed_logs if l['event'] == 'AUTH_FAIL'])
    total_success = len([l for l in parsed_logs if l['event'] == 'AUTH_SUCCESS'])
    total_priv = len([l for l in parsed_logs if l['event'] == 'PRIV_CHANGE'])

    sev_counts = {}
    for flag in all_flags:
        sev_counts[flag['severity']] = sev_counts.get(flag['severity'], 0) + 1

    with open(filename, 'w') as f:
        f.write("=" * 64 + "\n")
        f.write("LOG ANALYZER - ANALYST REPORT\n")
        f.write("=" * 64 + "\n\n")
        f.write(f"Total log lines processed:   {total_lines}\n")
        f.write(f"Total successful logins:     {total_success}\n")
        f.write(f"Total failed logins:         {total_fails}\n")
        f.write(f"Total privilege events:      {total_priv}\n")
        f.write(f"Empty/malformed lines skipped: {skipped}\n")
        f.write(f"Exact duplicates removed:    {duplicates}\n")
        f.write("-" * 64 + "\n")
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            f.write(f"{sev:<9}: {sev_counts.get(sev, 0)}\n")
        f.write(f"Total flagged events:        {len(all_flags)}\n")
        f.write("=" * 64 + "\n\n")

        f.write("FLAGGED EVENTS (sorted by severity)\n")
        f.write("=" * 64 + "\n")
        for i, event in enumerate(sorted_flags, 1):
            f.write(f"\nFlag #{i}  [{event['severity']}]\n")
            f.write(f"  Window:    {event['first_seen']}  ->  {event['last_seen']}\n")
            f.write(f"  User:      {event['user']}\n")
            f.write(f"  IP:        {event['ip']}\n")
            f.write(f"  Event:     {event['event']}\n")
            f.write(f"  MITRE:     {event['mitre']}\n")
            f.write(f"  Reason:    {event['reason']}\n")
        f.write("\n" + "=" * 64 + "\n")

    print(f"\nReport exported to text file: {filename}")


def main():
    """
    The main function that runs when you type 'python3 log_analyzer.py'.
    argparse is Python's built-in way of reading command-line options
    like --csv or --threshold.
    """
    parser = argparse.ArgumentParser(
        description='Analyze authentication logs for suspicious activity.'
    )
    parser.add_argument(
        'logfile',
        help='Path to the log file you want to analyze (e.g., sample_log.txt)'
    )
    parser.add_argument(
        '--csv',
        help='Optional: Export findings to a CSV file (e.g., findings.csv)',
        default=None
    )
    parser.add_argument(
        '--txt',
        help='Optional: Export a text report to a file (e.g., report_output.txt)',
        default=None
    )
    parser.add_argument(
        '--threshold',
        type=int,
        default=5,
        help='Optional: Set the failed-login threshold (default: 5)'
    )
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Optional: Disable colored output (useful if colors look odd)'
    )

    args = parser.parse_args()

    # flip the global color switch based on the flag
    global USE_COLOR
    USE_COLOR = not args.no_color

    # Step 1: load and parse the log file.
    # Without try/except, a missing file crashes with an ugly 'traceback'.
    # This catches it and prints something a human can actually read.
    print(f"Loading log file: {args.logfile}")
    try:
        parsed_logs, skipped, duplicates = load_log_file(args.logfile)
    except FileNotFoundError:
        print(f"\nError: file not found: '{args.logfile}'")
        print("Tip: check the spelling and make sure you are in the project folder.")
        sys.exit(1)   # exit code 1 = the standard way to say 'this run failed'
    print(f"Parsed {len(parsed_logs)} unique log entries "
          f"({skipped} empty/malformed skipped, {duplicates} duplicates removed).\n")

    # Step 2: run the detection rules
    failed_flags = detect_failed_logins(parsed_logs, threshold=args.threshold)
    ip_flags = detect_suspicious_ips(parsed_logs, fail_threshold=args.threshold)
    priv_flags = detect_privilege_events(parsed_logs)
    bfs_flags = detect_brute_force_success(parsed_logs, threshold=args.threshold)

    # Rule E needs to know WHO is already flagged (that's the correlation
    # part), so I build sets of the flagged usernames and IPs from rules
    # A, B and D. A set is perfect here: no duplicates, fast lookups.
    flagged_users = {f['user'] for f in failed_flags + bfs_flags if f['user'] != 'N/A'}
    flagged_ips = {f['ip'] for f in ip_flags + bfs_flags if f['ip'] != 'N/A'}
    odd_flags = detect_odd_hours(parsed_logs, flagged_users, flagged_ips)

    # combine every rule's findings into one master list
    all_flags = failed_flags + ip_flags + priv_flags + bfs_flags + odd_flags

    # Step 3: show the results in the terminal
    print_summary(parsed_logs, skipped, duplicates, all_flags)
    print_top_activity(parsed_logs)
    print_flagged_events(all_flags)

    # Step 4: optional exports
    if args.csv:
        export_csv(all_flags, args.csv)
    if args.txt:
        export_txt(parsed_logs, skipped, duplicates, all_flags, args.txt)


# this standard Python idiom means: only run main() if this file is executed directly
if __name__ == '__main__':
    main()