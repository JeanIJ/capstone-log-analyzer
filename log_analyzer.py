#!/usr/bin/env python3
"""
log_analyzer.py
The main script you run from the terminal.
It loads the log file, runs all three detection rules, and prints a professional report.

Usage:
    python log_analyzer.py sample_log.txt
    python log_analyzer.py sample_log.txt --csv findings.csv
    python log_analyzer.py sample_log.txt --txt report.txt
    python log_analyzer.py sample_log.txt --threshold 3 --csv findings.csv
"""

import csv
import argparse

# Import our helper modules from the same folder
from log_parser import load_log_file
from detectors import (
    detect_failed_logins,
    detect_suspicious_ips,
    detect_privilege_events,
    get_top_users,
    get_top_ips
)


def print_summary(parsed_logs, failed_flags, ip_flags, priv_flags):
    """
    Print a high-level summary in the terminal.
    This gives the SOC analyst the "big picture" numbers first.
    """
    total_lines = len(parsed_logs)
    total_fails = len([log for log in parsed_logs if log['event'] == 'AUTH_FAIL'])
    total_success = len([log for log in parsed_logs if log['event'] == 'AUTH_SUCCESS'])
    total_priv = len([log for log in parsed_logs if log['event'] == 'PRIV_CHANGE'])
    
    print("=" * 60)
    print("LOG ANALYZER - SUMMARY REPORT")
    print("=" * 60)
    print(f"Total log lines processed: {total_lines}")
    print(f"Total successful logins:   {total_success}")
    print(f"Total failed logins:       {total_fails}")
    print(f"Total privilege events:    {total_priv}")
    print("-" * 60)
    print(f"Repeated failed login flags: {len(failed_flags)}")
    print(f"Suspicious IP flags:         {len(ip_flags)}")
    print(f"Privilege escalation flags:  {len(priv_flags)}")
    total_flagged = len(failed_flags) + len(ip_flags) + len(priv_flags)
    print(f"Total flagged events:        {total_flagged}")
    print("=" * 60)


def print_top_activity(parsed_logs):
    """
    Print extra analytics: top users and top IPs.
    This gives the analyst context about what is normal in the environment.
    """
    top_users = get_top_users(parsed_logs, n=10)
    top_ips = get_top_ips(parsed_logs, n=5)
    
    print("\n" + "=" * 60)
    print("EXTRA ANALYTICS")
    print("=" * 60)
    
    print("\nTop 10 Most Active Usernames:")
    for user, count in top_users:
        print(f"  {count:4d}  {user}")
    
    print("\nTop 5 Most Active IP Addresses:")
    for ip, count in top_ips:
        print(f"  {count:4d}  {ip}")
    
    print("=" * 60)


def print_flagged_events(failed_flags, ip_flags, priv_flags):
    """
    Print the detailed list of every suspicious event we found.
    Each entry shows WHO, WHEN, WHERE (IP), and WHY it was flagged.
    """
    all_flags = failed_flags + ip_flags + priv_flags
    
    if not all_flags:
        print("\nNo suspicious activity detected.")
        return
    
    print("\n" + "=" * 60)
    print("FLAGGED EVENTS (DETAILS)")
    print("=" * 60)
    
    for i, event in enumerate(all_flags, 1):
        print(f"\nFlag #{i}")
        print(f"  Timestamp: {event['timestamp']}")
        print(f"  User:      {event['user']}")
        print(f"  IP:        {event['ip']}")
        print(f"  Event:     {event['event']}")
        print(f"  Reason:    {event['reason']}")
    
    print("\n" + "=" * 60)


def export_csv(failed_flags, ip_flags, priv_flags, filename):
    """
    Write all flagged events to a CSV file.
    CSV = Comma-Separated Values, a format that opens in Excel or Google Sheets.
    """
    all_flags = failed_flags + ip_flags + priv_flags
    
    if not all_flags:
        print(f"\nNo events to export to {filename}.")
        return
    
    # These will be the column headers in the spreadsheet
    fieldnames = ['timestamp', 'user', 'ip', 'event', 'reason']
    
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for event in all_flags:
            writer.writerow(event)
    
    print(f"\nFindings exported to CSV: {filename}")


def export_txt(parsed_logs, failed_flags, ip_flags, priv_flags, filename):
    """
    Write a professional text report to a file.
    This creates a shareable report that can be emailed or attached to a ticket.
    """
    all_flags = failed_flags + ip_flags + priv_flags
    total_lines = len(parsed_logs)
    total_fails = len([log for log in parsed_logs if log['event'] == 'AUTH_FAIL'])
    total_success = len([log for log in parsed_logs if log['event'] == 'AUTH_SUCCESS'])
    total_priv = len([log for log in parsed_logs if log['event'] == 'PRIV_CHANGE'])
    
    with open(filename, 'w') as f:
        f.write("=" * 60 + "\n")
        f.write("LOG ANALYZER - ANALYST REPORT\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Total log lines processed: {total_lines}\n")
        f.write(f"Total successful logins:   {total_success}\n")
        f.write(f"Total failed logins:       {total_fails}\n")
        f.write(f"Total privilege events:    {total_priv}\n")
        f.write("-" * 60 + "\n")
        f.write(f"Repeated failed login flags: {len(failed_flags)}\n")
        f.write(f"Suspicious IP flags:         {len(ip_flags)}\n")
        f.write(f"Privilege escalation flags:  {len(priv_flags)}\n")
        f.write(f"Total flagged events:        {len(all_flags)}\n")
        f.write("=" * 60 + "\n\n")
        
        if all_flags:
            f.write("FLAGGED EVENTS (DETAILS)\n")
            f.write("=" * 60 + "\n")
            for i, event in enumerate(all_flags, 1):
                f.write(f"\nFlag #{i}\n")
                f.write(f"  Timestamp: {event['timestamp']}\n")
                f.write(f"  User:      {event['user']}\n")
                f.write(f"  IP:        {event['ip']}\n")
                f.write(f"  Event:     {event['event']}\n")
                f.write(f"  Reason:    {event['reason']}\n")
            f.write("\n" + "=" * 60 + "\n")
    
    print(f"\nReport exported to text file: {filename}")


def main():
    """
    The main function that runs when you type 'python log_analyzer.py'.
    It uses 'argparse' to handle command-line arguments professionally.
    """
    # Set up the argument parser
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
        help='Optional: Export a text report to a file (e.g., report.txt)',
        default=None
    )
    parser.add_argument(
        '--threshold',
        type=int,
        default=5,
        help='Optional: Set the failed-login threshold (default: 5)'
    )
    
    # Parse the arguments the user typed in the terminal
    args = parser.parse_args()
    
    # Step 1: Load and parse the log file
    print(f"Loading log file: {args.logfile}")
    parsed_logs = load_log_file(args.logfile)
    print(f"Successfully parsed {len(parsed_logs)} log entries.\n")
    
    # Step 2: Run the three detection rules
    # The threshold is now configurable from the command line
    failed_flags = detect_failed_logins(parsed_logs, threshold=args.threshold)
    ip_flags = detect_suspicious_ips(parsed_logs, fail_threshold=args.threshold)
    priv_flags = detect_privilege_events(parsed_logs)
    
    # Step 3: Display the results in the terminal
    print_summary(parsed_logs, failed_flags, ip_flags, priv_flags)
    print_top_activity(parsed_logs)  # NEW: Extra analytics
    print_flagged_events(failed_flags, ip_flags, priv_flags)
    
    # Step 4: Optional exports
    if args.csv:
        export_csv(failed_flags, ip_flags, priv_flags, args.csv)
    if args.txt:
        export_txt(parsed_logs, failed_flags, ip_flags, priv_flags, args.txt)


# This standard Python idiom means: only run main() if this file is executed directly
if __name__ == '__main__':
    main()