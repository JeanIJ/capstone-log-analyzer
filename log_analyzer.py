#!/usr/bin/env python3
"""
log_analyzer.py
The main script you run from the terminal.
It loads the log file, runs all three detection rules, and prints a professional report.

Usage:
    python log_analyzer.py sample_log.txt
    python log_analyzer.py sample_log.txt --csv findings.csv
"""

import csv
import argparse

# Import our helper modules from the same folder
from log_parser import load_log_file
from detectors import detect_failed_logins, detect_suspicious_ips, detect_privilege_events


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
    
    print(f"\nFindings exported to: {filename}")


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
    
    # Parse the arguments the user typed in the terminal
    args = parser.parse_args()
    
    # Step 1: Load and parse the log file
    print(f"Loading log file: {args.logfile}")
    parsed_logs = load_log_file(args.logfile)
    print(f"Successfully parsed {len(parsed_logs)} log entries.\n")
    
    # Step 2: Run the three detection rules
    failed_flags = detect_failed_logins(parsed_logs)
    ip_flags = detect_suspicious_ips(parsed_logs)
    priv_flags = detect_privilege_events(parsed_logs)
    
    # Step 3: Display the results in the terminal
    print_summary(parsed_logs, failed_flags, ip_flags, priv_flags)
    print_flagged_events(failed_flags, ip_flags, priv_flags)
    
    # Step 4: Optional CSV export
    if args.csv:
        export_csv(failed_flags, ip_flags, priv_flags, args.csv)


# This standard Python idiom means: only run main() if this file is executed directly
if __name__ == '__main__':
    main()