"""
log_parser.py
This module reads the log file and turns each line into a Python dictionary.
A dictionary is like a labeled box where we store data with named keys.
"""

def parse_log_line(line):
    """
    Parse one line from the log file into a dictionary.
    
    The log file uses TAB characters to separate fields.
    Example line:
    2026-03-17T23:13:01Z	AUTH_SUCCESS	user=mtampling0	ip=10.93.238.87	message=Login successful
    
    We split the line by tabs, then turn the key=value pieces into dictionary entries.
    """
    # .strip() removes invisible newline characters at the end of each line
    line = line.strip()
    
    # Skip empty lines so they don't crash the program
    if not line:
        return None
    
    # Split the line into pieces using the TAB character (\t)
    parts = line.split('\t')
    
    # A valid line should have at least 3 parts: timestamp, event, and some data
    if len(parts) < 3:
        return None
    
    # Start a dictionary with the first two columns
    entry = {
        'timestamp': parts[0],  # The date and time of the event
        'event': parts[1]       # The type of event, like AUTH_SUCCESS or AUTH_FAIL
    }
    
    # The remaining columns look like "user=mtampling0" or "ip=10.93.238.87"
    # We split each one at the "=" sign to get the key and the value
    for part in parts[2:]:
        if '=' in part:
            key, value = part.split('=', 1)  # split at the FIRST = only
            entry[key] = value
    
    # Make sure these keys exist even if a line was missing them
    for key in ['user', 'ip', 'message']:
        if key not in entry:
            entry[key] = ''
    
    return entry


def load_log_file(filename):
    """
    Open a log file, parse every line, and return a list of dictionaries.
    
    'filename' is the path to the log file (for example: 'sample_log.txt').
    We use 'with open()' so the file automatically closes when we are done.
    """
    parsed_logs = []  # Create an empty list to hold all parsed entries
    
    with open(filename, 'r') as file:
        for line in file:
            parsed = parse_log_line(line)
            if parsed:
                parsed_logs.append(parsed)
    
    return parsed_logs