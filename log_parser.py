"""
log_parser.py
This file reads the log file and turns each line into a Python dictionary
(a dictionary is just a labeled box that stores data with named keys).

It also does a small "log hygiene" check:
- counts lines it can't parse (blank or weird-looking lines)
- removes exact duplicate lines. My dataset actually had a couple of these:
  same timestamp + user + ip + message twice, which is almost always a
  logging glitch, not two real events. Counting them twice would
  throw off my numbers.
"""

def parse_log_line(line):
    """
    Turn one log line into a dictionary.

    The log file uses TAB characters between fields. Example line:
    2026-03-17T23:13:01Z  AUTH_SUCCESS  user=mtampling0  ip=10.93.238.87  message=Login successful

    Returns None for blank or too-short lines so they get skipped
    instead of crashing the program.
    """
    # .strip() removes the invisible newline character at the end of each line
    line = line.strip()

    if not line:
        return None

    # split the line wherever there's a TAB
    parts = line.split('\t')

    # a valid line has at least 3 parts: timestamp, event type, and some data
    if len(parts) < 3:
        return None

    # the first two columns are always the timestamp and the event type
    entry = {
        'timestamp': parts[0],
        'event': parts[1]
    }

    # the rest look like "user=mtampling0" -> split each one at the FIRST "="
    for part in parts[2:]:
        if '=' in part:
            key, value = part.split('=', 1)
            entry[key] = value

    # make sure these keys exist even if a line was missing them
    for key in ['user', 'ip', 'message']:
        if key not in entry:
            entry[key] = ''

    return entry


def load_log_file(filename):
    """
    Read the whole file and return 3 things together (a tuple):

        parsed_logs  -> list of dictionaries, one per good line
        skipped      -> how many lines were blank or malformed
        duplicates   -> how many exact repeat lines were removed

    main() unpacks them like this:
        parsed_logs, skipped, duplicates = load_log_file(name)
    """
    parsed_logs = []
    skipped = 0
    duplicates = 0
    seen_lines = set()   # a set remembers every raw line I've already seen

    # 'with open()' automatically closes the file when we're done
    with open(filename, 'r') as file:
        for line in file:
            stripped = line.strip()

            # blank line: count it and move on
            if not stripped:
                skipped += 1
                continue

            # exact same line already processed? skip it
            if stripped in seen_lines:
                duplicates += 1
                continue
            seen_lines.add(stripped)

            parsed = parse_log_line(line)
            if parsed:
                parsed_logs.append(parsed)
            else:
                skipped += 1   # had text, but not the shape we expect

    return parsed_logs, skipped, duplicates