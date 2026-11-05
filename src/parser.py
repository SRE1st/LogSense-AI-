import re


def parse_log_line(line):

    pattern = (
        r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)"
        r"\s+(?P<hostname>\S+)"
        r"\s+sshd\[\d+\]:"
        r"\s+(?P<message>.*)"
    )

    match = re.search(pattern, line)

    if not match:
        return None

    data = match.groupdict()
    message = data["message"]

    failed = re.search(
        r"Failed password for (?:invalid user )?(\S+) from (\S+)",
        message
    )

    accepted = re.search(
        r"Accepted (?:password|publickey) for (\S+) from (\S+)",
        message
    )

    invalid = re.search(
        r"Invalid user (\S+) from (\S+)",
        message
    )

    if failed:
        event = "failed_login"
        username, ip_address = failed.groups()

    elif accepted:
        event = "successful_login"
        username, ip_address = accepted.groups()

    elif invalid:
        event = "invalid_user"
        username, ip_address = invalid.groups()

    else:
        event = "other"
        username = None
        ip_address = None

    return {
        "timestamp": data["timestamp"],
        "hostname": data["hostname"],
        "event": event,
        "username": username,
        "ip_address": ip_address,
        "raw_log": line.strip()
    }