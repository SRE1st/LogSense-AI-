
from datetime import datetime, timedelta


def parse_timestamp(timestamp):
    """Convert a syslog timestamp into a datetime object."""

    if not timestamp:
        return None

    try:
        current_year = datetime.now().year

        return datetime.strptime(
            f"{current_year} {timestamp}",
            "%Y %b %d %H:%M:%S"
        )

    except ValueError:
        return None


def detect_threats(logs):
    """
    Detect suspicious SSH activity using a 5-minute window.
    Handles unordered logs and multiple targeted usernames.
    """

    failed_logins = {}
    failed_by_ip = {}
    invalid_users = {}
    threats = []

    window = timedelta(minutes=5)

    # Prepare valid logs and sort chronologically
    valid_logs = []

    for log in logs:
        if not log:
            continue

        timestamp = parse_timestamp(log.get("timestamp"))

        if timestamp and log.get("ip_address"):
            valid_logs.append((timestamp, log))

    valid_logs.sort(key=lambda item: item[0])

    # Process events chronologically
    for timestamp, log in valid_logs:

        event = log.get("event")
        ip = log.get("ip_address")
        username = log.get("username")

        if event == "failed_login" and username:

            key = (ip, username)

            failed_logins.setdefault(key, []).append(timestamp)

            failed_by_ip.setdefault(ip, []).append({
                "username": username,
                "timestamp": timestamp
            })

        elif event == "invalid_user":

            invalid_users.setdefault(ip, []).append(timestamp)

        elif event == "successful_login" and username:

            key = (ip, username)

            previous_attempts = failed_logins.get(key, [])

            recent_attempts = [
                attempt for attempt in previous_attempts
                if timedelta(0) <= timestamp - attempt <= window
            ]

            if len(recent_attempts) >= 3:

                threats.append({
                    "type": "Suspicious Successful Login",
                    "ip_address": ip,
                    "username": username,
                    "previous_failures": len(recent_attempts),
                    "severity": "HIGH"
                })

            failed_logins[key] = []

    # Detect brute-force attacks across individual accounts
    for (ip, username), attempts in failed_logins.items():

        if not attempts:
            continue

        latest_time = attempts[-1]

        recent_attempts = [
            attempt for attempt in attempts
            if timedelta(0) <= latest_time - attempt <= window
        ]

        count = len(recent_attempts)

        if count >= 5:
            severity = "HIGH"
        elif count >= 3:
            severity = "MEDIUM"
        else:
            continue

        threats.append({
            "type": "Brute Force Attempt",
            "ip_address": ip,
            "username": username,
            "attempts": count,
            "severity": severity
        })

    # Detect repeated failed attempts across multiple accounts
    for ip, attempts in failed_by_ip.items():

        if not attempts:
            continue

        latest_time = max(
            attempt["timestamp"] for attempt in attempts
        )

        recent_attempts = [
            attempt for attempt in attempts
            if timedelta(0) <= latest_time - attempt["timestamp"] <= window
        ]

        count = len(recent_attempts)

        unique_users = {
            attempt["username"]
            for attempt in recent_attempts
        }

        if count >= 5 and 2 <= len(unique_users)<5:

            threats.append({
                "type": "Multiple Account Brute Force",
                "ip_address": ip,
                "username": "Multiple accounts",
                "targeted_accounts": len(unique_users),
                "attempts": count,
                "severity": "HIGH"
            })

        # Password spraying: attempts against many accounts
        if len(unique_users) >= 5 and count >= 5:

            threats.append({
                "type": "Possible Password Spraying",
                "ip_address": ip,
                "targeted_accounts": len(unique_users),
                "attempts": count,
                "severity": "MEDIUM"
            })

    # Detect invalid username enumeration
    for ip, attempts in invalid_users.items():

        if not attempts:
            continue

        latest_time = max(attempts)

        recent_attempts = [
            attempt for attempt in attempts
            if timedelta(0) <= latest_time - attempt <= window
        ]

        count = len(recent_attempts)

        if count >= 5:
            severity = "HIGH"
        elif count >= 3:
            severity = "MEDIUM"
        else:
            continue

        threats.append({
            "type": "Invalid Username Enumeration",
            "ip_address": ip,
            "attempts": count,
            "severity": severity
        })

    return threats
