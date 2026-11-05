from src.detector import detect_threats


def create_log(timestamp, event, ip, username):
    return {
        "timestamp": timestamp,
        "event": event,
        "ip_address": ip,
        "username": username
    }


def test_detect_brute_force_attempt():
    logs = [
        create_log("Nov  3 10:15:21", "failed_login", "192.168.1.15", "root"),
        create_log("Nov  3 10:15:25", "failed_login", "192.168.1.15", "root"),
        create_log("Nov  3 10:15:29", "failed_login", "192.168.1.15", "root")
    ]

    threats = detect_threats(logs)

    assert len(threats) == 1
    assert threats[0]["type"] == "Brute Force Attempt"
    assert threats[0]["ip_address"] == "192.168.1.15"
    assert threats[0]["attempts"] == 3
    assert threats[0]["severity"] == "MEDIUM"



def test_different_ips_are_counted_separately():
    logs = [
        create_log("Nov  3 10:15:21", "failed_login", "192.168.1.15", "root"),
        create_log("Nov  3 10:15:25", "failed_login", "192.168.1.20", "root"),
        create_log("Nov  3 10:15:29", "failed_login", "192.168.1.25", "root")
    ]

    threats = detect_threats(logs)

    assert threats == []


def test_attempts_outside_five_minute_window():
    logs = [
        create_log("Nov  3 10:15:00", "failed_login", "192.168.1.15", "root"),
        create_log("Nov  3 10:18:00", "failed_login", "192.168.1.15", "root"),
        create_log("Nov  3 10:21:00", "failed_login", "192.168.1.15", "root")
    ]

    threats = detect_threats(logs)

    assert threats == []


def test_invalid_username_enumeration():
    logs = [
        create_log("Nov  3 10:15:21", "invalid_user", "192.168.1.50", "hacker"),
        create_log("Nov  3 10:15:25", "invalid_user", "192.168.1.50", "admin2"),
        create_log("Nov  3 10:15:29", "invalid_user", "192.168.1.50", "guest")
    ]

    threats = detect_threats(logs)

    assert len(threats) == 1
    assert threats[0]["type"] == "Invalid Username Enumeration"
    assert threats[0]["attempts"] == 3
    assert threats[0]["severity"] == "MEDIUM"


def test_successful_login_after_repeated_failures():
    logs = [
        create_log("Nov  3 10:15:21", "failed_login", "192.168.1.15", "admin"),
        create_log("Nov  3 10:15:25", "failed_login", "192.168.1.15", "admin"),
        create_log("Nov  3 10:15:29", "failed_login", "192.168.1.15", "admin"),
        create_log("Nov  3 10:15:35", "successful_login", "192.168.1.15", "admin")
    ]

    threats = detect_threats(logs)

    assert any(
        threat["type"] == "Suspicious Successful Login"
        for threat in threats
    )


def test_empty_logs_return_no_threats():
    threats = detect_threats([])

    assert threats == []


def test_logs_with_missing_fields_are_ignored():
    logs = [
        {},
        {"event": "failed_login"},
        None
    ]

    threats = detect_threats(logs)

    assert threats == []

def test_password_spraying_detection():
    logs = [
        create_log("Nov  3 10:15:01", "failed_login", "192.168.1.50", "admin"),
        create_log("Nov  3 10:15:10", "failed_login", "192.168.1.50", "root"),
        create_log("Nov  3 10:15:20", "failed_login", "192.168.1.50", "guest"),
        create_log("Nov  3 10:15:30", "failed_login", "192.168.1.50", "test"),
        create_log("Nov  3 10:15:40", "failed_login", "192.168.1.50", "user")
    ]

    threats = detect_threats(logs)

    spraying_alerts = [
        threat for threat in threats
        if threat["type"] == "Possible Password Spraying"
    ]

    assert len(spraying_alerts) == 1
    assert spraying_alerts[0]["targeted_accounts"] == 5
    assert spraying_alerts[0]["severity"] == "MEDIUM"

def test_password_spraying_below_threshold():
    logs = [
       create_log("Nov  3 10:15:01", "failed_login", "192.168.1.50", "admin"),
       create_log("Nov  3 10:15:10", "failed_login", "192.168.1.50", "root"),
       create_log("Nov  3 10:15:20", "failed_login", "192.168.1.50", "guest"),
       create_log("Nov  3 10:15:30", "failed_login", "192.168.1.50", "test")
    ]
    threats = detect_threats(logs)

    spraying_alerts = [
        threat for threat in threats
        if threat["type"] == "Possible Password Spraying"
    ]

    assert spraying_alerts == []

def test_password_spraying_outside_five_minute_window():
    logs = [
        create_log("Nov  3 10:10:00", "failed_login", "192.168.1.50", "admin"),
        create_log("Nov  3 10:11:00", "failed_login", "192.168.1.50", "root"),
        create_log("Nov  3 10:12:00", "failed_login", "192.168.1.50", "guest"),
        create_log("Nov  3 10:13:00", "failed_login", "192.168.1.50", "test"),
        create_log("Nov  3 10:16:00", "failed_login", "192.168.1.50", "user")
    ]

    threats = detect_threats(logs)

    spraying_alerts = [
        threat for threat in threats
        if threat["type"] == "Possible Password Spraying"
    ]

    assert spraying_alerts == []

def test_repeated_attempts_on_one_account_are_not_password_spraying():
    logs = [
        create_log("Nov  3 10:15:01", "failed_login", "192.168.1.50", "admin"),
        create_log("Nov  3 10:15:10", "failed_login", "192.168.1.50", "admin"),
        create_log("Nov  3 10:15:20", "failed_login", "192.168.1.50", "admin"),
        create_log("Nov  3 10:15:30", "failed_login", "192.168.1.50", "admin"),
        create_log("Nov  3 10:15:40", "failed_login", "192.168.1.50", "admin")
    ]

    threats = detect_threats(logs)

    spraying_alerts = [
        threat for threat in threats
        if threat["type"] == "Possible Password Spraying"
    ]

    assert spraying_alerts == []

def test_password_spraying_attempts_from_different_ips_are_separate():
    logs = [
        create_log("Nov  3 10:15:01", "failed_login", "192.168.1.50", "admin"),
        create_log("Nov  3 10:15:10", "failed_login", "192.168.1.50", "root"),
        create_log("Nov  3 10:15:20", "failed_login", "192.168.1.50", "guest"),
        create_log("Nov  3 10:15:30", "failed_login", "192.168.1.60", "test"),
        create_log("Nov  3 10:15:40", "failed_login", "192.168.1.60", "user")
    ]

    threats = detect_threats(logs)

    spraying_alerts = [
        threat for threat in threats
        if threat["type"] == "Possible Password Spraying"
    ]

    assert spraying_alerts == []