from src.parser import parse_log_line

log_line = (
    "Nov  3 10:15:21 ubuntu sshd[1234]: "
    "Failed password for root from 192.168.1.15 port 51234 ssh2"
)

result = parse_log_line(log_line)

if result:
    for key, value in result.items():
        print(f"{key}: {value}")
else:
    print("Unable to parse log.")