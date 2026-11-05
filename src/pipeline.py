
from src.parser import parse_log_line
from src.detector import detect_threats
from src.ai_analyzer import analyze_threat
from src.report import generate_report


def analyze_logs(log_lines):
    """
    Process raw log lines and generate a security report.
    """

    parsed_logs = []

    # Step 1: Parse logs
    for line in log_lines:
        parsed = parse_log_line(line)

        if parsed is not None:
            parsed_logs.append(parsed)

    # Step 2: Detect threats
    threats = detect_threats(parsed_logs)

    # Step 3: Generate AI analysis
    ai_analyses = []

    for threat in threats:
        analysis = analyze_threat(threat)
        ai_analyses.append(analysis)

    # Step 4: Generate report
    report = generate_report(
        parsed_logs,
        threats,
        ai_analyses
    )

    return report
