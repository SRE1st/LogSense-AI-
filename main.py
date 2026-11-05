
import json
import os

from src.parser import parse_log_line
from src.detector import detect_threats
from src.ai_analyzer import analyze_threat
from src.report import generate_report, generate_text_report


def main():

    log_file = "data/sample_logs.txt"
    parsed_logs = []
    ai_analyses = []

    # Read and parse log file
    with open(log_file, "r") as file:
        for line in file:
            parsed = parse_log_line(line)

            if parsed is not None:
                parsed_logs.append(parsed)

    print("\n========== LOGSENSE AI ==========")
    print(f"\nTotal parsed logs: {len(parsed_logs)}")

    # Detect suspicious activity
    threats = detect_threats(parsed_logs)

    print("\n========== THREAT REPORT ==========")

    if threats:
        for threat in threats:

            print("\nThreat detected!")

            for key, value in threat.items():
                print(f"{key}: {value}")

            print("\n========== AI ANALYSIS ==========")

            analysis = analyze_threat(threat)
            ai_analyses.append(analysis)

            print(analysis)

    else:
        print("\nNo suspicious activity detected.")

    # Generate structured report
    report = generate_report(
        parsed_logs,
        threats,
        ai_analyses
    )

    # Create reports directory
    os.makedirs("reports", exist_ok=True)

    # Save report as JSON
    with open("reports/latest_report.json", "w") as file:
        json.dump(report, file, indent=4)

    text_report = generate_text_report(report)
    with open("reports/latest_report.txt", "w") as file:
        file.write(text_report)

    print("\n========== REPORTS GENERATED ==========")
    print("JSON report: reports/latest_report.json")
    print("Text report: reports/latest_report.txt")
    print(f"Total threats: {report['total_threats']}")
    print(f"Severity summary: {report['severity_summary']}")
    print("\n======================================")


if __name__ == "__main__":
    main()

