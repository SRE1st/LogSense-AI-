from datetime import datetime

def generate_report(parsed_logs, threats, ai_analyses=None):
    """
    Generate a structured security report.
    """

    if ai_analyses is None:
        ai_analyses = []

    severity_counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for threat in threats:
        severity = threat.get("severity", "LOW")

        if severity in severity_counts:
            severity_counts[severity] += 1

    report = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_logs": len(parsed_logs),
        "total_threats": len(threats),
        "severity_summary": severity_counts,
        "threats": threats,
        "ai_analyses": ai_analyses
    }

    return report


def generate_text_report(report):

    lines = []

    lines.append("=" * 45)
    lines.append("          LOGSENSE AI - SECURITY REPORT")
    lines.append("=" * 45)

    lines.append(f"\nGenerated: {report['generated_at']}")
    lines.append(f"Total logs analyzed: {report['total_logs']}")
    lines.append(f"Total threats detected: {report['total_threats']}")

    lines.append("\n--- SEVERITY SUMMARY ---")

    for severity, count in report["severity_summary"].items():
        lines.append(f"{severity}: {count}")

    lines.append("\n--- THREAT DETAILS ---")

    if report["threats"]:

        for index, threat in enumerate(report["threats"], start=1):

            lines.append(f"\nThreat #{index}")
            lines.append(f"Type: {threat['type']}")
            lines.append(f"IP Address: {threat['ip_address']}")

            if "targeted_accounts" in threat:
                lines.append(
                    f"Targeted Accounts: {threat['targeted_accounts']}"
                )
            else:
                lines.append(
                    f"Username: {threat.get('username', 'N/A')}"
                )

            if "previous_failures" in threat:
                lines.append(
                    f"Previous Failed Attempts: {threat['previous_failures']}"
                )

            elif threat.get("type") == "Invalid Username Enumeration":
                lines.append(
                    f"Invalid Username Attempts: {threat.get('attempts', 'N/A')}"
                )

            elif "attempts" in threat:
                lines.append(
                f"Failed Attempts: {threat['attempts']}"
            )

            lines.append(f"Severity: {threat['severity']}")

    else:
        lines.append("No suspicious activity detected.")

    lines.append("\n--- AI ANALYSIS ---")

    if report["ai_analyses"]:

        for index, analysis in enumerate(report["ai_analyses"], start=1):
            lines.append(f"\nAnalysis #{index}")
            lines.append(analysis)

    else:
        lines.append("No AI analysis available.")

    lines.append("\n" + "=" * 45)
    lines.append("             END OF REPORT")
    lines.append("=" * 45)

    return "\n".join(lines)
