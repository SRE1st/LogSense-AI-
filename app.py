import json
import pandas as pd
import streamlit as st

from src.pipeline import analyze_logs
from src.report import generate_text_report

st.set_page_config(
    page_title="LogSense AI",
    page_icon="〰️",
    layout="wide"
)
# Professional dashboard styling
st.markdown("""
<style>

/* Main background */
.stApp {
    background-color: #0B1220;
    color: #E5E7EB;
}

/* Main content width and spacing */
.block-container {
    max-width: 1250px;
    padding-top: 2rem;
    padding-bottom: 3rem;
}

/* Main headings */
h1 {
    color: #F8FAFC !important;
    font-weight: 750 !important;
    letter-spacing: -1px;
}

h2, h3 {
    color: #E2E8F0 !important;
    font-weight: 650 !important;
}

/* Metric cards */
div[data-testid="stMetric"] {
    background: #111C2E;
    border: 1px solid #26364D;
    border-radius: 12px;
    padding: 18px;
}

/* Metric labels */
div[data-testid="stMetricLabel"] {
    color: #94A3B8 !important;
}

/* Metric values */
div[data-testid="stMetricValue"] {
    color: #F8FAFC !important;
    font-weight: 700;
}

/* Buttons */
.stButton > button {
    background-color: #0D9488;
    color: white;
    border: none;
    border-radius: 8px;
    font-weight: 600;
    padding: 0.55rem 1.2rem;
}

.stButton > button:hover {
    background-color: #0F766E;
    color: white;
    border: none;
}

/* Download buttons */
.stDownloadButton > button {
    background-color: #17263B;
    color: #5EEAD4;
    border: 1px solid #286B70;
    border-radius: 8px;
    font-weight: 600;
}

/* Expanders */
div[data-testid="stExpander"] {
    background-color: #111C2E;
    border: 1px solid #26364D;
    border-radius: 10px;
}

/* File uploader */
div[data-testid="stFileUploader"] {
    background-color: #111C2E;
    border: 1px dashed #3B6475;
    border-radius: 12px;
    padding: 12px;
}

/* Divider */
hr {
    border-color: #26364D !important;
}

/* Captions */
.stCaption {
    color: #94A3B8 !important;
}

</style>
""", unsafe_allow_html=True)

# Header
st.title("〰️ LogSense AI")
st.caption("Cybersecurity Log Monitoring & Threat Analysis")


# Log upload
st.subheader("Analyze Your Own Logs")

uploaded_file = st.file_uploader(
    "Upload a log file",
    type=["log", "txt"]
)

if uploaded_file is not None:

    st.caption(f"Selected file: {uploaded_file.name}")

    if st.button("Analyze Logs", type="primary"):

        try:
            log_text = uploaded_file.getvalue().decode(
                "utf-8",
                errors="replace"
            )

            with st.spinner("Analyzing logs..."):
                report = analyze_logs(log_text.splitlines())

            st.session_state["active_report"] = report
            st.success("Log analysis completed!")

        except Exception as error:
            st.error(f"Analysis failed: {error}")

# Display uploaded report only
if "active_report" not in st.session_state:
    st.info("Upload a log file and click Analyze Logs to view security results.")
    st.stop()

report = st.session_state["active_report"]


# Security overview
st.subheader("Security Overview")

col1, col2, col3 = st.columns(3)

col1.metric("Logs Analyzed", report["total_logs"])
col2.metric("Threats Detected", report["total_threats"])
col3.metric(
    "High Severity",
    report["severity_summary"]["HIGH"]
)

st.divider()

# Threat summary
st.subheader("Detected Security Events")

if not report["threats"]:
    st.success("No suspicious activity detected in the analyzed logs.")

else:
    for index, threat in enumerate(report["threats"]):
        with st.container(border=True):

            severity = threat.get("severity", "UNKNOWN")

            if severity == "HIGH":
                st.error(f"🔴 {severity} SEVERITY")
            elif severity == "MEDIUM":
                st.warning(f"🟠 {severity} SEVERITY")
            else:
                st.info(f"{severity} SEVERITY")

            st.markdown(f"### {threat['type']}")

            col1, col2, col3 = st.columns(3)

            col1.metric("Source IP", threat.get("ip_address", "N/A"))

            if "targeted_accounts" in threat:
                col2.metric("Targeted Accounts", threat["targeted_accounts"])
            else:
                col2.metric("Target Account", threat.get("username", "N/A"))

            if "previous_failures" in threat:
                col3.metric(
                    "Previous Failed Attempts",
                    threat["previous_failures"]
                )

            elif "attempts" in threat:
                col3.metric(
                    "Failed Attempts",
                    threat["attempts"]
                )

            else:
                col3.metric("Attempts", "N/A")

            st.caption(
                "Detection is based on the supplied log evidence. "
                "Further investigation may be needed to confirm the source."
            )

            # Optional AI explanation
            if index < len(report["ai_analyses"]):
                with st.expander("View AI Analysis"):
                    st.markdown(report["ai_analyses"][index])

st.divider()

# Severity summary
st.subheader("Severity Distribution")

severity = report["severity_summary"]

chart_data = pd.DataFrame({
    "Severity": ["HIGH", "MEDIUM", "LOW"],
    "Count": [
        severity["HIGH"],
        severity["MEDIUM"],
        severity["LOW"]
    ]
})

st.bar_chart(
    chart_data,
    x="Severity",
    y="Count",
    horizontal=True,
    height=250
)

st.divider()

# Download security reports
st.subheader("Download Security Report")

json_report = json.dumps(report, indent=4)
text_report = generate_text_report(report)

col1, col2 = st.columns(2)

with col1:
    st.download_button(
        label="📥 Download JSON Report",
        data=json_report,
        file_name="logsense_security_report.json",
        mime="application/json",
        use_container_width=True
    )

with col2:
    st.download_button(
        label="📥 Download Text Report",
        data=text_report,
        file_name="logsense_security_report.txt",
        mime="text/plain",
        use_container_width=True
    )

st.divider()

st.caption(
    "LogSense AI | AI-assisted security monitoring | "
    "Always verify alerts against the original logs."
)
