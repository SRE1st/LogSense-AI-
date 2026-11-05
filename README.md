# 〰️ LogSense AI

### AI-Powered Log Analysis & Cybersecurity Threat Detection

LogSense AI is a Python-based cybersecurity monitoring tool that analyzes system logs, identifies suspicious activities, detects potential security threats, and uses Generative AI to explain detected incidents in understandable language.

The project aims to make log analysis easier by combining rule-based threat detection with AI-powered security explanations.

## 🚀 Features

- **Log Parsing:** Reads and processes system log entries.
- **Threat Detection:** Identifies suspicious login activities and potential attacks.
- **Brute Force Detection:** Detects repeated failed login attempts.
- **Suspicious Login Detection:** Identifies potentially suspicious successful logins.
- **AI-Powered Analysis:** Uses Groq-powered AI to explain detected security events.
- **Interactive Dashboard:** Displays log statistics, detected threats, and severity levels.
- **Log Upload:** Allows users to upload `.log` and `.txt` files directly.
- **Report Generation:** Generates downloadable text and JSON reports.

## 🛠️ Technologies Used

- Python
- Streamlit
- Pandas
- Groq API
- Python-dotenv
- Pytest

## 📂 Project Structure

```text
LogSense-AI/
│
├── app.py
├── main.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── data/
│   └── sample log files
│
├── src/
│   ├── __init__.py
│   ├── parser.py
│   ├── detector.py
│   ├── ai_analyzer.py
│   ├── pipeline.py
│   └── report.py
│
└── tests/
    ├── test_parser.py
    └── test_detector.py
```

## ⚙️ Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/SRE1st/LogSense-AI.git
cd LogSense-AI
```


### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it:

**Linux / macOS**
```bash
source .venv/bin/activate
```

**Windows**
```bash
.venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure the Groq API key

Create a `.env` file in the project root:

```env
GROQ_API_KEY=your_groq_api_key
```


### 5. Run the application

```bash
streamlit run app.py
```

Open the local URL displayed in your terminal.

## 🧪 Testing

Run the test suite using:

```bash
pytest -q
```

## 🔍 How It Works

1. The user uploads a log file through the dashboard.
2. LogSense AI parses the log entries.
3. The detection engine analyzes events for suspicious patterns.
4. Detected threats are classified by severity.
5. The AI analyzer generates explanations and recommended actions.
6. The dashboard displays the results and provides downloadable reports.

## 🎯 Project Objective

The objective of LogSense AI is to explore how traditional rule-based cybersecurity monitoring can be combined with Generative AI to make security log analysis more understandable and accessible.

## ⚠️ Disclaimer

LogSense AI is an educational project and a prototype for security log analysis. Its detections are intended to assist investigation and should not replace professional security monitoring systems.

---

**Built with Python, Cybersecurity & Generative AI.**
