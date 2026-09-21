# 🛡️ Defense Cyber Log Extraction Engine

An AI-driven Security Operations Center (SOC) application designed to ingest raw system logs, detect cyber threat indicators using LLM-powered parsing, and present structured threat intelligence in real time.

---

## 📌 Features

* **Real-Time Attack Parsing:** Identifies web attack vectors including SQL Injection (SQLi), Local File Inclusion (LFI), Directory Traversal, Automated Scanners (Nikto/Gobuster), and Remote Command Execution.
* **Dual Input Modes:** Analyze logs via direct text input or by uploading raw `.log` / `.txt` files.
* **Structured SIEM Output:** Categorizes threats by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), extracts Indicators of Compromise (IoCs), and maps actions to MITRE ATT&CK categories.
* **Streamlit Interface:** Interactive dashboard for SOC analyst workflows.

---

## 📂 Project Structure

```text
defense-cyber-log-engine/
├── app.py              # Main Streamlit application
├── requirements.txt    # Python dependencies
├── README.md           # Project documentation
└── sample_logs.log     # Test dataset