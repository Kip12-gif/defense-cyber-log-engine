import os
import re
import streamlit as st

# Page Configuration
st.set_page_config(
    page_title="Defense Cyber Log Extraction Engine",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Defense Cyber Log Extraction Engine")
st.caption("Autonomous Threat Detection & Incident Isolation System")

# Sidebar Configuration
st.sidebar.header("Engine Settings")
execution_mode = st.sidebar.radio(
    "Execution Mode",
    ["Offline Mock Mode (No Key Required)", "Live API Mode (OpenAI)"],
    index=0
)

api_key = ""
model_choice = "gpt-4o"

if execution_mode == "Live API Mode (OpenAI)":
    api_key = st.sidebar.text_input("OpenAI API Key", type="password", value=os.getenv("OPENAI_API_KEY", ""))
    model_choice = st.sidebar.selectbox("Model", ["gpt-4o", "gpt-4o-mini"], index=0)
else:
    st.sidebar.success("⚡ Running locally using signature-based threat parsing.")

# SYSTEM PROMPT (Used in Live API Mode)
SYSTEM_PROMPT = """
SYSTEM PROMPT: ATTACK LOG EXTRACTION ENGINE

ROLE: You are an automated SIEM parser specialized in isolating hostile cyber activity from raw log dumps.

TASK: Filter the provided log block. Ignore all benign and normal system events. Extract and highlight ONLY lines or clusters indicating an attack or reconnaissance effort.

DETECTION INDICATORS TO PARSE:
1. Directory Traversal / LFI / RFI (e.g., ../, /etc/passwd, %2e%2e%)
2. SQL Injection / NoSQLi (e.g., ' OR 1=1 --, UNION SELECT, sleep())
3. Suspicious Process Executions (e.g., powershell -e, cmd.exe /c, /bin/sh via web service)
4. Rapid Failure Thresholds (e.g., >10 failed logins within 10 seconds from one IP)
5. Web Scanners & Reconnaissance (e.g., Nikto, Gobuster, SQLmap, Nmap)

OUTPUT STRUCTURE:
Format your response using Markdown headers:

### 🚨 Threat Summary
- **Total Log Lines Analyzed:** <Number>
- **Hostile Entries Detected:** <Number>
- **Primary Attack Type(s):** <List>

### ⚠️ Flagged Log Entries
For each detected attack line, provide:
- **Raw Log Line:** `<Exact raw line>`
- **Attacker IP/Source:** `<IP or Account>`
- **Attack Vector:** `<Specific Technique>`
- **Severity:** `[CRITICAL / HIGH / MEDIUM / LOW]`

### 💡 Recommended Mitigation
- <Single bullet point immediate action item for the SOC team>
"""

# Mock Engine Function (Used in Offline Mock Mode)
def run_mock_engine(logs_text):
    lines = [line.strip() for line in logs_text.strip().split("\n") if line.strip()]
    flagged_entries = []
    
    patterns = {
        "Directory Traversal / LFI": r"(\.\./|/etc/passwd|%2e%2e%)",
        "SQL Injection (SQLi)": r"(UNION\s+SELECT|'--|OR\s+1=1|select.*from|user=admin)",
        "Automated Scanner": r"(Nikto|Gobuster|SQLmap|Nmap)",
        "Command Injection / RCE": r"(\(\)\s*\{\s*:;\s*\};|powershell|-c\s+nc|eval-stdin)",
        "Brute Force Attempt": r"(401|4625|Failed login)"
    }
    
    for line in lines:
        detected_vectors = []
        for attack_type, pattern in patterns.items():
            if re.search(pattern, line, re.IGNORECASE):
                detected_vectors.append(attack_type)
        
        if detected_vectors:
            ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
            ip = ip_match.group(0) if ip_match else "Unknown Source"
            
            severity = "CRITICAL" if any(v in ["SQL Injection (SQLi)", "Command Injection / RCE"] for v in detected_vectors) else "HIGH"
            
            flagged_entries.append({
                "line": line,
                "ip": ip,
                "vectors": ", ".join(detected_vectors),
                "severity": severity
            })

    output = f"### 🚨 Threat Summary\n"
    output += f"- **Total Log Lines Analyzed:** {len(lines)}\n"
    output += f"- **Hostile Entries Detected:** {len(flagged_entries)}\n"
    
    all_vectors = list(set([v for entry in flagged_entries for v in entry['vectors'].split(', ')]))
    output += f"- **Primary Attack Type(s):** {', '.join(all_vectors) if all_vectors else 'None Detected'}\n\n"
    
    output += "### ⚠️ Flagged Log Entries\n"
    if flagged_entries:
        for entry in flagged_entries:
            output += f"- **Raw Log Line:** `{entry['line']}`\n"
            output += f"- **Attacker IP/Source:** `{entry['ip']}`\n"
            output += f"- **Attack Vector:** {entry['vectors']}\n"
            output += f"- **Severity:** `[{entry['severity']}]` \n\n"
    else:
        output += "No hostile entries detected. All log lines appear to be normal operational traffic.\n\n"
        
    output += "### 💡 Recommended Mitigation\n"
    if flagged_entries:
        ips = list(set([e['ip'] for e in flagged_entries if e['ip'] != "Unknown Source"]))
        ip_str = f"`{', '.join(ips)}`" if ips else "detected attacker sources"
        output += f"- Immediately isolate and block source IP addresses {ip_str} at the Web Application Firewall (WAF) / boundary router.\n"
    else:
        output += "- Maintain standard system monitoring controls.\n"
        
    return output

# Main UI Inputs
col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("Raw Log Feed Input")
    uploaded_file = st.file_uploader("Upload a raw log file (.txt, .log)", type=["txt", "log"])
    
    default_sample = """10.0.0.12 - - [21/Sep/2026:10:00:01] "GET /index.html HTTP/1.1" 200 1024 "Mozilla/5.0"
198.51.100.44 - - [21/Sep/2026:10:00:12] "GET /etc/passwd HTTP/1.1" 404 230 "Nikto/2.1.6"
10.0.0.15 - - [21/Sep/2026:10:00:15] "GET /about.html HTTP/1.1" 200 2048 "Mozilla/5.0"
203.0.113.88 - - [21/Sep/2026:10:00:22] "GET /login.php?user=admin'-- HTTP/1.1" 200 4520 "Mozilla/5.0"
198.51.100.120 - - [21/Sep/2026:10:01:05] "GET /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1" 404 180 "Gobuster/3.1"
"""

    if uploaded_file is not None:
        raw_logs = uploaded_file.read().decode("utf-8")
    else:
        raw_logs = st.text_area(
            "Or paste raw log block here:",
            value=default_sample,
            height=300
        )

    run_btn = st.button("🚀 Analyze & Extract Attacks", type="primary", use_container_width=True)

with col2:
    st.subheader("Automated Threat Analysis")
    if run_btn:
        if not raw_logs.strip():
            st.warning("Please enter raw logs first.")
        elif execution_mode == "Live API Mode (OpenAI)" and not api_key:
            st.error("Please enter an OpenAI API Key in the sidebar or switch to Offline Mock Mode.")
        else:
            with st.spinner("Analyzing log streams..."):
                if execution_mode == "Offline Mock Mode (No Key Required)":
                    analysis = run_mock_engine(raw_logs)
                    st.markdown(analysis)
                else:
                    try:
                        from openai import OpenAI
                        client = OpenAI(api_key=api_key.strip().strip('"').strip("'"))
                        response = client.chat.completions.create(
                            model=model_choice,
                            messages=[
                                {"role": "system", "content": SYSTEM_PROMPT},
                                {"role": "user", "content": f"RAW LOG BLOCK:\n\n{raw_logs}"}
                            ],
                            temperature=0.1
                        )
                        analysis = response.choices[0].message.content
                        st.markdown(analysis)
                    except Exception as e:
                        st.error(f"Execution Error: {str(e)}")
    else:
        st.info("Click 'Analyze & Extract Attacks' to process the log payload.")