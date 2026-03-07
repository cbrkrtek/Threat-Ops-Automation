
# 🛡️SOC-LogParser: Advanced HTTP Threat Detection & Log Analysis | by cbrkrtek

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Security Focus](https://img.shields.io/badge/Focus-CyberSecurity-red.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](#)

**Log analyzer** is a high-performance Python-based analytical tool leveraging the **Pandas** library to automate the audit of web server logs (Nginx/Apache). It identifies exploitation attempts, performs behavioral analysis, and generates executive-level security incident reports. It was my first python script for automatization and analysis logs.

---

## 🔍 Main Capabilities

This tool automates critical tasks for SOC analysts:
* **Log Parsing & Normalization:** Developed a robust regex-based parser to transform unstructured Nginx/Apache logs into structured DataFrames using Pandas
* **Signature-based Detection Engine:** Implemented a detection logic to identify common web attack vectors including SQLi, XSS, RCE, and Path Traversal by mapping logs against predefined security signatures.
* **Behavioral Analysis (Traffic Anomalies):** Integrated a flood-detection module to identify potential DoS/Brute-force attempts by calculating request-per-IP thresholds.
* **Automated Incident Reporting** Created a reporting system that generates HTML-based Security Incident Reports, facilitating faster data interpretation for L1/L2 analysts.
* **Error Handling & Scalability:** Designed the tool to handle large log files and manage OS-level permissions (sudo check), ensuring reliability in a production-like environment.
---

## 📋 Threat Intelligence Coverage

The engine is pre-configured to detect the following common attack vectors:

| Category | Detection Logic |
| :--- | :--- |
| **SQL Injection** | Injection of SQL syntax (`UNION`, `SELECT`, `OR 1=1`, `benchmark`) |
| **Cross-Site Scripting** | Malicious script execution attempts (`<script>`, `onerror`, `onload`) |
| **Remote Code Execution** | System command execution via web requests (`/bin/sh`, `powershell`, `wget`) |
| **Path Traversal** | Unauthorized filesystem access attempts (`/etc/passwd`, `../`, `boot.ini`) |
| **Information Disclosure** | Probing for sensitive files (`.env`, `.git`, `config.php`, `web.config`) |

---
## 🛠 Technology Stack

* **Language:** Python 3.10
* **Data Analysis:** [Pandas](https://pandas.pydata.org/)
* **Text Processing:** Regular Expressions (Re)
* **Reporting:** HTML5 / Bootstrap 4.5

---

## 🚀 Deployment & Usage

### 1. Prerequisites
Ensure you have Python installed and the Pandas library available:
```bash
pip install pandas
```
### 2. Execution
For execution you can paste this python script to a .py file in your Operational System and change variable **LOG_PATH**. In this variable you need to paste a path to a file access.log.txt or basic access.log.
## Script execution results and main conclusions
If everything goes well and you manage to run the script, you should see a file like this on your desktop:

![](https://github.com/cbrKrtek/Threat-Ops-Automation/blob/main/SOC-LogParser/Pictures%20for%20README.md/screenshot_desktop.PNG)

Click on this and then in a browser you will see a report for logs

![](https://github.com/cbrKrtek/Threat-Ops-Automation/blob/main/SOC-LogParser/Pictures%20for%20README.md/report1.PNG)

![](https://github.com/cbrKrtek/Threat-Ops-Automation/blob/main/SOC-LogParser/Pictures%20for%20README.md/report2.PNG)
