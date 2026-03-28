# 🛡️SOC-LogParser: Advanced HTTP Threat Detection & Log Analysis | by cbrkrtek

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Security Focus](https://img.shields.io/badge/Focus-CyberSecurity-red.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](#)

**Log analyzer** is a high-performance Python-based analytical tool leveraging the **Pandas** library to automate the audit of web server logs (Nginx/Apache). It identifies exploitation attempts, performs behavioral analysis, and generates executive-level security incident reports. It was my first python script for automatization and analysis logs.

---

## 🚀 Main Capabilities

The analyzer provides a comprehensive suite of tools for proactive web security monitoring:

* **High-Speed Parsing**: Leverages the **Pandas engine** to process large `access.log` files with minimal memory overhead.
* **Entropy-Based Detection**: Uses **Shannon Entropy** to identify obfuscated or encrypted payloads (Base64, Hex, Polymorphic code) that often bypass traditional WAF signatures.
* **Contextual Scoring**: Implements a dynamic risk-weighting system that correlates:
    * Signature matches (Regex)
    * HTTP status codes (e.g., higher risk for `200 OK` responses)
    * User-Agent reputation
    * Structural anomalies in URIs
* **Hybrid Geolocation**: Identifies attacker origin using local **GeoLite2** databases, ensuring zero-latency analysis.
* **SIEM-Ready Output**: Generates structured **JSONL** (JSON Lines) alerts, making it easy to stream data into **Elasticsearch, Splunk, or Wazuh**.
* **Passive Fingerprinting**: Detects automated vulnerability scanners and exploitation frameworks via specialized User-Agent analysis.

---

## 🔬 Threat Intelligence Coverage

The system is pre-configured to detect a wide range of common web-based attack vectors:

| Attack Category | Detection Method | Description |
| :--- | :--- | :--- |
| **SQL Injection (SQLi)** | Signature + Logic | Detects `UNION SELECT`, `OR 1=1`, and schema exhaustion attempts. |
| **Cross-Site Scripting (XSS)** | Signature + Entropy | Identifies `<script>` tags, event handlers, and obfuscated JS payloads. |
| **Remote Code Execution (RCE)** | Signature + Entropy | Flags usage of `eval()`, `base64_decode()`, and `system()` calls. |
| **Path Traversal** | Signature | Detects attempts to access sensitive files like `/etc/passwd` or `win.ini`. |
| **Tool Detection** | User-Agent Fingerprint | Identifies `sqlmap`, `nmap`, `nikto`, `dirbuster`, and other scanners. |
| **Obfuscated Payloads** | Shannon Entropy | Flags high-entropy strings often used in web shells and exploit delivery. |
| **IP Reputation** | VirusTotal API | Cross-references suspicious IPs with global malware and phishing databases. |
---
## 💻 Technology Stack

The analyzer is built with a focus on performance, accuracy, and ease of integration:

* **Language**: [Python 3.10+](https://www.python.org/) — The core logic for log parsing and threat analysis.
* **Data Analysis**: [Pandas](https://pandas.pydata.org/) — High-performance library used for processing large `access.log` files and structured data manipulation.
* **Threat Intelligence**:
    * **[MaxMind GeoIP2](https://www.maxmind.com/)**: Local binary database integration for high-speed offline IP geolocation.
    * **[VirusTotal API v3](https://developers.virustotal.com/reference/overview)**: Cloud-based reputation scoring for identifying known malicious IP addresses.
* **Detection Algorithms**:
    * **Regex Engine**: Advanced regular expressions for signature-based attack detection (SQLi, XSS, RCE).
    * **Shannon Entropy**: Mathematical approach to detect obfuscated payloads and non-human-readable data patterns.
* **Data Format**: [JSONL (JSON Lines)](https://jsonlines.org/) — Optimized output format for seamless integration with SIEM systems (ElasticSearch, Splunk).

---
## 📂 Project Structure

To ensure the analyzer functions correctly, your project directory should look like this:

```text
SOC-LogParser/
├── venv/                   # Virtual environment folder (created automatically)
├── SOC-LogParser.py        # Main python code
├── requirements.txt        # List of dependencies (pandas, requests, geoip2)
├── access.log              # web server logs aka input file
├── GeoLite2-City.mmdb      # MaxMind database (must be downloaded manually)
├── threats.jsonl           # Generated threat alerts (output file)
└── README.md               # Project documentatio
```
##  🛠 Installation & Setup

Follow these steps to get the analyzer running on your system.

### 1. Initialize Project Directory
Open your terminal and create a dedicated workspace:
```bash
mkdir SOC-LogParser && cd parser
```
Then sign up at ![](https://www.virustotal.com/) and copy your API Key from the API Key section in your profile in VirusTotal.
Paste it in a variable **VT_API_KEY**.

### 2. Set up virtual everionment
```bash
python3 -m venv venv
source venv/bin/activate
```
### 3. Install Required Libraries
```bash
pip install pandas geoip2 requests
```
### 4. Configure Intelligence Databases
The analyzer relies on local and cloud intelligence for accurate detection. 

**For MaxMind GeoIP2** you need to sign up your free account in this platform, then download the GeoLite2 City binary database (.mmdb format) and place the GeoLite2-City.mmdb file directly in the **parser** folder.

**For VirusTotal** you need to sign up your free account in this platform, then paste **API KEY** in code.
### 5*. Some tips on how it should look:
![](https://github.com/cbrkrtek/Threat-Ops-Automation/blob/main/SOC-LogParser/Pictures%20for%20README.md/SOC-LogParser-screenshot-1.PNG)

**Screenshot 1: "Execution SOC-LogParser script"**

![](https://github.com/cbrkrtek/Threat-Ops-Automation/blob/main/SOC-LogParser/Pictures%20for%20README.md/SOC-LogParser-screenshot-2.PNG)

**Screenshot 2: "Result of SOC-LogParser script"**
In a screenshot i don't have a country, because i didn't create GeoLite2-City.mmdb. 
P.S. *access.log.txt* you can see in my directory *SOC-LogParser*. 
## 🔄 Project Updates & Changelog
## 🚀 [v1.3.0] - 2026-03-28 (Current)
### Added
- **Shannon Entropy Analysis**: Detects obfuscated, Base64-encoded, and encrypted payloads in URIs that bypass traditional regex filters.
- **Hybrid Geolocation & Intelligence**: 
  - Integrated **MaxMind GeoIP2** for instant, offline country identification.
  - Added **VirusTotal API** integration to fetch real-time IP reputation for high-risk threats.
- **Smart Scoring System**: Context-aware threat leveling that correlates HTTP status codes (e.g., 200 OK), signature matches, and entropy scores.
- **User-Agent Fingerprinting**: Automatic detection of common attack tools like `sqlmap`, `nmap`, and `nikto`.
- **SIEM Integration**: Exported results to **JSONL format** (JSON Lines) for easy ingestion into ELK Stack, Splunk, or Wazuh.

### Fixed
- **Case Sensitivity**: All signature matching is now case-insensitive (detects `sElEcT` as `SELECT`).
- **False Positive Reduction**: Added logic to prioritize threats based on server response status and entropy thresholds.
## 🚀 [v1.1.1] - 2026-03-22
**Intelligence Enrichment & Stability**
- **Added:** Integration with **VirusTotal API v3** to provide real-time reputation scoring for suspicious IP addresses.
- **Added:** Automated **Threat Intelligence enrichment** (mapping local detections to global threat databases).
- **Fixed:** Robust exception handling for OS-level permission errors when accessing protected log directories.

## 🚀 [v1.1.0] - 2026-03-07
**Created fundamentals to improve future versions**
- **Feature:** Migrated core processing to **Pandas**, enabling high-speed analysis of large-scale datasets.
- **Feature:** Introduced **DoS/HTTP Flood detection** based on configurable request-per-IP thresholds.
- **Detection:** Implemented initial signature-based detection for **SQL Injection**,**Cross-Site Scripting (XSS)** and **Path Traversal**.
- **Added:** Expanded signature library to detect **RCE** (Remote Code Execution) and attempts to access **Sensitive Files** (.env, .git, config).
- **Reporting:** Created the first version of the **HTML Report** generator using Bootstrap tables.
- **Statistics:** Added basic console telemetry (Total requests, Unique IPs, and HTTP Status Code distribution).
- **Core:** Developed the primary log parsing engine using **Regular Expressions (Regex)** for Nginx/Apache combined log formats.
