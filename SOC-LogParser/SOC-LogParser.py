###Created by cbrkrtek:https://github.com/cbrkrtek###
#!/usr/share/bin
import pandas as pd
import re
import os
import requests # we need to write: pip install requests
import time
from datetime import datetime
from typing import Optional, List
class Colors:
    HEADER = '\033[95m'
    INFO = '\033[94m'
    SUCCESS = '\033[92m'
    WARNING = '\033[93m'
    DANGER = '\033[91m'
    ENDC = '\033[0m'
class check:
    def __init__(self, vt_api_key: Optional[str] = None):
        # pattern for nginx/apache
        self.log_pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<date>.*?)\] "(?P<method>\w+) (?P<url>.*?) HTTP/.*?" (?P<status>\d+) (?P<size>\d+)'
        # attack signatures
        self.signatures = {
            'SQLi': r'(UNION|SELECT|INSERT|DELETE|DROP|--|OR 1=1|benchmark|sleep)',
            'Path Traversal': r'(\.\.\/|\.\.\\|/etc/passwd|/etc/shadow|boot\.ini)',
            'XSS': r'(<script>|alert\(|%3Cscript%3E|onerror|onload)',
            'RCE': r'(ncat|bash|/bin/sh|cmd\.exe|powershell|curl\s|wget\s)',
            'Sensitive Files': r'(\.env|\.git|\.config|config\.php|web\.config)'
        }
        # API key from virustotal
        self.vt_api_key = vt_api_key
    def check_vt_reputation(self, ip: str) -> str:
        """check ip via  VirusTotal API v3"""
        if not self.vt_api_key:
            return "No API Key Provided"
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": self.vt_api_key}
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                return f"MALICIOUS ({malicious} hits)" if malicious > 0 else "Clean / Unknown"
            elif response.status_code == 429:
                return "Quota Exceeded (API limit)"
            else:
                return f"Error {response.status_code}"
        except Exception as e:
            return f"Connection Error: {str(e)}"

    def load_logs(self, file_path: str) -> pd.DataFrame:
        data = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    match = re.search(self.log_pattern, line)
                    if match:
                        entry = match.groupdict()
                        try:
                            clean_date = entry['date'].split(' ')[0]
                            entry['timestamp'] = datetime.strptime(clean_date, '%d/%b/%Y:%H:%M:%S')
                        except:
                            entry['timestamp'] = None
                        data.append(entry)
        except PermissionError:
            print(f"{Colors.DANGER}permission error! launch this file using sudo{Colors.ENDC}")
            return pd.DataFrame()
        except FileNotFoundError:
            print(f"{Colors.DANGER}File not found: {file_path}{Colors.ENDC}")
            return pd.DataFrame()
        df = pd.DataFrame(data)
        if not df.empty:
            df['status'] = df['status'].astype(int)
        return df
    def analyze_threats(self, df: pd.DataFrame):
        findings = []
        for attack_name, pattern in self.signatures.items():
            matches = df[df['url'].str.contains(pattern, case=False, na=False)].copy()
            if not matches.empty:
                matches['threat_category'] = attack_name
                findings.append(matches)
        return pd.concat(findings) if findings else pd.DataFrame()
    def detect_flood(self, df: pd.DataFrame, limit: int = 100):
        counts = df['ip'].value_counts()
        return counts[counts > limit]
    def generate_report(self, df: pd.DataFrame, threats: pd.DataFrame, flood: pd.Series):
        report_file = f"threat_analysis_{datetime.now().strftime('%Y%m%d_%H%M')}.html"
        if not threats.empty and self.vt_api_key:
            print(f"{Colors.INFO}Enriching threat report with VirusTotal data...{Colors.ENDC}")
            unique_ips = threats['ip'].unique()
            vt_results = {}
            for ip in unique_ips:
                print(f"Checking IP: {ip}")
                vt_results[ip] = self.check_vt_reputation(ip)
                time.sleep(15) # Because I used a free API, need to wait ( 4 requests a minute)
            threats['VT_Reputation'] = threats['ip'].map(vt_results)
        html = f"""
        <html>
        <head>
            <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
            <title>Cyber Security Report</title>
        </head>
        <body class="bg-light">
            <div class="container mt-5">
                <div class="card shadow">
                    <div class="card-header bg-dark text-white"><h1>Security Incident Report</h1></div>
                    <div class="card-body">
                        <p><strong>date of analysis:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                        <hr>
                        <h3 class="text-danger">detected threats: {len(threats)}</h3>
                        {threats.to_html(classes='table table-striped table-hover') if not threats.empty else "<p>No threats found</p>"}
                        <hr>
                        <h3 class="text-warning">Suspicious activity (DoS/Flood):</h3>
                        {flood.to_frame(name='requests count:').to_html(classes='table table-bordered') if not flood.empty else "<p>No flood activity</p>"}
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"{Colors.SUCCESS}html report is created: {report_file}{Colors.ENDC}")
def main():
    #Here you need to paste your API key from virustotal
    VT_API_KEY = "your_API"
    LOG_PATH = '/path/to/access.log' # Here you need to paste a path to your file "access.log"
    analyze = check(vt_api_key=VT_API_KEY)
    df = analyze.load_logs(LOG_PATH)
    if df.empty:
        print(f"{Colors.WARNING}can't find or parse a file!{Colors.ENDC}")
        return
    threats = analyze.analyze_threats(df)
    flood = analyze.detect_flood(df, limit=50)
    print(f"\n{Colors.HEADER}STATISTIC{Colors.ENDC}")
    print(f"All requests: {len(df)}")
    print(f"Unique IP: {df['ip'].nunique()}")
    print(f"Errors like 4xx/5xx: {len(df[df['status'] >= 400])}")
    analyze.generate_report(df, threats, flood)
if __name__ == "__main__":
    main()
###Created by cbrkrtek:https://github.com/cbrkrtek###
