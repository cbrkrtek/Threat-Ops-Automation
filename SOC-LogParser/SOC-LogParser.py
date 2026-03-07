###Created by cbrkrtek:https://github.com/cbrKrtek###
import pandas as pd
import re
import os
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
    def __init__(self):
        # pattern for nginx/apache
        self.log_pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<date>.*?)\] "(?P<method>\w+) (?P<url>.*?) HTTP/.*?" (?P<status>\d+) (?P<size>\d+)'
        #attack signatures
        self.signatures = {
            'SQLi': r'(UNION|SELECT|INSERT|DELETE|DROP|--|OR 1=1|benchmark|sleep)',
            'Path Traversal': r'(\.\.\/|\.\.\\|/etc/passwd|/etc/shadow|boot\.ini)',
            'XSS': r'(<script>|alert\(|%3Cscript%3E|onerror|onload)',
            'RCE': r'(ncat|bash|/bin/sh|cmd\.exe|powershell|curl\s|wget\s)',
            'Sensitive Files': r'(\.env|\.git|\.config|config\.php|web\.config)'
        }
    def load_logs(self, file_path: str) -> pd.DataFrame:
        data = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    match = re.search(self.log_pattern, line)
                    if match:
                        entry = match.groupdict()
                        #parce time
                        try:
                            #clean UTC
                            clean_date = entry['date'].split(' ')[0]
                            entry['timestamp'] = datetime.strptime(clean_date, '%d/%b/%Y:%H:%M:%S')
                        except:
                            entry['timestamp'] = None
                        data.append(entry)
        except PermissionError:
            print(f"permission error! launch this file using sudo")
            return pd.DataFrame()
        df = pd.DataFrame(data)
        if not df.empty:
            df['status'] = df['status'].astype(int)
        return df
    def analyze_threats(self, df: pd.DataFrame):
        #looking for anomalies and signatures
        findings = []
        for attack_name, pattern in self.signatures.items():
            matches = df[df['url'].str.contains(pattern, case=False, na=False)].copy()
            if not matches.empty:
                matches['threat_category'] = attack_name
                findings.append(matches)
        return pd.concat(findings) if findings else pd.DataFrame()
    def detect_flood(self, df: pd.DataFrame, limit: int = 100):
        #detect http flude via IP
        counts = df['ip'].value_counts()
        return counts[counts > limit]
    def generate_report(self, df: pd.DataFrame, threats: pd.DataFrame, flood: pd.Series):
        #generate final report:
        report_file = f"threat_analysis_{datetime.now().strftime('%Y%m%d_%H%M')}.html"
        #here i created an html pattern for good view
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
                        {threats[['ip', 'threat_category', 'url', 'status']].to_html(classes='table table-striped table-hover')}
                        <hr>
                        <h3 class="text-warning">Suspicious activity (DoS/Flood):</h3>
                        {flood.to_frame(name='requests count:').to_html(classes='table table-bordered')}
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"html report is created {report_file}")

def main():
    #path to log!!!
    LOG_PATH = '/var/log/nginx/access.log.txt'
    analyze = check()
    df = analyze.load_logs(LOG_PATH)
    if df.empty:
        print(f"can't find a file!")
        return
    # signature analyze
    threats = analyze.analyze_threats(df)
    # flood analyze
    flood = analyze.detect_flood(df, limit=50)
    # 3.echo statistic to a console
    print(f"\nSTATISTIC")
    print(f"All requests: {len(df)}")
    print(f"Unique IP: {df['ip'].nunique()}")
    print(f"errors like: 4xx/5xx: {len(df[df['status'] >= 400])}")
    # 4.saving report
    analyze.generate_report(df, threats, flood)
if __name__ == "__main__":
    main()
###Created by cbrkrtek:https://github.com/cbrKrtek###