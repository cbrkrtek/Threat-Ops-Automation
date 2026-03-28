###Created by cbrkrtek:https://github.com/cbrkrtek###
import pandas as pd
import re, json, math, os, time, requests, geoip2.database
from collections import Counter
from datetime import datetime
LOG_FILE = 'access.log'
OUTPUT_JSONL = 'threats.jsonl' 
GEOIP_DB = 'GeoLite2-City.mmdb'
VT_API_KEY = 'your API-KEY' #here you need to paste an API-KEY from VirusTotal account

SIGNATURES = { # сase-insensitive regex patterns for common web attacks
    "SQLi": re.compile(r"(SELECT|UNION|INSERT|--|OR\s+1=1|information_schema)", re.I),
    "XSS": re.compile(r"(<script|alert\(|onerror|onclick)", re.I),
    "RCE": re.compile(r"(base64_decode|system\(|eval\(|exec\(|passthru)", re.I),
    "PathTraversal": re.compile(r"(\.\.\/|/etc/passwd|/windows/win\.ini)", re.I)
}

BAD_AGENTS = re.compile(r"(sqlmap|nmap|nikto|dirbuster|zgrab)", re.I) # signatures for automated security scanners and bots

def calculate_entropy(text): #calculate Shannon entropy to detect obfuscated or encoded payloads.
                             #important to understand, that high entropy usually indicates non-human readable data (Base64, shellcodes)!!!
    if not text or len(text) < 5: return 0
    text = re.sub(r'%[0-9a-fA-F]{2}', 'X', text) #normalize URL encoding (replace %xx with X) to avoid skewing results
    probs = [n / len(text) for n in Counter(text).values()]
    return round(-sum(p * math.log2(p) for p in probs), 2)

def get_vt_data(ip): #fetches IP reputation from VirusTotal API v3.
                     #used only for high-risk alerts to conserve API quota.
    if not VT_API_KEY or VT_API_KEY == 'your API-KEY': return None
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        time.sleep(0.5) #rate limiting, free tier allows 4 requests per minute
        resp = requests.get(url, headers=headers, timeout=5)
        if resp.status_code == 200:
            stats = resp.json()['data']['attributes']['last_analysis_stats']
            return {"malicious": stats['malicious'], "suspicious": stats['suspicious']}
    except: pass
    return None
def process():
    print(f" Starting SOC-LogParser")
    geo_reader = None #initialize GeoIP2 Reader if database exists
    if os.path.exists(GEOIP_DB):
        geo_reader = geoip2.database.Reader(GEOIP_DB)
        print("Local GeoIP DB loaded.")
    else:
        print("GeoIP DB not found. Country detection disabled.")
    regex = r'(?P<ip>[\d\.]+) - - \[(?P<date>.*?)\] "(?P<method>\w+) (?P<uri>.*?) HTTP/.*?" (?P<status>\d+) (?P<size>\d+) "(?P<referrer>.*?)" "(?P<agent>.*?)"'#regex for Nginx/Apache Combined Log Format
    try:
        with open(LOG_FILE, 'r') as f: #load and parse the log file into a list of dictionaries
            valid_lines = [re.search(regex, l).groupdict() for l in f if re.search(regex, l)]
    except: print("access.log not found"); return
    df = pd.DataFrame(valid_lines) #use Pandas for efficient data handling
    df['status'] = df['status'].astype(int)
    with open(OUTPUT_JSONL, 'w') as out_f:
        for _, row in df.iterrows():
            #1.signature-based Analysis
            uri_hits = [n for n, p in SIGNATURES.items() if p.search(row['uri'])]
            #2.automated tool identification
            bot_detected = True if BAD_AGENTS.search(row['agent']) else False
            #3.statistical anomaly analysis (entropy)
            entropy = calculate_entropy(row['uri']) #calculate Shannon entropy
            #4.multi-factor Scoring Logic
            #base score from hits, bots, and high entropy
            score = len(uri_hits) * 3 + (5 if bot_detected else 0) + (4 if entropy > 5.0 else 0)
            #escalation: Successful attacks (status 200) are significantly more critical
            if row['status'] == 200 and score > 0: score *= 1.5
            level = "LOW"#severity levels
            if score >= 8: level = "CRITICAL"
            elif score >= 5: level = "HIGH"
            elif score >= 2: level = "MEDIUM"
            #5.geolocation enrichment
            geo = {"country": "Unknown"}
            if geo_reader:
                try:
                    res = geo_reader.city(row['ip'])
                    geo = {"country": res.country.name, "iso": res.country.iso_code}
                except: pass
            #6.external Threat Intel Enrichment(VirusTotal)
            vt_info = None
            if level in ["HIGH", "CRITICAL"]:
                print(f"[!] threat found!checking VirusTotal for {row['ip']}...")
                vt_info = get_vt_data(row['ip'])
            #construct the final event object
            event = {
                "ts": datetime.now().isoformat(),
                "ip": row['ip'],
                "uri": row['uri'],
                "level": level,
                "geo": geo,
                "vt_stats": vt_info,
                "entropy": entropy,
                "signatures": uri_hits
            }
            out_f.write(json.dumps(event, ensure_ascii=False) + '\n')
    if geo_reader: geo_reader.close()
    print(f"Analysis saved to {OUTPUT_JSONL}")#export to SIEM-ready format( .jsonl)
if __name__ == "__main__":
    process()
###Created by cbrkrtek:https://github.com/cbrkrtek###
