"""SQL Injection Test Module - Safe SQLi detection."""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import re


# Safe SQL injection test payloads
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "1' ORDER BY 1--",
    "1 UNION SELECT NULL--",
]

# Common SQL error patterns indicating vulnerability
SQL_ERROR_PATTERNS = [
    r'SQL syntax.*MySQL',
    r'Warning.*mysql_',
    r'MySqlException',
    r'valid MySQL result',
    r'check the manual that corresponds to your (MySQL|MariaDB)',
    r'PostgreSQL.*ERROR',
    r'Warning.*pg_',
    r'valid PostgreSQL result',
    r'Npgsql\.',
    r'Microsoft.*ODBC.*SQL Server',
    r'SQLServer JDBC Driver',
    r'SqlException',
    r'ORA-\d{5}',
    r'Oracle error',
    r'SQLite.*(?:error|warning)',
    r'sqlite3\.OperationalError',
    r'SQLITE_ERROR',
    r'Unclosed quotation mark',
    r'quoted string not properly terminated',
    r'SQL command not properly ended',
]


def test_sqli(url):
    """
    Test for SQL injection vulnerabilities using safe payloads.
    Returns a list of vulnerability findings.
    """
    findings = []
    tested = False

    try:
        # Get baseline response
        baseline_resp = requests.get(url, timeout=10)
        baseline_length = len(baseline_resp.text)

        # Test URL parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if params:
            for param_name in params:
                for payload in SQLI_PAYLOADS:
                    tested = True
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

                    try:
                        test_resp = requests.get(test_url, timeout=10)

                        # Check for SQL error messages
                        for pattern in SQL_ERROR_PATTERNS:
                            if re.search(pattern, test_resp.text, re.IGNORECASE):
                                findings.append({
                                    'type': 'sqli',
                                    'severity': 'high',
                                    'description': f'SQL Injection detected in parameter "{param_name}"',
                                    'details': (
                                        f'SQL error message found in response when injecting '
                                        f'payload into "{param_name}". The application appears '
                                        'to be vulnerable to SQL injection attacks.'
                                    ),
                                    'solution': 'Always use prepared statements or parameterized queries instead of string concatenation for database operations.'
                                })
                                break

                        # Check for significant response length changes
                        resp_length = len(test_resp.text)
                        if abs(resp_length - baseline_length) > baseline_length * 0.5 and baseline_length > 100:
                            findings.append({
                                'type': 'sqli',
                                'severity': 'medium',
                                'description': f'Suspicious response change in parameter "{param_name}"',
                                'details': (
                                    f'Response length changed significantly ({baseline_length} → {resp_length} chars) '
                                    'when SQL payload was injected. This may indicate SQLi vulnerability.'
                                )
                            })
                            break

                    except requests.exceptions.RequestException:
                        continue

        # Test form inputs
        soup = BeautifulSoup(baseline_resp.text, 'html.parser')
        forms = soup.find_all('form')

        for i, form in enumerate(forms, 1):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            form_url = urljoin(url, action) if action else url
            inputs = form.find_all('input')

            text_inputs = [
                inp for inp in inputs
                if inp.get('type', 'text') in ('text', 'search', 'url', 'email', '')
                and inp.get('name')
            ]

            for inp in text_inputs:
                input_name = inp.get('name')
                for payload in SQLI_PAYLOADS[:2]:
                    tested = True
                    form_data = {input_name: payload}
                    for other_inp in inputs:
                        other_name = other_inp.get('name')
                        if other_name and other_name != input_name:
                            form_data[other_name] = 'test'

                    try:
                        if method == 'post':
                            test_resp = requests.post(form_url, data=form_data, timeout=10)
                        else:
                            test_resp = requests.get(form_url, params=form_data, timeout=10)

                        for pattern in SQL_ERROR_PATTERNS:
                            if re.search(pattern, test_resp.text, re.IGNORECASE):
                                findings.append({
                                    'type': 'sqli',
                                    'severity': 'high',
                                    'description': f'SQL Injection in form #{i}, field "{input_name}"',
                                    'details': (
                                        f'SQL error detected when injecting payload into '
                                        f'form field "{input_name}". Database queries may be '
                                        'constructing SQL from unsanitized user input.'
                                    )
                                })
                                break
                    except requests.exceptions.RequestException:
                        continue

        if not tested:
            findings.append({
                'type': 'sqli',
                'severity': 'info',
                'description': 'No injectable parameters found for SQLi testing',
                'details': 'No URL parameters or text form inputs were found to test.'
            })
        elif not findings:
            findings.append({
                'type': 'sqli',
                'severity': 'info',
                'description': 'No SQL injection vulnerabilities detected',
                'details': 'No SQL error patterns found in responses. Application may use parameterized queries.'
            })

    except requests.exceptions.RequestException as e:
        findings.append({
            'type': 'sqli',
            'severity': 'medium',
            'description': 'SQL injection testing could not be completed',
            'details': f'Request failed: {str(e)}'
        })

    return findings
