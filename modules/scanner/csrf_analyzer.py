"""CSRF Analyzer Module - Detailed detection of Cross-Site Request Forgery vulnerabilities."""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def test_csrf(url):
    """Analyze forms specifically for CSRF vulnerabilities."""
    findings = []
    try:
        resp = requests.get(url, timeout=10)
        soup = BeautifulSoup(resp.text, 'html.parser')
        forms = soup.find_all('form')

        for i, form in enumerate(forms, 1):
            method = form.get('method', 'get').lower()
            if method != 'post':
                continue

            # Standard CSRF token names
            token_names = ['csrf', 'xsrf', 'token', 'authenticity_token', 'requestverificationtoken']
            
            inputs = form.find_all('input')
            has_token = False
            for inp in inputs:
                name = (inp.get('name', '') or '').lower()
                id_attr = (inp.get('id', '') or '').lower()
                if any(t in name or t in id_attr for t in token_names):
                    has_token = True
                    break
            
            if not has_token:
                findings.append({
                    'type': 'csrf',
                    'severity': 'high',
                    'description': f'Likely CSRF vulnerability in Form #{i}',
                    'details': (
                        f'Form #{i} on {url} uses POST but does not contain a visible CSRF token. '
                        'Attackers can force users to submit this form without their consent.'
                    ),
                    'solution': 'Implement synchronized token pattern (anti-CSRF tokens) for all state-changing forms.'
                })

    except requests.exceptions.RequestException as e:
        findings.append({
            'type': 'csrf',
            'severity': 'medium',
            'description': 'CSRF analysis failed',
            'details': str(e)
        })

    return findings
