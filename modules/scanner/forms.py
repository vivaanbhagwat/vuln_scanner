"""Form Analysis Module - Detects form security issues."""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


def analyze_forms(url):
    """
    Analyze HTML forms for security vulnerabilities.
    Returns a list of vulnerability findings.
    """
    findings = []

    try:
        resp = requests.get(url, timeout=10)
        soup = BeautifulSoup(resp.text, 'html.parser')
        forms = soup.find_all('form')

        if not forms:
            return [{
                'type': 'insecure_form',
                'severity': 'info',
                'description': 'No forms detected on the page',
                'details': 'No HTML forms were found on the target page.'
            }]

        for i, form in enumerate(forms, 1):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            form_url = urljoin(url, action) if action else url

            # Check for forms submitting over HTTP
            if form_url.startswith('http://'):
                findings.append({
                    'type': 'insecure_form',
                    'severity': 'high',
                    'description': f'Form #{i} submits data over HTTP',
                    'details': (
                        f'Form action points to {form_url} which uses HTTP. '
                        'Form data including credentials will be transmitted in plaintext.'
                    ),
                    'solution': 'Configure your web server to use HTTPS and update all form action URLs to use the https:// protocol.'
                })

            # Check for password fields without HTTPS
            password_fields = form.find_all('input', {'type': 'password'})
            if password_fields and not url.startswith('https'):
                findings.append({
                    'type': 'insecure_form',
                    'severity': 'high',
                    'description': f'Form #{i} has password field on non-HTTPS page',
                    'details': 'Password fields should only appear on HTTPS pages to prevent credential theft.',
                    'solution': 'Move the login form and all pages containing sensitive input to an HTTPS-secured domain.'
                })

            # Check for missing CSRF protection
            csrf_indicators = form.find_all('input', {'type': 'hidden'})
            has_csrf = any(
                'csrf' in (inp.get('name', '') + inp.get('id', '')).lower()
                for inp in csrf_indicators
            )
            if method == 'post' and not has_csrf:
                findings.append({
                    'type': 'missing_csrf',
                    'severity': 'medium',
                    'description': f'Form #{i} may lack CSRF protection',
                    'details': (
                        'POST form does not appear to have a CSRF token. '
                        'This could allow cross-site request forgery attacks.'
                    ),
                    'solution': 'Implement CSRF tokens for all state-changing requests (POST, PUT, DELETE). Use a framework-provided library like Flask-WTF.'
                })

            # Check for autocomplete on sensitive fields
            sensitive_inputs = form.find_all('input', {'type': ['password', 'email', 'tel']})
            for inp in sensitive_inputs:
                if inp.get('autocomplete') not in ['off', 'new-password']:
                    field_name = inp.get('name', inp.get('type', 'unknown'))
                    findings.append({
                        'type': 'insecure_form',
                        'severity': 'low',
                        'description': f'Form #{i}: Autocomplete enabled on sensitive field "{field_name}"',
                        'details': (
                            'Sensitive form fields should have autocomplete="off" to prevent '
                            'browsers from caching sensitive data.'
                        ),
                        'solution': f'Set autocomplete="off" on the sensitive input field "{field_name}".'
                    })

            # Check for GET method on forms with sensitive data
            if method == 'get' and password_fields:
                findings.append({
                    'type': 'insecure_form',
                    'severity': 'high',
                    'description': f'Form #{i} sends password via GET method',
                    'details': (
                        'Using GET for forms containing password fields exposes credentials '
                        'in the URL, browser history, and server logs.'
                    ),
                    'solution': 'Change the form method to POST for all forms that contain sensitive fields like passwords.'
                })

    except requests.exceptions.RequestException as e:
        findings.append({
            'type': 'insecure_form',
            'severity': 'medium',
            'description': 'Unable to analyze forms',
            'details': f'Request failed: {str(e)}'
        })

    return findings
