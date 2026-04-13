"""XSS Test Module - Safe reflected XSS detection."""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode


# Safe test payloads (non-malicious, used only for detection)
XSS_PAYLOADS = [
    '<script>alert("xss_test")</script>',
    '"><img src=x onerror=alert("xss_test")>',
    "'-alert('xss_test')-'",
    '<svg onload=alert("xss_test")>',
]


def test_xss(url):
    """
    Test for reflected XSS vulnerabilities using safe payloads.
    Only tests on the target URL's own parameters.
    Returns a list of vulnerability findings.
    """
    findings = []
    tested = False

    try:
        # First, discover forms and input parameters
        resp = requests.get(url, timeout=10)
        soup = BeautifulSoup(resp.text, 'html.parser')

        # Test URL parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if params:
            for param_name in params:
                for payload in XSS_PAYLOADS:
                    tested = True
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

                    try:
                        test_resp = requests.get(test_url, timeout=10)
                        if payload in test_resp.text:
                            findings.append({
                                'type': 'xss',
                                'severity': 'high',
                                'description': f'Reflected XSS detected in parameter "{param_name}"',
                                'details': (
                                    f'The parameter "{param_name}" reflects user input without '
                                    f'sanitization. Payload was found in the response body, '
                                    'indicating potential XSS vulnerability.'
                                ),
                                'solution': 'Use a security library to encode output based on its context (e.g., HTML, attribute, JS). For Flask/Jinja2, ensure auto-escaping is enabled.'
                            })
                            break  # One finding per parameter is enough
                    except requests.exceptions.RequestException:
                        continue

        # Test form inputs
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
                for payload in XSS_PAYLOADS[:2]:  # Test fewer payloads for forms
                    tested = True
                    form_data = {input_name: payload}

                    # Fill other required fields with dummy data
                    for other_inp in inputs:
                        other_name = other_inp.get('name')
                        if other_name and other_name != input_name:
                            form_data[other_name] = 'test'

                    try:
                        if method == 'post':
                            test_resp = requests.post(form_url, data=form_data, timeout=10)
                        else:
                            test_resp = requests.get(form_url, params=form_data, timeout=10)

                        if payload in test_resp.text:
                            findings.append({
                                'type': 'xss',
                                'severity': 'high',
                                'description': f'Reflected XSS in form #{i}, field "{input_name}"',
                                'details': (
                                    f'Form input "{input_name}" reflects user input without '
                                    'proper sanitization, enabling potential XSS attacks.'
                                )
                            })
                            break
                    except requests.exceptions.RequestException:
                        continue

        if not tested:
            findings.append({
                'type': 'xss',
                'severity': 'info',
                'description': 'No injectable parameters found for XSS testing',
                'details': 'No URL parameters or text form inputs were found to test.'
            })
        elif not findings:
            findings.append({
                'type': 'xss',
                'severity': 'info',
                'description': 'No reflected XSS vulnerabilities detected',
                'details': 'Tested payloads were not reflected in response. Site may have proper input sanitization.'
            })

    except requests.exceptions.RequestException as e:
        findings.append({
            'type': 'xss',
            'severity': 'medium',
            'description': 'XSS testing could not be completed',
            'details': f'Request failed: {str(e)}'
        })

    return findings
