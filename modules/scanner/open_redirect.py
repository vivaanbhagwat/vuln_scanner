"""Open Redirect Module - Tests for unvalidated redirects."""
import requests
from urllib.parse import urlparse, parse_qs, urlencode

# Redirection payloads
REDIRECT_PAYLOADS = [
    'https://www.google.com',
    '//www.google.com',
    '/\/\/google.com',
]

def test_open_redirect(url):
    """Test URL parameters for open redirect vulnerabilities."""
    findings = []
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return []

        # Common redirect parameter names
        redirect_params = ['url', 'next', 'redirect', 'return', 'goto', 'target']

        for param_name in params:
            if any(rp in param_name.lower() for rp in redirect_params):
                for payload in REDIRECT_PAYLOADS:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

                    try:
                        resp = requests.get(test_url, timeout=10, allow_redirects=False)
                        if resp.status_code in (301, 302, 303, 307, 308):
                            location = resp.headers.get('Location', '')
                            if 'google.com' in location:
                                findings.append({
                                    'type': 'open_redirect',
                                    'severity': 'medium',
                                    'description': f'Open Redirect detected in "{param_name}"',
                                    'details': f'The application redirects to an external site based on the "{param_name}" parameter. Redirected to: {location}',
                                    'solution': 'Validate redirect targets against a whitelist of allowed domains or use relative paths only.'
                                })
                                break
                    except requests.exceptions.RequestException:
                        continue

    except Exception as e:
        findings.append({
            'type': 'open_redirect',
            'severity': 'low',
            'description': 'Open redirect testing error',
            'details': str(e)
        })

    return findings
