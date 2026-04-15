"""Cookie Security Analyzer - Checks for Secure, HttpOnly, and SameSite flags."""
import requests

def check_cookie_security(url):
    """Analyze cookies for missing security flags."""
    findings = []
    try:
        resp = requests.get(url, timeout=10)
        cookies = resp.cookies

        if not cookies:
            return [{
                'type': 'cookie_security',
                'severity': 'info',
                'description': 'No cookies set by the application',
                'details': 'The application does not appear to set any cookies during the initial request.'
            }]

        for cookie in cookies:
            missing_flags = []
            if not cookie.has_nonstandard_attr('HttpOnly') and not getattr(cookie, 'http_only', False):
                # Python's requests CookieJar handling for HttpOnly is a bit internal
                # but we can check the 'Rest' or specific attributes if needed
                # For simplicity in this scanner, we'll check common names
                pass 

            # Improved check using raw headers
            raw_cookies = resp.headers.get('Set-Cookie', '')
            if raw_cookies:
                cookie_parts = [c.strip() for c in raw_cookies.split(',')]
                for cp in cookie_parts:
                    name = cp.split('=')[0]
                    if 'HttpOnly' not in cp:
                        findings.append({
                            'type': 'cookie_security',
                            'severity': 'medium',
                            'description': f'Cookie "{name}" missing HttpOnly flag',
                            'details': 'The HttpOnly flag prevents JavaScript from accessing the cookie, mitigating XSS-based session theft.',
                            'solution': 'Add the "HttpOnly" attribute to the Set-Cookie header.'
                        })
                    if 'Secure' not in cp and not url.startswith('http://'):
                        findings.append({
                            'type': 'cookie_security',
                            'severity': 'medium',
                            'description': f'Cookie "{name}" missing Secure flag',
                            'details': 'The Secure flag ensures the cookie is only transmitted over encrypted (HTTPS) connections.',
                            'solution': 'Add the "Secure" attribute to the Set-Cookie header.'
                        })
                    if 'SameSite' not in cp:
                        findings.append({
                            'type': 'cookie_security',
                            'severity': 'low',
                            'description': f'Cookie "{name}" missing SameSite flag',
                            'details': 'The SameSite flag helps protect against CSRF attacks by controlling when cookies are sent with cross-site requests.',
                            'solution': 'Set the "SameSite=Lax" or "SameSite=Strict" attribute on the cookie.'
                        })

    except requests.exceptions.RequestException as e:
        findings.append({
            'type': 'cookie_security',
            'severity': 'medium',
            'description': 'Unable to analyze cookies',
            'details': f'Request failed: {str(e)}'
        })

    return findings
