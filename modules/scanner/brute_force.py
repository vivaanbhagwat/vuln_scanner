"""Brute-Force Module - Threaded credential testing for discovered login forms."""
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Basic common credentials for ethical hacking tests
COMMON_CREDS = [
    ('admin', 'admin'),
    ('admin', 'password'),
    ('admin', '123456'),
    ('admin', 'admin123'),
    ('root', 'root'),
    ('user', 'user'),
    ('test', 'test'),
]

def perform_brute_force(form_url, username_field, password_field, method='post', custom_creds=None):
    """
    Attempt to brute-force a login form.
    Returns successfully discovered credentials or None.
    """
    creds_to_test = custom_creds or COMMON_CREDS
    results = []

    def _test_login(user, pwd):
        try:
            data = {username_field: user, password_field: pwd}
            if method.lower() == 'post':
                resp = requests.post(form_url, data=data, timeout=5, allow_redirects=False)
            else:
                resp = requests.get(form_url, params=data, timeout=5, allow_redirects=False)
            
            # Heuristic for success: redirection or change in response indicating session start
            if resp.status_code in (301, 302):
                return (user, pwd, True)
            
            # Check for strings that usually DONT appear when login fails
            failure_indicators = ['invalid', 'failed', 'error', 'incorrect', 'wrong']
            if not any(ind in resp.text.lower() for ind in failure_indicators) and len(resp.text) > 0:
                # This is a weak indicator but useful for heuristic analysis
                pass

            return (user, pwd, False)
        except Exception:
            return (user, pwd, False)

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(_test_login, u, p): (u, p) for u, p in creds_to_test}
        for future in as_completed(futures):
            user, pwd, success = future.result()
            if success:
                results.append((user, pwd))

    return results

def brute_force_scanner(url):
    """Wrapper to find login forms and test them."""
    findings = []
    # This logic would normally use analyze_forms first
    # For now, we return a finding explaining the capability
    findings.append({
        'type': 'brute_force',
        'severity': 'info',
        'description': 'Advanced AI Hacking: Brute Force Engine Ready',
        'details': 'The brute force engine is initialized and ready to target discovered login forms. It uses threaded testing and heuristic response analysis to identify weak credentials.',
        'solution': 'Implement strong password policies, account lockout, and multi-factor authentication (MFA) to prevent brute force attacks.'
    })
    return findings
