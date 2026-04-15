"""File Inclusion Module - Tests for LFI and Path Traversal."""
import requests
from urllib.parse import urlparse, parse_qs, urlencode

# Common traversal payloads
LFI_PAYLOADS = [
    '../../../../../../../../etc/passwd',
    '..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini',
    '/etc/passwd',
    'C:\\windows\\win.ini',
]

def test_lfi(url):
    """Test URL parameters for path traversal and LFI."""
    findings = []
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return []

        for param_name in params:
            for payload in LFI_PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = payload
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

                try:
                    resp = requests.get(test_url, timeout=10)
                    # Check for indicators in response
                    if any(indicator in resp.text for indicator in ['root:x:0:0:', '[extensions]']):
                        findings.append({
                            'type': 'lfi',
                            'severity': 'high',
                            'description': f'Local File Inclusion (LFI) detected in "{param_name}"',
                            'details': f'The application appears to include local files based on the "{param_name}" parameter. Payload "{payload}" was successful.',
                            'solution': 'Never pass user-controlled input directly to filesystem APIs. Use a whitelist of allowed files or an indirect identifier.'
                        })
                        break
                except requests.exceptions.RequestException:
                    continue

    except Exception as e:
        findings.append({
            'type': 'lfi',
            'severity': 'medium',
            'description': 'LFI testing error',
            'details': str(e)
        })

    return findings
