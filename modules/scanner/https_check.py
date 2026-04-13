"""HTTPS Check Module - Detects whether a site uses HTTPS."""
import requests
from urllib.parse import urlparse


def check_https(url):
    """
    Check if the target URL uses HTTPS.
    Returns a list of vulnerability findings.
    """
    findings = []
    parsed = urlparse(url)

    # Check if scheme is HTTP
    if parsed.scheme == 'http':
        findings.append({
            'type': 'https_check',
            'severity': 'high',
            'description': 'Site does not use HTTPS encryption',
            'details': (
                f'The target URL ({url}) uses HTTP instead of HTTPS. '
                'All data transmitted between the user and the server is unencrypted '
                'and vulnerable to interception (man-in-the-middle attacks).'
            ),
            'solution': 'Install an SSL/TLS certificate and configure your web server to redirect all HTTP traffic to HTTPS.'
        })

    # Check if HTTPS redirect exists for HTTP sites
    if parsed.scheme == 'http':
        try:
            https_url = url.replace('http://', 'https://', 1)
            resp = requests.get(https_url, timeout=5, allow_redirects=False)
            if resp.status_code >= 400:
                findings.append({
                    'type': 'https_check',
                    'severity': 'medium',
                    'description': 'HTTPS version not available',
                    'details': (
                        f'The HTTPS version of the site returned status {resp.status_code}. '
                        'The site may not have a valid SSL/TLS certificate configured.'
                    )
                })
        except requests.exceptions.SSLError:
            findings.append({
                'type': 'https_check',
                'severity': 'high',
                'description': 'Invalid SSL/TLS certificate',
                'details': 'The site has an invalid or expired SSL/TLS certificate.'
            })
        except requests.exceptions.RequestException:
            pass

    # Check for mixed content indicators
    if parsed.scheme == 'https':
        try:
            resp = requests.get(url, timeout=10)
            if 'http://' in resp.text and 'src=' in resp.text:
                findings.append({
                    'type': 'https_check',
                    'severity': 'medium',
                    'description': 'Potential mixed content detected',
                    'details': (
                        'The HTTPS page may contain resources loaded over HTTP, '
                        'which can compromise the security of the encrypted connection.'
                    )
                })
        except requests.exceptions.RequestException:
            pass

    if not findings:
        findings.append({
            'type': 'https_check',
            'severity': 'info',
            'description': 'HTTPS is properly configured',
            'details': f'The target URL ({url}) uses HTTPS encryption.'
        })

    return findings
