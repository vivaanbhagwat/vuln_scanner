"""Server Fingerprinting Module - Identifies server technology and version exposure."""
import requests

def analyze_server_fingerprint(url):
    """Analyze server headers and common indicators for technology disclosure."""
    findings = []
    try:
        resp = requests.get(url, timeout=10)
        headers = resp.headers

        # Check for Server header disclosure
        server = headers.get('Server')
        if server:
            # Check if it exposes version numbers (e.g. Apache/2.4.41)
            import re
            if re.search(r'\/\d', server):
                findings.append({
                    'type': 'fingerprinting',
                    'severity': 'low',
                    'description': 'Server version disclosure detected',
                    'details': f'The "Server" header discloses specific software versions: {server}. This helps attackers target specific vulnerabilities.',
                    'solution': 'Configure your web server (e.g., ServerTokens Prod for Apache) to minimize information disclosure.'
                })

        # Check for X-Powered-By
        powered_by = headers.get('X-Powered-By')
        if powered_by:
            findings.append({
                'type': 'fingerprinting',
                'severity': 'low',
                'description': 'Technology stack disclosure (X-Powered-By)',
                'details': f'The "X-Powered-By" header reveals the backend technology: {powered_by}.',
                'solution': 'Disable the "X-Powered-By" header in your application or web server configuration.'
            })

    except requests.exceptions.RequestException as e:
        findings.append({
            'type': 'fingerprinting',
            'severity': 'low',
            'description': 'Fingerprinting analysis error',
            'details': str(e)
        })

    return findings
