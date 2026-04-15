"""Sensitive File Disclosure Module - Expanded checks for sensitive system files."""
import requests
from urllib.parse import urljoin

DISCLOSURE_PATHS = [
    '/.env', '/.git/config', '/.git/HEAD', '/.bash_history', 
    '/config.php', '/web.config', '/.htaccess', '/docker-compose.yml',
    '/phpinfo.php', '/server-status', '/server-info'
]

def check_sensitive_disclosure(url):
    """Check for exposure of sensitive configuration and system files."""
    findings = []
    
    for path in DISCLOSURE_PATHS:
        try:
            full_url = urljoin(url, path)
            resp = requests.get(full_url, timeout=5, allow_redirects=False)
            
            if resp.status_code == 200:
                # Basic check for false positives (like a custom 404 page)
                if 'not found' not in resp.text.lower() and len(resp.text) > 20:
                    findings.append({
                        'type': 'disclosure',
                        'severity': 'high',
                        'description': f'Sensitive file exposed: {path}',
                        'details': f'The sensitive file {path} is publicly accessible. This could reveal credentials, source code details, or server configuration.',
                        'solution': 'Restrict access to these files in your web server configuration (e.g., in .htaccess or Nginx conf) or remove them from the web-accessible root.'
                    })
        except requests.exceptions.RequestException:
            continue

    return findings
