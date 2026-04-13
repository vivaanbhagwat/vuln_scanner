"""Directory Enumeration Module - Checks for common exposed paths."""
import requests
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed


# Common directories to check
COMMON_PATHS = [
    '/admin', '/admin/', '/administrator/',
    '/login', '/login/', '/signin/',
    '/dashboard', '/dashboard/',
    '/wp-admin/', '/wp-login.php',
    '/phpmyadmin/', '/pma/',
    '/.env', '/.git/', '/.git/config',
    '/config/', '/configuration/',
    '/backup/', '/backups/',
    '/api/', '/api/v1/',
    '/debug/', '/test/', '/testing/',
    '/uploads/', '/upload/',
    '/secret/', '/private/',
    '/robots.txt', '/sitemap.xml',
    '/.htaccess', '/web.config',
    '/server-status', '/server-info',
    '/phpinfo.php',
    '/readme.md', '/README.md', '/CHANGELOG.md',
]

# Paths that indicate high severity when accessible
HIGH_SEVERITY_PATHS = {
    '/.env', '/.git/', '/.git/config', '/.htaccess', '/web.config',
    '/phpmyadmin/', '/pma/', '/phpinfo.php', '/server-status', '/server-info',
    '/backup/', '/backups/', '/secret/', '/private/', '/debug/',
}

MEDIUM_SEVERITY_PATHS = {
    '/admin', '/admin/', '/administrator/', '/wp-admin/', '/wp-login.php',
    '/config/', '/configuration/', '/uploads/', '/upload/',
}


def _check_path(base_url, path, timeout):
    """Check if a path exists on the target server."""
    try:
        full_url = urljoin(base_url, path)
        resp = requests.get(full_url, timeout=timeout, allow_redirects=False)
        return path, resp.status_code, len(resp.text)
    except requests.exceptions.RequestException:
        return path, None, 0


def enumerate_directories(url, timeout=5):
    """
    Check for common exposed directories and files.
    Returns a list of vulnerability findings.
    """
    findings = []
    accessible_paths = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(_check_path, url, path, timeout): path
            for path in COMMON_PATHS
        }

        for future in as_completed(futures):
            path, status, content_len = future.result()
            if status and status < 400 and status != 301:
                accessible_paths.append((path, status, content_len))

    for path, status, content_len in sorted(accessible_paths):
        # Determine severity
        if path in HIGH_SEVERITY_PATHS:
            severity = 'high'
        elif path in MEDIUM_SEVERITY_PATHS:
            severity = 'medium'
        else:
            severity = 'low'

        # robots.txt and sitemap.xml are informational
        if path in ('/robots.txt', '/sitemap.xml'):
            severity = 'info'

        findings.append({
            'type': 'exposed_directory',
            'severity': severity,
            'description': f'Accessible path found: {path}',
            'details': (
                f'HTTP {status} response ({content_len} bytes) at {path}. '
                'Exposed directories and files can reveal sensitive information '
                'or provide attack vectors.'
            ),
            'solution': 'Restrict access to sensitive paths in your web server configuration (Nginx/Apache), or move sensitive files outside of the web-accessible root directory.'
        })

    if not findings:
        findings.append({
            'type': 'exposed_directory',
            'severity': 'info',
            'description': 'No common exposed directories found',
            'details': 'None of the common sensitive paths returned accessible responses.'
        })

    return findings
