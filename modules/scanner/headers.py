"""Security Headers Analyzer - Checks for missing or misconfigured security headers."""
import requests


# Required security headers and their descriptions
SECURITY_HEADERS = {
    'Content-Security-Policy': {
        'severity': 'high',
        'description': 'Content-Security-Policy header is missing',
        'details': (
            'CSP helps prevent XSS attacks by specifying which dynamic resources '
            'are allowed to load. Without it, the site is vulnerable to content injection.'
        ),
        'solution': 'Implement a strong Content-Security-Policy (CSP) header. Example: "Content-Security-Policy: default-src \'self\'; script-src \'self\' https://trusted.cdn.com;"'
    },
    'X-Frame-Options': {
        'severity': 'medium',
        'description': 'X-Frame-Options header is missing',
        'details': (
            'This header prevents clickjacking attacks by controlling whether the site '
            'can be embedded in frames. Without it, attackers can overlay invisible frames.'
        ),
        'solution': 'Add the "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN" header to prevent clickjacking.'
    },
    'Strict-Transport-Security': {
        'severity': 'high',
        'description': 'Strict-Transport-Security (HSTS) header is missing',
        'details': (
            'HSTS forces browsers to use HTTPS for all future requests. '
            'Without it, users may be vulnerable to SSL stripping attacks.'
        ),
        'solution': 'Add the "Strict-Transport-Security: max-age=31536000; includeSubDomains" header to enforce HTTPS.'
    },
    'X-Content-Type-Options': {
        'severity': 'medium',
        'description': 'X-Content-Type-Options header is missing',
        'details': (
            'This header prevents MIME type sniffing. Without "nosniff", '
            'browsers may interpret files as a different MIME type, enabling attacks.'
        ),
        'solution': 'Add the "X-Content-Type-Options: nosniff" header to prevent MIME-type sniffing.'
    },
    'X-XSS-Protection': {
        'severity': 'low',
        'description': 'X-XSS-Protection header is missing',
        'details': (
            'While largely deprecated in favor of CSP, this header can still provide '
            'an extra layer of XSS protection in older browsers.'
        ),
        'solution': 'Add the "X-XSS-Protection: 1; mode=block" header.'
    },
    'Referrer-Policy': {
        'severity': 'low',
        'description': 'Referrer-Policy header is missing',
        'details': (
            'Controls how much referrer information is sent with requests. '
            'Without it, sensitive URL parameters may leak to third parties.'
        ),
        'solution': 'Add the "Referrer-Policy: strict-origin-when-cross-origin" header.'
    },
    'Permissions-Policy': {
        'severity': 'low',
        'description': 'Permissions-Policy header is missing',
        'details': (
            'Controls which browser features and APIs can be used. '
            'Without it, embedded content may access sensitive device features.'
        ),
        'solution': 'Add a "Permissions-Policy" header to restrict unnecessary browser features like geolocation or camera.'
    },
}


def check_security_headers(url):
    """
    Analyze response headers for security best practices.
    Returns a list of vulnerability findings.
    """
    findings = []

    try:
        resp = requests.get(url, timeout=10, allow_redirects=True)
        headers = resp.headers

        for header_name, info in SECURITY_HEADERS.items():
            if header_name not in headers:
                findings.append({
                    'type': 'missing_header',
                    'severity': info['severity'],
                    'description': info['description'],
                    'details': info['details']
                })

        # Check for overly permissive CORS
        if 'Access-Control-Allow-Origin' in headers:
            if headers['Access-Control-Allow-Origin'] == '*':
                findings.append({
                    'type': 'missing_header',
                    'severity': 'medium',
                    'description': 'Overly permissive CORS policy',
                    'details': (
                        'Access-Control-Allow-Origin is set to *, allowing any domain '
                        'to make requests. This may expose sensitive data to unauthorized origins.'
                    )
                })

        # Check for server info disclosure
        if 'Server' in headers:
            findings.append({
                'type': 'missing_header',
                'severity': 'low',
                'description': 'Server version information disclosed',
                'details': (
                    f'Server header reveals: {headers["Server"]}. '
                    'Disclosing server software and version helps attackers target known vulnerabilities.'
                )
            })

        if 'X-Powered-By' in headers:
            findings.append({
                'type': 'missing_header',
                'severity': 'low',
                'description': 'Technology stack information disclosed',
                'details': (
                    f'X-Powered-By header reveals: {headers["X-Powered-By"]}. '
                    'This information can help attackers identify technology-specific vulnerabilities.'
                )
            })

    except requests.exceptions.RequestException as e:
        findings.append({
            'type': 'missing_header',
            'severity': 'medium',
            'description': 'Unable to analyze security headers',
            'details': f'Request failed: {str(e)}'
        })

    return findings
