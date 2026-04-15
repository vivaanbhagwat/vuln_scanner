"""Insecure CORS Module - Detailed analysis of Cross-Origin Resource Sharing."""
import requests

def analyze_cors_security(url):
    """Analyze CORS headers by sending Origin headers and checking responses."""
    findings = []
    try:
        # Test with an untrusted origin
        test_origin = 'https://evil-attacker.com'
        resp = requests.get(url, headers={'Origin': test_origin}, timeout=10)
        headers = resp.headers

        allow_origin = headers.get('Access-Control-Allow-Origin')
        allow_credentials = headers.get('Access-Control-Allow-Credentials')

        if allow_origin == '*' and allow_credentials == 'true':
            findings.append({
                'type': 'insecure_cors',
                'severity': 'high',
                'description': 'Critical CORS misconfiguration',
                'details': 'The application allows any origin (*) AND allows credentials. This is highly insecure as it allows attackers to bypass SOP on authenticated sessions.',
                'solution': 'Never use Access-Control-Allow-Origin: * when Access-Control-Allow-Credentials is true. Use a whitelist of allowed origins.'
            })
        elif allow_origin == test_origin:
            findings.append({
                'type': 'insecure_cors',
                'severity': 'medium',
                'description': 'Reflected Origin CORS vulnerability',
                'details': f'The application reflects the "Origin" header ({test_origin}) in "Access-Control-Allow-Origin". This effectively allows any site to access responses.',
                'solution': 'Validate the "Origin" header against a whitelist of trusted domains.'
            })

    except requests.exceptions.RequestException as e:
        findings.append({
            'type': 'insecure_cors',
            'severity': 'low',
            'description': 'CORS analysis error',
            'details': str(e)
        })

    return findings
