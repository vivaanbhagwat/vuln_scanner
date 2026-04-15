"""Robots.txt Analyzer - Parses robots.txt for sensitive path exposure."""
import requests
from urllib.parse import urljoin

def analyze_robots_txt(url):
    """Check robots.txt for disallowed paths that reveal interesting locations."""
    findings = []
    try:
        robots_url = urljoin(url, '/robots.txt')
        resp = requests.get(robots_url, timeout=5)
        
        if resp.status_code == 200:
            lines = resp.text.split('\n')
            disallowed = []
            for line in lines:
                if line.lower().startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/':
                        disallowed.append(path)
            
            if disallowed:
                findings.append({
                    'type': 'robots_analysis',
                    'severity': 'info',
                    'description': f'Disallowed paths found in robots.txt: {len(disallowed)}',
                    'details': f'The robots.txt file reveals paths that the owner wants hidden from crawlers: {", ".join(disallowed[:5])}... This can help an attacker identify sensitive administrative or hidden locations.',
                    'solution': 'Ensure robots.txt does not reveal highly sensitive paths. Use server-side authentication instead of relying on robots.txt for security.'
                })
                
    except requests.exceptions.RequestException:
        pass

    return findings
