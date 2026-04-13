"""
Scan Engine Orchestrator - Coordinates all scanner modules and aggregates results.
"""
import json
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from extensions import db
from models.scan import Scan
from models.vulnerability import Vulnerability, OWASP_MAPPING, SEVERITY_WEIGHTS
from modules.scanner import (
    check_https, check_security_headers, analyze_forms,
    test_xss, test_sqli, scan_ports, enumerate_directories
)


def validate_url(url):
    """Validate and normalize the target URL."""
    if not url:
        return None, "URL is required"

    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed = urlparse(url)
    if not parsed.hostname:
        return None, "Invalid URL format"

    return url, None


def run_scan(user_id, url):
    """
    Execute a full vulnerability scan on the target URL.
    Returns the Scan object with results.
    """
    url, error = validate_url(url)
    if error:
        raise ValueError(error)

    # Create scan record
    scan = Scan(user_id=user_id, url=url, status='running')
    db.session.add(scan)
    db.session.commit()

    all_findings = []

    # Define scanner modules to run
    scanners = {
        'HTTPS Check': lambda: check_https(url),
        'Security Headers': lambda: check_security_headers(url),
        'Form Analysis': lambda: analyze_forms(url),
        'XSS Testing': lambda: test_xss(url),
        'SQL Injection Testing': lambda: test_sqli(url),
        'Port Scanning': lambda: scan_ports(url),
        'Directory Enumeration': lambda: enumerate_directories(url),
    }

    scan_results = {}

    # Run scanners concurrently
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(func): name
            for name, func in scanners.items()
        }

        for future in as_completed(futures):
            scanner_name = futures[future]
            try:
                findings = future.result()
                scan_results[scanner_name] = findings
                all_findings.extend(findings)
            except Exception as e:
                scan_results[scanner_name] = [{
                    'type': 'error',
                    'severity': 'info',
                    'description': f'{scanner_name} encountered an error',
                    'details': str(e)
                }]

    # Filter out info-only findings for vulnerability storage
    vuln_findings = [f for f in all_findings if f['severity'] != 'info']

    # Store vulnerabilities in database
    for finding in vuln_findings:
        vuln = Vulnerability(
            scan_id=scan.id,
            type=finding['type'],
            severity=finding['severity'],
            description=finding['description'],
            details=finding.get('details', ''),
            solution=finding.get('solution', ''),
            owasp_category=OWASP_MAPPING.get(finding['type'], 'Uncategorized'),
            status='open'
        )
        db.session.add(vuln)

    # Calculate risk score
    risk_score = calculate_risk_score(vuln_findings)

    # Update scan record
    scan.result_json = json.dumps(scan_results)
    scan.risk_score = risk_score
    scan.status = 'completed'
    scan.completed_at = datetime.now(timezone.utc)
    db.session.commit()

    return scan


def calculate_risk_score(findings):
    """
    Calculate a risk score (0-100) based on findings.
    Uses severity weights for scoring.
    """
    if not findings:
        return 0

    total_weight = 0
    for finding in findings:
        severity = finding.get('severity', 'low').lower()
        total_weight += SEVERITY_WEIGHTS.get(severity, 5)

    # Cap at 100
    return min(total_weight, 100)


def get_scan_summary(scan):
    """Generate a human-readable summary of scan results."""
    vulns = scan.vulnerabilities.all()
    severity_counts = {'high': 0, 'medium': 0, 'low': 0}

    for v in vulns:
        sev = v.severity.lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    total = sum(severity_counts.values())

    return {
        'total_vulnerabilities': total,
        'high': severity_counts['high'],
        'medium': severity_counts['medium'],
        'low': severity_counts['low'],
        'risk_score': scan.risk_score,
        'url': scan.url,
        'scanned_at': scan.created_at,
    }
