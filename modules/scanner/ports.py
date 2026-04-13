"""Port Scanner Module - Scans common ports using sockets."""
import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed


# Common ports to scan with service descriptions
COMMON_PORTS = {
    21: ('FTP', 'high', 'File Transfer Protocol - often allows anonymous access or has known vulnerabilities'),
    22: ('SSH', 'info', 'Secure Shell - generally safe, but should be restricted'),
    23: ('Telnet', 'high', 'Telnet transmits data in plaintext including credentials'),
    25: ('SMTP', 'medium', 'Mail server - can be used for email spoofing if misconfigured'),
    53: ('DNS', 'low', 'DNS service - check for zone transfer vulnerabilities'),
    80: ('HTTP', 'info', 'Web server (HTTP)'),
    110: ('POP3', 'medium', 'Email retrieval - transmits credentials in plaintext'),
    143: ('IMAP', 'medium', 'Email access - should use IMAPS (port 993) instead'),
    443: ('HTTPS', 'info', 'Web server (HTTPS)'),
    445: ('SMB', 'high', 'Server Message Block - frequently targeted by ransomware'),
    3306: ('MySQL', 'high', 'MySQL database - should never be publicly accessible'),
    3389: ('RDP', 'high', 'Remote Desktop - high-value target for attackers'),
    5432: ('PostgreSQL', 'high', 'PostgreSQL database - should never be publicly accessible'),
    8080: ('HTTP-Alt', 'low', 'Alternative HTTP port - may expose development/admin interfaces'),
    8443: ('HTTPS-Alt', 'low', 'Alternative HTTPS port'),
}


def _scan_single_port(host, port, timeout):
    """Scan a single port on the target host."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port, result == 0
    except (socket.error, OSError):
        return port, False


def scan_ports(url, timeout=2):
    """
    Scan common ports on the target host.
    Uses threading for faster scanning.
    Returns a list of vulnerability findings.
    """
    findings = []
    parsed = urlparse(url)
    host = parsed.hostname

    if not host:
        return [{
            'type': 'open_port',
            'severity': 'medium',
            'description': 'Could not determine hostname for port scanning',
            'details': f'Unable to parse hostname from URL: {url}'
        }]

    open_ports = []

    # Use thread pool for concurrent port scanning
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(_scan_single_port, host, port, timeout): port
            for port in COMMON_PORTS
        }

        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)

    # Generate findings for open ports
    for port in sorted(open_ports):
        service, severity, description = COMMON_PORTS[port]

        # Skip expected web ports
        if port in (80, 443):
            severity = 'info'

        findings.append({
            'type': 'open_port',
            'severity': severity,
            'description': f'Port {port} ({service}) is open',
            'details': f'{description}. Open port detected on {host}:{port}.',
            'solution': 'Close the port if it is not required for public access, or restrict access to specific IP ranges using a host-based firewall (e.g., iptables, UFW) or network firewall.'
        })

    if not open_ports:
        findings.append({
            'type': 'open_port',
            'severity': 'info',
            'description': 'No additional open ports detected',
            'details': f'Common ports scan on {host} found no open ports (ports may be filtered by firewall).'
        })

    return findings
