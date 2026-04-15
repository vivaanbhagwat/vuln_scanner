"""Command Injection Module - Tests for shell command execution."""
import requests
from urllib.parse import urlparse, parse_qs, urlencode

# Command execution payloads
# Note: These are safe probes that produce a detectable output
CMDI_PAYLOADS = [
    '; echo "cmdi_vulnerability_detected"',
    '| echo "cmdi_vulnerability_detected"',
    '& echo "cmdi_vulnerability_detected"',
    '`echo "cmdi_vulnerability_detected"`',
    '$(echo "cmdi_vulnerability_detected")',
]

def test_command_injection(url):
    """Test URL parameters for command injection vulnerabilities."""
    findings = []
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return []

        for param_name in params:
            for payload in CMDI_PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = payload
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

                try:
                    resp = requests.get(test_url, timeout=10)
                    if "cmdi_vulnerability_detected" in resp.text:
                        findings.append({
                            'type': 'command_injection',
                            'severity': 'high',
                            'description': f'Command Injection detected in "{param_name}"',
                            'details': f'The application appears to execute shell commands using input from the "{param_name}" parameter. Payload "{payload}" was successful.',
                            'solution': 'Never pass user input to system shell commands. Use language-specific APIs that do not invoke a shell (e.g., subprocess.run(["cmd", "arg"]) instead of os.system("cmd arg")).'
                        })
                        break
                except requests.exceptions.RequestException:
                    continue

    except Exception as e:
        findings.append({
            'type': 'command_injection',
            'severity': 'medium',
            'description': 'Command injection testing error',
            'details': str(e)
        })

    return findings
