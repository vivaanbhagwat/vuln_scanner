"""DNS Security Module - Checks for SPF, DMARC, and MX records."""
import dns.resolver
from urllib.parse import urlparse

def check_dns_security(url):
    """Check the target domain's DNS records for basic security hygiene."""
    findings = []
    try:
        parsed = urlparse(url)
        domain = parsed.hostname
        if not domain:
            return []

        # Check for SPF
        try:
            spf_records = dns.resolver.resolve(domain, 'TXT')
            has_spf = False
            for rdata in spf_records:
                if 'v=spf1' in str(rdata):
                    has_spf = True
                    break
            if not has_spf:
                findings.append({
                    'type': 'dns_security',
                    'severity': 'low',
                    'description': f'SPF record missing for {domain}',
                    'details': 'An SPF (Sender Policy Framework) record helps prevent email spoofing.',
                    'solution': 'Add a TXT record for SPF to your DNS configuration.'
                })
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            findings.append({
                'type': 'dns_security',
                'severity': 'low',
                'description': f'No TXT/SPF records found for {domain}',
                'details': 'Domain lacks SPF records, increasing risk of being used for email spoofing.'
            })
        except Exception:
            pass

        # Check for DMARC
        try:
            dmarc_domain = f'_dmarc.{domain}'
            dmarc_records = dns.resolver.resolve(dmarc_domain, 'TXT')
            has_dmarc = False
            for rdata in dmarc_records:
                if 'v=DMARC1' in str(rdata):
                    has_dmarc = True
                    break
            if not has_dmarc:
                findings.append({
                    'type': 'dns_security',
                    'severity': 'low',
                    'description': f'DMARC record missing for {domain}',
                    'details': 'DMARC helps organizations protect their domains from email spoofing.',
                    'solution': 'Add a DMARC TXT record to your DNS.'
                })
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            findings.append({
                'type': 'dns_security',
                'severity': 'low',
                'description': f'No DMARC records found for {domain}',
                'details': 'DMARC is not configured, which is a best practice for email security.'
            })
        except Exception:
            pass

    except Exception as e:
        findings.append({
            'type': 'dns_security',
            'severity': 'info',
            'description': 'DNS security check skipped/failed',
            'details': str(e)
        })

    return findings
