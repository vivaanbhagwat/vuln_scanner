"""
Report Generation Module - PDF, JSON, and TXT export.
"""
import json
import io
from datetime import datetime
from fpdf import FPDF


class VulnReportPDF(FPDF):
    """Custom PDF class for vulnerability reports."""

    def header(self):
        self.set_font('Helvetica', 'B', 16)
        self.set_text_color(41, 128, 185)
        self.cell(0, 10, 'Vulnerability Scan Report', 0, 1, 'C')
        self.set_font('Helvetica', '', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 5, 'Auto Website Vulnerability Scanner', 0, 1, 'C')
        self.ln(5)
        self.set_draw_color(41, 128, 185)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', 0, 0, 'C')

    def severity_color(self, severity):
        colors = {
            'high': (231, 76, 60),
            'medium': (243, 156, 18),
            'low': (46, 204, 113),
            'info': (52, 152, 219),
        }
        return colors.get(severity.lower(), (128, 128, 128))


def generate_pdf_report(scan, vulnerabilities):
    """Generate a PDF vulnerability report."""
    pdf = VulnReportPDF()
    pdf.alias_nb_pages()
    pdf.add_page()

    # Scan Overview
    pdf.set_font('Helvetica', 'B', 14)
    pdf.set_text_color(44, 62, 80)
    pdf.cell(0, 10, 'Scan Overview', 0, 1)

    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(50, 7, 'Target URL:', 0, 0)
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(0, 7, scan.url, 0, 1)

    pdf.set_font('Helvetica', '', 10)
    pdf.cell(50, 7, 'Scan Date:', 0, 0)
    pdf.cell(0, 7, scan.created_at.strftime('%Y-%m-%d %H:%M:%S UTC'), 0, 1)

    pdf.cell(50, 7, 'Risk Score:', 0, 0)
    score = scan.risk_score
    if score >= 70:
        pdf.set_text_color(231, 76, 60)
    elif score >= 40:
        pdf.set_text_color(243, 156, 18)
    else:
        pdf.set_text_color(46, 204, 113)
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(0, 7, f'{score}/100', 0, 1)
    pdf.set_text_color(0, 0, 0)

    # Severity Summary
    severity_counts = {'high': 0, 'medium': 0, 'low': 0}
    for v in vulnerabilities:
        sev = v.severity.lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    pdf.ln(5)
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(50, 7, 'Total Findings:', 0, 0)
    pdf.cell(0, 7, str(len(vulnerabilities)), 0, 1)
    pdf.cell(50, 7, 'High Severity:', 0, 0)
    pdf.set_text_color(231, 76, 60)
    pdf.cell(0, 7, str(severity_counts['high']), 0, 1)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(50, 7, 'Medium Severity:', 0, 0)
    pdf.set_text_color(243, 156, 18)
    pdf.cell(0, 7, str(severity_counts['medium']), 0, 1)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(50, 7, 'Low Severity:', 0, 0)
    pdf.set_text_color(46, 204, 113)
    pdf.cell(0, 7, str(severity_counts['low']), 0, 1)
    pdf.set_text_color(0, 0, 0)

    # Vulnerabilities Detail
    pdf.ln(10)
    pdf.set_font('Helvetica', 'B', 14)
    pdf.set_text_color(44, 62, 80)
    pdf.cell(0, 10, 'Vulnerability Details', 0, 1)

    for i, vuln in enumerate(vulnerabilities, 1):
        pdf.ln(3)
        color = pdf.severity_color(vuln.severity)

        # Severity badge
        pdf.set_fill_color(*color)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('Helvetica', 'B', 9)
        badge_text = f' {vuln.severity.upper()} '
        badge_w = pdf.get_string_width(badge_text) + 4
        pdf.cell(badge_w, 6, badge_text, 0, 0, 'C', True)

        pdf.set_text_color(0, 0, 0)
        pdf.set_font('Helvetica', 'B', 10)
        pdf.cell(0, 6, f'  #{i}: {vuln.description}', 0, 1)

        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(30, 5, '  Type:', 0, 0)
        pdf.cell(0, 5, vuln.type, 0, 1)
        if vuln.owasp_category:
            pdf.cell(30, 5, '  OWASP:', 0, 0)
            pdf.cell(0, 5, vuln.owasp_category, 0, 1)

        if vuln.details:
            pdf.set_font('Helvetica', '', 8)
            pdf.set_text_color(100, 100, 100)
            pdf.multi_cell(0, 4, f'  {vuln.details}')

        pdf.set_text_color(0, 0, 0)

    # Output
    return pdf.output()


def generate_json_report(scan, vulnerabilities):
    """Generate a JSON vulnerability report."""
    report = {
        'scan_info': {
            'id': scan.id,
            'target_url': scan.url,
            'scan_date': scan.created_at.isoformat(),
            'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            'risk_score': scan.risk_score,
            'status': scan.status,
        },
        'summary': {
            'total_vulnerabilities': len(vulnerabilities),
            'high': sum(1 for v in vulnerabilities if v.severity == 'high'),
            'medium': sum(1 for v in vulnerabilities if v.severity == 'medium'),
            'low': sum(1 for v in vulnerabilities if v.severity == 'low'),
        },
        'vulnerabilities': [
            {
                'id': v.id,
                'type': v.type,
                'severity': v.severity,
                'description': v.description,
                'details': v.details,
                'owasp_category': v.owasp_category,
                'status': v.status,
            }
            for v in vulnerabilities
        ]
    }

    return json.dumps(report, indent=2)


def generate_txt_report(scan, vulnerabilities):
    """Generate a plain text vulnerability report."""
    lines = []
    lines.append('=' * 60)
    lines.append('  VULNERABILITY SCAN REPORT')
    lines.append('  Auto Website Vulnerability Scanner')
    lines.append('=' * 60)
    lines.append('')
    lines.append(f'  Target URL:    {scan.url}')
    lines.append(f'  Scan Date:     {scan.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")}')
    lines.append(f'  Risk Score:    {scan.risk_score}/100')
    lines.append(f'  Total Issues:  {len(vulnerabilities)}')
    lines.append('')
    lines.append('-' * 60)
    lines.append('  SEVERITY SUMMARY')
    lines.append('-' * 60)

    severity_counts = {'high': 0, 'medium': 0, 'low': 0}
    for v in vulnerabilities:
        sev = v.severity.lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    lines.append(f'  HIGH:    {severity_counts["high"]}')
    lines.append(f'  MEDIUM:  {severity_counts["medium"]}')
    lines.append(f'  LOW:     {severity_counts["low"]}')
    lines.append('')
    lines.append('-' * 60)
    lines.append('  VULNERABILITY DETAILS')
    lines.append('-' * 60)

    for i, vuln in enumerate(vulnerabilities, 1):
        lines.append('')
        lines.append(f'  [{vuln.severity.upper()}] #{i}: {vuln.description}')
        lines.append(f'    Type:   {vuln.type}')
        if vuln.owasp_category:
            lines.append(f'    OWASP:  {vuln.owasp_category}')
        if vuln.details:
            lines.append(f'    Detail: {vuln.details}')

    lines.append('')
    lines.append('=' * 60)
    lines.append('  End of Report')
    lines.append('=' * 60)

    return '\n'.join(lines)
