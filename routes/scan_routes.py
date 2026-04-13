"""
Scan routes - User dashboard, scan execution, history, and reports.
"""
import json
from flask import Blueprint, render_template, redirect, url_for, flash, request, Response, abort
from flask_login import login_required, current_user
from extensions import db
from models.scan import Scan
from models.vulnerability import Vulnerability
from models.report import Report
from modules.scan_engine import run_scan, get_scan_summary
from modules.report_generator import generate_pdf_report, generate_json_report, generate_txt_report

scan_bp = Blueprint('scan', __name__)


@scan_bp.route('/')
def index():
    """Landing page."""
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin.dashboard'))
        return redirect(url_for('scan.dashboard'))
    return render_template('index.html')


@scan_bp.route('/dashboard')
@login_required
def dashboard():
    """User dashboard with scan input and recent results."""
    recent_scans = Scan.query.filter_by(user_id=current_user.id)\
        .order_by(Scan.created_at.desc()).limit(10).all()

    # Stats
    total_scans = Scan.query.filter_by(user_id=current_user.id).count()
    total_vulns = db.session.query(Vulnerability).join(Scan)\
        .filter(Scan.user_id == current_user.id).count()
    high_vulns = db.session.query(Vulnerability).join(Scan)\
        .filter(Scan.user_id == current_user.id, Vulnerability.severity == 'high').count()

    return render_template('dashboard.html',
                           scans=recent_scans,
                           total_scans=total_scans,
                           total_vulns=total_vulns,
                           high_vulns=high_vulns)


@scan_bp.route('/scan', methods=['POST'])
@login_required
def start_scan():
    """Start a new vulnerability scan."""
    url = request.form.get('url', '').strip()

    if not url:
        flash('Please enter a URL to scan.', 'warning')
        return redirect(url_for('scan.dashboard'))

    try:
        scan = run_scan(current_user.id, url)
        flash(f'Scan completed! Risk score: {scan.risk_score}/100', 'success')
        return redirect(url_for('scan.scan_result', scan_id=scan.id))
    except ValueError as e:
        flash(str(e), 'danger')
        return redirect(url_for('scan.dashboard'))
    except Exception as e:
        flash(f'Scan failed: {str(e)}', 'danger')
        return redirect(url_for('scan.dashboard'))


@scan_bp.route('/scan/<int:scan_id>')
@login_required
def scan_result(scan_id):
    """View scan results."""
    scan = Scan.query.get_or_404(scan_id)

    # Ensure user owns this scan or is admin
    if scan.user_id != current_user.id and not current_user.is_admin:
        abort(403)

    vulnerabilities = scan.vulnerabilities.order_by(
        db.case(
            (Vulnerability.severity == 'high', 1),
            (Vulnerability.severity == 'medium', 2),
            (Vulnerability.severity == 'low', 3),
        )
    ).all()

    summary = get_scan_summary(scan)

    return render_template('scan_result.html',
                           scan=scan,
                           vulnerabilities=vulnerabilities,
                           summary=summary)


@scan_bp.route('/history')
@login_required
def scan_history():
    """View scan history."""
    page = request.args.get('page', 1, type=int)
    scans = Scan.query.filter_by(user_id=current_user.id)\
        .order_by(Scan.created_at.desc())\
        .paginate(page=page, per_page=15, error_out=False)

    return render_template('history.html', scans=scans)


@scan_bp.route('/scan/<int:scan_id>/export/<format>')
@login_required
def export_report(scan_id, format):
    """Export scan report in various formats."""
    scan = Scan.query.get_or_404(scan_id)

    if scan.user_id != current_user.id and not current_user.is_admin:
        abort(403)

    vulnerabilities = scan.vulnerabilities.all()
    filename = f'scan_report_{scan_id}'

    if format == 'pdf':
        pdf_bytes = generate_pdf_report(scan, vulnerabilities)
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename={filename}.pdf'}
        )
    elif format == 'json':
        json_data = generate_json_report(scan, vulnerabilities)
        return Response(
            json_data,
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename={filename}.json'}
        )
    elif format == 'txt':
        txt_data = generate_txt_report(scan, vulnerabilities)
        return Response(
            txt_data,
            mimetype='text/plain',
            headers={'Content-Disposition': f'attachment; filename={filename}.txt'}
        )
    else:
        abort(400, 'Invalid export format')


@scan_bp.route('/scan/<int:scan_id>/report', methods=['POST'])
@login_required
def report_vulnerability(scan_id):
    """Report scan findings to admin."""
    scan = Scan.query.get_or_404(scan_id)

    if scan.user_id != current_user.id:
        abort(403)

    message = request.form.get('message', '').strip()
    vuln_id = request.form.get('vulnerability_id', type=int)

    if not message:
        flash('Please provide a message for your report.', 'warning')
        return redirect(url_for('scan.scan_result', scan_id=scan_id))

    report = Report(
        user_id=current_user.id,
        scan_id=scan_id,
        vulnerability_id=vuln_id,
        message=message
    )
    db.session.add(report)
    db.session.commit()

    flash('Report submitted to admin successfully!', 'success')
    return redirect(url_for('scan.scan_result', scan_id=scan_id))
