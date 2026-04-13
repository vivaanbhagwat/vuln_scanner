"""
Admin routes - Dashboard, user management, vulnerability & report management.
"""
from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request, abort, jsonify
from flask_login import login_required, current_user
from functools import wraps
from extensions import db
from models.user import User
from models.scan import Scan
from models.vulnerability import Vulnerability
from models.report import Report

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


def admin_required(f):
    """Decorator to require admin role."""
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


@admin_bp.route('/')
@admin_required
def dashboard():
    """Admin dashboard overview."""
    total_users = User.query.count()
    total_scans = Scan.query.count()
    total_vulns = Vulnerability.query.count()
    total_reports = Report.query.filter_by(status='pending').count()
    high_vulns = Vulnerability.query.filter_by(severity='high').count()

    recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(10).all()
    recent_reports = Report.query.order_by(Report.created_at.desc()).limit(5).all()

    # Severity distribution for chart
    severity_data = {
        'high': Vulnerability.query.filter_by(severity='high').count(),
        'medium': Vulnerability.query.filter_by(severity='medium').count(),
        'low': Vulnerability.query.filter_by(severity='low').count(),
    }

    # Most common vulnerability types
    vuln_types = db.session.query(
        Vulnerability.type, db.func.count(Vulnerability.id)
    ).group_by(Vulnerability.type).order_by(db.func.count(Vulnerability.id).desc()).limit(10).all()

    # Most scanned domains
    top_domains = db.session.query(
        Scan.url, db.func.count(Scan.id)
    ).group_by(Scan.url).order_by(db.func.count(Scan.id).desc()).limit(10).all()

    return render_template('admin/dashboard.html',
                           total_users=total_users,
                           total_scans=total_scans,
                           total_vulns=total_vulns,
                           total_reports=total_reports,
                           high_vulns=high_vulns,
                           recent_scans=recent_scans,
                           recent_reports=recent_reports,
                           severity_data=severity_data,
                           vuln_types=vuln_types,
                           top_domains=top_domains)


@admin_bp.route('/users')
@admin_required
def users():
    """User management."""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')

    query = User.query
    if search:
        query = query.filter(
            db.or_(
                User.username.ilike(f'%{search}%'),
                User.email.ilike(f'%{search}%')
            )
        )

    users = query.order_by(User.created_at.desc()).paginate(page=page, per_page=20, error_out=False)
    return render_template('admin/users.html', users=users, search=search)


@admin_bp.route('/users/<int:user_id>/toggle', methods=['POST'])
@admin_required
def toggle_user(user_id):
    """Suspend or activate a user."""
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot suspend yourself.', 'danger')
        return redirect(url_for('admin.users'))

    user.is_active_user = not user.is_active_user
    db.session.commit()

    status = 'activated' if user.is_active_user else 'suspended'
    flash(f'User {user.username} has been {status}.', 'success')
    return redirect(url_for('admin.users'))


@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Delete a user and all their data."""
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot delete yourself.', 'danger')
        return redirect(url_for('admin.users'))

    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.username} has been deleted.', 'success')
    return redirect(url_for('admin.users'))


@admin_bp.route('/scans')
@admin_required
def scans():
    """Scan monitoring."""
    page = request.args.get('page', 1, type=int)
    severity = request.args.get('severity', '')
    user_filter = request.args.get('user', '')
    search = request.args.get('search', '')

    query = Scan.query

    if search:
        query = query.filter(Scan.url.ilike(f'%{search}%'))

    if user_filter:
        query = query.join(User).filter(User.username.ilike(f'%{user_filter}%'))

    scans = query.order_by(Scan.created_at.desc()).paginate(page=page, per_page=20, error_out=False)
    return render_template('admin/scans.html', scans=scans, search=search,
                           severity=severity, user_filter=user_filter)


@admin_bp.route('/vulnerabilities')
@admin_required
def vulnerabilities():
    """Vulnerability management."""
    page = request.args.get('page', 1, type=int)
    severity = request.args.get('severity', '')
    status = request.args.get('status', '')

    query = Vulnerability.query

    if severity:
        query = query.filter_by(severity=severity)
    if status:
        query = query.filter_by(status=status)

    vulns = query.order_by(
        db.case(
            (Vulnerability.severity == 'high', 1),
            (Vulnerability.severity == 'medium', 2),
            (Vulnerability.severity == 'low', 3),
        )
    ).paginate(page=page, per_page=20, error_out=False)

    return render_template('admin/vulnerabilities.html', vulns=vulns,
                           severity=severity, status=status)


@admin_bp.route('/vulnerabilities/<int:vuln_id>/status', methods=['POST'])
@admin_required
def update_vuln_status(vuln_id):
    """Update vulnerability status."""
    vuln = Vulnerability.query.get_or_404(vuln_id)
    new_status = request.form.get('status')

    if new_status in ('open', 'reviewed', 'fixed', 'false_positive'):
        vuln.status = new_status
        db.session.commit()
        flash(f'Vulnerability status updated to {new_status}.', 'success')
    else:
        flash('Invalid status.', 'danger')

    return redirect(request.referrer or url_for('admin.vulnerabilities'))


@admin_bp.route('/reports')
@admin_required
def reports():
    """Report management."""
    page = request.args.get('page', 1, type=int)
    status = request.args.get('status', '')

    query = Report.query
    if status:
        query = query.filter_by(status=status)

    reports = query.order_by(Report.created_at.desc()).paginate(page=page, per_page=20, error_out=False)
    return render_template('admin/reports.html', reports=reports, status=status)


@admin_bp.route('/reports/<int:report_id>/status', methods=['POST'])
@admin_required
def update_report_status(report_id):
    """Update report status."""
    report = Report.query.get_or_404(report_id)
    new_status = request.form.get('status')
    response = request.form.get('admin_response', '').strip()

    if new_status in ('pending', 'reviewed', 'resolved'):
        report.status = new_status
        report.updated_at = datetime.now(timezone.utc)
        if response:
            report.admin_response = response
        db.session.commit()
        flash(f'Report status updated to {new_status}.', 'success')
    else:
        flash('Invalid status.', 'danger')

    return redirect(url_for('admin.reports'))


# ---- Analytics API for charts ----
@admin_bp.route('/api/analytics/severity')
@admin_required
def analytics_severity():
    """Severity distribution data."""
    data = {
        'high': Vulnerability.query.filter_by(severity='high').count(),
        'medium': Vulnerability.query.filter_by(severity='medium').count(),
        'low': Vulnerability.query.filter_by(severity='low').count(),
    }
    return jsonify(data)


@admin_bp.route('/api/analytics/vuln-types')
@admin_required
def analytics_vuln_types():
    """Most common vulnerability types."""
    results = db.session.query(
        Vulnerability.type, db.func.count(Vulnerability.id)
    ).group_by(Vulnerability.type).order_by(db.func.count(Vulnerability.id).desc()).limit(10).all()

    return jsonify({'labels': [r[0] for r in results], 'values': [r[1] for r in results]})


@admin_bp.route('/api/analytics/domains')
@admin_required
def analytics_domains():
    """Most scanned domains."""
    results = db.session.query(
        Scan.url, db.func.count(Scan.id)
    ).group_by(Scan.url).order_by(db.func.count(Scan.id).desc()).limit(10).all()

    return jsonify({'labels': [r[0] for r in results], 'values': [r[1] for r in results]})
