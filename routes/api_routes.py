"""
REST API routes for programmatic access.
"""
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from extensions import db
from models.scan import Scan
from models.vulnerability import Vulnerability
from modules.scan_engine import run_scan

api_bp = Blueprint('api', __name__, url_prefix='/api')


@api_bp.route('/scan', methods=['POST'])
@login_required
def api_scan():
    """POST /api/scan - Start a new scan."""
    data = request.get_json()
    if not data or not data.get('url'):
        return jsonify({'error': 'URL is required'}), 400

    try:
        scan = run_scan(current_user.id, data['url'])
        vulns = scan.vulnerabilities.all()

        return jsonify({
            'scan_id': scan.id,
            'url': scan.url,
            'risk_score': scan.risk_score,
            'status': scan.status,
            'vulnerabilities': [
                {
                    'type': v.type,
                    'severity': v.severity,
                    'description': v.description,
                    'owasp': v.owasp_category,
                }
                for v in vulns
            ]
        }), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500


@api_bp.route('/user/scans', methods=['GET'])
@login_required
def api_user_scans():
    """GET /api/user/scans - Get current user's scans."""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)

    scans = Scan.query.filter_by(user_id=current_user.id)\
        .order_by(Scan.created_at.desc())\
        .paginate(page=page, per_page=min(per_page, 100), error_out=False)

    return jsonify({
        'scans': [
            {
                'id': s.id,
                'url': s.url,
                'risk_score': s.risk_score,
                'status': s.status,
                'created_at': s.created_at.isoformat(),
                'vulnerability_count': s.vulnerabilities.count(),
            }
            for s in scans.items
        ],
        'total': scans.total,
        'pages': scans.pages,
        'current_page': scans.page,
    })


@api_bp.route('/admin/scans', methods=['GET'])
@login_required
def api_admin_scans():
    """GET /api/admin/scans - Get all scans (admin only)."""
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    page = request.args.get('page', 1, type=int)

    scans = Scan.query.order_by(Scan.created_at.desc())\
        .paginate(page=page, per_page=20, error_out=False)

    return jsonify({
        'scans': [
            {
                'id': s.id,
                'user_id': s.user_id,
                'url': s.url,
                'risk_score': s.risk_score,
                'status': s.status,
                'created_at': s.created_at.isoformat(),
                'vulnerability_count': s.vulnerabilities.count(),
            }
            for s in scans.items
        ],
        'total': scans.total,
        'pages': scans.pages,
    })
