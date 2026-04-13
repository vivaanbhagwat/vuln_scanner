"""Report model for user-submitted vulnerability reports."""
from datetime import datetime, timezone
from extensions import db


class Report(db.Model):
    """User report to admin about a vulnerability."""
    __tablename__ = 'reports'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerabilities.id'), nullable=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=True)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, reviewed, resolved
    admin_response = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    vulnerability = db.relationship('Vulnerability', backref='reports')
    scan = db.relationship('Scan', backref='reports')

    def __repr__(self):
        return f'<Report {self.id} - {self.status}>'
