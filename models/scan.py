"""Scan model for storing vulnerability scan results."""
import json
from datetime import datetime, timezone
from extensions import db


class Scan(db.Model):
    """Vulnerability scan record."""
    __tablename__ = 'scans'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    url = db.Column(db.String(500), nullable=False)
    result_json = db.Column(db.Text, nullable=True)
    risk_score = db.Column(db.Integer, default=0)  # 0-100
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy='dynamic', cascade='all, delete-orphan')

    @property
    def results(self):
        """Parse stored JSON results."""
        if self.result_json:
            return json.loads(self.result_json)
        return {}

    @results.setter
    def results(self, data):
        """Serialize results to JSON."""
        self.result_json = json.dumps(data)

    @property
    def severity_counts(self):
        """Count vulnerabilities by severity."""
        counts = {'high': 0, 'medium': 0, 'low': 0}
        for vuln in self.vulnerabilities:
            sev = vuln.severity.lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def __repr__(self):
        return f'<Scan {self.id} - {self.url}>'
