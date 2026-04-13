"""
Auto Website Vulnerability Scanner - Flask Application Entry Point.
"""
import os
from flask import Flask
from config import config_map
from extensions import db, login_manager


def create_app(config_name=None):
    """Application factory."""
    if config_name is None:
        config_name = os.environ.get('FLASK_CONFIG', 'development')

    app = Flask(__name__)
    app.config.from_object(config_map.get(config_name, config_map['default']))

    # Ensure instance folder exists
    os.makedirs(os.path.join(app.root_path, 'instance'), exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)

    # User loader for Flask-Login
    from models.user import User

    @login_manager.user_loader
    def load_user(user_id):
        from models.user import User
        return db.session.get(User, int(user_id))

    # Register blueprints
    from routes.auth_routes import auth_bp
    from routes.scan_routes import scan_bp
    from routes.admin_routes import admin_bp
    from routes.api_routes import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp)

    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; img-src 'self' data:; connect-src 'self';"
        return response

    # Create database tables and default admin
    with app.app_context():
        db.create_all()
        _create_default_admin()

    return app


def _create_default_admin():
    """Create specific admin user if none exists."""
    from models.user import User

    # Only Vivaan is the admin
    vivaan = User.query.filter_by(email='viv08.bhagwat@gmail.com').first()
    if not vivaan:
        vivaan = User(
            username='vivaan',
            email='viv08.bhagwat@gmail.com',
            role='admin',
        )
        vivaan.set_password('Admin@123') # Initial password
        db.session.add(vivaan)
        db.session.commit()
        print('[+] Admin account created for: viv08.bhagwat@gmail.com')


if __name__ == '__main__':
    from waitress import serve
    app = create_app()
    print('[*] CyberShield Vulnerability Scanner Starting...')
    print('[*] Mode: Production (Waitress)')
    print('[*] Address: http://cybershield.127.0.0.1.nip.io:8080')
    print('[*] (Note: No setup required! This domain maps to your localhost automatically.)')
    
    # Use waitress for production-ready serving
    serve(app, host='0.0.0.0', port=8080)
