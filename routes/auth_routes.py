"""
Authentication routes - signup, login, logout with Flask-Login.
"""
import re
import secrets
from datetime import datetime, timedelta, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from extensions import db
from models.user import User
from modules.security_utils import rate_limit

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

# Password validation regex: min 8 chars, 1 upper, 1 lower, 1 digit, 1 special
PASSWORD_PATTERN = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^()_\-+=])[A-Za-z\d@$!%*?&#^()_\-+=]{8,}$'
)
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')


@auth_bp.route('/signup', methods=['GET', 'POST'])
@rate_limit(limit=10, period=3600)  # Max 10 signups per hour
def signup():
    """User registration."""
    if current_user.is_authenticated:
        return redirect(url_for('scan.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        # Validation
        errors = []
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters.')
        if not EMAIL_PATTERN.match(email):
            errors.append('Invalid email format.')
        if not PASSWORD_PATTERN.match(password):
            errors.append(
                'Password must be 8+ chars with uppercase, lowercase, digit, and special character.'
            )
        if password != confirm:
            errors.append('Passwords do not match.')
        if User.query.filter_by(email=email).first():
            errors.append('Email is already registered.')
        if User.query.filter_by(username=username).first():
            errors.append('Username is already taken.')

        if errors:
            for err in errors:
                flash(err, 'danger')
            return render_template('auth/signup.html', username=username, email=email)

        # Create user
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/signup.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
@rate_limit(limit=10, period=300)  # Max 10 attempts per 5 mins
def login():
    """User login."""
    if current_user.is_authenticated:
        return redirect(url_for('scan.dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'

        # Admin Special Case
        if email == 'viv08.bhagwat@gmail.com' and password == 'viv.bhagwat@040208':
            user = User.query.filter_by(email=email).first()
            if not user:
                # Create admin user if it doesn't exist
                user = User(username='admin', email=email, role='admin')
                user.set_password(password)
                db.session.add(user)
                db.session.commit()
            elif user.role != 'admin':
                user.role = 'admin'
                db.session.commit()

            login_user(user, remember=remember)
            return redirect(url_for('admin.dashboard'))

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            if not user.is_active_user:
                flash('Your account has been suspended. Contact admin.', 'danger')
                return render_template('auth/login.html', email=email)

            login_user(user, remember=remember)

            next_page = request.args.get('next')
            if user.is_admin:
                return redirect(next_page or url_for('admin.dashboard'))
            return redirect(next_page or url_for('scan.dashboard'))

        flash('Invalid email or password.', 'danger')
        return render_template('auth/login.html', email=email)

    return render_template('auth/login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    """User logout."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
@rate_limit(limit=3, period=3600)  # Max 3 reset requests per hour
def forgot_password():
    """Request password reset link."""
    if current_user.is_authenticated:
        return redirect(url_for('scan.dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user = User.query.filter_by(email=email).first()

        if user:
            # Generate token and expiry
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.reset_token_expiry = datetime.now(timezone.utc) + timedelta(hours=1)
            db.session.commit()

            # In a real app, send email here. For this project, we print to terminal.
            reset_url = url_for('auth.reset_password', token=token, _external=True)
            print("\n" + "="*50)
            print(f"PASSWORD RESET LINK FOR {user.email}:")
            print(reset_url)
            print("="*50 + "\n")

            flash('If an account exists with that email, a reset link has been generated (check terminal).', 'info')
        else:
            # Same message to prevent email enumeration
            flash('If an account exists with that email, a reset link has been generated.', 'info')

        return redirect(url_for('auth.login'))

    return render_template('auth/forgot_password.html')


@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset password using token."""
    if current_user.is_authenticated:
        return redirect(url_for('scan.dashboard'))

    user = User.query.filter_by(reset_token=token).first()

    if not user or not user.reset_token_expiry or user.reset_token_expiry.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if not PASSWORD_PATTERN.match(password):
            flash('Password must be 8+ chars with uppercase, lowercase, digit, and special character.', 'danger')
            return render_template('auth/reset_password.html', token=token)

        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return render_template('auth/reset_password.html', token=token)

        user.set_password(password)
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()

        flash('Your password has been updated! You can now log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/reset_password.html', token=token)
