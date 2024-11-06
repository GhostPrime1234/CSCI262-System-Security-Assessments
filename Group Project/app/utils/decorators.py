from functools import wraps
from flask import redirect, url_for, flash, session
from flask_login import current_user

def login_required_with_flash(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('You need to be logged in to access this page.', 'warning')
            return redirect(url_for('main.login'))
        return f(*args, **kwargs)
    return decorated_function

def mfa_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('main.login'))
        if not current_user.mfa_completed:
            flash('Please complete MFA setup', 'warning')
            return redirect(url_for('main.mfa_setup', user_id=current_user.id))
        return f(*args, **kwargs)
    return decorated_function

def temp_user_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        temp_user = session.get('temp_user')
        if not temp_user or (current_user.is_authenticated and current_user.id != temp_user['id']):
            flash('Unauthorized access or session expired', 'danger')
            return redirect(url_for('main.login'))
        return f(*args, **kwargs)
    return decorated_function