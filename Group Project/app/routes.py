from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from flask_login import login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from app import limiter
from app.forms import LoginForm, RegisterForm, MFAForm
from app.utils.security import verify_password, generate_unique_user_id, hash_password, password_checker
from app.utils.register_users import register_user
from app.utils.decorators import login_required_with_flash, mfa_required, temp_user_required
from app.models import User
import pyotp
import qrcode
from io import BytesIO
from flask import send_file
import base64
import os
from datetime import datetime

def log_to_file(message, filename='app_log.txt'):
    log_dir = os.path.join(os.path.dirname(__file__), 'logs')  
    os.makedirs(log_dir, exist_ok=True)  
    file_path = os.path.join(log_dir, filename)

    
    with open(file_path, 'a') as log_file:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_file.write(f"{timestamp} - {message}\n")

main_bp = Blueprint('main', __name__)

@main_bp.route('/', methods=['GET', 'POST'])
def index():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    else:
        return redirect(url_for('main.login'))

@main_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user_data = current_app.users.get(username)

        
        log_to_file(f"Login attempt for username: {username}, password: {password}")

        if user_data and verify_password(user_data['password']['hashed_password'], user_data['password']['salt'], password):
            user = User(user_data['id'], username, user_data['password'])
            login_user(user)
            if not user_data.get('mfa_completed', False):
                flash('Please complete MFA setup', 'warning')
                return redirect(url_for('main.mfa_setup', user_id=user.id))
            flash('Login successful, please complete MFA', 'success')
            return redirect(url_for('main.mfa'))
        else:
            log_to_file(f"Failed login attempt for username: {username}, password: {password}")
            flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)
    
@main_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        confirm_password = form.confirm_password.data
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html', form=form)

        if password_checker(password):
            first_name = form.first_name.data
            last_name = form.last_name.data
            email = form.email.data
            hashed_password = hash_password(password)
            
            log_to_file(f"Registration attempt for username: {username}, password: {hashed_password}")
            mfa_secret = pyotp.random_base32()  

            if username not in current_app.users:
                user_id = generate_unique_user_id()
                current_app.users[username] = {
                    'id': user_id,
                    'username': username,
                    'first_name': first_name,
                    'last_name': last_name,
                    'email': email,
                    'password': hashed_password,
                    'mfa_secret': mfa_secret
                }
                flash('Registration successful, please setup your MFA', 'success')
                login_user(User(user_id, username, hashed_password))
                return redirect(url_for('main.mfa_setup', user_id=user_id))
            else:
                log_to_file(f"Registration failed: Username {username} already exists.")
                flash('Username already exists', 'danger')
        else:
            log_to_file(f"Registration failed: Password for {username} does not meet security requirements.")
            flash('Password does not meet security requirements', 'danger')
    return render_template('register.html', form=form)

@main_bp.route('/mfa-setup/<user_id>', methods=['GET', 'POST'])
@login_required_with_flash
@limiter.limit("10 per minute")
def mfa_setup(user_id):
    user_data = None
    for user in current_app.users.values():
        if user['id'] == user_id:
            user_data = user
            break

    if not user_data:
        flash('User not found', 'danger')
        flash('Redirecting to registration page', 'info')
        return redirect(url_for('main.register'))

    
    if current_user.id != user_id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('main.index'))

    totp = pyotp.TOTP(user_data['mfa_secret'])
    uri = totp.provisioning_uri(user_data['username'], issuer_name="derekis.cool")
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf)
    buf.seek(0)
    img_data = base64.b64encode(buf.getvalue()).decode('utf-8')  

    form = MFAForm()
    if form.validate_on_submit():
        otp = form.otp.data
        if totp.verify(otp):
            user_data['mfa_completed'] = True
            flash('MFA setup completed successfully!', 'success')
            logout_user()  
            flash('Please log in again to complete the process', 'info')
            return redirect(url_for('main.login'))  
        else:
            flash('Invalid OTP, please try again.', 'danger')

    return render_template('mfa_setup.html', img_data=img_data, form=form)

@main_bp.route('/mfa', methods=['GET', 'POST'])
@login_required_with_flash
@limiter.limit("10 per minute")
def mfa():
    form = MFAForm()
    if form.validate_on_submit():
        otp = form.otp.data
        user = current_user
        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(otp):
            
            for user_data in current_app.users.values():
                if user_data['id'] == user.id:
                    user_data['mfa_completed'] = True
                    break
            flash('MFA completed successfully!', 'success')
            flash('Redirecting to dashboard', 'info')
            return redirect(url_for('main.dashboard'))  
        else:
            flash('Invalid OTP', 'danger')
    return render_template('mfa.html', form=form)

@main_bp.route('/dashboard')
@login_required_with_flash
@mfa_required
def dashboard():
    return render_template('dashboard.html')

@main_bp.route('/list_users', methods=['GET'])
@limiter.limit("10 per minute")
def list_users():
    return render_template('list_users.html', users=current_app.users)

@main_bp.route('/logout')
@login_required_with_flash
@limiter.limit("10 per minute")
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('main.login'))

