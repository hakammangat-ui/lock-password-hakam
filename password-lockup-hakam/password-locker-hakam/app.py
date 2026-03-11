from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import string
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from functools import wraps
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lockup.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ==================== DATABASE MODELS ====================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    master_key_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    verification_code = db.Column(db.String(10))
    verification_code_expires = db.Column(db.DateTime)
    is_verified = db.Column(db.Boolean, default=False)
    passwords = db.relationship('SavedPassword', backref='user', lazy=True, cascade='all, delete-orphan')

class SavedPassword(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    url = db.Column(db.String(500))
    category = db.Column(db.String(100), default='Other')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# ==================== EMAIL CONFIGURATION ====================

EMAIL_ADDRESS = "gautavsharma534@gmail.com"
EMAIL_PASSWORD = "edch hmzj jrks tiuh"

def send_email(recipient_email, subject, body, is_html=False):
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = recipient_email
        
        if is_html:
            msg.attach(MIMEText(body, 'html'))
        else:
            msg.attach(MIMEText(body, 'plain'))
        
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Email sending error: {e}")
        return False

# ==================== UTILITY FUNCTIONS ====================

def generate_verification_code():
    return ''.join(random.choices(string.digits, k=6))

def check_password_strength(password):
    score = 0
    feedback = []
    
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("At least 8 characters")
    
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Lowercase letter")
    
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Uppercase letter")
    
    if re.search(r'[0-9]', password):
        score += 1
    else:
        feedback.append("Number")
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 2
    else:
        feedback.append("Special character")
    
    if score <= 1:
        strength = 'Weak'
    elif score <= 2:
        strength = 'Medium'
    elif score <= 4:
        strength = 'Strong'
    else:
        strength = 'Excellent'
    
    return {
        'strength': strength,
        'score': min(score, 5),
        'feedback': feedback
    }

def generate_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== AUTH ROUTES ====================

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        confirm_password = data.get('confirm_password', '')
        master_key = data.get('master_key', '')
        
        # Validation
        if not all([username, email, password, confirm_password, master_key]):
            return jsonify({'success': False, 'message': 'All fields required'}), 400
        
        if len(username) < 3:
            return jsonify({'success': False, 'message': 'Username must be at least 3 characters'}), 400
        
        if password != confirm_password:
            return jsonify({'success': False, 'message': 'Passwords do not match'}), 400
        
        if len(master_key) < 4:
            return jsonify({'success': False, 'message': 'Master key must be at least 4 characters'}), 400
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already exists'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email already registered'}), 400
        
        # Create verification code
        verification_code = generate_verification_code()
        
        # Create user
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            master_key_hash=generate_password_hash(master_key),
            verification_code=verification_code,
            verification_code_expires=datetime.utcnow() + timedelta(hours=1)
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Send verification email
        email_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
                <div style="max-width: 500px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                    <h2 style="color: #333; text-align: center;">Welcome to Lockup</h2>
                    <p style="color: #666; font-size: 16px;">Your verification code is:</p>
                    <p style="background-color: #f0f0f0; padding: 15px; text-align: center; font-size: 24px; font-weight: bold; color: #FF4444; border-radius: 5px; letter-spacing: 5px;">
                        {verification_code}
                    </p>
                    <p style="color: #999; font-size: 14px; text-align: center;">This code expires in 1 hour.</p>
                </div>
            </body>
        </html>
        """
        
        send_email(email, 'Lockup - Verify Your Email', email_body, is_html=True)
        
        return jsonify({
            'success': True,
            'message': 'Signup successful! Check your email for verification code.',
            'email': email,
            'user_id': user.id
        }), 201
    
    return render_template('signup.html')

@app.route('/verify-email', methods=['POST'])
def verify_email():
    data = request.get_json()
    user_id = data.get('user_id')
    code = data.get('code')
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    if user.verification_code != code:
        return jsonify({'success': False, 'message': 'Invalid verification code'}), 400
    
    if user.verification_code_expires < datetime.utcnow():
        return jsonify({'success': False, 'message': 'Verification code expired'}), 400
    
    user.is_verified = True
    user.verification_code = None
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Email verified successfully'}), 200

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username_or_email = data.get('username', '').strip()
        password = data.get('password', '')
        
        user = User.query.filter(
            (User.username == username_or_email) | (User.email == username_or_email)
        ).first()
        
        if user and check_password_hash(user.password_hash, password):
            if not user.is_verified:
                return jsonify({'success': False, 'message': 'Please verify your email first'}), 401
            
            session['user_id'] = user.id
            session['username'] = user.username
            return jsonify({'success': True, 'message': 'Login successful'}), 200
        
        return jsonify({'success': False, 'message': 'Invalid username or password'}), 401
    
    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email', '').strip()
        
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'success': False, 'message': 'Email not found'}), 404
        
        # Generate verification code
        verification_code = generate_verification_code()
        user.verification_code = verification_code
        user.verification_code_expires = datetime.utcnow() + timedelta(hours=1)
        db.session.commit()
        
        # Send email
        email_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
                <div style="max-width: 500px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                    <h2 style="color: #333; text-align: center;">Reset Your Password</h2>
                    <p style="color: #666; font-size: 16px;">Your password reset code is:</p>
                    <p style="background-color: #f0f0f0; padding: 15px; text-align: center; font-size: 24px; font-weight: bold; color: #FF4444; border-radius: 5px; letter-spacing: 5px;">
                        {verification_code}
                    </p>
                    <p style="color: #999; font-size: 14px; text-align: center;">This code expires in 1 hour.</p>
                </div>
            </body>
        </html>
        """
        
        send_email(email, 'Lockup - Reset Your Password', email_body, is_html=True)
        
        return jsonify({
            'success': True,
            'message': 'Reset code sent to your email',
            'email': email
        }), 200
    
    return render_template('forgot_password.html')

@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email', '').strip()
    code = data.get('code', '')
    new_password = data.get('new_password', '')
    confirm_password = data.get('confirm_password', '')
    
    if new_password != confirm_password:
        return jsonify({'success': False, 'message': 'Passwords do not match'}), 400
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    if user.verification_code != code:
        return jsonify({'success': False, 'message': 'Invalid verification code'}), 400
    
    if user.verification_code_expires < datetime.utcnow():
        return jsonify({'success': False, 'message': 'Verification code expired'}), 400
    
    user.password_hash = generate_password_hash(new_password)
    user.verification_code = None
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Password reset successful'}), 200

@app.route('/master-key-verify', methods=['POST'])
def master_key_verify():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    data = request.get_json()
    master_key = data.get('master_key', '')
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    if check_password_hash(user.master_key_hash, master_key):
        session['master_key_verified'] = True
        return jsonify({'success': True, 'message': 'Master key verified'}), 200
    
    return jsonify({'success': False, 'message': 'Invalid master key'}), 401

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ==================== DASHBOARD ROUTES ====================

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', username=user.username)

@app.route('/api/password-strength', methods=['POST'])
@login_required
def password_strength():
    data = request.get_json()
    password = data.get('password', '')
    
    result = check_password_strength(password)
    return jsonify(result), 200

@app.route('/api/generate-password', methods=['GET'])
@login_required
def api_generate_password():
    length = request.args.get('length', 16, type=int)
    if length < 8 or length > 32:
        length = 16
    
    password = generate_password(length)
    strength = check_password_strength(password)
    
    return jsonify({
        'password': password,
        'strength': strength['strength']
    }), 200

# ==================== PASSWORD MANAGEMENT ROUTES ====================
@app.route('/api/passwords', methods=['GET', 'POST'])
@login_required
def manage_passwords():
    if request.method == 'POST':
        data = request.get_json()
        
        required_fields = ['name', 'username', 'password', 'category']
        if not all(field in data for field in required_fields):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        # Encrypt password before storing (simple encryption for demo)
        password = SavedPassword(
            user_id=session['user_id'],
            name=data.get('name'),
            username=data.get('username'),
            password=data.get('password'),
            url=data.get('url', ''),
            category=data.get('category', 'Other')
        )
        
        db.session.add(password)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Password saved successfully',
            'id': password.id
        }), 201
    
    # GET - retrieve all passwords for user
    passwords = SavedPassword.query.filter_by(user_id=session['user_id']).all()
    
    return jsonify({
        'success': True,
        'passwords': [{
            'id': p.id,
            'name': p.name,
            'username': p.username,
            'password': p.password,
            'url': p.url,
            'category': p.category,
            'created_at': p.created_at.strftime('%Y-%m-%d %H:%M')
        } for p in passwords]
    }), 200

# ==================== SINGLE PASSWORD MANAGEMENT ROUTE ====================

@app.route('/api/passwords/<int:password_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def manage_single_password(password_id):
    password = SavedPassword.query.get(password_id)
    
    if not password or password.user_id != session['user_id']:
        return jsonify({'success': False, 'message': 'Password not found'}), 404
    
    if request.method == 'GET':
        return jsonify({
            'success': True,
            'password': {
                'id': password.id,
                'name': password.name,
                'username': password.username,
                'password': password.password,
                'url': password.url,
                'category': password.category
            }
        }), 200
    
    elif request.method == 'PUT':
        data = request.get_json()
        
        # Verify master key for updates
        if 'master_key_verified' not in session:
            master_key = data.get('master_key', '')
            user = User.query.get(session['user_id'])
            if not check_password_hash(user.master_key_hash, master_key):
                return jsonify({'success': False, 'message': 'Invalid master key'}), 401
        
        password.name = data.get('name', password.name)
        password.username = data.get('username', password.username)
        password.password = data.get('password', password.password)
        password.url = data.get('url', password.url)
        password.category = data.get('category', password.category)
        password.updated_at = datetime.utcnow()
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Password updated successfully'}), 200
    
# ==================== USER SETTINGS ROUTES ====================
@app.route('/api/user-settings', methods=['GET', 'PUT'])
@login_required
def user_settings():
    user = User.query.get(session['user_id'])
    
    if request.method == 'GET':
        return jsonify({
            'success': True,
            'user': {
                'username': user.username,
                'email': user.email
            }
        }), 200
    
    elif request.method == 'PUT':
        data = request.get_json()
        
        # Verify master key
        master_key = data.get('master_key', '')
        if not check_password_hash(user.master_key_hash, master_key):
            return jsonify({'success': False, 'message': 'Invalid master key'}), 401
        
        # Update fields
        if 'username' in data and data['username']:
            if User.query.filter_by(username=data['username']).first() and data['username'] != user.username:
                return jsonify({'success': False, 'message': 'Username already taken'}), 400
            user.username = data['username']
            session['username'] = user.username
        
        if 'email' in data and data['email']:
            if User.query.filter_by(email=data['email']).first() and data['email'] != user.email:
                return jsonify({'success': False, 'message': 'Email already registered'}), 400
            user.email = data['email']
        
        if 'password' in data and data['password']:
            if data['password'] != data.get('confirm_password', ''):
                return jsonify({'success': False, 'message': 'Passwords do not match'}), 400
            user.password_hash = generate_password_hash(data['password'])
        

        if 'master_key' in data and data['master_key']:
            if data['master_key'] != data.get('confirm_master_key', ''):
                return jsonify({'success': False, 'message': 'Master keys do not match'}), 400
            user.master_key_hash = generate_password_hash(data['master_key'])
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Settings updated successfully'}), 200

# ==================== CATEGORIES ROUTES ====================
@app.route('/api/categories')
@login_required
def get_categories():
    categories = [
        'Entertainment',
        'Social Media',
        'Email',
        'Banking',
        'Shopping',
        'Work',
        'Gaming',
        'Education',
        'Other'
    ]
    return jsonify({'categories': categories}), 200

# ==================== CHANGE PASSWORD ROUTES ====================

@app.route('/api/change-password', methods=['POST'])
@login_required
def change_password_route():
    data = request.get_json()
    user = User.query.get(session['user_id'])
    
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    
    if not check_password_hash(user.password_hash, current_password):
        return jsonify({'success': False, 'message': 'Current password is incorrect'}), 401
    
    user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Password changed successfully'}), 200

@app.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'message': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'success': False, 'message': 'Internal server error'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
