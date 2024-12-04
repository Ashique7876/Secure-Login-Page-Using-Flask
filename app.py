from flask import Flask, request, render_template, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
from datetime import datetime, timedelta
from flask_mail import Mail, Message
import os
from flask_sslify import SSLify
from flask_talisman import Talisman
from flask_limiter import Limiter
from dotenv import load_dotenv
from markupsafe import escape

load_dotenv()

# Flask app configuration
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY') 
limiter = Limiter(app)
sslify = SSLify(app)


csp = {
    'default-src': ["'self'"],
    'style-src': ["'self'", "'unsafe-inline'"],
    'script-src': ["'self'"]
}

talisman = Talisman(app, content_security_policy=csp)

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Email Configuration 
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'False') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
mail = Mail(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# OTP Model 
class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

# Create tables
with app.app_context():
    db.drop_all()
    db.create_all()

# Function To Create OTP
def send_otp(email):
    otp = ''.join(random.choices(string.digits, k=6))  
    expires_at = datetime.now() + timedelta(minutes=2) 

    # Check if the email already has an OTP entry
    otp_record = OTP.query.filter_by(email=email).first()

    if otp_record:
        # Update the existing record
        otp_record.otp_code = otp
        otp_record.expires_at = expires_at
    else:
        # Create a new record 
        otp_record = OTP(email=email, otp_code=otp, expires_at=expires_at)
        db.session.add(otp_record)


    db.session.commit()

    # Send OTP email
    msg = Message('Your OTP Code', sender='Your Email Address', recipients=[email])
    msg.body = f'Your OTP code is {otp}. It will expire in 2 minutes.'
    mail.send(msg)

# Routes

# Login Page
@app.route('/', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        email = escape(request.form['email'])  # Escape user input
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['email'] = email
            session['logged_in'] = True
            return redirect(url_for('dashboard'))

        flash('Invalid Credentials', 'error')
        return redirect(url_for('login'))

    return render_template('login.html')

# Registration Page with OTP
@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if request.method == 'POST':
        username = escape(request.form['name'])  # Escape user input
        email = escape(request.form['email'])  # Escape user input
        password = request.form['password']
        confirm_password = request.form['password2']
        
        if password != confirm_password:
            flash("Passwords do not match", "error")
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email is already registered", "error")
            return redirect(url_for('login'))

        # Temporarily save OTP for verification
        send_otp(email)
        session['email'] = email  # Store email in session for OTP verification
        session['username'] = username
        session['password'] = generate_password_hash(password)  # Store hashed password
        flash("OTP sent to your email. Please verify.", "info")
        return redirect(url_for('otpverify'))

    return render_template('register.html')

# OTP Verification Page
@app.route('/otpverify', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def otpverify():
    if request.method == 'POST':
        otp = request.form['otp']
        email = session.get('email')
        username = session.get('username')
        password = session.get('password')
        
        if not email or not username or not password:
            flash("Session expired or invalid request.", "error")
            return redirect(url_for('register'))

        otp_record = OTP.query.filter_by(email=email).first()
        if not otp_record or otp != otp_record.otp_code or datetime.now() > otp_record.expires_at:
            flash('Invalid or expired OTP', 'error')
            return redirect(url_for('otpverify'))

        # OTP is valid. Register the user.
        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()

        # Clean up the OTP record
        db.session.delete(otp_record)
        db.session.commit()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('otpverify.html')

# Dashboard Page
@app.route('/dashboard')
@limiter.limit("5 per minute")
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user_email = session.get('email')
    user = User.query.filter_by(email=user_email).first()

    return render_template('dashboard.html', username=escape(user.username)) 

# Logout Page
@app.route('/logout')
@limiter.limit("5 per minute")
def logout():
    session.pop('logged_in', None)
    session.pop('email', None)
    flash("Logged out successfully!", "success")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)



