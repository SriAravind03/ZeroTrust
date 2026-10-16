import re
import math
import csv
import logging
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, g, make_response
import sqlite3, os, json, secrets, hashlib, hmac, time, random, datetime
from functools import wraps
import pyotp
import qrcode
import io
import base64
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from contextlib import closing
from typing import Tuple, Dict, Any, Optional, Union, List

# ---------------- LOGGING CONFIG ----------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ---------------- CONFIGURATION ----------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
DB_NAME = os.environ.get("DATABASE_PATH", "database.db")
JWT_SECRET = os.environ.get("JWT_SECRET_KEY") or secrets.token_hex(32)

# ---------------- DATABASE INIT ----------------
def get_db():
    db_path = app.config.get('DATABASE', DB_NAME)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with closing(get_db()) as conn:
        c = conn.cursor()
        
        # Users Table
        c.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password_hash TEXT,
            role TEXT DEFAULT 'user',
            otp_secret TEXT,
            trust_score REAL DEFAULT 1.0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        
        # Devices Table (Device Trust Engine)
        c.execute("""CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            fingerprint TEXT,
            user_agent TEXT,
            ip_address TEXT,
            is_trusted INTEGER DEFAULT 0,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")
        
        # Sessions Table (Session Monitor)
        c.execute("""CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            token TEXT UNIQUE,
            ip_address TEXT,
            user_agent TEXT,
            risk_score REAL,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")
        
        # Risk Logs (Risk Engine History)
        c.execute("""CREATE TABLE IF NOT EXISTS risk_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            event_type TEXT,
            risk_score REAL,
            reason TEXT,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        
        # Policies (PDP Rules)
        c.execute("""CREATE TABLE IF NOT EXISTS policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            resource TEXT UNIQUE,
            required_role TEXT,
            max_risk_score REAL,
            mfa_required INTEGER DEFAULT 1,
            allow_iot INTEGER DEFAULT 0
        )""")

        # Protected Internal Apps (Micro-segmentation)
        c.execute("""CREATE TABLE IF NOT EXISTS protected_apps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            description TEXT,
            url_slug TEXT UNIQUE,
            sensitivity_level TEXT, -- low, medium, high
            required_trust_score REAL DEFAULT 50.0
        )""")

        # Device Posture/Compliance (Device Trust)
        c.execute("""CREATE TABLE IF NOT EXISTS device_posture (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER,
            os_version TEXT,
            is_encrypted INTEGER DEFAULT 1,
            is_firewall_enabled INTEGER DEFAULT 1,
            is_antivirus_active INTEGER DEFAULT 1,
            last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(device_id) REFERENCES devices(id)
        )""")
        
        # IoT Devices (IoT Module)
        c.execute("""CREATE TABLE IF NOT EXISTS iot_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT UNIQUE,
            secret_key TEXT,
            name TEXT,
            owner_id INTEGER,
            status TEXT DEFAULT 'active',
            last_heartbeat TIMESTAMP,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        )""")
        
        # Update Users table with missing columns if not exists
        try:
            c.execute("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'")
        except sqlite3.OperationalError: pass
        
        try:
            c.execute("ALTER TABLE users ADD COLUMN permissions TEXT DEFAULT ''")
        except sqlite3.OperationalError: pass

        try:
            c.execute("ALTER TABLE users ADD COLUMN trust_score REAL DEFAULT 1.0")
        except sqlite3.OperationalError: pass

        # Seed Default Policies
        if c.execute("SELECT COUNT(*) FROM policies").fetchone()[0] == 0:
            c.executemany("INSERT INTO policies (resource, required_role, max_risk_score, mfa_required) VALUES (?,?,?,?)", [
                ('dashboard', 'user', 70.0, 1),
                ('admin_panel', 'admin', 30.0, 1),
                ('iot_control', 'user', 50.0, 0),
                ('hr_portal', 'user', 40.0, 1),
                ('finance_system', 'user', 20.0, 1)
            ])

        # Seed Protected Apps
        if c.execute("SELECT COUNT(*) FROM protected_apps").fetchone()[0] == 0:
            c.executemany("INSERT INTO protected_apps (name, description, url_slug, sensitivity_level, required_trust_score) VALUES (?,?,?,?,?)", [
                ('HR Portal', 'Employee records and payroll information.', 'hr-portal', 'medium', 60.0),
                ('Finance System', 'Core financial transactions and auditing.', 'finance-system', 'high', 85.0),
                ('Engineering Wiki', 'Internal technical documentation.', 'eng-wiki', 'low', 30.0)
            ])
            
        conn.commit()

init_db()

# ---------------- ZERO TRUST ENGINES ----------------

class RiskEngine:
    """
    Core engine for calculating user risk scores based on context and behavior.
    Implements the Zero Trust 'verify explicitly' principle.
    """
    @staticmethod
    def calculate_risk(user_id: int, current_ip: str, current_ua: str, device_fp: str) -> Tuple[float, str]:
        """
        Calculates a risk score (0-100) for the current access attempt.
        
        Args:
            user_id: The ID of the user.
            current_ip: The IP address of the request.
            current_ua: The User-Agent string.
            device_fp: The device fingerprint.
            
        Returns:
            Tuple containing (risk_score, reason_string).
        """
        score = 0
        reasons = []
        with closing(get_db()) as conn:
            c = conn.cursor()
            
            # Factor 1: New IP Address (Velocity Check)
            last_login = c.execute("SELECT ip_address, timestamp FROM risk_logs WHERE user_id=? AND event_type='login' ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()
            if last_login and last_login['ip_address'] != current_ip:
                score += 30
                reasons.append("New IP Address detected")
                
            # Factor 2: Device Trust (Known Device?)
            device = c.execute("SELECT * FROM devices WHERE user_id=? AND fingerprint=?", (user_id, device_fp)).fetchone()
            if not device:
                score += 40
                reasons.append("Unknown Device")
            elif not device['is_trusted']:
                score += 20
                reasons.append("Untrusted Device")
                
            # Factor 3: Geo Anomaly (New Country / Far Distance)
            last_login = c.execute("SELECT ip_address, timestamp FROM risk_logs WHERE user_id=? AND event_type='login' ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()
            if last_login:
                prev_geo = get_geo_details(last_login['ip_address'])
                curr_geo = get_geo_details(current_ip)
                
                # Check Country Change
                if prev_geo['country'] != 'Localhost' and curr_geo['country'] != 'Localhost' and prev_geo['country'] != curr_geo['country']:
                    score += 20
                    reasons.append(f"New Country ({curr_geo['country']})")
                    
                # Check Distance
                if prev_geo['lat'] != 0 and curr_geo['lat'] != 0:
                    dist = calculate_distance(prev_geo['lat'], prev_geo['lon'], curr_geo['lat'], curr_geo['lon'])
                    if dist > 500: # 500km threshold
                        score += 40
                        reasons.append(f"Far distance login ({int(dist)}km)")
            
            # Factor 4: Failed Attempts
            recent_fails = c.execute("SELECT COUNT(*) FROM risk_logs WHERE user_id=? AND event_type='failed_login' AND timestamp > datetime('now', '-10 minutes')", (user_id,)).fetchone()[0]
            if recent_fails > 3:
                score += 50
                reasons.append(f"High recent failed attempts ({recent_fails})")

            # Factor 5: Device Posture (Compliance)
            # Simulated check: if no posture record exists, or if antivirus/firewall is off
            posture = c.execute("""
                SELECT dp.* FROM device_posture dp
                JOIN devices d ON dp.device_id = d.id
                WHERE d.user_id=? AND d.fingerprint=?
                ORDER BY dp.last_check DESC LIMIT 1
            """, (user_id, device_fp)).fetchone()
            
            if not posture:
                score += 20
                reasons.append("Missing Device Posture Check")
            else:
                if not posture['is_encrypted']:
                    score += 30
                    reasons.append("Device Not Encrypted")
                if not posture['is_firewall_enabled']:
                    score += 15
                    reasons.append("Firewall Disabled")
                if not posture['is_antivirus_active']:
                    score += 25
                    reasons.append("Antivirus Inactive")
            
        return min(score, 100), "; ".join(reasons)

class PolicyEngine:
    """
    Policy Decision Point (PDP) that evaluates access requests against defined policies.
    """
    @staticmethod
    def evaluate(user_role: str, resource: str, current_risk: float) -> Tuple[bool, str]:
        """
        Evaluates whether a user can access a resource based on role and risk.
        
        Args:
            user_role: The role of the user (e.g., 'admin', 'user').
            resource: The name of the resource being accessed.
            current_risk: The current calculated risk score.
            
        Returns:
            Tuple containing (allowed_bool, reason_string).
        """
        with closing(get_db()) as conn:
            policy = conn.execute("SELECT * FROM policies WHERE resource=?", (resource,)).fetchone()
        
        if not policy:
            return True, "No specific policy, default allow" 
            
        # Strict RBAC Enforcement
        if policy['required_role'] == 'admin' and user_role != 'admin':
            return False, "Role mismatch: Admin required"
            
        if policy['required_role'] == 'user' and user_role == 'admin':
            return False, "Role mismatch: Admin cannot access User Dashboard"
            
        if current_risk > policy['max_risk_score']:
            return False, f"Risk score {current_risk} exceeds policy limit {policy['max_risk_score']}"
            
        return True, "Access Granted"

import jwt

# ---------------- MIDDLEWARE ----------------

@app.before_request
def security_headers_and_csrf():
    # CSRF Protection
    # Skip CSRF for API endpoints
    if request.path.startswith('/api/'):
        return

    if request.method == "POST" and request.endpoint not in ['iot_register']:
        if app.config.get('TESTING'): 
            pass
        else:
            token = session.get('_csrf_token')
            if not token or token != request.form.get('_csrf_token'):
                return "CSRF Token Missing or Invalid", 403

    g.csrf_token = generate_csrf_token()

def verify_jwt(token):
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return data
    except:
        return None

def api_zero_trust_guard(resource_name):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith("Bearer "):
                return jsonify({"error": "Missing or Invalid Token"}), 401
            
            token = auth_header.split(" ")[1]
            payload = verify_jwt(token)
            if not payload:
                return jsonify({"error": "Invalid Token"}), 401
            
            user_id = payload['user_id']
            
            # Zero Trust Checks for API
            with closing(get_db()) as conn:
                user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            
            if not user:
                return jsonify({"error": "User not found"}), 401
                
            # Risk Check
            risk, reasons = RiskEngine.calculate_risk(
                user['id'], 
                request.remote_addr, 
                request.headers.get('User-Agent'), 
                'api_client'
            )
            
            # Policy Check
            allowed, reason = PolicyEngine.evaluate(user['role'], resource_name, risk)
            if not allowed:
                return jsonify({"error": "Access Denied", "reason": reason, "risk_score": risk}), 403
                 
            return f(*args, **kwargs)
        return wrapper
    return decorator

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # CSP: Allow self, scripts/styles from CDN (for Chart.js/CSS), and inline styles/scripts (needed for current templating)
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:;"
    return response

def zero_trust_guard(resource_name):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            # Continuous Verification
            with closing(get_db()) as conn:
                user = conn.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()
            
            if not user:
                session.clear()
                return redirect(url_for('login'))

            # Re-evaluate Risk on every request (Continuous Trust)
            current_risk, reasons = RiskEngine.calculate_risk(
                user['id'], 
                request.remote_addr, 
                request.headers.get('User-Agent'), 
                session.get('device_fp', 'unknown')
            )
            
            # Policy Decision
            allowed, reason = PolicyEngine.evaluate(user['role'], resource_name, current_risk)
            
            if not allowed:
                # Log the denial
                with closing(get_db()) as conn:
                    conn.execute("INSERT INTO risk_logs (user_id, event_type, risk_score, reason, ip_address) VALUES (?, ?, ?, ?, ?)",
                                 (user['id'], 'access_denied', current_risk, f"Denied {resource_name}: {reason}", request.remote_addr))
                    conn.commit()
                
                # Special Case: Step-up Auth
                # If denial is due to risk being slightly over limit, or resource requires high trust
                if current_risk > 30 and current_risk <= 80:
                    # Check if user has verified MFA in this session recently (within last 30 mins)
                    last_mfa = session.get('last_mfa_verify', 0)
                    if time.time() - last_mfa > 1800: # 30 mins
                        session['step_up_target'] = request.url
                        session['step_up_resource'] = resource_name
                        return redirect(url_for('mfa_step_up'))

                return render_template('error.html', error=f"Zero Trust Policy Denial: {reason}", risk=current_risk), 403
            
            # Update session activity
            with closing(get_db()) as conn:
                conn.execute("UPDATE sessions SET last_activity=CURRENT_TIMESTAMP, risk_score=? WHERE user_id=? AND is_active=1", (current_risk, user['id']))
                conn.commit()

            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/mfa-step-up', methods=['GET', 'POST'])
def mfa_step_up() -> Union[str, Any]:
    """Handles Step-up Authentication when risk increases or sensitive resources are accessed."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    with closing(get_db()) as conn:
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        
    if request.method == 'POST':
        code = request.form.get('code')
        totp = pyotp.TOTP(user['otp_secret'])
        if totp.verify(code):
            session['last_mfa_verify'] = time.time()
            target = session.pop('step_up_target', url_for('dashboard'))
            return redirect(target)
        else:
            return render_template('mfa_step_up.html', error="Invalid Code", user=user)
            
    return render_template('mfa_step_up.html', user=user, resource=session.get('step_up_resource', 'Sensitive Resource'))

# ---------------- ROUTES ----------------

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET'])
def register_choice():
    # Deprecated in favor of direct links, but keep for fallback
    return redirect(url_for('index'))

@app.route('/register/<role>', methods=['GET', 'POST'])
def register(role: str) -> Union[str, Any]:
    """
    Handles user registration process.
    
    Args:
        role: The role to register ('user' or 'admin').
        
    Returns:
        Rendered template or redirect response.
    """
    if role not in ['user', 'admin']:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        # Validation
        if not username or not email or not password:
            return render_template('register.html', error="All fields are required", role=role)
        
        if len(password) < 8:
            return render_template('register.html', error="Password must be at least 8 characters", role=role)
        
        # Check existing
        with closing(get_db()) as conn:
            if conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
                return render_template('register.html', error="Username taken", role=role)
            
            # Create User in pending state (until MFA setup)
            # For simplicity, we create them but require MFA setup immediately
            pw_hash = generate_password_hash(password)
            otp_secret = pyotp.random_base32()
            
            try:
                # We insert now, but flow continues to MFA Setup
                # In a real app, maybe use a temp table or session
                cur = conn.cursor()
                cur.execute("INSERT INTO users (username, email, password_hash, otp_secret, role) VALUES (?, ?, ?, ?, ?)",
                             (username, email, pw_hash, otp_secret, role))
                user_id = cur.lastrowid
                conn.commit()
                
                # Set session for MFA Setup
                session['setup_user_id'] = user_id
                session['setup_secret'] = otp_secret
                
                return redirect(url_for('mfa_setup')) 
            except Exception as e:
                return render_template('register.html', error=str(e), role=role)
            
    return render_template('register.html', role=role)

@app.route('/mfa-setup', methods=['GET', 'POST'])
def mfa_setup() -> Union[str, Any]:
    """
    Handles the setup of Multi-Factor Authentication (MFA) for new users.
    
    Returns:
        Rendered template or redirect response.
    """
    if 'setup_user_id' not in session:
        return redirect(url_for('login'))
        
    secret = session['setup_secret']
    user_id = session['setup_user_id']
    
    with closing(get_db()) as conn:
        user = conn.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    
    if request.method == 'POST':
        code = request.form['code']
        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            # MFA Verified, Setup Complete
            session.clear() # Force login
            return redirect(url_for('login', message="Registration Complete! Please Login."))
        else:
             return render_template('mfa_setup.html', error="Invalid Code", secret=secret, username=user['username'])

    # Generate QR Code
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user['username'], issuer_name="ZeroTrustApp")
    
    # Create QR image
    img = qrcode.make(totp_uri)
    buf = io.BytesIO()
    img.save(buf)
    img_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    
    return render_template('mfa_setup.html', secret=secret, username=user['username'], qr_code=img_b64)

@app.route('/login', methods=['GET', 'POST'])
def login() -> Union[str, Any]:
    """
    Handles user login, including credentials verification and initial risk assessment.
    
    Returns:
        Rendered template or redirect response.
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        device_fp = request.form.get('device_fp', 'unknown')
        
        with closing(get_db()) as conn:
            user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            
            if user and check_password_hash(user['password_hash'], password):
                # Clear old session but keep pre-auth info we need
                session.clear()
                
                # 1. Identity Verified -> Check Risk
                risk, reasons = RiskEngine.calculate_risk(user['id'], request.remote_addr, request.headers.get('User-Agent'), device_fp)
                
                # Log login attempt
                conn.execute("INSERT INTO risk_logs (user_id, event_type, risk_score, reason, ip_address) VALUES (?, ?, ?, ?, ?)",
                             (user['id'], 'login_attempt', risk, reasons, request.remote_addr))
                
                # 2. Risk Policy Check
                if risk > 80:
                    conn.commit()
                    return render_template('login.html', error=f"Login Blocked: High Risk Detected ({risk}). {reasons}")
                
                # 3. MFA Challenge (Always required)
                session['pre_auth_user_id'] = user['id']
                session['pre_auth_risk'] = risk
                session['device_fp'] = device_fp
                conn.commit()
                return redirect(url_for('mfa_verify'))
            
        return render_template('login.html', error="Invalid Credentials")
        
    message = request.args.get('message')
    return render_template('login.html', message=message)

@app.route('/verify-mfa', methods=['GET', 'POST'])
def mfa_verify() -> Union[str, Any]:
    """
    Verifies the MFA code provided by the user.
    
    Returns:
        Rendered template or redirect response.
    """
    if 'pre_auth_user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['pre_auth_user_id']
    with closing(get_db()) as conn:
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        
        if request.method == 'POST':
            method = request.form.get('method', 'totp')
            
            if method == 'push_simulate':
                # Simulate Push Notification Logic
                # In real world: Send push to device, poll status.
                # Here: We just auto-approve for demo or show a "success" state
                session['push_pending'] = True
                return jsonify({"status": "sent", "message": "Push notification sent to registered device."})
                
            if method == 'push_check':
                # Check if push was approved (Simulation)
                # In a real app, this would check DB/Redis for approval status
                if session.get('push_pending'):
                    # Simulate delay/approval
                    # For demo: auto approve after 3 seconds of waiting logic in frontend?
                    # Actually, let's just approve it if requested.
                    return complete_login(user, conn, return_json=True)
                return jsonify({"status": "pending"})
    
            # TOTP Logic
            code = request.form.get('code')
            totp = pyotp.TOTP(user['otp_secret'])
            
            if totp.verify(code):
                session['last_mfa_verify'] = time.time()
                return complete_login(user, conn)
            else:
                return render_template('mfa.html', error="Invalid Code", user=user)
                
    # GET
    return render_template('mfa.html', user=user)

def complete_login(user: sqlite3.Row, conn: sqlite3.Connection, return_json: bool = False) -> Union[Any, Tuple[Any, int]]:
    """
    Finalizes the login process, creates a session, and logs the event.
    
    Args:
        user: The user row from the database.
        conn: The active database connection.
        return_json: Whether to return a JSON response (for API/AJAX).
        
    Returns:
        Redirect response or JSON response.
    """
    # MFA Success -> Create Session
    session.pop('pre_auth_user_id', None)
    session.pop('push_pending', None)
    
    session['user_id'] = user['id']
    session['role'] = user['role']
    session['login_time'] = time.time()
    session['last_mfa_verify'] = time.time() # Track MFA verification time for Step-up Auth
    
    # Register Device if new
    device_fp = session.get('device_fp')
    existing_dev = conn.execute("SELECT * FROM devices WHERE user_id=? AND fingerprint=?", (user['id'], device_fp)).fetchone()
    if not existing_dev:
        conn.execute("INSERT INTO devices (user_id, fingerprint, user_agent, ip_address, is_trusted) VALUES (?, ?, ?, ?, 1)",
                     (user['id'], device_fp, request.headers.get('User-Agent'), request.remote_addr))
    
    # Log Successful Login
    conn.execute("INSERT INTO risk_logs (user_id, event_type, risk_score, reason, ip_address) VALUES (?, ?, ?, ?, ?)",
                 (user['id'], 'login', 0, 'MFA Verified', request.remote_addr))

    conn.commit()
    
    redirect_url = url_for('admin') if user['role'] == 'admin' else url_for('dashboard')
    
    if return_json:
        return jsonify({"status": "approved", "redirect": redirect_url})
    
    return redirect(redirect_url)

# ---------------- SOC MODULE ----------------

# ---------------- GEO LOCATION SERVICES ----------------

GEO_DB = {
    "USA": (37.0902, -95.7129),
    "Germany": (51.1657, 10.4515),
    "China": (35.8617, 104.1954),
    "Russia": (61.5240, 105.3188),
    "Brazil": (-14.2350, -51.9253),
    "India": (20.5937, 78.9629),
    "UK": (55.3781, -3.4360),
    "Unknown": (0, 0)
}

def get_geo_details(ip: str) -> Dict[str, Any]:
    """
    Simulates a GeoIP service to retrieve location data for an IP address.
    
    Args:
        ip: The IP address to lookup.
        
    Returns:
        Dictionary containing country, lat, and lon.
    """
    # Robustness check
    if not ip or not isinstance(ip, str):
        return {'country': 'Unknown', 'lat': 0, 'lon': 0}

    # Simulated GeoIP Service
    if ip == '127.0.0.1': 
        return {'country': 'Localhost', 'lat': 0, 'lon': 0}
    if ip.startswith('192.168'): 
        return {'country': 'Internal', 'lat': 0, 'lon': 0}
    
    # Mock some anomalies based on IP hash
    try:
        hash_val = sum(ord(c) for c in ip)
        countries = list(GEO_DB.keys())
        country = countries[hash_val % len(countries)]
        lat, lon = GEO_DB.get(country, (0,0))
        return {'country': country, 'lat': lat, 'lon': lon}
    except:
        return {'country': 'Unknown', 'lat': 0, 'lon': 0}

def calculate_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculates the great-circle distance between two points using the Haversine formula.
    
    Args:
        lat1, lon1: Coordinates of the first point.
        lat2, lon2: Coordinates of the second point.
        
    Returns:
        Distance in kilometers.
    """
    # Haversine formula
    R = 6371 # Earth radius in km
    dLat = math.radians(lat2 - lat1)
    dLon = math.radians(lon2 - lon1)
    a = math.sin(dLat/2) * math.sin(dLat/2) + \
        math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * \
        math.sin(dLon/2) * math.sin(dLon/2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    return R * c

def get_geo_location(ip: str) -> str:
    """Helper to get just the country name."""
    return get_geo_details(ip)['country']

@app.route('/soc')
@zero_trust_guard('admin_panel')
def soc_dashboard() -> str:
    """
    Renders the Security Operations Center (SOC) dashboard.
    
    Returns:
        Rendered SOC dashboard template.
    """
    with closing(get_db()) as conn:
        # 1. Fetch Active Sessions with enriched data
        # We join sessions with users to get username
        sessions_raw = conn.execute("""
            SELECT s.*, u.username, u.role, u.trust_score 
            FROM sessions s 
            JOIN users u ON s.user_id = u.id 
            WHERE s.is_active=1 
            ORDER BY s.last_activity DESC
        """).fetchall()
        
        sessions = []
        for s in sessions_raw:
            curr_geo = get_geo_details(s['ip_address'])
            geo = curr_geo['country']
            
            # Geo Anomaly Logic:
            # Check if this geo is different from user's usual geo (mocked by checking last 5 logins)
            # Also check for large distances
            prev_logins = conn.execute("""
                SELECT ip_address FROM risk_logs 
                WHERE user_id=? AND event_type='login' 
                ORDER BY id DESC LIMIT 5
            """, (s['user_id'],)).fetchall()
            
            geo_anomaly = False
            if prev_logins:
                # Check country anomaly
                prev_countries = {get_geo_details(l['ip_address'])['country'] for l in prev_logins}
                if geo not in prev_countries and len(prev_countries) > 0:
                    geo_anomaly = True
                
                # Check distance anomaly (against most recent login)
                last_login_ip = prev_logins[0]['ip_address']
                last_geo = get_geo_details(last_login_ip)
                if last_geo['lat'] != 0 and curr_geo['lat'] != 0:
                    dist = calculate_distance(last_geo['lat'], last_geo['lon'], curr_geo['lat'], curr_geo['lon'])
                    if dist > 500:
                        geo_anomaly = True
            
            # Ensure risk_score is a float for safe template rendering
            try:
                risk_score = float(s['risk_score']) if s['risk_score'] is not None else 0.0
            except:
                risk_score = 0.0
                
            sessions.append({
                'id': s['id'],
                'user_id': s['user_id'],
                'username': s['username'],
                'role': s['role'],
                'ip_address': s['ip_address'],
                'geo_location': geo,
                'geo_anomaly': geo_anomaly,
                'device_info': s['user_agent'][:20] + '...', # Truncate for display
                'risk_score': risk_score,
                'is_active': s['is_active'],
                'last_activity': s['last_activity']
            })
            
        # 2. Device Trust Panel
        devices = conn.execute("""
            SELECT d.*, u.username 
            FROM devices d 
            JOIN users u ON d.user_id = u.id 
            ORDER BY d.last_seen DESC LIMIT 10
        """).fetchall()
        
        # 3. Risk Logs (Pre-processed for safe template rendering)
        risk_logs_raw = conn.execute("""
            SELECT r.*, u.username 
            FROM risk_logs r 
            LEFT JOIN users u ON r.user_id = u.id 
            WHERE r.risk_score > 20 
            ORDER BY r.timestamp DESC LIMIT 20
        """).fetchall()
        
        risk_logs = []
        for rl in risk_logs_raw:
            rl_dict = dict(rl)
            try:
                rl_dict['risk_score'] = float(rl['risk_score']) if rl['risk_score'] is not None else 0.0
            except:
                rl_dict['risk_score'] = 0.0
            risk_logs.append(rl_dict)
        
        # 4. IoT Devices
        iot_devices = conn.execute("SELECT * FROM iot_devices ORDER BY last_heartbeat DESC").fetchall()
        
        # 5. All Users (for User Management Panel)
        all_users = conn.execute("SELECT * FROM users ORDER BY id DESC").fetchall()

        # 6. Audit Logs (Admin Actions)
        audit_logs_raw = conn.execute("""
            SELECT r.*, u.username 
            FROM risk_logs r 
            LEFT JOIN users u ON r.user_id = u.id 
            WHERE r.event_type='admin_action' 
            ORDER BY r.timestamp DESC LIMIT 50
        """).fetchall()
        
        audit_logs = []
        for al in audit_logs_raw:
            al_dict = dict(al)
            try:
                al_dict['risk_score'] = float(al['risk_score']) if al['risk_score'] is not None else 0.0
            except:
                al_dict['risk_score'] = 0.0
            audit_logs.append(al_dict)

        # 7. Protected Apps (Micro-segmentation)
        protected_apps = conn.execute("SELECT * FROM protected_apps").fetchall()
        
        # 8. System Health (Mock)
        import psutil
        try:
            cpu_percent = psutil.cpu_percent()
            memory_percent = psutil.virtual_memory().percent
            disk_percent = psutil.disk_usage('/').percent
        except:
            cpu_percent = 12.5
            memory_percent = 45.2
            disk_percent = 68.1

        system_health = {
            'cpu': cpu_percent,
            'memory': memory_percent,
            'disk': disk_percent,
            'db_size': '1.2 MB' # Mock
        }
        
        # Metrics
        active_users_row = conn.execute("SELECT COUNT(DISTINCT user_id) FROM sessions WHERE is_active=1").fetchone()
        active_users_count = active_users_row[0] if active_users_row else 0
        
        high_risk_row = conn.execute("SELECT COUNT(*) FROM risk_logs WHERE risk_score > 70 AND timestamp > datetime('now', '-1 hour')").fetchone()
        high_risk_count = high_risk_row[0] if high_risk_row else 0
        
        geo_anomalies_count = sum(1 for s in sessions if s['geo_anomaly'])
        
        blocked_attacks_row = conn.execute("SELECT COUNT(*) FROM risk_logs WHERE event_type='access_denied'").fetchone()
        blocked_attacks_count = blocked_attacks_row[0] if blocked_attacks_row else 0
        
        # Chart Data: Risk Trend (Last 24 hours)
        risk_trend_raw = conn.execute("""
            SELECT strftime('%H:00', timestamp) as hour, AVG(risk_score) as avg_risk 
            FROM risk_logs 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY hour 
            ORDER BY timestamp ASC
        """).fetchall()
        risk_trend_labels = [r['hour'] for r in risk_trend_raw]
        risk_trend_data = [round(r['avg_risk'] if r['avg_risk'] is not None else 0.0, 1) for r in risk_trend_raw]
        
    return render_template('soc.html', 
                           sessions=sessions, 
                           devices=devices, 
                           risk_logs=risk_logs, 
                           iot_devices=iot_devices,
                           all_users=all_users,
                           audit_logs=audit_logs,
                           system_health=system_health,
                           active_users_count=active_users_count,
                           high_risk_count=high_risk_count,
                           geo_anomalies_count=geo_anomalies_count,
                           blocked_attacks_count=blocked_attacks_count,
                           risk_trend_labels=risk_trend_labels,
                           risk_trend_data=risk_trend_data,
                           now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

@app.route('/soc/data')
@zero_trust_guard('admin_panel')
def soc_data() -> Any:
    """
    API endpoint to retrieve SOC dashboard data in JSON format.
    
    Returns:
        JSON response containing SOC metrics and logs.
    """
    with closing(get_db()) as conn:
        # Re-fetch everything as JSON
        # 1. Active Sessions
        sessions_raw = conn.execute("""
            SELECT s.*, u.username, u.role, u.trust_score 
            FROM sessions s 
            JOIN users u ON s.user_id = u.id 
            WHERE s.is_active=1 
            ORDER BY s.last_activity DESC
        """).fetchall()
        
        sessions = []
        for s in sessions_raw:
            curr_geo = get_geo_details(s['ip_address'])
            geo = curr_geo['country']
            
            prev_logins = conn.execute("""
                SELECT ip_address FROM risk_logs 
                WHERE user_id=? AND event_type='login' 
                ORDER BY id DESC LIMIT 5
            """, (s['user_id'],)).fetchall()
            
            geo_anomaly = False
            if prev_logins:
                # Check country anomaly
                prev_countries = {get_geo_details(l['ip_address'])['country'] for l in prev_logins}
                if geo not in prev_countries and len(prev_countries) > 0:
                    geo_anomaly = True
                
                # Check distance anomaly
                last_login_ip = prev_logins[0]['ip_address']
                last_geo = get_geo_details(last_login_ip)
                if last_geo['lat'] != 0 and curr_geo['lat'] != 0:
                    dist = calculate_distance(last_geo['lat'], last_geo['lon'], curr_geo['lat'], curr_geo['lon'])
                    if dist > 500:
                        geo_anomaly = True
                    
            # Ensure risk_score is a float for JSON serialization
            try:
                risk_score = float(s['risk_score']) if s['risk_score'] is not None else 0.0
            except:
                risk_score = 0.0
                
            sessions.append({
                'id': s['id'],
                'user_id': s['user_id'],
                'username': s['username'],
                'role': s['role'],
                'ip_address': s['ip_address'],
                'geo_location': geo,
                'geo_anomaly': geo_anomaly,
                'device_info': s['user_agent'][:20] + '...',
                'risk_score': risk_score,
                'is_active': s['is_active'],
                'last_activity': s['last_activity']
            })
            
        # 2. Risk Logs
        risk_logs_raw = conn.execute("""
            SELECT r.*, u.username 
            FROM risk_logs r 
            LEFT JOIN users u ON r.user_id = u.id 
            WHERE r.risk_score > 20 
            ORDER BY r.timestamp DESC LIMIT 20
        """).fetchall()
        
        risk_logs = []
        for rl in risk_logs_raw:
            rl_dict = dict(rl)
            try:
                rl_dict['risk_score'] = float(rl['risk_score']) if rl['risk_score'] is not None else 0.0
            except:
                rl_dict['risk_score'] = 0.0
            risk_logs.append(rl_dict)
        
        # 3. Audit Logs
        audit_logs_raw = conn.execute("""
            SELECT r.*, u.username 
            FROM risk_logs r 
            LEFT JOIN users u ON r.user_id = u.id 
            WHERE r.event_type='admin_action' 
            ORDER BY r.timestamp DESC LIMIT 50
        """).fetchall()
        
        audit_logs = []
        for al in audit_logs_raw:
            al_dict = dict(al)
            try:
                al_dict['risk_score'] = float(al['risk_score']) if al['risk_score'] is not None else 0.0
            except:
                al_dict['risk_score'] = 0.0
            audit_logs.append(al_dict)

        # 4. System Health (Mock)
        import psutil
        try:
            cpu_percent = psutil.cpu_percent()
            memory_percent = psutil.virtual_memory().percent
            disk_percent = psutil.disk_usage('/').percent
        except:
            cpu_percent = 12.5
            memory_percent = 45.2
            disk_percent = 68.1

        system_health = {
            'cpu': cpu_percent,
            'memory': memory_percent,
            'disk': disk_percent,
            'db_size': '1.2 MB'
        }

        # Metrics
        active_users_row = conn.execute("SELECT COUNT(DISTINCT user_id) FROM sessions WHERE is_active=1").fetchone()
        high_risk_row = conn.execute("SELECT COUNT(*) FROM risk_logs WHERE risk_score > 70 AND timestamp > datetime('now', '-1 hour')").fetchone()
        blocked_attacks_row = conn.execute("SELECT COUNT(*) FROM risk_logs WHERE event_type='access_denied'").fetchone()

        metrics = {
            'active_users': active_users_row[0] if active_users_row else 0,
            'high_risk': high_risk_row[0] if high_risk_row else 0,
            'geo_anomalies': sum(1 for s in sessions if s['geo_anomaly']),
            'blocked_attacks': blocked_attacks_row[0] if blocked_attacks_row else 0
        }
        
        # Chart Data: Risk Trend (Last 24 hours)
        risk_trend_raw = conn.execute("""
            SELECT strftime('%H:00', timestamp) as hour, AVG(risk_score) as avg_risk 
            FROM risk_logs 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY hour 
            ORDER BY timestamp ASC
        """).fetchall()
        risk_trend_labels = [r['hour'] for r in risk_trend_raw]
        risk_trend_data = [round(r['avg_risk'] if r['avg_risk'] is not None else 0.0, 1) for r in risk_trend_raw]
        
        # 5. Protected Apps
        protected_apps = conn.execute("SELECT * FROM protected_apps").fetchall()
        
    return jsonify({
        'sessions': sessions,
        'risk_logs': risk_logs,
        'audit_logs': audit_logs,
        'protected_apps': [dict(a) for a in protected_apps],
        'system_health': system_health,
        'metrics': metrics,
        'risk_trend': {
            'labels': risk_trend_labels,
            'data': risk_trend_data
        },
        'now': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })


# --- SOC ACTIONS ---

@app.route('/soc/user_history/<int:user_id>')
@zero_trust_guard('admin_panel')
def user_history(user_id: int) -> Any:
    """Retrieves risk log history for a specific user."""
    with closing(get_db()) as conn:
        logs = conn.execute("""
            SELECT event_type, risk_score, reason, ip_address, timestamp 
            FROM risk_logs 
            WHERE user_id=? 
            ORDER BY timestamp DESC LIMIT 50
        """, (user_id,)).fetchall()
        return jsonify([dict(l) for l in logs])

@app.route('/soc/user_sessions/<int:user_id>')
@zero_trust_guard('admin_panel')
def user_sessions_history(user_id: int) -> Any:
    """Retrieves session history for a specific user."""
    with closing(get_db()) as conn:
        sessions = conn.execute("""
            SELECT * FROM sessions 
            WHERE user_id=? 
            ORDER BY last_activity DESC LIMIT 20
        """, (user_id,)).fetchall()
        return jsonify([dict(s) for s in sessions])

@app.route('/soc/user_devices/<int:user_id>')
@zero_trust_guard('admin_panel')
def user_devices_history(user_id: int) -> Any:
    """Retrieves device history for a specific user."""
    with closing(get_db()) as conn:
        devices = conn.execute("""
            SELECT * FROM devices 
            WHERE user_id=? 
            ORDER BY last_seen DESC
        """, (user_id,)).fetchall()
        return jsonify([dict(d) for d in devices])

@app.route('/block_session/<int:id>', methods=['POST'])
@zero_trust_guard('admin_panel')
def block_session(id: int) -> Any:
    """Admin action to block a specific session."""
    with closing(get_db()) as conn:
        conn.execute("UPDATE sessions SET is_active=0 WHERE id=?", (id,))
        # Log action
        conn.execute("INSERT INTO risk_logs (user_id, event_type, risk_score, reason, ip_address) VALUES (?, ?, ?, ?, ?)",
                     (session['user_id'], 'admin_action', 0, f'Admin blocked session {id}', request.remote_addr))
        conn.commit()
    return redirect(url_for('admin'))

@app.route('/force_reauth/<int:id>', methods=['POST'])
@zero_trust_guard('admin_panel')
def force_reauth(id: int) -> Any:
    """Admin action to force re-authentication for a user (kills all sessions)."""
    # Invalidate all sessions for user
    with closing(get_db()) as conn:
        conn.execute("UPDATE sessions SET is_active=0 WHERE user_id=?", (id,))
        conn.execute("INSERT INTO risk_logs (user_id, event_type, risk_score, reason, ip_address) VALUES (?, ?, ?, ?, ?)",
                     (id, 'admin_action', 0, 'Admin forced re-authentication', request.remote_addr))
        conn.commit()
    return redirect(url_for('admin'))

@app.route('/delete_device/<int:id>', methods=['POST'])
@zero_trust_guard('admin_panel')
def delete_device(id):
    with closing(get_db()) as conn:
        conn.execute("DELETE FROM devices WHERE id=?", (id,))
        conn.commit()
    return redirect(url_for('admin'))

@app.route('/block_iot/<int:id>', methods=['POST'])
@zero_trust_guard('admin_panel')
def block_iot(id: int) -> Any:
    """Admin action to toggle IoT device status (active/blocked)."""
    with closing(get_db()) as conn:
        # Toggle status
        curr = conn.execute("SELECT status FROM iot_devices WHERE id=?", (id,)).fetchone()
        new_status = 'blocked' if curr['status'] == 'active' else 'active'
        conn.execute("UPDATE iot_devices SET status=? WHERE id=?", (new_status, id))
        conn.commit()
    return redirect(url_for('admin'))

@app.route('/block_user/<int:id>', methods=['POST'])
@zero_trust_guard('admin_panel')
def block_user(id):
    with closing(get_db()) as conn:
        # Toggle status
        curr = conn.execute("SELECT status FROM users WHERE id=?", (id,)).fetchone()
        # Default to active if None
        current_status = curr['status'] if curr['status'] else 'active'
        new_status = 'blocked' if current_status == 'active' else 'active'
        
        conn.execute("UPDATE users SET status=? WHERE id=?", (new_status, id))
        
        # Also kill sessions if blocking
        if new_status == 'blocked':
            conn.execute("UPDATE sessions SET is_active=0 WHERE user_id=?", (id,))
            
        conn.execute("INSERT INTO risk_logs (user_id, event_type, risk_score, reason, ip_address) VALUES (?, ?, ?, ?, ?)",
                     (id, 'admin_action', 0, f'Admin changed status to {new_status}', request.remote_addr))
        conn.commit()
    return redirect(url_for('admin'))

@app.route('/reset_mfa/<int:id>', methods=['POST'])
@zero_trust_guard('admin_panel')
def reset_mfa(id: int) -> Any:
    """Admin action to reset MFA secret for a user."""
    with closing(get_db()) as conn:
        # Reset OTP secret -> User will need to re-register
        new_secret = pyotp.random_base32() 
        conn.execute("UPDATE users SET otp_secret=? WHERE id=?", (new_secret, id))
        conn.execute("INSERT INTO risk_logs (user_id, event_type, risk_score, reason, ip_address) VALUES (?, ?, ?, ?, ?)",
                     (id, 'admin_action', 0, 'Admin reset MFA secret', request.remote_addr))
        conn.commit()
    return redirect(url_for('admin'))

@app.route('/change_role/<int:id>', methods=['POST'])
@zero_trust_guard('admin_panel')
def change_role(id):
    with closing(get_db()) as conn:
        curr = conn.execute("SELECT role FROM users WHERE id=?", (id,)).fetchone()
        new_role = 'admin' if curr['role'] == 'user' else 'user'
        conn.execute("UPDATE users SET role=? WHERE id=?", (new_role, id))
        conn.execute("INSERT INTO risk_logs (user_id, event_type, risk_score, reason, ip_address) VALUES (?, ?, ?, ?, ?)",
                     (id, 'admin_action', 0, f'Admin changed role to {new_role}', request.remote_addr))
        conn.commit()
    return redirect(url_for('admin'))

@app.route('/soc/toggle_device_trust/<int:id>', methods=['POST'])
@zero_trust_guard('admin_panel')
def toggle_device_trust(id: int) -> Any:
    """Admin action to toggle device trust status."""
    with closing(get_db()) as conn:
        curr = conn.execute("SELECT is_trusted, fingerprint FROM devices WHERE id=?", (id,)).fetchone()
        if curr:
            new_status = 0 if curr['is_trusted'] else 1
            conn.execute("UPDATE devices SET is_trusted=? WHERE id=?", (new_status, id))
            
            # Log action
            status_str = "Trusted" if new_status else "Untrusted"
            conn.execute("INSERT INTO risk_logs (user_id, event_type, risk_score, reason, ip_address) VALUES (?, ?, ?, ?, ?)",
                         (session['user_id'], 'admin_action', 0, f'Admin set device {curr["fingerprint"][:8]}... to {status_str}', request.remote_addr))
            
            conn.commit()
    return redirect(url_for('admin'))

@app.route('/soc/update_permissions/<int:id>', methods=['POST'])
@zero_trust_guard('admin_panel')
def update_permissions(id):
    with closing(get_db()) as conn:
        # Expecting comma separated string
        perms = request.form.get('permissions', '')
        # Sanitize: simple alphanumeric and commas
        perms = ",".join([p.strip() for p in perms.split(',') if p.strip()])
        
        try:
            conn.execute("UPDATE users SET permissions=? WHERE id=?", (perms, id))
            conn.execute("INSERT INTO risk_logs (user_id, event_type, risk_score, reason, ip_address) VALUES (?, ?, ?, ?, ?)",
                         (session['user_id'], 'admin_action', 0, f'Admin updated permissions for user {id} to [{perms}]', request.remote_addr))
            conn.commit()
        except sqlite3.OperationalError:
            logger.warning(f"Failed to update permissions for user {id}: 'permissions' column might be missing.")
            
    return redirect(url_for('admin'))

@app.route('/admin/export_csv')
@zero_trust_guard('admin_panel')
def export_csv():
    with closing(get_db()) as conn:
        users = conn.execute("SELECT * FROM users").fetchall()
        
        # Create CSV in memory
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(['ID', 'Username', 'Role', 'Status', 'Risk Score', 'Last Activity', 'Geo Location', 'Device Info'])
        
        for u in users:
            # Fetch enriched data
            last_session = conn.execute("SELECT * FROM sessions WHERE user_id=? ORDER BY last_activity DESC LIMIT 1", (u['id'],)).fetchone()
            risk_score = last_session['risk_score'] if last_session else 0
            ip_addr = last_session['ip_address'] if last_session else None
            geo = get_geo_details(ip_addr)['country'] if ip_addr else "Unknown"
            ua = last_session['user_agent'] if last_session else ""
            
            cw.writerow([u['id'], u['username'], u['role'], u['status'] or 'active', risk_score, last_session['last_activity'] if last_session else '', geo, ua])
            
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=soc_users_export.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/soc/create_user', methods=['POST'])
@zero_trust_guard('admin_panel')
def create_user():
    """
    Admin action to create a new user.
    Includes input validation and audit logging.
    """
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    role = request.form.get('role', 'user')
    
    if not username or not email or not password:
         # In a real app we'd flash a message, here we just redirect
         # Ideally we should show an error, but workflow is simple redirect
         logger.warning(f"Admin failed to create user: Missing fields")
         return redirect(url_for('admin'))

    pw_hash = generate_password_hash(password)
    otp_secret = pyotp.random_base32()
    
    with closing(get_db()) as conn:
        try:
            conn.execute("INSERT INTO users (username, email, password_hash, otp_secret, role, status) VALUES (?, ?, ?, ?, ?, 'active')",
                         (username, email, pw_hash, otp_secret, role))
            # Log action
            conn.execute("INSERT INTO risk_logs (user_id, event_type, risk_score, reason, ip_address) VALUES (?, ?, ?, ?, ?)",
                         (session['user_id'], 'admin_action', 0, f'Admin created user {username}', request.remote_addr))
            conn.commit()
        except sqlite3.IntegrityError:
            logger.warning(f"Admin failed to create user: Username or Email already exists.")
        except Exception as e:
            logger.error(f"Error creating user: {str(e)}")

    return redirect(url_for('admin'))

@app.route('/soc/delete_user/<int:id>', methods=['POST'])
@zero_trust_guard('admin_panel')
def delete_user(id: int):
    """
    Admin action to delete a user and all associated data.
    """
    with closing(get_db()) as conn:
        try:
            # Delete dependent data first
            conn.execute("DELETE FROM sessions WHERE user_id=?", (id,))
            conn.execute("DELETE FROM devices WHERE user_id=?", (id,))
            conn.execute("DELETE FROM risk_logs WHERE user_id=?", (id,))
            conn.execute("DELETE FROM iot_devices WHERE owner_id=?", (id,))
            conn.execute("DELETE FROM users WHERE id=?", (id,))
            
            # Log action (assigned to admin since user is gone)
            conn.execute("INSERT INTO risk_logs (user_id, event_type, risk_score, reason, ip_address) VALUES (?, ?, ?, ?, ?)",
                         (session['user_id'], 'admin_action', 0, f'Admin deleted user ID {id}', request.remote_addr))
                         
            conn.commit()
        except Exception as e:
             logger.error(f"Error deleting user {id}: {str(e)}")

    return redirect(url_for('admin'))

@app.route('/dashboard')
@zero_trust_guard('dashboard')
def dashboard():
    """
    User dashboard view.
    Displays user status, recent logs, devices, and current risk score.
    """
    # Strict RBAC: Admin should not be here
    if session.get('role') == 'admin':
        return redirect(url_for('admin'))
        
    with closing(get_db()) as conn:
        user = conn.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()
        raw_logs = conn.execute("SELECT * FROM risk_logs WHERE user_id=? ORDER BY id DESC LIMIT 10", (user['id'],)).fetchall()
        devices = conn.execute("SELECT * FROM devices WHERE user_id=?", (user['id'],)).fetchall()
        protected_apps = conn.execute("SELECT * FROM protected_apps").fetchall()
    
    # Pre-process logs for safe rendering
    def get_safe_risk(val):
        try:
            return float(val) if val is not None else 0.0
        except:
            return 0.0
            
    logs = []
    for l in raw_logs:
        l_dict = dict(l)
        l_dict['risk_score'] = get_safe_risk(l['risk_score'])
        logs.append(l_dict)
        
    current_risk, risk_reasons = RiskEngine.calculate_risk(
        user['id'],
        request.remote_addr,
        request.headers.get('User-Agent'),
        session.get('device_fp', 'unknown')
    )
    if current_risk >= 70:
        risk_level = "High"
    elif current_risk >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"
    return render_template(
        'dashboard.html',
        user=user,
        logs=logs,
        devices=devices,
        current_risk=current_risk,
        risk_reasons=risk_reasons,
        risk_level=risk_level,
        protected_apps=protected_apps
    )

@app.route('/apps/<slug>')
def internal_app_gateway(slug):
    """Simulates a micro-segmented access gateway to internal applications."""
    with closing(get_db()) as conn:
        app_data = conn.execute("SELECT * FROM protected_apps WHERE url_slug=?", (slug,)).fetchone()
    
    if not app_data:
        return render_template('error.html', error="Application not found", risk=0), 404
        
    # Dynamically apply zero_trust_guard based on app slug (resource name in policies)
    # Using 'hr_portal' or 'finance_system' as the resource name
    resource_name = app_data['url_slug'].replace('-', '_')
    
    @zero_trust_guard(resource_name)
    def render_app():
        return render_template('internal_app.html', app=app_data)
        
    return render_app()

def calculate_soc_data(users: List[Dict[str, Any]], all_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculates SOC analytics data from users and logs with robust error handling.
    """
    # Helper to safely get numeric risk score
    def get_risk(log):
        try:
            val = log['risk_score']
            return float(val) if val is not None else 0.0
        except (ValueError, TypeError):
            return 0.0

    # Risk overview
    risk_values = [get_risk(l) for l in all_logs]
    risk_chart_labels = [l['timestamp'] for l in all_logs]
    risk_chart_data = risk_values
    avg_risk = round(sum(risk_values)/len(risk_values), 2) if risk_values else 0.0
    max_risk = max(risk_values) if risk_values else 0.0
    high_risk_count = sum(1 for v in risk_values if v >= 70)
    
    # Geo anomaly: multiple IPs per user across logs
    ips_by_user = {}
    for l in all_logs:
        if l['event_type'] in ('login', 'login_attempt'):
             if l['ip_address']:
                ips_by_user.setdefault(l['user_id'], set()).add(l['ip_address'])
    
    geo_anomalies = {uid: len(ips) for uid, ips in ips_by_user.items() if len(ips) > 1}
    geo_anomaly_count = len(geo_anomalies)

    # Geo anomaly points for Scatter Chart
    geo_points = []
    for uid, ips in ips_by_user.items():
        # Get user name
        u_name = next((u['username'] for u in users if u['id'] == uid), f"User {uid}")
        is_anomaly = len(ips) > 1
        
        for ip in ips:
            geo_info = get_geo_details(ip)
            if geo_info.get('lat', 0) != 0:
                 geo_points.append({
                     'x': geo_info['lon'], 
                     'y': geo_info['lat'], 
                     'user': u_name,
                     'country': geo_info['country'],
                     'is_anomaly': is_anomaly
                 })

    # Behavioural analysis
    failed_attempts_by_user = {}
    new_device_events_by_user = {}
    for l in all_logs:
        reason = str(l['reason'] or '')
        if l['event_type'] == 'login_attempt' and ('Failed' in reason or 'Unknown Device' in reason):
            failed_attempts_by_user[l['user_id']] = failed_attempts_by_user.get(l['user_id'], 0) + 1
        if 'Unknown Device' in reason or 'New Device' in reason:
            new_device_events_by_user[l['user_id']] = new_device_events_by_user.get(l['user_id'], 0) + 1
            
    # Policy denials breakdown
    denials_by_resource = {}
    for l in all_logs:
        if l['event_type'] == 'access_denied' and l['reason']:
            m = re.search(r'Denied\s+(\w+):', l['reason'])
            resource = m.group(1) if m else 'unknown'
            denials_by_resource[resource] = denials_by_resource.get(resource, 0) + 1
            
    # AI risk assessment
    ai_score_by_user = {}
    for u in users:
        uid = u['id']
        score = 0
        score += 3 * sum(1 for l in all_logs if l['user_id'] == uid and get_risk(l) >= 70)
        score += 2 * (geo_anomalies.get(uid, 0))
        score += 2 * failed_attempts_by_user.get(uid, 0)
        score += 2 * new_device_events_by_user.get(uid, 0)
        ai_score_by_user[uid] = score
    
    return {
        "avg_risk": avg_risk,
        "max_risk": max_risk,
        "high_risk_count": high_risk_count,
        "geo_anomaly_count": geo_anomaly_count,
        "geo_points": geo_points,
        "failed_attempts_by_user": failed_attempts_by_user,
        "new_device_events_by_user": new_device_events_by_user,
        "denials_by_resource": denials_by_resource,
        "ai_score_by_user": ai_score_by_user,
        "risk_chart_labels": risk_chart_labels,
        "risk_chart_data": risk_chart_data
    }

@app.route('/api/admin/soc_data')
@zero_trust_guard('admin_panel')
def api_soc_data() -> Any:
    """API endpoint for real-time SOC data updates."""
    with closing(get_db()) as conn:
        users = conn.execute("SELECT * FROM users").fetchall()
        all_logs = conn.execute("SELECT * FROM risk_logs ORDER BY id DESC LIMIT 200").fetchall()
    
    soc_data = calculate_soc_data(users, all_logs)
    return jsonify(soc_data)

@app.route('/admin')
@zero_trust_guard('admin_panel')
def admin():
    """
    Admin SOC Dashboard.
    Displays comprehensive security metrics, logs, and user management.
    """
    with closing(get_db()) as conn:
        users = conn.execute("SELECT * FROM users").fetchall()
        policies = conn.execute("SELECT * FROM policies").fetchall()
        all_logs = conn.execute("SELECT * FROM risk_logs ORDER BY id DESC LIMIT 200").fetchall()
        
        # Build per-user table rows
        user_rows = []
        for u in users:
            # Latest session for activity, risk, IP, UA
            last_session = conn.execute(
                "SELECT * FROM sessions WHERE user_id=? ORDER BY last_activity DESC LIMIT 1",
                (u['id'],)
            ).fetchone()
            
            last_activity = last_session['last_activity'] if last_session else None
            # Ensure risk_score is a float for comparisons
            risk_score_raw = last_session['risk_score'] if last_session else 0
            try:
                risk_score = float(risk_score_raw) if risk_score_raw is not None else 0.0
            except:
                risk_score = 0.0
                
            ip_addr = last_session['ip_address'] if last_session else None
            ua = last_session['user_agent'] if last_session else ""
            geo = get_geo_details(ip_addr)['country'] if ip_addr else "Unknown"
            
            # Geo anomaly vs previous logins
            prev_logins = conn.execute(
                "SELECT ip_address FROM risk_logs WHERE user_id=? AND event_type='login' ORDER BY id DESC LIMIT 5",
                (u['id'],)
            ).fetchall()
            
            geo_anomaly = False
            if prev_logins and ip_addr:
                prev_countries = {get_geo_details(l['ip_address'])['country'] for l in prev_logins}
                if geo not in prev_countries and len(prev_countries) > 0:
                    geo_anomaly = True
                
                last_login_ip = prev_logins[0]['ip_address']
                last_geo = get_geo_details(last_login_ip)
                curr_geo = get_geo_details(ip_addr)
                if last_geo['lat'] != 0 and curr_geo['lat'] != 0:
                    dist = calculate_distance(last_geo['lat'], last_geo['lon'], curr_geo['lat'], curr_geo['lon'])
                    if dist > 500:
                        geo_anomaly = True
                        
            # Device info from latest device record
            last_device = conn.execute(
                "SELECT * FROM devices WHERE user_id=? ORDER BY last_seen DESC LIMIT 1",
                (u['id'],)
            ).fetchone()
            
            if last_device:
                device_info = f"{(last_device['fingerprint'] or '-') } | {ua[:18]}..."
            else:
                device_info = f"{ua[:18]}..."
                
            user_rows.append({
                "id": u['id'],
                "username": u['username'],
                "timestamp": last_activity,
                "risk_score": risk_score,
                "geo_location": geo,
                "geo_anomaly": geo_anomaly,
                "device_info": device_info,
                "status": (u['status'] or 'active')
            })

    # Safe risk scoring for templates
    def get_safe_risk(val):
        try:
            return float(val) if val is not None else 0.0
        except:
            return 0.0

    soc_data = calculate_soc_data(users, all_logs)
    
    # Pre-process logs for safe rendering
    safe_logs = []
    for l in all_logs:
        l_dict = dict(l)
        l_dict['risk_score'] = get_safe_risk(l['risk_score'])
        safe_logs.append(l_dict)

    # Protected Apps
    with closing(get_db()) as conn:
        protected_apps = conn.execute("SELECT * FROM protected_apps").fetchall()
    soc_data['protected_apps'] = [dict(a) for a in protected_apps]

    return render_template(
        'admin.html',
        users=users,
        policies=policies,
        logs=safe_logs, # Use pre-processed logs
        soc=soc_data,
        user_rows=user_rows,
        risk_chart_labels=soc_data['risk_chart_labels'],
        risk_chart_data=soc_data['risk_chart_data'],
    )

@app.route('/iot')
@zero_trust_guard('iot_control')
def iot_dashboard() -> Union[str, Any]:
    """Renders the IoT control dashboard."""
    with closing(get_db()) as conn:
        devices = conn.execute("SELECT * FROM iot_devices WHERE owner_id=?", (session['user_id'],)).fetchall()
    return render_template('iot.html', devices=devices)

@app.route('/devices')
@zero_trust_guard('dashboard')
def device_management() -> Union[str, Any]:
    """Renders the User Device Management page."""
    with closing(get_db()) as conn:
        devices = conn.execute("SELECT * FROM devices WHERE user_id=?", (session['user_id'],)).fetchall()
    return render_template('device.html', devices=devices)

@app.route('/api/iot/register', methods=['POST'])
def iot_register():
    data = request.json
    if not data or 'device_id' not in data:
        return jsonify({"status": "error", "message": "Missing device_id"}), 400
        
    device_id = data.get('device_id')
    secret = secrets.token_hex(16)
    
    # In real world, this would be an authenticated user action
    # For demo, we just create it linked to a default user or passed user_id
    # Let's assume passed user_id for simplicity or 1
    user_id = data.get('user_id', 1) 
    
    with closing(get_db()) as conn:
        try:
            conn.execute("INSERT INTO iot_devices (device_id, secret_key, name, owner_id) VALUES (?, ?, ?, ?)",
                         (device_id, secret, data.get('name', 'New IoT'), user_id))
            conn.commit()
            return jsonify({"status": "success", "secret_key": secret})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)})

@app.route('/api/login', methods=['POST'])
def api_login() -> Tuple[Any, int]:
    """
    API endpoint for user login via JSON credentials.
    
    Returns:
        JSON response containing JWT token or error.
    """
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    with closing(get_db()) as conn:
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    
    if user and check_password_hash(user['password_hash'], password):
        # Issue JWT
        token = jwt.encode({
            'user_id': user['id'],
            'role': user['role'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, JWT_SECRET, algorithm="HS256")
        
        return jsonify({"token": token})
    
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/api/secure-data')
@api_zero_trust_guard('dashboard') # Reuse dashboard policy
def api_secure_data():
    return jsonify({"data": "This is sensitive data protected by Zero Trust", "status": "secure"})

@app.route('/logout')
def logout() -> Any:
    """Logs out the current user and clears session."""
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
