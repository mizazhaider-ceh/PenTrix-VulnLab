"""
routes/auth.py — Authentication routes for The PenTrix
Contains INTENTIONAL vulnerabilities: SQLi, broken auth, weak sessions, JWT bypass
"""
import base64
import hashlib
import time
import jwt as pyjwt
from flask import Blueprint, request, session, redirect, render_template, jsonify, make_response
from db import get_db
from flags import get_flag

auth_bp = Blueprint('auth', __name__)

# [VULN: CH06-C10] Weak JWT secret
JWT_SECRET = 'super_secret_key_12345'

# ═══════════════════════════════════════
# LOGIN — [VULN: CH16-C01] SQL Injection in login
# ═══════════════════════════════════════
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    flag = None
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        db = get_db()
        
        # [VULN: CH16-C01] INTENTIONALLY VULNERABLE: raw string SQL injection
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        
        try:
            user = db.execute(query).fetchone()
            
            if user:
                # [VULN: CH06-C04] Short predictable session ID
                session_id = hashlib.md5(f"{user['id']}{time.time()}".encode()).hexdigest()[:8]
                
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                session['session_id'] = session_id
                
                # [VULN: CH06-C07] Weak "remember me" cookie
                if request.form.get('remember'):
                    resp = make_response(redirect('/dashboard'))
                    # Cookie is just base64(username:role) — easily forgeable
                    cookie_val = base64.b64encode(f"{user['username']}:{user['role']}".encode()).decode()
                    resp.set_cookie('remember_me', cookie_val, max_age=86400*30)
                    # [VULN: CH04-C09] Sensitive data in cookies
                    resp.set_cookie('user_session_debug', f"uid={user['id']}|role={user['role']}|db=sqlite:///app/data/pentrix.db", max_age=86400)
                    resp.set_cookie('pentrix_env', 'development', max_age=86400)
                    resp.set_cookie('internal_api', 'http://internal:8080', max_age=86400)
                    return resp
                
                # Check for default creds — flag for CH06-C01
                if username == 'admin' and password == 'admin':
                    flag = get_flag('CH06-C01')
                    session['auth_flag'] = flag
                
                # [VULN: CH06-C05] Empty password bypass
                if password == '' and user:
                    flag = get_flag('CH06-C05')
                
                return redirect('/dashboard')
            else:
                # [VULN: CH06-C09] Different error messages reveal valid usernames
                user_check = db.execute(f"SELECT * FROM users WHERE username='{username}'").fetchone()
                if user_check:
                    error = "Invalid password for this account"  # Reveals username exists
                else:
                    error = "Username not found"  # Reveals username doesn't exist
        except Exception as e:
            # [VULN: CH02-C05] Verbose SQL error with database type info
            error = f"Database error: {str(e)}"
    
    return render_template('auth/login.html', error=error, flag=flag)


# ═══════════════════════════════════════
# REGISTER — [VULN: CH03-C10] Mass assignment
# ═══════════════════════════════════════
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    success = None
    flag = None
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        email = request.form.get('email', '')
        
        # [VULN: CH03-C10] Mass assignment — accepts any field from the form
        role = request.form.get('role', 'user')
        is_admin = request.form.get('is_admin', '0')
        
        if role != 'user' or is_admin == '1':
            flag = get_flag('CH03-C10')
        
        db = get_db()
        
        try:
            actual_role = role if role in ('user', 'admin', 'superadmin') else 'user'
            
            db.execute(
                'INSERT INTO users (username, password, email, role, email_verified) VALUES (?, ?, ?, ?, 0)',
                [username, password, email, actual_role]
            )
            db.commit()
            
            success = "Registration successful! Please login."
            if flag:
                success += f" {flag}"
                
        except Exception as e:
            error = f"Registration failed: {str(e)}"
    
    return render_template('auth/register.html', error=error, success=success, flag=flag)


# ═══════════════════════════════════════
# LOGOUT
# ═══════════════════════════════════════
@auth_bp.route('/logout')
def logout():
    # [VULN: CH06-C06] Session not properly invalidated — token can be reused
    session.clear()
    return redirect('/login')


# ═══════════════════════════════════════
# PASSWORD RESET — [VULN: CH06-C03] Predictable token
# ═══════════════════════════════════════
@auth_bp.route('/reset', methods=['GET', 'POST'])
def reset_password():
    message = None
    flag = None
    
    if request.method == 'POST':
        email = request.form.get('email', '')
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email=?', [email]).fetchone()
        
        if user:
            # [VULN: CH06-C03] Sequential predictable reset token
            new_seq = (user['token_seq'] or 0) + 1
            # Token is just base64 of the sequential number — trivially predictable
            token = base64.b64encode(str(new_seq).encode()).decode()
            
            db.execute('UPDATE users SET reset_token=?, token_seq=? WHERE id=?',
                       [token, new_seq, user['id']])
            db.commit()
            
            message = f"Password reset token sent to {email}. Token: {token} (In production this would be emailed)"
        else:
            message = "If this email exists, you will receive a reset link."
    
    return render_template('auth/reset.html', message=message, flag=flag)


@auth_bp.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    message = None
    flag = None
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE reset_token=?', [token]).fetchone()
    
    if not user:
        return render_template('auth/reset_confirm.html', error="Invalid reset token", flag=None)
    
    if request.method == 'POST':
        new_password = request.form.get('password', '')
        
        # [VULN: CH06-C08] Token not invalidated after use — can be reused
        db.execute('UPDATE users SET password=? WHERE id=?', [new_password, user['id']])
        db.commit()
        
        flag = get_flag('CH06-C08')
        message = f"Password reset successful! {flag}"
    
    return render_template('auth/reset_confirm.html', message=message, flag=flag, token=token)


# ═══════════════════════════════════════
# JWT TOKEN — [VULN: CH06-C10] algorithm=none bypass
# ═══════════════════════════════════════
@auth_bp.route('/api/token', methods=['POST'])
def get_jwt_token():
    username = request.form.get('username', request.json.get('username', '') if request.is_json else '')
    password = request.form.get('password', request.json.get('password', '') if request.is_json else '')
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username=? AND password=?', [username, password]).fetchone()
    
    if user:
        payload = {
            'user_id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'iat': int(time.time())
        }
        token = pyjwt.encode(payload, JWT_SECRET, algorithm='HS256')
        return jsonify({'token': token})
    
    return jsonify({'error': 'Invalid credentials'}), 401


@auth_bp.route('/api/token/verify')
def verify_jwt_token():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not token:
        token = request.args.get('token', '')
    
    # [VULN: CH06-C10] Accepts algorithm=none — verify_signature disabled
    try:
        payload = pyjwt.decode(
            token,
            options={"verify_signature": False}  # INTENTIONALLY VULNERABLE
        )
        flag = get_flag('CH06-C10')
        payload['flag'] = flag
        return jsonify(payload)
    except Exception as e:
        return jsonify({'error': str(e)}), 401


# ═══════════════════════════════════════
# REMEMBER ME — [VULN: CH06-C07] Weak cookie forgery
# ═══════════════════════════════════════
@auth_bp.route('/auto-login')
def auto_login():
    cookie = request.cookies.get('remember_me', '')
    if cookie:
        try:
            decoded = base64.b64decode(cookie).decode()
            username, role = decoded.split(':')
            
            db = get_db()
            user = db.execute('SELECT * FROM users WHERE username=?', [username]).fetchone()
            
            if user:
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = role  # Uses role from cookie, not DB!
                
                flag = get_flag('CH06-C07')
                return redirect(f'/dashboard?msg=Auto-login+successful+{flag}')
        except Exception:
            pass
    
    return redirect('/login')


# ═══════════════════════════════════════
# SESSION FIXATION — [VULN: CH06-C04]
# ═══════════════════════════════════════
@auth_bp.route('/set-session')
def set_session():
    """Allows setting a session ID externally — enables session fixation."""
    sid = request.args.get('sid', '')
    if sid:
        session['session_id'] = sid
        flag = get_flag('CH06-C04')
        return jsonify({'session_id': sid, 'flag': flag, 'message': 'Session ID set externally'})
    return jsonify({'error': 'Provide sid parameter'}), 400
