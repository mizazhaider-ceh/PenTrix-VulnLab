"""
routes/profile.py — User profile routes for The PenTrix
Contains INTENTIONAL vulnerabilities: IDOR, XSS, CSRF, mass assignment
"""
from flask import Blueprint, request, session, redirect, render_template, jsonify
from db import get_db
from flags import get_flag

profile_bp = Blueprint('profile', __name__)

# [VULN: CH03-C01] IDOR — no authorization check on profile view
@profile_bp.route('/profile/<int:user_id>')
def view_profile(user_id):
    db = get_db()
    
    # INTENTIONALLY VULNERABLE: no check that user_id == session user
    user = db.execute("SELECT * FROM users WHERE id=?", [user_id]).fetchone()
    
    if not user:
        return "User not found", 404
    
    # [VULN: CH03-C01] Returns ALL fields including salary, SSN, password
    flag = None
    if 'user_id' in session and session['user_id'] != user_id:
        flag = get_flag('CH03-C01')
    
    return render_template('dashboard/profile.html', user=user, flag=flag)


# [VULN: CH03-C04 / CH10-C01] Profile update — no CSRF, no auth check, mass assignment
@profile_bp.route('/profile/<int:user_id>/update', methods=['POST'])
def update_profile(user_id):
    db = get_db()
    
    # [VULN: CH03-C04] No check that the user owns this profile
    # [VULN: CH07-C06] Hidden POST parameter acceptance
    updates = []
    params = []
    
    # Accept ANY field — mass assignment vulnerability
    allowed_fields = ['display_name', 'email', 'password', 'role', 'is_active', 'salary', 'ssn', 'balance']
    
    for field in allowed_fields:
        value = request.form.get(field)
        if value is not None:
            updates.append(f"{field} = ?")
            params.append(value)
    
    flag = None
    if updates:
        params.append(user_id)
        query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
        db.execute(query, params)
        db.commit()
        
        # Check for horizontal privilege escalation
        if 'user_id' in session and session['user_id'] != user_id:
            flag = get_flag('CH03-C04')
        
        # Check for hidden parameter usage
        if request.form.get('salary') or request.form.get('role'):
            flag = get_flag('CH07-C06')
    
    return jsonify({'success': True, 'flag': flag})


# [VULN: CH16-C04] Error-based SQLi on profile search
@profile_bp.route('/profile/search')
def search_profile():
    q = request.args.get('q', '')
    db = get_db()
    
    # [VULN: CH16-C04] Error-based SQLi
    try:
        result = db.execute(f"SELECT * FROM users WHERE username='{q}' OR display_name='{q}'").fetchall()
        users = [dict(u) for u in result]
        return jsonify({'results': users})
    except Exception as e:
        # [VULN: CH02-C05] Verbose error with DB info
        flag = get_flag('CH16-C04')
        return jsonify({'error': str(e), 'flag': flag, 'database': 'SQLite'}), 500
