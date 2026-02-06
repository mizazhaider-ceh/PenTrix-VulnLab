"""
routes/admin.py — Admin panel for The PenTrix
Contains INTENTIONAL vulnerabilities: Broken Access Control, data exposure
"""
from flask import Blueprint, request, session, redirect, render_template, jsonify
from db import get_db
from flags import get_flag

admin_bp = Blueprint('admin', __name__)

# [VULN: CH03-C03] Admin panel — no role check
@admin_bp.route('/admin')
@admin_bp.route('/admin/')
def admin_panel():
    # INTENTIONALLY VULNERABLE: no authentication or role check
    # Any logged-in user (or even unauthenticated) can access
    
    db = get_db()
    users = db.execute('SELECT * FROM users').fetchall()
    posts_count = db.execute('SELECT COUNT(*) as c FROM posts').fetchone()['c']
    tickets_count = db.execute('SELECT COUNT(*) as c FROM tickets').fetchone()['c']
    users_count = len(users)
    
    # Build stats dict expected by template
    stats = {
        'total_users': users_count,
        'total_posts': posts_count,
        'total_tickets': tickets_count
    }
    
    # Fetch recent access logs for admin panel
    logs = db.execute('SELECT * FROM access_logs ORDER BY id DESC LIMIT 50').fetchall()
    
    flag = get_flag('CH03-C03')
    
    # Check if user is NOT an admin — proves broken access control
    is_unauthorized = True
    if 'role' in session and session['role'] in ('admin', 'superadmin'):
        is_unauthorized = False
    
    return render_template('dashboard/admin.html',
        users=users,
        stats=stats,
        logs=logs,
        posts_count=posts_count,
        tickets_count=tickets_count,
        flag=flag if is_unauthorized else None,
        is_unauthorized=is_unauthorized
    )


# [VULN: CH03-C06 / CH04-C07] Admin users endpoint — exposes passwords
@admin_bp.route('/admin/users')
def admin_users():
    db = get_db()
    # [VULN: CH03-C06] No authentication check
    # [VULN: CH04-C07] Returns ALL fields including password hashes
    users = db.execute('SELECT * FROM users').fetchall()
    
    flag_access = get_flag('CH03-C06')
    flag_data = get_flag('CH04-C07')
    
    user_list = []
    for u in users:
        user_list.append({
            'id': u['id'],
            'username': u['username'],
            'password': u['password'],  # [VULN: CH04-C07] Password exposed!
            'email': u['email'],
            'role': u['role'],
            'salary': u['salary'],
            'ssn': u['ssn'],
            'created_at': u['created_at']
        })
    
    return jsonify({
        'users': user_list,
        'flag_access': flag_access,
        'flag_data_exposure': flag_data
    })


# [VULN: CH03-C05] Vertical privilege escalation via API
@admin_bp.route('/admin/users/<int:user_id>/role', methods=['POST'])
def change_role(user_id):
    # INTENTIONALLY VULNERABLE: no role check on the caller
    new_role = request.form.get('role', request.json.get('role', 'user') if request.is_json else 'user')
    
    db = get_db()
    db.execute("UPDATE users SET role=? WHERE id=?", [new_role, user_id])
    db.commit()
    
    flag = get_flag('CH03-C05')
    return jsonify({'success': True, 'user_id': user_id, 'new_role': new_role, 'flag': flag})


# [VULN: CH03-C08] API admin config — no auth
@admin_bp.route('/api/admin/config')
def api_admin_config():
    # INTENTIONALLY VULNERABLE: no authentication required
    flag = get_flag('CH03-C08')
    
    return jsonify({
        'app_name': 'PenTrix Corp Internal Portal',
        'version': '1.3.2',
        'debug': True,
        'secret_key': 'super_secret_key_12345',
        'database_url': 'sqlite:////app/data/pentrix.db',
        'internal_service': 'http://internal:8080',
        'redis_url': 'redis://redis:6379/0',
        'api_key': 'sk-pentrix-internal-key-9876',
        'flag': flag
    })
