"""
routes/dashboard.py — Main portal dashboard for The PenTrix
"""
from flask import Blueprint, request, session, redirect, render_template, jsonify
from db import get_db
from flags import get_flag

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard')
def index():
    if 'user_id' not in session:
        return redirect('/login')
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', [session['user_id']]).fetchone()
    
    # Get stats
    posts_count = db.execute('SELECT COUNT(*) as c FROM posts').fetchone()['c']
    messages_count = db.execute('SELECT COUNT(*) as c FROM messages WHERE recipient_id=?', [session['user_id']]).fetchone()['c']
    tickets_count = db.execute('SELECT COUNT(*) as c FROM tickets WHERE user_id=?', [session['user_id']]).fetchone()['c']
    files_count = db.execute('SELECT COUNT(*) as c FROM files WHERE user_id=?', [session['user_id']]).fetchone()['c']
    
    # Get recent posts
    recent_posts = db.execute('SELECT p.*, u.username FROM posts p JOIN users u ON p.user_id=u.id ORDER BY p.created_at DESC LIMIT 5').fetchall()
    
    # Get unread messages
    unread = db.execute('SELECT COUNT(*) as c FROM messages WHERE recipient_id=? AND is_read=0', [session['user_id']]).fetchone()['c']
    
    # Auth flag from login
    auth_flag = session.pop('auth_flag', None)
    
    return render_template('dashboard/index.html',
        user=user,
        posts_count=posts_count,
        messages_count=messages_count,
        tickets_count=tickets_count,
        files_count=files_count,
        recent_posts=recent_posts,
        unread_messages=unread,
        auth_flag=auth_flag
    )


# [VULN: CH08-C01] Reflected XSS in search
@dashboard_bp.route('/search')
def search():
    if 'user_id' not in session:
        return redirect('/login')
    
    q = request.args.get('q', '')
    db = get_db()
    
    # [VULN: CH16-C05] Blind SQLi (boolean-based) on search
    # [VULN: CH08-C01] Query reflected without sanitization in template
    try:
        results = db.execute(
            f"SELECT * FROM posts WHERE title LIKE '%{q}%' OR content LIKE '%{q}%'"
        ).fetchall()
    except Exception as e:
        results = []
    
    flag = None
    if '<script>' in q.lower() or 'onerror' in q.lower() or 'onload' in q.lower():
        flag = get_flag('CH08-C01')
    
    return render_template('dashboard/search.html', query=q, results=results, flag=flag)


# [VULN: CH16-C06] Time-based blind SQLi on sort parameter
@dashboard_bp.route('/employees')
def employees():
    if 'user_id' not in session:
        return redirect('/login')
    
    sort = request.args.get('sort', 'id')
    order = request.args.get('order', 'ASC')
    
    db = get_db()
    
    # [VULN: CH16-C08] SQLi in ORDER BY clause
    try:
        users = db.execute(f"SELECT id, username, display_name, email, role FROM users ORDER BY {sort} {order}").fetchall()
    except Exception:
        users = db.execute("SELECT id, username, display_name, email, role FROM users ORDER BY id ASC").fetchall()
    
    return render_template('dashboard/employees.html', employees=users, sort=sort, order=order)
